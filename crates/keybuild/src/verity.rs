//! dm-verity over the immutable base: a SHA-256 Merkle hash tree that makes the
//! read-only base tamper-evident.
//!
//! The base is mounted read-only, but read-only is not the same as trusted: a Key's base
//! partition could be rewritten offline. dm-verity closes that by hashing the base into a
//! Merkle tree whose single root hash is the trust anchor. The kernel checks every base
//! block against the tree on read and the tree against the root, so a single flipped byte
//! anywhere in the base is caught the moment it is read, and the root is small enough to
//! carry through a trusted channel (a signed initramfs, a measured boot). See
//! `docs/03-PORTABILITY-AND-BOOT.md`.
//!
//! This module is the producer: it builds the hash tree and superblock in the exact
//! on-disk format `veritysetup` writes (so the kernel's `dm-verity` target opens it
//! unchanged) and returns the root hash. It owns the format rather than shelling out to
//! `veritysetup` for the same reasons the rest of keybuild owns its formats: the build
//! stays reproducible and runs on any host, and the security-critical core is pure logic
//! tested everywhere. The proof it is byte-exact is a gated test that cross-checks the
//! output against `veritysetup format` itself; the kernel-side open is eye-verified by
//! booting, since this build container's kernel lacks `CONFIG_DM_VERITY`.
//!
//! The format implemented is the cryptsetup default: superblock version 1, hash type 1
//! (the salt is prepended to each hashed block), SHA-256 digests, 4096-byte data and hash
//! blocks. Levels are hashed bottom-up (leaves over the data blocks, then each level over
//! the full padded blocks beneath it) and laid out on the hash device top level first,
//! leaves last, with the superblock occupying the first hash block.

use sha2::{Digest, Sha256};

/// SHA-256 digest length, the size of one hash in the tree.
pub const DIGEST_SIZE: usize = 32;

/// The default data and hash block size, matching veritysetup's default.
pub const DEFAULT_BLOCK_SIZE: u32 = 4096;

/// The reproducible salt prepended to every hashed block. dm-verity stores the salt in the
/// clear in the superblock; its only job is to keep one image's hashes from being reused to
/// attack another, so a fixed per-build salt is exactly right for a reproducible OS base
/// (every Horizon base of a version then has the same root hash). 32 printable bytes, so it
/// is legible in a hexdump of the superblock.
pub const DEFAULT_SALT: [u8; 32] = *b"horizon-os immutable base verity";

/// The reproducible UUID written into the superblock. Fixed for the same reason as the
/// salt: a reproducible base is byte-identical, UUID included. 16 printable bytes.
pub const DEFAULT_UUID: [u8; 16] = *b"horizonbaseverit";

/// The parameters of a verity build. The defaults are veritysetup's defaults plus
/// Horizon's reproducible salt and UUID, so a base built with [`VerityParams::default`]
/// is byte-for-byte reproducible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerityParams {
    pub data_block_size: u32,
    pub hash_block_size: u32,
    /// Prepended to each hashed block (hash type 1). Up to 256 bytes; empty is valid.
    pub salt: Vec<u8>,
    pub uuid: [u8; 16],
}

impl Default for VerityParams {
    fn default() -> VerityParams {
        VerityParams {
            data_block_size: DEFAULT_BLOCK_SIZE,
            hash_block_size: DEFAULT_BLOCK_SIZE,
            salt: DEFAULT_SALT.to_vec(),
            uuid: DEFAULT_UUID,
        }
    }
}

/// A built verity hash device: the bytes to write alongside the base, plus the root hash
/// that anchors them and the shape that produced it.
#[derive(Debug, Clone)]
pub struct Verity {
    /// The hash device image: the superblock block followed by the hash tree, ready to
    /// write to a file or partition and hand to the kernel's `dm-verity` target.
    pub hash_device: Vec<u8>,
    /// The Merkle root: the trust anchor, hash of the topmost tree block.
    pub root_hash: [u8; DIGEST_SIZE],
    /// How many data blocks the base was divided into.
    pub data_blocks: u64,
    /// The number of tree levels (1 when every data-block hash fits in one block).
    pub levels: usize,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub salt: Vec<u8>,
    pub uuid: [u8; 16],
}

impl Verity {
    /// The root hash as lowercase hex, the form `veritysetup` prints and a boot command
    /// line carries.
    pub fn root_hex(&self) -> String {
        to_hex(&self.root_hash)
    }
}

/// Build the verity hash device over `data`, the bytes of the base image. Pure: the same
/// data and params always yield the same hash device and root, so the result can be
/// asserted with no kernel and the base stays reproducible.
pub fn format(data: &[u8], params: &VerityParams) -> Verity {
    let dbs = params.data_block_size as usize;
    let hbs = params.hash_block_size as usize;
    let hashes_per_block = hbs / DIGEST_SIZE;
    // At least one block, so an (unrealistically) empty base still has a one-block tree.
    let data_blocks = (data.len().div_ceil(dbs)).max(1) as u64;

    // A single data block is the degenerate tree: veritysetup stores no hash blocks at all
    // and the root hashes the one data block directly (the hash device is just the
    // superblock). With two or more blocks the leaf level below holds the data-block hashes
    // and is stored, so this only diverges at the smallest size.
    if data_blocks == 1 {
        let root_hash = hash_data_block(&params.salt, &data[..data.len().min(dbs)], dbs);
        return Verity {
            hash_device: superblock(params, data_blocks),
            root_hash,
            data_blocks,
            levels: 0,
            data_block_size: params.data_block_size,
            hash_block_size: params.hash_block_size,
            salt: params.salt.clone(),
            uuid: params.uuid,
        };
    }

    // The leaf level: one SHA-256(salt || data_block) per data block, packed
    // hashes_per_block to a hash block, the trailing slots of the last block left zero.
    let leaf_blocks = (data_blocks as usize).div_ceil(hashes_per_block);
    let mut leaves = vec![0u8; leaf_blocks * hbs];
    for (i, slot) in leaves
        .chunks_exact_mut(DIGEST_SIZE)
        .take(data_blocks as usize)
        .enumerate()
    {
        let start = i * dbs;
        let end = (start + dbs).min(data.len());
        slot.copy_from_slice(&hash_data_block(&params.salt, &data[start..end], dbs));
    }

    // Stack levels upward: each level hashes the full (padded) blocks of the level below,
    // until a level is a single block. levels[0] is the leaves; the last is the top.
    let mut levels: Vec<Vec<u8>> = vec![leaves];
    while levels.last().unwrap().len() / hbs > 1 {
        let below = levels.last().unwrap();
        let below_blocks = below.len() / hbs;
        let up_blocks = below_blocks.div_ceil(hashes_per_block);
        let mut up = vec![0u8; up_blocks * hbs];
        for (slot, block) in up
            .chunks_exact_mut(DIGEST_SIZE)
            .zip(below.chunks_exact(hbs))
        {
            slot.copy_from_slice(&hash_block(&params.salt, block));
        }
        levels.push(up);
    }

    // The root anchors the tree: SHA-256(salt || top block).
    let top = levels.last().unwrap();
    let root_hash = hash_block(&params.salt, top);

    // The hash device: the superblock block, then the levels top first and leaves last,
    // the layout veritysetup writes and the kernel reads.
    let mut hash_device = superblock(params, data_blocks);
    for level in levels.iter().rev() {
        hash_device.extend_from_slice(level);
    }

    Verity {
        hash_device,
        root_hash,
        data_blocks,
        levels: levels.len(),
        data_block_size: params.data_block_size,
        hash_block_size: params.hash_block_size,
        salt: params.salt.clone(),
        uuid: params.uuid,
    }
}

// Hash one data block, zero-padding a short trailing block up to the data block size first
// (the last base block when the image is not a block multiple). The common full block is
// hashed in place with no copy.
fn hash_data_block(salt: &[u8], block: &[u8], data_block_size: usize) -> [u8; DIGEST_SIZE] {
    if block.len() == data_block_size {
        hash_block(salt, block)
    } else {
        let mut padded = vec![0u8; data_block_size];
        padded[..block.len()].copy_from_slice(block);
        hash_block(salt, &padded)
    }
}

// SHA-256(salt || block), the hash type 1 (salt-prepended) digest dm-verity uses.
fn hash_block(salt: &[u8], block: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(block);
    h.finalize().into()
}

// The dm-verity superblock (512 bytes of fields, little-endian) padded to one hash block,
// the first block of the hash device. Layout is the kernel's `struct verity_sb`.
fn superblock(params: &VerityParams, data_blocks: u64) -> Vec<u8> {
    let mut sb = vec![0u8; params.hash_block_size as usize];
    sb[0..8].copy_from_slice(b"verity\0\0"); // signature
    sb[8..12].copy_from_slice(&1u32.to_le_bytes()); // version
    sb[12..16].copy_from_slice(&1u32.to_le_bytes()); // hash type 1 (salt prepended)
    sb[16..32].copy_from_slice(&params.uuid);
    sb[32..38].copy_from_slice(b"sha256"); // algorithm, rest of the 32 bytes left zero
    sb[64..68].copy_from_slice(&params.data_block_size.to_le_bytes());
    sb[68..72].copy_from_slice(&params.hash_block_size.to_le_bytes());
    sb[72..80].copy_from_slice(&data_blocks.to_le_bytes());
    let salt = &params.salt[..params.salt.len().min(256)];
    sb[80..82].copy_from_slice(&(salt.len() as u16).to_le_bytes());
    // bytes 82..88 are padding
    sb[88..88 + salt.len()].copy_from_slice(salt);
    sb
}

/// Format 16 raw UUID bytes as the canonical `8-4-4-4-12` hex string, the form
/// `veritysetup --uuid` takes, so the cross-check can drive veritysetup with the same
/// UUID this module writes.
pub fn format_uuid(uuid: &[u8; 16]) -> String {
    let h = to_hex(uuid);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // hashes_per_block for the default 4096/32: 128 hashes to a block.
    const HPB: usize = (DEFAULT_BLOCK_SIZE as usize) / DIGEST_SIZE;

    fn block_aligned(blocks: usize) -> Vec<u8> {
        // Distinct, non-zero per-block content so block hashes differ.
        let dbs = DEFAULT_BLOCK_SIZE as usize;
        let mut v = vec![0u8; blocks * dbs];
        for (i, b) in v.iter_mut().enumerate() {
            *b = (i % 251) as u8 + 1;
        }
        v
    }

    #[test]
    fn one_data_block_stores_only_the_superblock() {
        // The degenerate tree veritysetup writes: a single data block stores no hash blocks,
        // so the hash device is just the superblock and the root hashes the data directly.
        let v = format(&block_aligned(1), &VerityParams::default());
        assert_eq!(v.data_blocks, 1);
        assert_eq!(v.levels, 0);
        assert_eq!(v.hash_device.len(), DEFAULT_BLOCK_SIZE as usize);
    }

    #[test]
    fn levels_grow_with_the_data() {
        // Up to hashes_per_block leaves fit in a single hash block: still one level.
        let v = format(&block_aligned(HPB), &VerityParams::default());
        assert_eq!(v.data_blocks, HPB as u64);
        assert_eq!(v.levels, 1);

        // One more data block needs a second leaf block, hence a level above to cover them.
        let v = format(&block_aligned(HPB + 1), &VerityParams::default());
        assert_eq!(v.levels, 2);
        // Two leaf blocks + one level-1 block + the superblock.
        assert_eq!(v.hash_device.len(), 4 * DEFAULT_BLOCK_SIZE as usize);

        // Just past hashes_per_block^2 leaf-coverage needs a third level.
        let v = format(&block_aligned(HPB * HPB + 1), &VerityParams::default());
        assert_eq!(v.levels, 3);
    }

    #[test]
    fn hash_device_size_matches_the_level_sizes() {
        // 200 data blocks: ceil(200/128)=2 leaf blocks, ceil(2/128)=1 top block.
        let v = format(&block_aligned(200), &VerityParams::default());
        assert_eq!(v.levels, 2);
        let hbs = DEFAULT_BLOCK_SIZE as usize;
        // superblock + 1 top + 2 leaves.
        assert_eq!(v.hash_device.len(), (1 + 1 + 2) * hbs);
    }

    #[test]
    fn superblock_fields_are_the_dm_verity_layout() {
        let v = format(&block_aligned(200), &VerityParams::default());
        let sb = &v.hash_device[..DEFAULT_BLOCK_SIZE as usize];
        assert_eq!(&sb[0..8], b"verity\0\0");
        assert_eq!(u32::from_le_bytes(sb[8..12].try_into().unwrap()), 1); // version
        assert_eq!(u32::from_le_bytes(sb[12..16].try_into().unwrap()), 1); // hash type
        assert_eq!(&sb[16..32], &DEFAULT_UUID);
        assert_eq!(&sb[32..38], b"sha256");
        assert_eq!(&sb[38..64], &[0u8; 26]); // algorithm name zero-padded
        assert_eq!(
            u32::from_le_bytes(sb[64..68].try_into().unwrap()),
            DEFAULT_BLOCK_SIZE
        );
        assert_eq!(
            u32::from_le_bytes(sb[68..72].try_into().unwrap()),
            DEFAULT_BLOCK_SIZE
        );
        assert_eq!(u64::from_le_bytes(sb[72..80].try_into().unwrap()), 200);
        assert_eq!(u16::from_le_bytes(sb[80..82].try_into().unwrap()), 32); // salt size
        assert_eq!(&sb[88..88 + 32], &DEFAULT_SALT);
    }

    #[test]
    fn build_is_deterministic() {
        let data = block_aligned(200);
        let a = format(&data, &VerityParams::default());
        let b = format(&data, &VerityParams::default());
        assert_eq!(a.hash_device, b.hash_device);
        assert_eq!(a.root_hash, b.root_hash);
    }

    #[test]
    fn a_flipped_data_byte_changes_the_root() {
        // The whole point: tamper is detected. A single bit elsewhere in the base must
        // move the root hash, so a modified base fails verification against the anchor.
        let data = block_aligned(200);
        let base = format(&data, &VerityParams::default());

        let mut tampered = data.clone();
        tampered[5 * DEFAULT_BLOCK_SIZE as usize] ^= 0x01;
        let after = format(&tampered, &VerityParams::default());
        assert_ne!(base.root_hash, after.root_hash);
        assert_ne!(base.hash_device, after.hash_device);
    }

    #[test]
    fn the_salt_changes_the_root() {
        let data = block_aligned(8);
        let a = format(&data, &VerityParams::default());
        let params = VerityParams {
            salt: b"a different salt of any length..".to_vec(),
            ..VerityParams::default()
        };
        let b = format(&data, &params);
        assert_ne!(a.root_hash, b.root_hash);
    }

    #[test]
    fn root_of_one_zero_block_is_the_pinned_sha256() {
        // Pin the primitive wiring with a value computed independently, so a wrong hash
        // (BLAKE3, a wrong salt order) cannot pass: one data block of all zeros, no salt. A
        // single block is the degenerate tree, so the root is just SHA-256 of the 4096-zero
        // data block. SHA-256(zeros[4096]) is a known value (and `veritysetup format` itself
        // prints exactly this for a one-block, no-salt device).
        let params = VerityParams {
            data_block_size: 4096,
            hash_block_size: 4096,
            salt: Vec::new(),
            uuid: DEFAULT_UUID,
        };
        let v = format(&vec![0u8; 4096], &params);
        assert_eq!(v.levels, 0);
        assert_eq!(v.hash_device.len(), 4096); // superblock only
        assert_eq!(
            v.root_hex(),
            "ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
            "a single block's root must be plain salt-free SHA-256 of the data block"
        );
    }

    #[test]
    fn uuid_formats_canonically() {
        // 0x00,0x11,...,0xff packs into the canonical 8-4-4-4-12 grouping.
        let bytes: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_eq!(format_uuid(&bytes), "00112233-4455-6677-8899-aabbccddeeff");
        // The default UUID round-trips to legible hex of its printable bytes.
        assert_eq!(
            format_uuid(&DEFAULT_UUID),
            "686f7269-7a6f-6e62-6173-657665726974"
        );
    }
}
