//! A minimal FAT filesystem (FAT16/FAT32) over the EFI System Partition: the partition
//! firmware reads the bootloader from, and where the kernel and initramfs live.
//!
//! A Horizon Key's other partitions are squashfs/ext4/LUKS, which the kernel mounts but
//! firmware does not understand; the one partition UEFI firmware reads directly is the ESP,
//! and the ESP is FAT. keybuild produces every other filesystem itself (see
//! [`mod@crate::verity`] and [`mod@crate::gpt`]), so it produces this one too. The build
//! container has no `mkfs.fat`/`mtools`, exactly the verity/gpt situation, so this module
//! owns the FAT format in pure Rust for the same reasons: the layout is a deterministic
//! function of the contents, so a Key is reproducible and builds on any host, and the format
//! is fiddly-but-not-secret pure logic tested everywhere. The proof it is byte-correct is a
//! gated container test that loop-mounts the self-built ESP as `vfat` and reads its files
//! back (the kernel's own FAT driver is the cross-check, like the GPT loop test and verity's
//! `veritysetup` cross-check); firmware reading it is eye-verified by booting.
//!
//! Scope is deliberately minimal: 512-byte sectors, two FATs, files and subdirectories. A
//! name that fits an 8.3 short name is written as one (uppercased, the reproducible default
//! the existing tree relies on); a longer name (systemd-boot's `loader.conf` and
//! `entries/*.conf`, whose four-character extensions do not fit 8.3) is written as VFAT
//! long-name (LFN) entries with a generated `~N` short alias, the same way `mkfs.fat`/`mtools`
//! would, so a loader that reads its config by long name finds it. The FAT type is chosen by
//! volume size so a real ESP is FAT32 (the firmware-friendly default) and small volumes are
//! FAT16, always respecting the Microsoft cluster-count thresholds so firmware that keys off
//! the count agrees with the BPB this writes, and never landing on FAT12.

use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The logical sector size. 512 is universal and what the BPB's `256`-based FAT-size formula
/// assumes; the rest of keybuild (GPT, the partition images) uses it too.
pub const SECTOR: usize = 512;

/// The media descriptor byte: 0xF8, "fixed disk", the value for a hard disk or a partition.
/// It appears both in the BPB and as the low byte of FAT entry 0, which must match.
const MEDIA: u8 = 0xF8;

/// FAT16's fixed root-directory capacity, in 32-byte entries. 512 is the conventional value
/// (a whole 32 sectors of root), far more than an ESP's handful of top-level entries needs.
const FAT16_ROOT_ENTRIES: u64 = 512;

/// FAT32's first data cluster, which holds the root directory. Cluster numbering starts at 2
/// (0 and 1 are the reserved FAT entries), so the data region's first cluster is always 2.
const FAT32_ROOT_CLUSTER: u32 = 2;

/// Directory entry attribute bits.
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
/// The attribute marking a long-name slot (read-only + hidden + system + volume-id), the value
/// a FAT reader keys on to tell an LFN entry from a real 8.3 one.
const ATTR_LONG_NAME: u8 = 0x0F;

/// A fixed timestamp stamped on every directory entry so the image is byte-reproducible (the
/// same reason verity pins its salt and UUID). FAT dates cannot be zero (day and month are
/// 1-based), so this is the FAT epoch, 1980-01-01 (year field 0, month 1, day 1), with a zero
/// time of day.
const FIXED_DATE: u16 = (1 << 5) | 1;
const FIXED_TIME: u16 = 0;

/// Whether the ESP is formatted FAT16 or FAT32, decided from the volume size. The threshold
/// is 64 MiB: at or above it a volume has comfortably more than the 65525 clusters FAT32
/// requires (so a real ESP is FAT32, which firmware supports most universally), below it the
/// volume is FAT16. The Microsoft rule is that cluster count alone decides the type; this
/// picks geometry so the count agrees with the type written, and [`format`] asserts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatType {
    Fat16,
    Fat32,
}

/// The cosmetic and reproducibility parameters of a FAT volume: the OEM name in the boot
/// sector, the 11-byte volume label, and the volume id. [`Params::for_label`] derives a
/// stable id from the label so the same label yields the same volume.
#[derive(Debug, Clone)]
pub struct Params {
    pub oem_name: [u8; 8],
    pub volume_label: [u8; 11],
    pub volume_id: u32,
}

impl Params {
    /// Parameters for a volume labeled `label` (truncated to 11 chars, uppercased,
    /// space-padded, the FAT label form). The volume id is derived one-way from the label so
    /// it is stable across builds, the way [`crate::gpt::Guid::derive`] makes the disk GUIDs
    /// reproducible.
    pub fn for_label(label: &str) -> Params {
        let mut h = Sha256::new();
        h.update(b"horizon-fat:");
        h.update(label.as_bytes());
        let d = h.finalize();
        Params {
            oem_name: *b"HORIZON ",
            volume_label: label_field(label),
            volume_id: u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
        }
    }
}

/// One node in the directory tree to lay into the volume: a file with its bytes, or a
/// subdirectory.
enum Node {
    File(Vec<u8>),
    Dir(Dir),
}

/// One named child of a directory: the name exactly as requested (case preserved, for the
/// long-name entry when it does not fit an 8.3 short name) and its node.
struct Child {
    name: String,
    node: Node,
}

/// A directory tree to write into a FAT volume. Build one with [`Dir::new`] and
/// [`Dir::insert_file`]/[`Dir::mkdir`], then hand it to [`format`]. Entries are keyed by the
/// uppercased name (FAT is case-insensitive, so this dedups case variants) in a sorted map,
/// so the on-disk order, and thus the image, is deterministic.
#[derive(Default)]
pub struct Dir {
    entries: BTreeMap<String, Child>,
}

impl Dir {
    pub fn new() -> Dir {
        Dir::default()
    }

    /// Insert a file at `path` (slash-separated, e.g. `EFI/BOOT/BOOTX64.EFI`), creating the
    /// intermediate directories. Each component is either a valid 8.3 short name (written
    /// uppercased, no long-name entry) or a longer name (written with VFAT long-name entries
    /// and a generated short alias, e.g. `loader.conf`). Errors on a name that is neither (an
    /// illegal character, an empty or reserved name) or a path that runs through an existing
    /// file.
    pub fn insert_file(&mut self, path: &str, data: Vec<u8>) -> Result<()> {
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        let Some((file, dirs)) = parts.split_last() else {
            return Err(Error::BadName(path.to_string()));
        };
        let mut cur = self;
        for d in dirs {
            cur = cur.child_dir(d)?;
        }
        validate_name(file)?;
        cur.entries.insert(
            file.to_ascii_uppercase(),
            Child {
                name: file.to_string(),
                node: Node::File(data),
            },
        );
        Ok(())
    }

    /// Create a directory at `path` (and any parents), so an empty directory like
    /// `/EFI/BOOT` exists even before a file is placed in it.
    pub fn mkdir(&mut self, path: &str) -> Result<()> {
        let mut cur = self;
        for p in path.split('/').filter(|p| !p.is_empty()) {
            cur = cur.child_dir(p)?;
        }
        Ok(())
    }

    /// Descend into (or create) the subdirectory named `name`, validating the name. Errors if
    /// the path runs through an existing file.
    fn child_dir(&mut self, name: &str) -> Result<&mut Dir> {
        validate_name(name)?;
        let child = self
            .entries
            .entry(name.to_ascii_uppercase())
            .or_insert_with(|| Child {
                name: name.to_string(),
                node: Node::Dir(Dir::new()),
            });
        match &mut child.node {
            Node::Dir(sub) => Ok(sub),
            Node::File(_) => Err(Error::BadName(name.to_string())),
        }
    }
}

/// The computed geometry of a FAT volume: the sizes and offsets every region is laid out
/// from. Pure arithmetic over the volume size, so it is asserted with no kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Geometry {
    fat_type: FatType,
    sectors_per_cluster: u64,
    reserved_sectors: u64,
    num_fats: u64,
    root_entries: u64,     // FAT16: 512; FAT32: 0
    root_dir_sectors: u64, // FAT16: 32; FAT32: 0 (root is a cluster chain)
    fat_size: u64,         // sectors per FAT copy
    total_sectors: u64,
    cluster_count: u64,
}

impl Geometry {
    fn cluster_bytes(&self) -> u64 {
        self.sectors_per_cluster * SECTOR as u64
    }
    fn fat_start_sector(&self) -> u64 {
        self.reserved_sectors
    }
    fn root_start_sector(&self) -> u64 {
        self.reserved_sectors + self.num_fats * self.fat_size
    }
    fn data_start_sector(&self) -> u64 {
        self.root_start_sector() + self.root_dir_sectors
    }
    /// The byte offset of cluster `n` (n >= 2) in the data region.
    fn cluster_offset(&self, n: u64) -> usize {
        ((self.data_start_sector() + (n - 2) * self.sectors_per_cluster) * SECTOR as u64) as usize
    }
    /// The highest valid cluster number (clusters run 2..=max).
    fn max_cluster(&self) -> u64 {
        self.cluster_count + 1
    }
    /// The end-of-chain marker the last cluster of a chain carries.
    fn eoc(&self) -> u32 {
        match self.fat_type {
            FatType::Fat16 => 0xFFFF,
            FatType::Fat32 => 0x0FFF_FFFF,
        }
    }
}

/// Decide the FAT type and cluster size for a volume of `total_sectors` 512-byte sectors, and
/// compute its full [`Geometry`]. FAT32 at or above 64 MiB, FAT16 below; the cluster size is
/// the smallest that keeps the count in the chosen type's valid range. Errors if the volume
/// is too small to be a valid FAT16 (which would fall into FAT12).
fn geometry(total_sectors: u64) -> Result<Geometry> {
    let num_fats = 2u64;

    // FAT32 for a real ESP (>= 64 MiB has well over the 65525 clusters FAT32 needs at any of
    // these cluster sizes); FAT16 for smaller volumes (a test ESP, say).
    if total_sectors >= 64 * 2048 {
        let spc = fat32_spc(total_sectors);
        let reserved = 32; // boot sector + FSInfo + backup boot sector + slack
        let fat_size = fat_size_sectors(total_sectors, spc, num_fats, reserved, 0, FatType::Fat32);
        let cluster_count = (total_sectors - (reserved + num_fats * fat_size)) / spc;
        return Ok(Geometry {
            fat_type: FatType::Fat32,
            sectors_per_cluster: spc,
            reserved_sectors: reserved,
            num_fats,
            root_entries: 0,
            root_dir_sectors: 0,
            fat_size,
            total_sectors,
            cluster_count,
        });
    }

    // FAT16: pick the smallest cluster size keeping the count at or below 65524, the largest
    // count that is still FAT16 rather than FAT32.
    let reserved = 1u64; // FAT16 needs only the boot sector reserved
    let root_dir_sectors = FAT16_ROOT_ENTRIES * 32 / SECTOR as u64;
    let mut spc = 1u64;
    let geom = loop {
        let fat_size = fat_size_sectors(
            total_sectors,
            spc,
            num_fats,
            reserved,
            root_dir_sectors,
            FatType::Fat16,
        );
        let cluster_count =
            (total_sectors - (reserved + num_fats * fat_size + root_dir_sectors)) / spc;
        if cluster_count <= 65524 {
            break Geometry {
                fat_type: FatType::Fat16,
                sectors_per_cluster: spc,
                reserved_sectors: reserved,
                num_fats,
                root_entries: FAT16_ROOT_ENTRIES,
                root_dir_sectors,
                fat_size,
                total_sectors,
                cluster_count,
            };
        }
        spc *= 2;
        if spc > 64 {
            // Unreachable for a < 64 MiB volume, but never loop forever.
            return Err(Error::EspTooSmall(total_sectors * SECTOR as u64));
        }
    };
    Ok(geom)
}

/// The cluster size (sectors per cluster) for a FAT32 volume of `total_sectors`, a coarse
/// version of the table mkfs.fat uses: 0.5 KiB clusters up to 256 MiB, 1 KiB to 512 MiB,
/// 4 KiB beyond. Keeps the FAT a sane size without ever dropping the count below 65525 for
/// the ESP sizes Horizon builds.
fn fat32_spc(total_sectors: u64) -> u64 {
    let mib = total_sectors / 2048;
    if mib <= 256 {
        1
    } else if mib <= 512 {
        2
    } else {
        8
    }
}

/// The Microsoft `fatgen` FAT-size formula: the sectors one FAT copy needs to map the data
/// region. It slightly over-allocates (safe: the spare entries stay zero), and it assumes
/// 512-byte sectors via the `256` constant (entries-per-sector for FAT16; halved for FAT32's
/// 4-byte entries).
fn fat_size_sectors(
    total_sectors: u64,
    spc: u64,
    num_fats: u64,
    reserved: u64,
    root_dir_sectors: u64,
    fat_type: FatType,
) -> u64 {
    let tmp1 = total_sectors - (reserved + root_dir_sectors);
    let mut tmp2 = 256 * spc + num_fats;
    if fat_type == FatType::Fat32 {
        tmp2 /= 2;
    }
    tmp1.div_ceil(tmp2)
}

/// Lay the directory tree `root` into a FAT volume of exactly `total_bytes` (a multiple of
/// 512, the partition image's size) and return the image bytes. Pure and reproducible: the
/// same tree, params, and size always yield the same bytes, so the result is asserted with no
/// kernel and an ESP is byte-for-byte reproducible. Errors if the volume is too small to
/// format or the contents do not fit.
pub fn format(total_bytes: u64, root: &Dir, params: &Params) -> Result<Vec<u8>> {
    if !total_bytes.is_multiple_of(SECTOR as u64) {
        return Err(Error::EspTooSmall(total_bytes));
    }
    let geom = geometry(total_bytes / SECTOR as u64)?;

    // The type the geometry produced must match what its cluster count implies, or firmware
    // that keys off the count would read the volume as a different type than the BPB declares.
    match geom.fat_type {
        FatType::Fat16 if !(4085..=65524).contains(&geom.cluster_count) => {
            return Err(Error::EspTooSmall(total_bytes));
        }
        FatType::Fat32 if geom.cluster_count < 65525 => {
            return Err(Error::EspTooSmall(total_bytes));
        }
        _ => {}
    }

    let mut b = Builder {
        geom,
        params,
        image: vec![0u8; total_bytes as usize],
        fat: vec![0u32; (geom.cluster_count + 2) as usize],
        next_free: 2,
    };
    // The two reserved FAT entries: entry 0 is the media byte in the low bits with the rest
    // set, entry 1 is an end-of-chain marker.
    b.fat[0] = match geom.fat_type {
        FatType::Fat16 => 0xFF00 | MEDIA as u32,
        FatType::Fat32 => 0x0FFF_FF00 | MEDIA as u32,
    };
    b.fat[1] = geom.eoc();

    // The root directory: a fixed region on FAT16, a cluster chain starting at cluster 2 on
    // FAT32. Either way it holds the volume label and the top-level entries (no dot entries).
    match geom.fat_type {
        FatType::Fat16 => {
            let count = content_slots(root, true); // volume label + entries (with any LFN slots)
            if count > geom.root_entries {
                return Err(Error::EspFull {
                    needed: count,
                    available: geom.root_entries,
                });
            }
            b.render_dir(root, None, 0, 0, true)?;
        }
        FatType::Fat32 => {
            let count = content_slots(root, true);
            let clusters = (count * 32).div_ceil(geom.cluster_bytes()).max(1);
            let chain = b.alloc_chain(clusters)?;
            debug_assert_eq!(chain[0], FAT32_ROOT_CLUSTER);
            b.render_dir(root, Some(&chain), FAT32_ROOT_CLUSTER, 0, true)?;
        }
    }

    b.write_fats();
    b.write_boot_sector();
    if geom.fat_type == FatType::Fat32 {
        b.write_fsinfo();
    }
    Ok(b.image)
}

/// The mutable state of one format pass: the image being filled, the in-memory FAT, and the
/// next free cluster to hand out.
struct Builder<'a> {
    geom: Geometry,
    params: &'a Params,
    image: Vec<u8>,
    fat: Vec<u32>,
    next_free: u32,
}

impl Builder<'_> {
    /// Hand out `n` contiguous free clusters as one chain, linking them in the FAT (each to
    /// the next, the last to end-of-chain). Returns the cluster numbers. Errors if the volume
    /// has no room left, which is how "contents do not fit" surfaces.
    fn alloc_chain(&mut self, n: u64) -> Result<Vec<u32>> {
        let first = self.next_free as u64;
        if n == 0 || first + n - 1 > self.geom.max_cluster() {
            return Err(Error::EspFull {
                needed: (first - 2) + n,
                available: self.geom.cluster_count,
            });
        }
        let chain: Vec<u32> = (self.next_free..self.next_free + n as u32).collect();
        for (i, &c) in chain.iter().enumerate() {
            self.fat[c as usize] = chain.get(i + 1).copied().unwrap_or_else(|| self.geom.eoc());
        }
        self.next_free += n as u32;
        Ok(chain)
    }

    /// Write `data` across the clusters of `chain`, zero-padding the last cluster.
    fn write_clusters(&mut self, chain: &[u32], data: &[u8]) {
        let cb = self.geom.cluster_bytes() as usize;
        for (i, &c) in chain.iter().enumerate() {
            let off = self.geom.cluster_offset(c as u64);
            let start = i * cb;
            if start >= data.len() {
                break;
            }
            let end = (start + cb).min(data.len());
            self.image[off..off + (end - start)].copy_from_slice(&data[start..end]);
        }
    }

    /// Render one directory: build its 32-byte entries (the volume label for the root, or
    /// `.`/`..` for a subdirectory, then one per child), allocating and filling each child's
    /// clusters, and write the entries into this directory's own storage (`self_chain`, or the
    /// fixed root region when `None`). Recurses into subdirectories. `parent_first` is the
    /// cluster a subdirectory's `..` points at (0 when the parent is the root).
    fn render_dir(
        &mut self,
        dir: &Dir,
        self_chain: Option<&[u32]>,
        self_first: u32,
        parent_first: u32,
        is_root: bool,
    ) -> Result<()> {
        let cb = self.geom.cluster_bytes();
        let mut buf: Vec<u8> = Vec::new();
        if is_root {
            buf.extend_from_slice(&entry(&self.params.volume_label, 0, 0, ATTR_VOLUME_ID));
        } else {
            buf.extend_from_slice(&entry(&dot_name("."), self_first, 0, ATTR_DIRECTORY));
            buf.extend_from_slice(&entry(&dot_name(".."), parent_first, 0, ATTR_DIRECTORY));
        }

        // A subdirectory's `..` must point at its parent, except the root, whose children use 0.
        let child_dotdot = if is_root { 0 } else { self_first };

        // Each child's on-disk short field (an 8.3 name, or a generated `~N` alias) plus, for a
        // long name, the full name to write as LFN entries just before its short entry.
        for (field, long, child) in plan_children(dir) {
            match &child.node {
                Node::File(data) => {
                    let first = if data.is_empty() {
                        0
                    } else {
                        let n = (data.len() as u64).div_ceil(cb);
                        let chain = self.alloc_chain(n)?;
                        self.write_clusters(&chain, data);
                        chain[0]
                    };
                    if let Some(name) = long {
                        buf.extend_from_slice(&lfn_entries(name, &field));
                    }
                    buf.extend_from_slice(&entry(&field, first, data.len() as u32, ATTR_ARCHIVE));
                }
                Node::Dir(sub) => {
                    // dot + dotdot + each child (with any LFN slots), in 32-byte slots.
                    let n = (content_slots(sub, false) * 32).div_ceil(cb).max(1);
                    let chain = self.alloc_chain(n)?;
                    let first = chain[0];
                    if let Some(name) = long {
                        buf.extend_from_slice(&lfn_entries(name, &field));
                    }
                    buf.extend_from_slice(&entry(&field, first, 0, ATTR_DIRECTORY));
                    self.render_dir(sub, Some(&chain), first, child_dotdot, false)?;
                }
            }
        }

        match self_chain {
            Some(chain) => self.write_clusters(chain, &buf),
            None => {
                // FAT16 root region; the entry count was checked to fit before rendering.
                let off = (self.geom.root_start_sector() * SECTOR as u64) as usize;
                self.image[off..off + buf.len()].copy_from_slice(&buf);
            }
        }
        Ok(())
    }

    /// Serialize the in-memory FAT and write all `num_fats` identical copies into the FAT
    /// region. FAT16 entries are 2 bytes, FAT32 4 bytes (top nibble reserved, kept zero).
    fn write_fats(&mut self) {
        let mut bytes = Vec::with_capacity(self.fat.len() * 4);
        for &e in &self.fat {
            match self.geom.fat_type {
                FatType::Fat16 => bytes.extend_from_slice(&(e as u16).to_le_bytes()),
                FatType::Fat32 => bytes.extend_from_slice(&(e & 0x0FFF_FFFF).to_le_bytes()),
            }
        }
        for i in 0..self.geom.num_fats {
            let off =
                ((self.geom.fat_start_sector() + i * self.geom.fat_size) * SECTOR as u64) as usize;
            self.image[off..off + bytes.len()].copy_from_slice(&bytes);
        }
    }

    /// Write the boot sector (the BIOS Parameter Block) at sector 0, and on FAT32 its backup
    /// copy at sector 6. UEFI ignores the boot code; only the BPB geometry matters here, so
    /// the code area stays zero apart from the jump and the 0x55AA signature.
    fn write_boot_sector(&mut self) {
        let g = &self.geom;
        let mut s = [0u8; SECTOR];
        // Jump over the BPB (the offset differs between the FAT16 and FAT32 BPB lengths) then
        // a NOP, the conventional opening bytes.
        s[0..3].copy_from_slice(match g.fat_type {
            FatType::Fat16 => &[0xEB, 0x3C, 0x90],
            FatType::Fat32 => &[0xEB, 0x58, 0x90],
        });
        s[3..11].copy_from_slice(&self.params.oem_name);
        s[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        s[13] = g.sectors_per_cluster as u8;
        s[14..16].copy_from_slice(&(g.reserved_sectors as u16).to_le_bytes());
        s[16] = g.num_fats as u8;
        s[17..19].copy_from_slice(&(g.root_entries as u16).to_le_bytes());
        // Total sectors: the 16-bit field if it fits and we are not FAT32, else the 32-bit one.
        let small = g.fat_type == FatType::Fat16 && g.total_sectors < 0x10000;
        s[19..21].copy_from_slice(&(if small { g.total_sectors as u16 } else { 0 }).to_le_bytes());
        s[21] = MEDIA;
        s[22..24].copy_from_slice(
            &(if g.fat_type == FatType::Fat16 {
                g.fat_size as u16
            } else {
                0
            })
            .to_le_bytes(),
        );
        s[24..26].copy_from_slice(&32u16.to_le_bytes()); // sectors per track (cosmetic)
        s[26..28].copy_from_slice(&64u16.to_le_bytes()); // heads (cosmetic)
                                                         // hidden sectors (28..32) stay 0: the partition's start LBA, which the kernel and UEFI
                                                         // ignore for mounting, and zero keeps the image reproducible regardless of placement.
        s[32..36].copy_from_slice(&(if small { 0 } else { g.total_sectors as u32 }).to_le_bytes());

        match g.fat_type {
            FatType::Fat16 => self.write_fat16_tail(&mut s),
            FatType::Fat32 => self.write_fat32_tail(&mut s),
        }
        s[510] = 0x55;
        s[511] = 0xAA;

        self.image[0..SECTOR].copy_from_slice(&s);
        if g.fat_type == FatType::Fat32 {
            let bk = 6 * SECTOR;
            self.image[bk..bk + SECTOR].copy_from_slice(&s);
        }
    }

    /// The FAT16 extended BPB tail (offsets 36..): drive number, the 0x29 extended signature,
    /// volume id, label, and the (informational) `FAT16` type string.
    fn write_fat16_tail(&self, s: &mut [u8; SECTOR]) {
        s[36] = 0x80; // BIOS drive number (cosmetic for an ESP)
        s[38] = 0x29; // extended boot signature: id, label, and type follow
        s[39..43].copy_from_slice(&self.params.volume_id.to_le_bytes());
        s[43..54].copy_from_slice(&self.params.volume_label);
        s[54..62].copy_from_slice(b"FAT16   ");
    }

    /// The FAT32 BPB tail (offsets 36..): the 32-bit FAT size, the root cluster, the FSInfo and
    /// backup-boot sector numbers, then the same extended fields as FAT16 at their shifted
    /// offsets and the `FAT32` type string.
    fn write_fat32_tail(&self, s: &mut [u8; SECTOR]) {
        let g = &self.geom;
        s[36..40].copy_from_slice(&(g.fat_size as u32).to_le_bytes());
        // ext flags (40..42) and fs version (42..44) stay 0: FATs mirrored, version 0.0.
        s[44..48].copy_from_slice(&FAT32_ROOT_CLUSTER.to_le_bytes());
        s[48..50].copy_from_slice(&1u16.to_le_bytes()); // FSInfo at sector 1
        s[50..52].copy_from_slice(&6u16.to_le_bytes()); // backup boot sector at sector 6
                                                        // reserved (52..64) stays 0.
        s[64] = 0x80; // drive number
        s[66] = 0x29; // extended boot signature
        s[67..71].copy_from_slice(&self.params.volume_id.to_le_bytes());
        s[71..82].copy_from_slice(&self.params.volume_label);
        s[82..90].copy_from_slice(b"FAT32   ");
    }

    /// The FAT32 FSInfo sector at sector 1 (and its backup at sector 7): the lead/struct/trail
    /// signatures plus the free-cluster count and next-free hint, so a mounting OS does not
    /// have to scan the whole FAT to learn them.
    fn write_fsinfo(&mut self) {
        let used = self.next_free as u64 - 2;
        let free = self.geom.cluster_count.saturating_sub(used);
        let mut s = [0u8; SECTOR];
        s[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes()); // "RRaA" lead signature
        s[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes()); // "rrAa" struct signature
        s[488..492].copy_from_slice(&(free as u32).to_le_bytes());
        s[492..496].copy_from_slice(&self.next_free.to_le_bytes());
        s[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes()); // trail signature
        let off = SECTOR; // sector 1
        self.image[off..off + SECTOR].copy_from_slice(&s);
        let bk = 7 * SECTOR; // backup FSInfo alongside the backup boot sector
        self.image[bk..bk + SECTOR].copy_from_slice(&s);
    }
}

/// Build one 32-byte directory entry from an 11-byte name field, first cluster, size, and
/// attribute byte, with the reproducible fixed timestamps.
fn entry(name: &[u8; 11], first_cluster: u32, size: u32, attr: u8) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0..11].copy_from_slice(name);
    e[11] = attr;
    // 12 reserved, 13 creation-time tenths: 0.
    e[14..16].copy_from_slice(&FIXED_TIME.to_le_bytes());
    e[16..18].copy_from_slice(&FIXED_DATE.to_le_bytes());
    e[18..20].copy_from_slice(&FIXED_DATE.to_le_bytes()); // last access date
    e[20..22].copy_from_slice(&((first_cluster >> 16) as u16).to_le_bytes());
    e[22..24].copy_from_slice(&FIXED_TIME.to_le_bytes());
    e[24..26].copy_from_slice(&FIXED_DATE.to_le_bytes());
    e[26..28].copy_from_slice(&((first_cluster & 0xFFFF) as u16).to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

/// The 11-byte name field for the `.` and `..` directory entries: the dots left-justified,
/// the rest spaces.
fn dot_name(dots: &str) -> [u8; 11] {
    let mut f = [b' '; 11];
    f[..dots.len()].copy_from_slice(dots.as_bytes());
    f
}

/// The 11-byte name field for a volume label: the label uppercased and space-padded.
fn label_field(label: &str) -> [u8; 11] {
    let mut f = [b' '; 11];
    for (i, b) in label.bytes().take(11).enumerate() {
        f[i] = b.to_ascii_uppercase();
    }
    f
}

/// Split a canonical `BASE.EXT` name (already validated) into its 11-byte 8.3 field: the base
/// in the first 8 bytes, the extension in the last 3, both space-padded.
fn to_field(canon: &str) -> [u8; 11] {
    let mut f = [b' '; 11];
    let (base, ext) = match canon.split_once('.') {
        Some((b, e)) => (b, e),
        None => (canon, ""),
    };
    f[..base.len()].copy_from_slice(base.as_bytes());
    f[8..8 + ext.len()].copy_from_slice(ext.as_bytes());
    f
}

/// Validate and canonicalize a file or directory name to an uppercase 8.3 short name (the map
/// key and display form, e.g. `BOOTX64.EFI`). Rejects a name whose base exceeds 8 or extension
/// 3 characters, an empty base, or a character outside the conservative short-name set
/// (letters, digits, and `-_~`).
fn canon_83(name: &str) -> Result<String> {
    let up = name.to_ascii_uppercase();
    let (base, ext) = match up.rsplit_once('.') {
        Some((b, e)) => (b, e),
        None => (up.as_str(), ""),
    };
    let ok = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || "-_~".contains(c))
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 || !ok(base) || !ok(ext) {
        return Err(Error::BadName(name.to_string()));
    }
    Ok(if ext.is_empty() {
        base.to_string()
    } else {
        format!("{base}.{ext}")
    })
}

/// Whether `name` fits an 8.3 short name and, if so, its 11-byte field. A fitting name needs
/// no long-name entry; it is written uppercased exactly as before LFN support existed, so an
/// all-8.3 tree is byte-for-byte unchanged.
fn fits_83(name: &str) -> Option<[u8; 11]> {
    canon_83(name).ok().map(|c| to_field(&c))
}

/// Validate a path component: it must be a usable 8.3 short name or a usable long name.
fn validate_name(name: &str) -> Result<()> {
    if fits_83(name).is_some() || is_long_name(name) {
        Ok(())
    } else {
        Err(Error::BadName(name.to_string()))
    }
}

/// Whether `name` is a usable VFAT long name: non-empty, at most 255 UCS-2 units, no path or
/// reserved character, no control character, not `.`/`..`, and not a name FAT would alter by
/// stripping a trailing dot or space. Characters outside the Basic Multilingual Plane (which
/// would need UTF-16 surrogate pairs) are rejected, since the writer emits one code unit per
/// character; every name Horizon writes is ASCII, so this never bites in practice.
fn is_long_name(name: &str) -> bool {
    let units = name.encode_utf16().count();
    (1..=255).contains(&units)
        && name != "."
        && name != ".."
        && !name.ends_with('.')
        && !name.ends_with(' ')
        && name.chars().all(|c| {
            let u = c as u32;
            (0x20..0xFFFF).contains(&u) && !"/\\:*?\"<>|".contains(c)
        })
}

/// The number of 32-byte long-name slots a child needs: zero for an 8.3 name, else one per 13
/// UCS-2 characters plus one for the NUL terminator (so a name whose length is a multiple of
/// 13 gets its own terminator slot, the conservative layout every FAT reader accepts).
fn lfn_slots(name: &str) -> u64 {
    if fits_83(name).is_some() {
        0
    } else {
        name.encode_utf16().count() as u64 / 13 + 1
    }
}

/// The number of 32-byte directory-entry slots a directory's contents occupy: the volume label
/// (root) or the `.`/`..` pair (subdirectory), plus, per child, one short entry and any
/// long-name slots. The cluster and FAT16-root-capacity sizing is computed from this, so the
/// storage allocated always matches what [`Builder::render_dir`] writes.
fn content_slots(dir: &Dir, is_root: bool) -> u64 {
    let base = if is_root { 1 } else { 2 };
    base + dir
        .entries
        .values()
        .map(|c| 1 + lfn_slots(&c.name))
        .sum::<u64>()
}

/// Decide each child's on-disk short field, in the directory's deterministic order: the 8.3
/// field when the name fits, else a `~N` alias unique among the directory's real short names
/// and the aliases already handed out, in which case the full name is carried alongside to be
/// written as long-name entries before the short one.
fn plan_children(dir: &Dir) -> Vec<([u8; 11], Option<&str>, &Child)> {
    let mut taken: BTreeSet<[u8; 11]> = dir
        .entries
        .values()
        .filter_map(|c| fits_83(&c.name))
        .collect();
    let mut plan = Vec::with_capacity(dir.entries.len());
    for child in dir.entries.values() {
        match fits_83(&child.name) {
            Some(field) => plan.push((field, None, child)),
            None => {
                let field = short_alias(&child.name, &taken);
                taken.insert(field);
                plan.push((field, Some(child.name.as_str()), child));
            }
        }
    }
    plan
}

/// A `BASE~N.EXT` 8.3 alias for a long name, unique among `taken`: the long name's base and
/// extension cleaned to the 8.3 character set (illegal characters mapped to `_`, dots and
/// spaces dropped), the base truncated to leave room for the `~N` tail, with N counting up
/// until the field is free. The numbering is deterministic given the directory's fixed order.
fn short_alias(long: &str, taken: &BTreeSet<[u8; 11]>) -> [u8; 11] {
    let up = long.to_ascii_uppercase();
    let (lbase, lext) = match up.rsplit_once('.') {
        Some((b, e)) => (b, e),
        None => (up.as_str(), ""),
    };
    let clean = |s: &str, n: usize| -> Vec<u8> {
        s.chars()
            .filter(|c| *c != ' ' && *c != '.')
            .map(|c| {
                if c.is_ascii_uppercase() || c.is_ascii_digit() || "-_~".contains(c) {
                    c as u8
                } else {
                    b'_'
                }
            })
            .take(n)
            .collect()
    };
    let ext = clean(lext, 3);
    for i in 1..=u32::MAX {
        let tail = format!("~{i}");
        let base = clean(lbase, 8usize.saturating_sub(tail.len()));
        let mut field = [b' '; 11];
        for (j, b) in base.iter().chain(tail.as_bytes()).take(8).enumerate() {
            field[j] = *b;
        }
        for (j, b) in ext.iter().enumerate() {
            field[8 + j] = *b;
        }
        if !taken.contains(&field) {
            return field;
        }
    }
    unreachable!("a free ~N alias always exists for a realistic directory")
}

/// The VFAT checksum of an 11-byte 8.3 field, carried in every long-name slot so a reader can
/// tell the slots belong to the short entry that follows. The standard rotate-right-and-add.
fn lfn_checksum(field: &[u8; 11]) -> u8 {
    let mut sum = 0u8;
    for &b in field {
        sum = (sum >> 1 | (sum & 1) << 7).wrapping_add(b);
    }
    sum
}

/// The long-name (LFN) directory entries for `long`, decorating the short entry whose field is
/// `short_field`. The name is encoded UCS-2, terminated with `0x0000` and padded with `0xFFFF`
/// to fill the last slot; the slots are emitted last-part-first (the on-disk order), each
/// carrying its 1-based sequence number (the first physical slot OR'd with `0x40`), the short
/// field's checksum, and 13 characters split 5/6/2 across the slot.
fn lfn_entries(long: &str, short_field: &[u8; 11]) -> Vec<u8> {
    let cksum = lfn_checksum(short_field);
    let mut units: Vec<u16> = long.encode_utf16().collect();
    let nslots = units.len() / 13 + 1;
    units.push(0x0000); // NUL terminator
    units.resize(nslots * 13, 0xFFFF); // pad the last slot with 0xFFFF

    let mut out = Vec::with_capacity(nslots * 32);
    for seq in (1..=nslots).rev() {
        let chars = &units[(seq - 1) * 13..seq * 13];
        let mut e = [0u8; 32];
        e[0] = seq as u8 | if seq == nslots { 0x40 } else { 0 };
        e[11] = ATTR_LONG_NAME;
        e[13] = cksum; // 12 (type) and 26..28 (first-cluster-low) stay zero
        let put = |e: &mut [u8; 32], at: usize, c: u16| {
            e[at..at + 2].copy_from_slice(&c.to_le_bytes());
        };
        for (k, &c) in chars[0..5].iter().enumerate() {
            put(&mut e, 1 + k * 2, c);
        }
        for (k, &c) in chars[5..11].iter().enumerate() {
            put(&mut e, 14 + k * 2, c);
        }
        for (k, &c) in chars[11..13].iter().enumerate() {
            put(&mut e, 28 + k * 2, c);
        }
        out.extend_from_slice(&e);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal independent FAT reader, the pure cross-check (the kernel mount is the gated
    // container one): parse the BPB, walk a directory, follow a file's cluster chain. Proves
    // the writer produced a coherent filesystem, not just plausible-looking bytes.
    struct Reader<'a> {
        img: &'a [u8],
        fat_type: FatType,
        spc: u64,
        reserved: u64,
        num_fats: u64,
        root_entries: u64,
        fat_size: u64,
        root_cluster: u32,
    }

    impl<'a> Reader<'a> {
        fn new(img: &'a [u8]) -> Reader<'a> {
            let u16le = |o: usize| u16::from_le_bytes(img[o..o + 2].try_into().unwrap()) as u64;
            let u32le = |o: usize| u32::from_le_bytes(img[o..o + 4].try_into().unwrap()) as u64;
            let spc = img[13] as u64;
            let reserved = u16le(14);
            let num_fats = img[16] as u64;
            let root_entries = u16le(17);
            let fat16_size = u16le(22);
            let total = if u16le(19) != 0 { u16le(19) } else { u32le(32) };
            let root_dir_sectors = root_entries * 32 / SECTOR as u64;
            // FAT32 is exactly the case where the 16-bit FAT size is zero.
            let (fat_type, fat_size, root_cluster) = if fat16_size == 0 {
                (FatType::Fat32, u32le(36), u32le(44) as u32)
            } else {
                (FatType::Fat16, fat16_size, 0)
            };
            // Sanity: the declared type must match the cluster count, the rule the writer keeps.
            let data = total - (reserved + num_fats * fat_size + root_dir_sectors);
            let count = data / spc;
            match fat_type {
                FatType::Fat16 => assert!((4085..=65524).contains(&count), "count {count}"),
                FatType::Fat32 => assert!(count >= 65525, "count {count}"),
            }
            Reader {
                img,
                fat_type,
                spc,
                reserved,
                num_fats,
                root_entries,
                fat_size,
                root_cluster,
            }
        }

        fn fat_next(&self, c: u32) -> u32 {
            let base = self.reserved * SECTOR as u64;
            match self.fat_type {
                FatType::Fat16 => {
                    let o = (base + c as u64 * 2) as usize;
                    u16::from_le_bytes(self.img[o..o + 2].try_into().unwrap()) as u32
                }
                FatType::Fat32 => {
                    let o = (base + c as u64 * 4) as usize;
                    u32::from_le_bytes(self.img[o..o + 4].try_into().unwrap()) & 0x0FFF_FFFF
                }
            }
        }

        fn is_eoc(&self, c: u32) -> bool {
            match self.fat_type {
                FatType::Fat16 => c >= 0xFFF8,
                FatType::Fat32 => c >= 0x0FFF_FFF8,
            }
        }

        fn data_start(&self) -> u64 {
            let root_dir_sectors = self.root_entries * 32 / SECTOR as u64;
            self.reserved + self.num_fats * self.fat_size + root_dir_sectors
        }

        fn cluster_off(&self, c: u32) -> usize {
            ((self.data_start() + (c as u64 - 2) * self.spc) * SECTOR as u64) as usize
        }

        // Read a directory's raw 32-byte entries by following its cluster chain (or the fixed
        // root region for FAT16's root, passed as cluster 0).
        fn dir_bytes(&self, first_cluster: u32, is_fat16_root: bool) -> Vec<u8> {
            if is_fat16_root {
                let off =
                    ((self.reserved + self.num_fats * self.fat_size) * SECTOR as u64) as usize;
                let len = (self.root_entries * 32) as usize;
                return self.img[off..off + len].to_vec();
            }
            let mut out = Vec::new();
            let mut c = first_cluster;
            let csize = (self.spc * SECTOR as u64) as usize;
            while !self.is_eoc(c) && c >= 2 {
                let off = self.cluster_off(c);
                out.extend_from_slice(&self.img[off..off + csize]);
                c = self.fat_next(c);
            }
            out
        }

        fn root_bytes(&self) -> Vec<u8> {
            match self.fat_type {
                FatType::Fat16 => self.dir_bytes(0, true),
                FatType::Fat32 => self.dir_bytes(self.root_cluster, false),
            }
        }

        // Find an entry by its 8.3 name in a directory's bytes, returning (first_cluster, size,
        // attr). `.` and `..` are matched directly, since they are not ordinary 8.3 names.
        fn find(&self, dir: &[u8], name: &str) -> Option<(u32, u32, u8)> {
            let want = if name == "." || name == ".." {
                dot_name(name)
            } else {
                to_field(&canon_83(name).unwrap())
            };
            for e in dir.chunks_exact(32) {
                if e[0] == 0x00 {
                    break; // no more entries
                }
                if e[0] == 0xE5 || e[11] == 0x0F {
                    continue; // deleted, or an LFN slot (we write none)
                }
                if e[0..11] == want {
                    let hi = u16::from_le_bytes(e[20..22].try_into().unwrap()) as u32;
                    let lo = u16::from_le_bytes(e[26..28].try_into().unwrap()) as u32;
                    let size = u32::from_le_bytes(e[28..32].try_into().unwrap());
                    return Some(((hi << 16) | lo, size, e[11]));
                }
            }
            None
        }

        fn read_file(&self, first_cluster: u32, size: u32) -> Vec<u8> {
            let mut out = Vec::new();
            let mut c = first_cluster;
            let csize = (self.spc * SECTOR as u64) as usize;
            while !self.is_eoc(c) && c >= 2 {
                let off = self.cluster_off(c);
                out.extend_from_slice(&self.img[off..off + csize]);
                c = self.fat_next(c);
            }
            out.truncate(size as usize);
            out
        }

        // Reconstruct the long names in a directory: for each real (short) entry preceded by LFN
        // slots, return (long_name, short_field, first_cluster, size). Each slot's checksum is
        // asserted against the short field (the tie a reader uses to bind the two), and the
        // slots are reassembled in sequence order, terminated at the first 0x0000. This is the
        // pure round-trip cross-check; the kernel's own vfat driver is the authoritative one in
        // the gated mount test.
        fn long_entries(&self, dir: &[u8]) -> Vec<(String, [u8; 11], u32, u32)> {
            // The 13 character byte offsets within a long-name entry: 5, then 6, then 2.
            const OFF: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
            let mut out = Vec::new();
            let mut slots: Vec<(u8, [u16; 13], u8)> = Vec::new();
            for e in dir.chunks_exact(32) {
                if e[0] == 0x00 {
                    break;
                }
                if e[0] == 0xE5 {
                    slots.clear();
                    continue;
                }
                if e[11] == ATTR_LONG_NAME {
                    let mut chars = [0u16; 13];
                    for (slot, &o) in chars.iter_mut().zip(OFF.iter()) {
                        *slot = u16::from_le_bytes(e[o..o + 2].try_into().unwrap());
                    }
                    slots.push((e[0] & 0x3F, chars, e[13]));
                    continue;
                }
                if !slots.is_empty() {
                    let field: [u8; 11] = e[0..11].try_into().unwrap();
                    let cksum = lfn_checksum(&field);
                    assert!(
                        slots.iter().all(|(_, _, c)| *c == cksum),
                        "every LFN slot must carry the short field's checksum"
                    );
                    slots.sort_by_key(|(seq, _, _)| *seq);
                    let mut units: Vec<u16> = Vec::new();
                    for (_, chars, _) in &slots {
                        units.extend_from_slice(chars);
                    }
                    if let Some(pos) = units.iter().position(|&c| c == 0x0000) {
                        units.truncate(pos);
                    }
                    let hi = u16::from_le_bytes(e[20..22].try_into().unwrap()) as u32;
                    let lo = u16::from_le_bytes(e[26..28].try_into().unwrap()) as u32;
                    let size = u32::from_le_bytes(e[28..32].try_into().unwrap());
                    out.push((
                        String::from_utf16(&units).unwrap(),
                        field,
                        (hi << 16) | lo,
                        size,
                    ));
                }
                slots.clear();
            }
            out
        }
    }

    fn mib(n: u64) -> u64 {
        n * 1024 * 1024
    }

    #[test]
    fn small_volume_is_fat16_large_is_fat32() {
        // The size threshold picks the type, and each lands in its valid cluster range so the
        // count agrees with the declared type (never FAT12).
        let g16 = geometry(mib(16) / SECTOR as u64).unwrap();
        assert_eq!(g16.fat_type, FatType::Fat16);
        assert!((4085..=65524).contains(&g16.cluster_count));

        let g32 = geometry(mib(96) / SECTOR as u64).unwrap();
        assert_eq!(g32.fat_type, FatType::Fat32);
        assert!(g32.cluster_count >= 65525);
        assert_eq!(g32.root_entries, 0);
        assert_eq!(g32.reserved_sectors, 32);
    }

    #[test]
    fn boot_sector_has_the_signature_and_geometry() {
        let img = format(mib(96), &Dir::new(), &Params::for_label("HORIZON-ESP")).unwrap();
        assert_eq!([img[510], img[511]], [0x55, 0xAA]);
        assert_eq!(u16::from_le_bytes(img[11..13].try_into().unwrap()), 512);
        assert_eq!(img[21], MEDIA);
        assert_eq!(&img[3..11], b"HORIZON ");
        // FAT32 declares zero root entries and a zero 16-bit FAT size; the type string is
        // informational but conventional tools read it.
        assert_eq!(u16::from_le_bytes(img[17..19].try_into().unwrap()), 0);
        assert_eq!(u16::from_le_bytes(img[22..24].try_into().unwrap()), 0);
        assert_eq!(&img[82..90], b"FAT32   ");
        // FSInfo lead and trail signatures at sector 1.
        assert_eq!(
            u32::from_le_bytes(img[512..516].try_into().unwrap()),
            0x4161_5252
        );
        assert_eq!(
            u32::from_le_bytes(img[512 + 508..512 + 512].try_into().unwrap()),
            0xAA55_0000
        );
        // Backup boot sector at sector 6 mirrors the primary.
        assert_eq!(&img[6 * SECTOR..6 * SECTOR + 11], &img[0..11]);
        assert_eq!([img[6 * SECTOR + 510], img[6 * SECTOR + 511]], [0x55, 0xAA]);
    }

    #[test]
    fn fat16_boot_sector_tail() {
        let img = format(mib(16), &Dir::new(), &Params::for_label("ESP")).unwrap();
        assert_eq!([img[510], img[511]], [0x55, 0xAA]);
        // FAT16 keeps a non-zero 16-bit FAT size and 512 root entries.
        assert_eq!(u16::from_le_bytes(img[17..19].try_into().unwrap()), 512);
        assert!(u16::from_le_bytes(img[22..24].try_into().unwrap()) > 0);
        assert_eq!(img[38], 0x29);
        assert_eq!(&img[54..62], b"FAT16   ");
    }

    #[test]
    fn reserved_fat_entries_carry_the_media_byte() {
        // Entry 0's low byte is the media descriptor; entry 1 is an end-of-chain value.
        let img32 = format(mib(96), &Dir::new(), &Params::for_label("ESP")).unwrap();
        let r = Reader::new(&img32);
        assert_eq!(r.fat_next(0) & 0xFF, MEDIA as u32);
        assert!(r.is_eoc(r.fat_next(1)));

        let img16 = format(mib(16), &Dir::new(), &Params::for_label("ESP")).unwrap();
        let r = Reader::new(&img16);
        assert_eq!(r.fat_next(0) & 0xFF, MEDIA as u32);
        assert!(r.is_eoc(r.fat_next(1)));
    }

    fn sample_tree() -> Dir {
        let mut root = Dir::new();
        root.insert_file("EFI/BOOT/BOOTX64.EFI", b"this is the bootloader".to_vec())
            .unwrap();
        root.insert_file("VMLINUZ", vec![0xAB; 5000]).unwrap();
        root.insert_file("INITRD.IMG", vec![0xCD; 100_000]).unwrap();
        root.insert_file("EMPTY.TXT", Vec::new()).unwrap();
        root
    }

    fn assert_tree_reads_back(img: &[u8]) {
        let r = Reader::new(img);
        let root = r.root_bytes();

        // A file at the root, spanning more than one cluster, reads back exactly.
        let (c, size, attr) = r.find(&root, "INITRD.IMG").expect("initrd entry");
        assert_eq!(attr & ATTR_DIRECTORY, 0);
        assert_eq!(size, 100_000);
        assert_eq!(r.read_file(c, size), vec![0xCD; 100_000]);

        let (c, size, _) = r.find(&root, "VMLINUZ").expect("vmlinuz entry");
        assert_eq!(r.read_file(c, size), vec![0xAB; 5000]);

        // An empty file has first cluster 0 and zero size.
        let (c, size, _) = r.find(&root, "EMPTY.TXT").expect("empty entry");
        assert_eq!((c, size), (0, 0));

        // Descend EFI/BOOT and read the bootloader, checking the dot entries on the way.
        let (efi_c, _, attr) = r.find(&root, "EFI").expect("EFI dir");
        assert_eq!(attr & ATTR_DIRECTORY, ATTR_DIRECTORY);
        let efi = r.dir_bytes(efi_c, false);
        // `.` points at the directory itself, `..` at the root (cluster 0 by convention).
        assert_eq!(r.find(&efi, ".").unwrap().0, efi_c);
        assert_eq!(r.find(&efi, "..").unwrap().0, 0);

        let (boot_c, _, _) = r.find(&efi, "BOOT").expect("BOOT dir");
        let boot = r.dir_bytes(boot_c, false);
        // `..` of BOOT points back at EFI, a non-root parent.
        assert_eq!(r.find(&boot, "..").unwrap().0, efi_c);
        let (f, size, _) = r.find(&boot, "BOOTX64.EFI").expect("bootloader entry");
        assert_eq!(r.read_file(f, size), b"this is the bootloader");
    }

    #[test]
    fn fat32_tree_round_trips() {
        let img = format(mib(96), &sample_tree(), &Params::for_label("HORIZON-ESP")).unwrap();
        assert_tree_reads_back(&img);
    }

    #[test]
    fn fat16_tree_round_trips() {
        // The same tree on a small volume exercises the fixed-root-region and 2-byte-FAT path.
        let img = format(mib(16), &sample_tree(), &Params::for_label("HORIZON-ESP")).unwrap();
        assert_tree_reads_back(&img);
    }

    #[test]
    fn volume_label_is_in_the_root() {
        let img = format(mib(96), &Dir::new(), &Params::for_label("HORIZON-ESP")).unwrap();
        let r = Reader::new(&img);
        let root = r.root_bytes();
        // The first root entry is the volume label, name field space-padded, attr 0x08.
        assert_eq!(root[11], ATTR_VOLUME_ID);
        assert_eq!(&root[0..11], b"HORIZON-ESP");
    }

    #[test]
    fn image_is_reproducible() {
        // Same tree, params, and size: byte-identical (fixed timestamps, derived volume id).
        let a = format(mib(96), &sample_tree(), &Params::for_label("HORIZON-ESP")).unwrap();
        let b = format(mib(96), &sample_tree(), &Params::for_label("HORIZON-ESP")).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len() as u64, mib(96));
    }

    #[test]
    fn contents_that_do_not_fit_are_refused() {
        // A file far larger than the volume cannot be placed: an honest error, not a corrupt
        // image with a truncated chain.
        let mut root = Dir::new();
        root.insert_file("BIG.BIN", vec![0u8; mib(20) as usize])
            .unwrap();
        match format(mib(16), &root, &Params::for_label("ESP")) {
            Err(Error::EspFull { .. }) => {}
            other => panic!("expected EspFull, got {other:?}"),
        }
    }

    #[test]
    fn bad_names_are_rejected() {
        let mut root = Dir::new();
        // A name too long for 8.3 is no longer an error: it becomes a long name (see the LFN
        // test). What stays rejected is a name with no valid spelling at all.
        assert!(root.insert_file("bad*char.txt", vec![1]).is_err()); // illegal character
        assert!(root.insert_file("a:b.txt", vec![1]).is_err()); // reserved character
        assert!(root.insert_file("", vec![1]).is_err()); // empty path
        assert!(root.mkdir(".").is_err()); // reserved name
        assert!(root.mkdir("..").is_err()); // reserved name
        assert!(root.insert_file(&"x".repeat(256), vec![1]).is_err()); // past the 255-unit limit
                                                                       // A lowercase 8.3 name is still accepted and uppercased, with no long-name entry.
        root.insert_file("efi/grub.cfg", vec![1]).unwrap();
        let img = format(mib(16), &root, &Params::for_label("ESP")).unwrap();
        let r = Reader::new(&img);
        let efi = r.dir_bytes(r.find(&r.root_bytes(), "EFI").unwrap().0, false);
        assert!(r.find(&efi, "GRUB.CFG").is_some());
    }

    #[test]
    fn long_names_round_trip_as_lfn() {
        // The systemd-boot config names, whose four-character `.conf` extension does not fit
        // 8.3: one in the root's `loader/` and one a level deeper in `entries/`, alongside an
        // ordinary 8.3 file. Both FAT types exercise the cluster-chain and fixed-root paths.
        let mut root = Dir::new();
        root.insert_file("loader/loader.conf", b"default horizon\n".to_vec())
            .unwrap();
        root.insert_file(
            "loader/entries/horizon.conf",
            b"title Horizon OS\n".to_vec(),
        )
        .unwrap();
        root.insert_file("VMLINUZ", vec![0xAB; 2048]).unwrap();

        for size_mb in [16u64, 96u64] {
            let img = format(mib(size_mb), &root, &Params::for_label("HORIZON-ESP")).unwrap();
            let r = Reader::new(&img);

            // `loader/` is an 8.3 directory; descend it and read loader.conf back by long name.
            let (loader_c, _, attr) = r.find(&r.root_bytes(), "LOADER").expect("loader dir");
            assert_eq!(attr & ATTR_DIRECTORY, ATTR_DIRECTORY);
            let loader = r.dir_bytes(loader_c, false);
            let conf = r
                .long_entries(&loader)
                .into_iter()
                .find(|(n, ..)| n == "loader.conf")
                .expect("loader.conf by its long name");
            // The long name is backed by a generated ~N short alias, never a truncated 8.3 name.
            assert!(conf.1.contains(&b'~'), "a long name gets a ~N short alias");
            assert_eq!(r.read_file(conf.2, conf.3), b"default horizon\n");

            // entries/horizon.conf, a long name one directory deeper.
            let (entries_c, _, _) = r.find(&loader, "ENTRIES").expect("entries dir");
            let entries = r.dir_bytes(entries_c, false);
            let hz = r
                .long_entries(&entries)
                .into_iter()
                .find(|(n, ..)| n == "horizon.conf")
                .expect("horizon.conf by its long name");
            assert_eq!(r.read_file(hz.2, hz.3), b"title Horizon OS\n");

            // The plain 8.3 file still reads back with no long-name entry at all.
            assert!(r.long_entries(&r.root_bytes()).is_empty());
            let (c, size, _) = r.find(&r.root_bytes(), "VMLINUZ").expect("vmlinuz");
            assert_eq!(r.read_file(c, size), vec![0xAB; 2048]);
        }
    }
}
