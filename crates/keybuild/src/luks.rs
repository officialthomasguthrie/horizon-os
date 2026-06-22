//! LUKS2 over the Home writable layer: encrypted persistence for a Known Surface.
//!
//! The immutable base is read-only and tamper-evident (dm-verity), but a device that
//! remembers also has a writable layer, the OverlayFS upper where this machine's OS
//! state accumulates. On a Home (Known) Surface that layer persists across power-offs,
//! so it must be encrypted at rest: a lost or stolen Key reveals nothing without the
//! identity. This module is the producer of that layer: a LUKS2 volume keyed by the one
//! 32-byte master everything turns on (`docs/03-PORTABILITY-AND-BOOT.md` 4, Tails'
//! LUKS2 + Argon2id persistence is the reference design).
//!
//! The key is the master itself, not a second passphrase. Everything in Horizon derives
//! from that master (the Lifestream addresses with it, the Constellation binds Noise to
//! it, Reconstitution splits it), and `boot` recovers it from the identity store with a
//! touch or a passphrase. Keying the writable layer with the master means one unlock at
//! boot gates everything: recover the master, then `luksOpen` the layer with it. The
//! store stays on a plain, readable partition (its confidentiality is the Lifestream's
//! own object encryption), so it can be read to recover the master before the encrypted
//! layer is opened, which is what breaks the circularity.
//!
//! Unlike `verity`, this shells out to `cryptsetup` rather than owning the format, and
//! the reasons are the inverse of verity's. LUKS2's on-disk format is genuinely complex
//! and security-critical (a binary header, a JSON metadata area, Argon2id-sealed
//! keyslots, AEAD keyslot areas), so reimplementing it would be a large, fragile
//! surface. Verity owned its format because the kernel consumer (`CONFIG_DM_VERITY`) was
//! absent here, so the real open could not be tested and matching `veritysetup`
//! byte-for-byte was the only proof available; here `CONFIG_DM_CRYPT=y`, so a real
//! `luksFormat`/`luksOpen` runs in the build container and the whole round-trip is
//! proven end to end. And reproducibility, which argued for owning the verity tree, cuts
//! the other way: the writable layer is per-device mutable state, and LUKS deliberately
//! uses a random volume key and random salts, so a byte-reproducible container would be
//! a security regression.
//!
//! The split is the usual one. The argv construction is pure and unit-tested on every
//! host ([`luks_format_args`], [`luks_open_args`]); the execution (`luksFormat`,
//! `luksOpen`, `mkfs.ext4` inside, `luksClose`) needs device-mapper, so it runs and is
//! proven for real where that is permitted (the privileged container) and skips
//! gracefully where it is not (an unprivileged CI runner), exactly as the mount tests
//! do.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::{Error, Result};

/// The size in bytes of the raw master key cryptsetup reads from stdin. Fixed so the
/// read is exact: a raw master can contain a newline byte, and cryptsetup's `--key-file`
/// otherwise stops at the first newline, so `--keyfile-size 32` is what makes it take
/// all 32 bytes regardless of content.
pub const MASTER_KEY_SIZE: usize = 32;

/// The label written on the ext4 filesystem inside the LUKS2 container, and the label
/// the encrypted writable partition itself carries on a real Key, so the init finds it
/// the way it finds the base and the store: by label, no device path hardcoded.
pub const HOME_LABEL: &str = "HORIZON-HOME";

/// The cryptsetup argv (after the program name) to format `container` as a LUKS2 volume
/// keyed by a 32-byte master read from stdin. Pure, so it is asserted with no cryptsetup:
///
/// - `--type luks2`: the modern format (JSON metadata, Argon2id), not legacy LUKS1.
/// - `--batch-mode`: no interactive "this will overwrite" confirmation, since the build
///   tool drives it.
/// - `--pbkdf argon2id`: the memory-hard KDF Tails' persistence uses; also cryptsetup's
///   own LUKS2 default, named explicitly so the build does not drift if that changes.
/// - `--key-file -` with `--keyfile-size 32`: read exactly the 32-byte master from stdin,
///   so the master never touches disk as a key file.
pub fn luks_format_args(container: &Path) -> Vec<String> {
    vec![
        "luksFormat".into(),
        "--type".into(),
        "luks2".into(),
        "--batch-mode".into(),
        "--pbkdf".into(),
        "argon2id".into(),
        "--key-file".into(),
        "-".into(),
        "--keyfile-size".into(),
        MASTER_KEY_SIZE.to_string(),
        container.to_string_lossy().into_owned(),
    ]
}

/// The cryptsetup argv to open `container` with the 32-byte master from stdin, exposing
/// the decrypted volume at `/dev/mapper/<mapper>`. The inverse of [`luks_format_args`]'s
/// key handling, so the same master that formatted it opens it.
pub fn luks_open_args(container: &Path, mapper: &str) -> Vec<String> {
    vec![
        "luksOpen".into(),
        "--key-file".into(),
        "-".into(),
        "--keyfile-size".into(),
        MASTER_KEY_SIZE.to_string(),
        container.to_string_lossy().into_owned(),
        mapper.into(),
    ]
}

/// The cryptsetup argv to close (tear down the device-mapper node for) `mapper`.
pub fn luks_close_args(mapper: &str) -> Vec<String> {
    vec!["luksClose".into(), mapper.into()]
}

/// The path the kernel exposes an opened LUKS volume at.
pub fn mapper_path(mapper: &str) -> PathBuf {
    Path::new("/dev/mapper").join(mapper)
}

/// Format `container` as a LUKS2 volume keyed by `master`. Writes only the LUKS header
/// and keyslot to the container (no device-mapper, so this part needs no privilege), and
/// the master is fed on stdin so it is never written to disk as a key file.
pub fn format(container: &Path, master: &[u8; MASTER_KEY_SIZE]) -> Result<()> {
    run_with_key(&luks_format_args(container), master)
}

/// Open `container` with `master`, exposing the decrypted volume at `/dev/mapper/<mapper>`,
/// and return that path. Needs device-mapper (`CAP_SYS_ADMIN` and `CONFIG_DM_CRYPT`), so
/// it runs where that is permitted. A wrong master fails here rather than opening a
/// volume it cannot decrypt.
pub fn open(container: &Path, master: &[u8; MASTER_KEY_SIZE], mapper: &str) -> Result<PathBuf> {
    run_with_key(&luks_open_args(container, mapper), master)?;
    Ok(mapper_path(mapper))
}

/// Close the device-mapper node `mapper`. Best paired with [`open`] in a way that closes
/// even when the work in between fails, so a build does not leak an open mapping.
pub fn close(mapper: &str) -> Result<()> {
    let mut cmd = Command::new("cryptsetup");
    cmd.args(luks_close_args(mapper))
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    finish(cmd, "cryptsetup")
}

/// Whether `container` holds a LUKS volume, by `cryptsetup isLuks` (exit 0 if so). Used
/// by tests to confirm the producer wrote a real LUKS header.
pub fn is_luks(container: &Path) -> bool {
    Command::new("cryptsetup")
        .arg("isLuks")
        .arg(container)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// Run a cryptsetup command that reads the 32-byte master from stdin, then check its exit.
// The key is written to the child's stdin and the pipe closed, so cryptsetup reads
// exactly the master (with --keyfile-size 32) and the master never lands in a file or an
// argument visible in the process list.
fn run_with_key(args: &[String], master: &[u8; MASTER_KEY_SIZE]) -> Result<()> {
    let mut child = match Command::new("cryptsetup")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::Missing("cryptsetup"))
        }
        Err(e) => return Err(Error::Io(e)),
    };
    // Write the master and drop the handle so cryptsetup sees EOF; a broken pipe (the
    // child rejected the args before reading) is reported by the exit status below.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(master);
    }
    let out = child.wait_with_output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(Error::Tool {
            name: "cryptsetup",
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        })
    }
}

// Run a cryptsetup command that needs no key on stdin (close) and check its exit.
fn finish(mut cmd: Command, name: &'static str) -> Result<()> {
    match cmd.output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(Error::Tool {
            name,
            code: o.status.code(),
            stderr: String::from_utf8_lossy(&o.stderr).trim().to_string(),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::Missing(name)),
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_args_request_luks2_argon2id_and_an_exact_32_byte_key() {
        let args = luks_format_args(Path::new("/out/home.img"));
        // The modern format, the memory-hard KDF, and the batch flag the build needs.
        assert!(args.iter().any(|a| a == "luksFormat"));
        let pos = |s: &str| args.iter().position(|a| a == s);
        assert_eq!(args[pos("--type").unwrap() + 1], "luks2");
        assert_eq!(args[pos("--pbkdf").unwrap() + 1], "argon2id");
        assert!(args.iter().any(|a| a == "--batch-mode"));
        // The key comes from stdin, exactly 32 bytes, so a master with a newline is not
        // truncated and never becomes a file.
        assert_eq!(args[pos("--key-file").unwrap() + 1], "-");
        assert_eq!(args[pos("--keyfile-size").unwrap() + 1], "32");
        assert_eq!(args.last().unwrap(), "/out/home.img");
    }

    #[test]
    fn open_args_mirror_the_format_key_handling() {
        let args = luks_open_args(Path::new("/out/home.img"), "horizon-home");
        assert!(args.iter().any(|a| a == "luksOpen"));
        let pos = |s: &str| args.iter().position(|a| a == s).unwrap();
        assert_eq!(args[pos("--key-file") + 1], "-");
        assert_eq!(args[pos("--keyfile-size") + 1], "32");
        // The container then the mapper name are the trailing positional args.
        assert_eq!(args[args.len() - 2], "/out/home.img");
        assert_eq!(args[args.len() - 1], "horizon-home");
    }

    #[test]
    fn close_args_and_mapper_path() {
        assert_eq!(luks_close_args("m"), vec!["luksClose", "m"]);
        assert_eq!(
            mapper_path("horizon-home"),
            Path::new("/dev/mapper/horizon-home")
        );
    }
}
