//! Keybuild: assemble the filesystems of a Horizon Key.
//!
//! A Horizon Key carries two filesystems (see `docs/03-PORTABILITY-AND-BOOT.md`): an
//! immutable base image, mounted read-only, holding the OS, and a persistent data
//! partition holding the writable overlay layer and the identity store. This crate is
//! the host-side tool that builds them. It is the producer side of the contract the
//! `init` crate consumes: keybuild writes the partition labels and emits the kernel
//! command line, and init finds the partitions by those labels and parses that command
//! line, so the two agree by sharing `init`'s types rather than by convention.
//!
//! This piece builds the immutable base: [`build_base`] materializes a minimal base
//! skeleton (the standard mount directories and an os-release) and packs it into a
//! reproducible squashfs, so the same inputs yield byte-identical bytes and the base
//! can be verified by hash. The build shells out to `mksquashfs`, doing no kernel work
//! itself, so the crate builds and the pure parts test on every host; only the test
//! that mounts the result back (as the init's overlay lower) needs a Linux kernel and
//! is gated, run for real in a privileged container. Populating the base with the real
//! userland (binaries, libraries, kernel modules, firmware), the persistent data
//! partition, and the bootloader come next.

mod error;

pub use error::{Error, Result};

use std::path::{Path, PathBuf};
use std::process::Command;

pub use init::ModeChoice;
use init::{BASE_LABEL, DATA_LABEL};

/// The immutable base image's filename under a spec's output directory.
pub const BASE_IMAGE: &str = "base.squashfs";

/// The parameters of a Key to build: where to write it, the partition labels and
/// filesystems init looks for, the default boot mode, and how the system names itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySpec {
    /// The directory build artifacts are written into.
    pub out: PathBuf,
    /// The label written on the base partition and named on the boot command line.
    pub base_label: String,
    /// The label written on the data partition and named on the boot command line.
    pub data_label: String,
    pub basefs: String,
    pub datafs: String,
    /// The boot mode the command line requests (Auto picks Home or Ghost at boot).
    pub mode: ModeChoice,
    pub os_name: String,
    pub os_id: String,
    pub os_version: String,
}

impl KeySpec {
    /// A spec writing into `out` with Horizon's standard labels and filesystems, the
    /// ones `init`'s defaults look for, so a Key built this way boots with no explicit
    /// command line.
    pub fn new(out: impl Into<PathBuf>) -> KeySpec {
        KeySpec {
            out: out.into(),
            base_label: BASE_LABEL.to_string(),
            data_label: DATA_LABEL.to_string(),
            basefs: "squashfs".to_string(),
            datafs: "ext4".to_string(),
            mode: ModeChoice::Auto,
            os_name: "Horizon OS".to_string(),
            os_id: "horizon".to_string(),
            os_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// The kernel command line a bootloader passes so `init` finds this Key's partitions.
/// It names the base and data by label, their filesystems, and the boot mode; the
/// `init` parser reads exactly these tokens back, so a build and a boot cannot drift.
pub fn boot_cmdline(spec: &KeySpec) -> String {
    let mode = match spec.mode {
        ModeChoice::Auto => "auto",
        ModeChoice::Home => "home",
        ModeChoice::Ghost => "ghost",
    };
    format!(
        "horizon.base=LABEL={} horizon.basefs={} horizon.data=LABEL={} horizon.datafs={} horizon.mode={}",
        spec.base_label, spec.basefs, spec.data_label, spec.datafs, mode
    )
}

/// The minimal contents of the immutable base: the standard mountpoint directories the
/// init moves the kernel filesystems onto, plus an os-release naming the system. Kept
/// pure (no filesystem touched) so it is asserted with no build tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skeleton {
    pub dirs: Vec<String>,
    pub os_release: String,
}

pub fn base_skeleton(spec: &KeySpec) -> Skeleton {
    let dirs = [
        "dev", "proc", "sys", "run", "tmp", "etc", "var", "usr", "usr/bin",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    Skeleton {
        dirs,
        os_release: os_release(spec),
    }
}

fn os_release(spec: &KeySpec) -> String {
    format!(
        "NAME=\"{name}\"\nID={id}\nVERSION=\"{ver}\"\nPRETTY_NAME=\"{name} {ver}\"\n",
        name = spec.os_name,
        id = spec.os_id,
        ver = spec.os_version
    )
}

/// Build the immutable base image: materialize the [`base_skeleton`] into a staging
/// tree and pack it into a reproducible squashfs at `<out>/base.squashfs`. The squashfs
/// is built root-owned, without xattrs, and with fixed timestamps, so the same skeleton
/// always yields byte-identical bytes. Returns the path to the image.
pub fn build_base(spec: &KeySpec) -> Result<PathBuf> {
    std::fs::create_dir_all(&spec.out)?;

    // A clean staging tree each time, so the input to mksquashfs is deterministic.
    let staging = spec.out.join("base.staging");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    materialize(&base_skeleton(spec), &staging)?;

    let out = spec.out.join(BASE_IMAGE);
    if out.exists() {
        std::fs::remove_file(&out)?;
    }

    let mut cmd = Command::new("mksquashfs");
    cmd.arg(&staging)
        .arg(&out)
        // -noappend overwrites; the rest pin uid/gid, xattrs, and every timestamp so the
        // bytes are reproducible.
        .args([
            "-noappend",
            "-all-root",
            "-no-xattrs",
            "-mkfs-time",
            "0",
            "-all-time",
            "0",
        ])
        .stdout(std::process::Stdio::null());
    run(cmd, "mksquashfs")?;

    let _ = std::fs::remove_dir_all(&staging);
    Ok(out)
}

fn materialize(skeleton: &Skeleton, staging: &Path) -> Result<()> {
    for d in &skeleton.dirs {
        std::fs::create_dir_all(staging.join(d))?;
    }
    std::fs::write(staging.join("etc/os-release"), &skeleton.os_release)?;
    Ok(())
}

fn run(mut cmd: Command, name: &'static str) -> Result<()> {
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
    use init::{parse_cmdline, Spec};

    #[test]
    fn cmdline_round_trips_through_the_init_parser() {
        for mode in [ModeChoice::Auto, ModeChoice::Home, ModeChoice::Ghost] {
            let mut spec = KeySpec::new("/tmp/key");
            spec.mode = mode;
            let parsed = parse_cmdline(&boot_cmdline(&spec));
            assert_eq!(parsed.base, Spec::Label(spec.base_label.clone()));
            assert_eq!(parsed.data, Spec::Label(spec.data_label.clone()));
            assert_eq!(parsed.basefs, spec.basefs);
            assert_eq!(parsed.datafs, spec.datafs);
            assert_eq!(parsed.mode, mode);
        }
    }

    #[test]
    fn default_labels_are_the_ones_init_looks_for() {
        // keybuild's defaults write the labels init's own defaults search for, so a Key
        // built with no explicit command line still boots.
        let spec = KeySpec::new("/tmp/key");
        let init_default = parse_cmdline("");
        assert_eq!(init_default.base, Spec::Label(spec.base_label));
        assert_eq!(init_default.data, Spec::Label(spec.data_label));
    }

    #[test]
    fn skeleton_has_the_mount_dirs_and_names_the_system() {
        let spec = KeySpec::new("/tmp/key");
        let sk = base_skeleton(&spec);
        for d in ["dev", "proc", "sys", "run", "etc", "usr/bin"] {
            assert!(sk.dirs.iter().any(|x| x == d), "missing base dir {d}");
        }
        assert!(sk.os_release.contains("Horizon OS"));
        assert!(sk.os_release.contains("ID=horizon"));
    }
}

// Mounting the built base back, as the init's overlay lower, needs a Linux kernel, so
// it is proven for real where there is one: a privileged container packs a squashfs and
// stacks a writable overlay on it, the immutable-base + writable-overlay model the
// design turns on, now on the real image format the Key uses.
#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use init::{execute, is_unprivileged_error, Layout, MountFlags, Plan, Source, Step};
    use std::process::Command;

    fn losetup_ro(file: &Path) -> Option<String> {
        let out = Command::new("losetup")
            .args(["--find", "--show", "-r"])
            .arg(file)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!dev.is_empty()).then_some(dev)
    }

    fn losetup_d(dev: &str) {
        let _ = Command::new("losetup").arg("-d").arg(dev).output();
    }

    fn umount(p: &Path) {
        let _ = Command::new("umount").arg("-l").arg(p).output();
    }

    // Build a base, skipping if mksquashfs is not installed (CI) rather than failing.
    fn build_or_skip(out: &Path) -> Option<PathBuf> {
        match build_base(&KeySpec::new(out)) {
            Ok(p) => Some(p),
            Err(Error::Missing(_)) => {
                eprintln!("skipping: mksquashfs not installed");
                None
            }
            Err(e) => panic!("build base: {e}"),
        }
    }

    #[test]
    fn base_image_is_reproducible() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let Some(pa) = build_or_skip(a.path()) else {
            return;
        };
        let pb = build_or_skip(b.path()).unwrap();
        let bytes_a = std::fs::read(&pa).unwrap();
        let bytes_b = std::fs::read(&pb).unwrap();
        assert!(!bytes_a.is_empty());
        assert_eq!(
            bytes_a, bytes_b,
            "the immutable base must build byte-for-byte reproducibly"
        );
    }

    #[test]
    fn base_squashfs_mounts_read_only_as_the_overlay_lower() {
        let dir = tempfile::tempdir().unwrap();
        let Some(base) = build_or_skip(dir.path()) else {
            return;
        };

        // A read-only loop device over the squashfs file, the immutable base as the init
        // would see the Key's base partition.
        let Some(loopdev) = losetup_ro(&base) else {
            eprintln!("skipping: losetup not permitted here");
            return;
        };

        // Assemble on a private tmpfs so nothing escapes and the lower is isolated.
        let scratch = dir.path().join("run");
        std::fs::create_dir_all(&scratch).unwrap();
        if let Err(e) = execute(&Plan {
            steps: vec![Step::Mount {
                source: Source::tmpfs(),
                target: scratch.clone(),
            }],
        }) {
            losetup_d(&loopdev);
            if is_unprivileged_error(&e) {
                eprintln!("skipping: mounting not permitted here ({e})");
                return;
            }
            panic!("mount tmpfs: {e}");
        }

        let l = Layout::new(&scratch);
        let steps = vec![
            Step::Mkdir(l.lower.clone()),
            Step::Mount {
                source: Source::new(loopdev.as_str(), "squashfs", MountFlags::default())
                    .read_only(),
                target: l.lower.clone(),
            },
            Step::Mkdir(l.over.clone()),
            Step::Mount {
                source: Source::tmpfs(),
                target: l.over.clone(),
            },
            Step::Mkdir(l.upper.clone()),
            Step::Mkdir(l.work.clone()),
            Step::Mkdir(l.root.clone()),
            Step::Overlay {
                lower: l.lower.clone(),
                upper: l.upper.clone(),
                work: l.work.clone(),
                target: l.root.clone(),
            },
        ];
        if let Err(e) = execute(&Plan { steps }) {
            umount(&scratch);
            losetup_d(&loopdev);
            if is_unprivileged_error(&e) {
                eprintln!("skipping: assembling not permitted here ({e})");
                return;
            }
            panic!("assemble: {e}");
        }

        // The immutable base shows through the overlay root.
        let osr = std::fs::read_to_string(l.root.join("etc/os-release")).unwrap();
        assert!(osr.contains("Horizon OS"));
        // A write to the root lands in the writable tmpfs upper.
        std::fs::write(l.root.join("state"), b"session").unwrap();
        assert!(l.upper.join("state").exists());
        // The squashfs lower is genuinely read-only: it cannot be written.
        assert!(
            std::fs::write(l.lower.join("nope"), b"x").is_err(),
            "the immutable base must be read-only"
        );

        umount(&l.root);
        umount(&l.over);
        umount(&l.lower);
        umount(&scratch);
        losetup_d(&loopdev);
    }
}
