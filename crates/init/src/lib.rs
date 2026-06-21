//! Init: the first userspace process in Horizon's initramfs.
//!
//! When the kernel hands control to the initramfs it execs one program as PID 1.
//! That program's job is to turn "a kernel with a Key plugged in" into "the real
//! root, mounted, with `horizon boot` running on it". This crate is that program
//! (`horizon-init`) and the logic behind it.
//!
//! The on-disk model is the one in `docs/03-PORTABILITY-AND-BOOT.md`: an immutable
//! base image, mounted read-only, with a writable layer stacked over it by OverlayFS.
//! The base resets clean and cannot be corrupted by a runaway process; the writable
//! layer is where this machine's state goes. What that layer is made of is the whole
//! Home-vs-Ghost decision:
//!
//! - [`Mode::Home`] (a Known Surface): the writable layer is a persistent device, so
//!   OS state survives a power-off.
//! - [`Mode::Ghost`] (a Foreign Surface): the writable layer is tmpfs in RAM, so the
//!   machine writes nothing outside memory and the session is gone on power-off.
//!
//! The base is read-only in both modes; only the writable layer differs.
//!
//! The honest split is the one the rest of Horizon uses. The *policy* of a boot, what
//! to mount, in what order, where, the mode decision, the final pivot-and-exec, is
//! pure logic: a [`Recipe`] is folded into a [`Plan`] of ordered [`Step`]s by [`plan`],
//! and the kernel command line is parsed into a [`Params`] by [`parse_cmdline`]. None
//! of that touches a device, so it is tested on every host. The *execution* of the
//! plan (the `mount`/`overlay`/`switch_root` syscalls) is Linux-only; the overlay
//! assembly and the store carry are proven for real in a privileged container, and the
//! final `switch_root` into the base is proven by actually booting, exactly as the
//! compositor's display backends are.

mod error;

pub use error::{Error, Result};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{execute, is_unprivileged_error, mount_proc, resolve};

use std::path::{Path, PathBuf};

/// The default init to exec once the real root is mounted: the `horizon` binary in
/// the base image, which runs `boot` to unlock the identity and open the desktop.
pub const DEFAULT_INIT: &str = "/usr/bin/horizon";

/// The filesystem labels a Horizon Key carries: the rendezvous between the image
/// builder, which writes them onto the base and data partitions, and this init,
/// which finds those partitions by label so no device path is ever hardcoded.
pub const BASE_LABEL: &str = "HORIZON-BASE";
pub const DATA_LABEL: &str = "HORIZON-DATA";

/// Where the new root is assembled and where the Key's identity store is bound, both
/// under the initramfs's own tmpfs. The store path is what `horizon boot --root` is
/// pointed at after the pivot.
pub const SCRATCH: &str = "/run/horizon";
pub const STORE_MOUNT: &str = "/run/horizon/store";

/// Mount flags the plan cares about, in a host-independent form. The Linux executor
/// maps these to the kernel's `MsFlags`; keeping them plain bools is what lets the
/// plan and its tests build on a host with no mount syscall.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MountFlags {
    pub rdonly: bool,
    pub nosuid: bool,
    pub nodev: bool,
    pub noexec: bool,
}

impl MountFlags {
    /// The hardening a kernel virtual filesystem (proc, sysfs) is mounted with: no
    /// setuid bits, no device nodes, no executables.
    pub const PSEUDO: MountFlags = MountFlags {
        rdonly: false,
        nosuid: true,
        nodev: true,
        noexec: true,
    };

    /// A writable scratch filesystem (a tmpfs overlay backing): no setuid, no device
    /// nodes, but executables allowed (the upper layer holds real programs).
    pub const SCRATCH: MountFlags = MountFlags {
        rdonly: false,
        nosuid: true,
        nodev: true,
        noexec: false,
    };
}

/// A filesystem to mount: the source (a block device path, or a pseudo-source like
/// `tmpfs`/`proc`/`devtmpfs`), its type, and the flags it is mounted with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub dev: PathBuf,
    pub fstype: String,
    pub flags: MountFlags,
}

impl Source {
    pub fn new(dev: impl Into<PathBuf>, fstype: impl Into<String>, flags: MountFlags) -> Source {
        Source {
            dev: dev.into(),
            fstype: fstype.into(),
            flags,
        }
    }

    /// The same source mounted read-only (the immutable base, or a Ghost-mode store).
    pub fn read_only(mut self) -> Source {
        self.flags.rdonly = true;
        self
    }

    /// A tmpfs source: the Ghost-mode writable layer, in RAM, leaving no trace.
    pub fn tmpfs() -> Source {
        Source::new("tmpfs", "tmpfs", MountFlags::SCRATCH)
    }
}

/// What the writable overlay layer is made of, the Home-vs-Ghost decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// A Known Surface: a persistent device carries the writable layer, so OS state
    /// survives a power-off. The device also holds the identity store.
    Home(Source),
    /// A Foreign Surface: the writable layer is tmpfs in RAM, so nothing is written
    /// to the Key or the host and the session is gone on power-off.
    Ghost,
}

/// A path to carry into the new root before the pivot, as a bind mount. This is how
/// the Key (and the identity store on it) stays reachable after `switch_root`, so
/// `horizon boot` can find the store the session opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carry {
    /// A path in the current (initramfs) mount tree.
    pub from: PathBuf,
    /// Where it lands, relative to the new root.
    pub to: PathBuf,
}

/// The fixed mountpoints under the scratch directory. `plan` lays the root out here
/// and the binary reads the same layout to find, e.g., the store on the data device.
#[derive(Debug, Clone)]
pub struct Layout {
    pub scratch: PathBuf,
    /// The immutable base, mounted read-only (the overlay lower).
    pub lower: PathBuf,
    /// The writable layer's backing filesystem (a device or tmpfs), holding the
    /// upper and work directories overlay requires to live on one filesystem.
    pub over: PathBuf,
    pub upper: PathBuf,
    pub work: PathBuf,
    /// The assembled OverlayFS, the new root.
    pub root: PathBuf,
}

impl Layout {
    pub fn new(scratch: impl AsRef<Path>) -> Layout {
        let scratch = scratch.as_ref().to_path_buf();
        let over = scratch.join("over");
        Layout {
            lower: scratch.join("lower"),
            upper: over.join("upper"),
            work: over.join("work"),
            root: scratch.join("root"),
            over,
            scratch,
        }
    }
}

/// Everything the init needs to assemble the real root and hand off. The runtime
/// resolves a `Recipe` (find the Key, pick the mode); making `Recipe -> Plan` pure is
/// what lets the whole sequence be tested with no devices.
#[derive(Debug, Clone)]
pub struct Recipe {
    /// A writable scratch directory in the initramfs to assemble under.
    pub scratch: PathBuf,
    /// The immutable base image, mounted read-only as the overlay's lower layer.
    pub base: Source,
    /// What the writable overlay layer is made of (a Home device or a Ghost tmpfs).
    pub mode: Mode,
    /// Paths to bind into the new root before the pivot (the Key / identity store).
    pub carry: Vec<Carry>,
    /// The real init to exec after `switch_root` (a program in the base image).
    pub init: PathBuf,
    /// Arguments passed to that init (the argv after the program name).
    pub init_args: Vec<String>,
}

/// One ordered operation in a boot plan. The plan is a fully self-describing list of
/// these: the Linux executor walks it, and the tests assert its shape with no devices
/// and no root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Create a directory; a mountpoint must exist before something mounts onto it.
    Mkdir(PathBuf),
    /// Mount `source` at `target` (a block device, or a virtual fs like tmpfs/proc).
    Mount { source: Source, target: PathBuf },
    /// Assemble an OverlayFS at `target`: a read-only `lower`, a writable `upper`, and
    /// a `work` directory (which the kernel requires to share `upper`'s filesystem).
    Overlay {
        lower: PathBuf,
        upper: PathBuf,
        work: PathBuf,
        target: PathBuf,
    },
    /// Recursively bind `from` onto `to`: carry a path (the Key/store) into the new
    /// root so it survives the pivot.
    Bind { from: PathBuf, to: PathBuf },
    /// Move the mount at `from` to `to`: carry a kernel filesystem (proc/sys/dev) into
    /// the new root without remounting it.
    Move { from: PathBuf, to: PathBuf },
    /// `switch_root` into `new_root` and exec `init` with `args`: the handoff to real
    /// userspace. The last step in any plan; nothing runs after it in this process.
    SwitchRoot {
        new_root: PathBuf,
        init: PathBuf,
        args: Vec<String>,
    },
}

/// An ordered boot plan: the complete sequence from "kernel handed off to us" to
/// "horizon boot is running on the real root".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub steps: Vec<Step>,
}

impl Plan {
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }
}

/// The kernel virtual filesystems early userspace needs before it can do anything:
/// devtmpfs so block devices appear under /dev, proc so the command line and the
/// process tree are readable, sysfs so devices can be matched. These come first in
/// every plan.
pub fn early_mounts() -> Vec<Step> {
    vec![
        Step::Mount {
            source: Source::new("devtmpfs", "devtmpfs", MountFlags::SCRATCH),
            target: PathBuf::from("/dev"),
        },
        Step::Mount {
            source: Source::new("proc", "proc", MountFlags::PSEUDO),
            target: PathBuf::from("/proc"),
        },
        Step::Mount {
            source: Source::new("sysfs", "sysfs", MountFlags::PSEUDO),
            target: PathBuf::from("/sys"),
        },
    ]
}

// Join a relative target under the new root, dropping any leading slash so an
// absolute-looking carry target (e.g. /run/horizon/store) lands inside the root
// rather than replacing it.
fn under(root: &Path, rel: &Path) -> PathBuf {
    root.join(rel.strip_prefix("/").unwrap_or(rel))
}

/// Fold a `Recipe` into the ordered `Plan` that boots it. The shape is fixed:
///
/// 1. the kernel virtual filesystems ([`early_mounts`]);
/// 2. the immutable base, mounted read-only as the overlay lower;
/// 3. the writable layer's backing (a Home device or a Ghost tmpfs), holding the
///    upper and work directories;
/// 4. the OverlayFS assembled at the new root;
/// 5. the carried paths (the Key / store) bound into the new root;
/// 6. proc, sysfs, and devtmpfs moved into the new root so real userspace keeps them;
/// 7. `switch_root` into the base and exec of the init.
pub fn plan(r: &Recipe) -> Plan {
    let l = Layout::new(&r.scratch);
    let mut steps = early_mounts();

    // The immutable base, read-only, as the overlay lower.
    steps.push(Step::Mkdir(l.lower.clone()));
    steps.push(Step::Mount {
        source: r.base.clone().read_only(),
        target: l.lower.clone(),
    });

    // The writable layer's backing, holding the upper and work directories overlay
    // needs on one filesystem. In Ghost mode this is tmpfs, so nothing leaves RAM.
    let over_src = match &r.mode {
        Mode::Home(dev) => dev.clone(),
        Mode::Ghost => Source::tmpfs(),
    };
    steps.push(Step::Mkdir(l.over.clone()));
    steps.push(Step::Mount {
        source: over_src,
        target: l.over.clone(),
    });
    steps.push(Step::Mkdir(l.upper.clone()));
    steps.push(Step::Mkdir(l.work.clone()));

    // The assembled root: immutable lower, writable upper.
    steps.push(Step::Mkdir(l.root.clone()));
    steps.push(Step::Overlay {
        lower: l.lower.clone(),
        upper: l.upper.clone(),
        work: l.work.clone(),
        target: l.root.clone(),
    });

    // Carry the Key / identity store into the new root before the pivot.
    for c in &r.carry {
        let to = under(&l.root, &c.to);
        steps.push(Step::Mkdir(to.clone()));
        steps.push(Step::Bind {
            from: c.from.clone(),
            to,
        });
    }

    // Move the kernel virtual filesystems into the new root so userspace keeps them.
    // The mountpoints exist in any base image, but a generic init makes them rather
    // than assume it (the mkdir lands in the writable upper, never the immutable base).
    for name in ["dev", "proc", "sys"] {
        let from = PathBuf::from("/").join(name);
        let to = l.root.join(name);
        steps.push(Step::Mkdir(to.clone()));
        steps.push(Step::Move { from, to });
    }

    // Pivot into the base and hand off to the real init.
    steps.push(Step::SwitchRoot {
        new_root: l.root,
        init: r.init.clone(),
        args: r.init_args.clone(),
    });

    Plan { steps }
}

/// How a device is named on the kernel command line: by filesystem label, by UUID, or
/// by an explicit device path. The same `LABEL=`/`UUID=` convention the kernel's
/// `root=` and every initramfs use, so a generic image finds the Key with no path
/// hardcoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spec {
    Label(String),
    Uuid(String),
    Path(PathBuf),
}

impl Spec {
    pub fn parse(s: &str) -> Spec {
        if let Some(l) = s.strip_prefix("LABEL=") {
            Spec::Label(l.to_string())
        } else if let Some(u) = s.strip_prefix("UUID=") {
            Spec::Uuid(u.to_string())
        } else {
            Spec::Path(PathBuf::from(s))
        }
    }
}

/// What the kernel command line asks for: force a mode, or leave it to whether a
/// persistent device is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeChoice {
    /// Home if the data device is present, Ghost otherwise.
    Auto,
    /// Home: persist to the data device. Degrades to Ghost if the device is absent.
    Home,
    /// Ghost: never write to the Key, even if a data device is present.
    Ghost,
}

impl ModeChoice {
    pub fn parse(s: &str) -> ModeChoice {
        match s {
            "home" => ModeChoice::Home,
            "ghost" => ModeChoice::Ghost,
            _ => ModeChoice::Auto,
        }
    }
}

/// The boot parameters read off the kernel command line. The base defaults to the
/// `HORIZON-BASE` label and the data to `HORIZON-DATA`, so a Key built with those
/// labels boots with no command line beyond the defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    pub base: Spec,
    pub basefs: String,
    pub data: Spec,
    pub datafs: String,
    pub mode: ModeChoice,
    pub init: PathBuf,
    pub init_args: Vec<String>,
}

impl Default for Params {
    fn default() -> Params {
        Params {
            base: Spec::Label(BASE_LABEL.into()),
            basefs: "squashfs".into(),
            data: Spec::Label(DATA_LABEL.into()),
            datafs: "ext4".into(),
            mode: ModeChoice::Auto,
            init: PathBuf::from(DEFAULT_INIT),
            init_args: vec!["boot".into()],
        }
    }
}

/// Parse the kernel command line into [`Params`]. Recognized tokens, all optional:
/// `horizon.base=`, `horizon.basefs=`, `horizon.data=`, `horizon.datafs=`,
/// `horizon.mode=home|ghost|auto`, `horizon.init=`. Anything else (the kernel's own
/// arguments) is ignored.
pub fn parse_cmdline(cmdline: &str) -> Params {
    let mut p = Params::default();
    for tok in cmdline.split_whitespace() {
        if let Some(v) = tok.strip_prefix("horizon.base=") {
            p.base = Spec::parse(v);
        } else if let Some(v) = tok.strip_prefix("horizon.basefs=") {
            p.basefs = v.to_string();
        } else if let Some(v) = tok.strip_prefix("horizon.data=") {
            p.data = Spec::parse(v);
        } else if let Some(v) = tok.strip_prefix("horizon.datafs=") {
            p.datafs = v.to_string();
        } else if let Some(v) = tok.strip_prefix("horizon.mode=") {
            p.mode = ModeChoice::parse(v);
        } else if let Some(v) = tok.strip_prefix("horizon.init=") {
            p.init = PathBuf::from(v);
        }
    }
    p
}

/// Decide the writable-layer mode from the command-line choice and whether the data
/// device actually resolved. Home (or Auto) with a device present persists; anything
/// without a device, or an explicit Ghost, runs stateless. A "boots anywhere" device
/// must come up even when its persistent partition is missing, so Home degrades to
/// Ghost rather than failing.
pub fn choose_mode(choice: ModeChoice, data: Option<Source>) -> Mode {
    match (choice, data) {
        (ModeChoice::Ghost, _) | (_, None) => Mode::Ghost,
        (_, Some(d)) => Mode::Home(d),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Source {
        Source::new(
            "/dev/disk/by-label/HORIZON-BASE",
            "squashfs",
            MountFlags::default(),
        )
    }

    fn data() -> Source {
        Source::new(
            "/dev/disk/by-label/HORIZON-DATA",
            "ext4",
            MountFlags::default(),
        )
    }

    fn recipe(mode: Mode) -> Recipe {
        Recipe {
            scratch: PathBuf::from("/run/horizon"),
            base: base(),
            mode,
            carry: vec![Carry {
                from: PathBuf::from("/run/horizon/over/store"),
                to: PathBuf::from("/run/horizon/store"),
            }],
            init: PathBuf::from(DEFAULT_INIT),
            init_args: vec!["boot".into(), "--root".into(), "/run/horizon/store".into()],
        }
    }

    // Find the single Mount step landing on `target`.
    fn mount_at<'a>(plan: &'a Plan, target: &str) -> &'a Source {
        plan.steps
            .iter()
            .find_map(|s| match s {
                Step::Mount { source, target: t } if t == Path::new(target) => Some(source),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no mount at {target}"))
    }

    #[test]
    fn early_mounts_cover_dev_proc_sys() {
        let m = early_mounts();
        let types: Vec<&str> = m
            .iter()
            .filter_map(|s| match s {
                Step::Mount { source, .. } => Some(source.fstype.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(types, ["devtmpfs", "proc", "sysfs"]);
        // proc and sysfs are mounted hardened.
        assert!(m.iter().all(|s| match s {
            Step::Mount { source, .. } if source.fstype == "proc" || source.fstype == "sysfs" =>
                source.flags.nosuid && source.flags.nodev && source.flags.noexec,
            _ => true,
        }));
    }

    #[test]
    fn base_is_always_read_only() {
        for mode in [Mode::Home(data()), Mode::Ghost] {
            let p = plan(&recipe(mode));
            let lower = mount_at(&p, "/run/horizon/lower");
            assert_eq!(lower.dev, base().dev);
            assert!(
                lower.flags.rdonly,
                "the immutable base must be mounted read-only"
            );
        }
    }

    #[test]
    fn home_backs_the_writable_layer_with_the_data_device() {
        let p = plan(&recipe(Mode::Home(data())));
        let over = mount_at(&p, "/run/horizon/over");
        assert_eq!(over.dev, data().dev);
        assert_eq!(over.fstype, "ext4");
        assert!(
            !over.flags.rdonly,
            "the Home writable layer must be writable"
        );
    }

    #[test]
    fn ghost_writes_nothing_to_a_persistent_device() {
        let p = plan(&recipe(Mode::Ghost));
        // The writable layer is tmpfs (RAM), not the data device.
        let over = mount_at(&p, "/run/horizon/over");
        assert_eq!(over.fstype, "tmpfs");
        // No step anywhere references the persistent data device.
        let touches_data = p.steps.iter().any(|s| match s {
            Step::Mount { source, .. } => source.dev == data().dev,
            _ => false,
        });
        assert!(!touches_data, "Ghost mode must not mount the data device");
        // The base is still read-only: Ghost boots the same immutable OS.
        assert!(mount_at(&p, "/run/horizon/lower").flags.rdonly);
    }

    #[test]
    fn overlay_stacks_writable_upper_on_immutable_lower() {
        let p = plan(&recipe(Mode::Home(data())));
        let overlay = p
            .steps
            .iter()
            .find_map(|s| match s {
                Step::Overlay {
                    lower,
                    upper,
                    work,
                    target,
                } => Some((lower, upper, work, target)),
                _ => None,
            })
            .expect("an overlay step");
        let (lower, upper, work, target) = overlay;
        assert_eq!(lower, &PathBuf::from("/run/horizon/lower"));
        assert_eq!(target, &PathBuf::from("/run/horizon/root"));
        // upper and work share one filesystem (both under the over mount), as overlay
        // requires.
        assert_eq!(upper.parent(), Some(Path::new("/run/horizon/over")));
        assert_eq!(work.parent(), Some(Path::new("/run/horizon/over")));
    }

    #[test]
    fn carries_are_bound_into_the_new_root() {
        let p = plan(&recipe(Mode::Home(data())));
        let bind = p
            .steps
            .iter()
            .find_map(|s| match s {
                Step::Bind { from, to } => Some((from, to)),
                _ => None,
            })
            .expect("a bind step");
        let (from, to) = bind;
        assert_eq!(from, &PathBuf::from("/run/horizon/over/store"));
        // The carry lands inside the new root, not at an absolute host path.
        assert_eq!(to, &PathBuf::from("/run/horizon/root/run/horizon/store"));
    }

    #[test]
    fn pivot_is_last_and_moves_the_kernel_filesystems_first() {
        let p = plan(&recipe(Mode::Home(data())));
        // The kernel filesystems are moved into the new root.
        let moves: Vec<&PathBuf> = p
            .steps
            .iter()
            .filter_map(|s| match s {
                Step::Move { from, .. } => Some(from),
                _ => None,
            })
            .collect();
        assert_eq!(
            moves,
            [
                &PathBuf::from("/dev"),
                &PathBuf::from("/proc"),
                &PathBuf::from("/sys")
            ]
        );
        // switch_root is the final step and execs the chosen init.
        match p.steps.last().expect("a final step") {
            Step::SwitchRoot {
                new_root,
                init,
                args,
            } => {
                assert_eq!(new_root, &PathBuf::from("/run/horizon/root"));
                assert_eq!(init, &PathBuf::from(DEFAULT_INIT));
                assert_eq!(args, &["boot", "--root", "/run/horizon/store"]);
            }
            other => panic!("expected switch_root last, got {other:?}"),
        }
        // Nothing comes after the pivot.
        assert!(matches!(p.steps.last(), Some(Step::SwitchRoot { .. })));
    }

    #[test]
    fn parse_cmdline_reads_horizon_params() {
        let line = "ro quiet horizon.base=LABEL=BASE horizon.data=UUID=abcd \
                    horizon.mode=ghost horizon.init=/sbin/init horizon.basefs=erofs \
                    console=tty0";
        let p = parse_cmdline(line);
        assert_eq!(p.base, Spec::Label("BASE".into()));
        assert_eq!(p.data, Spec::Uuid("abcd".into()));
        assert_eq!(p.mode, ModeChoice::Ghost);
        assert_eq!(p.init, PathBuf::from("/sbin/init"));
        assert_eq!(p.basefs, "erofs");
        // unset fields keep their defaults
        assert_eq!(p.datafs, "ext4");
    }

    #[test]
    fn parse_cmdline_defaults_to_the_horizon_labels() {
        let p = parse_cmdline("ro quiet console=tty0");
        assert_eq!(p.base, Spec::Label("HORIZON-BASE".into()));
        assert_eq!(p.data, Spec::Label("HORIZON-DATA".into()));
        assert_eq!(p.mode, ModeChoice::Auto);
        assert_eq!(p.init, PathBuf::from(DEFAULT_INIT));
        assert_eq!(p.init_args, ["boot"]);
    }

    #[test]
    fn spec_parses_label_uuid_and_path() {
        assert_eq!(Spec::parse("LABEL=X"), Spec::Label("X".into()));
        assert_eq!(Spec::parse("UUID=1234"), Spec::Uuid("1234".into()));
        assert_eq!(Spec::parse("/dev/sda2"), Spec::Path("/dev/sda2".into()));
    }

    #[test]
    fn choose_mode_follows_the_data_device_and_the_request() {
        let d = || Some(data());
        // Auto / Home with a device persist; Ghost or no device runs stateless.
        assert_eq!(choose_mode(ModeChoice::Auto, d()), Mode::Home(data()));
        assert_eq!(choose_mode(ModeChoice::Home, d()), Mode::Home(data()));
        assert_eq!(choose_mode(ModeChoice::Ghost, d()), Mode::Ghost);
        assert_eq!(choose_mode(ModeChoice::Auto, None), Mode::Ghost);
        // Home with no persistent device degrades to Ghost rather than failing.
        assert_eq!(choose_mode(ModeChoice::Home, None), Mode::Ghost);
    }
}

// The executor runs the plan against the real kernel, so it is proven where there is
// a kernel to run it: a privileged container assembles the overlay root and carries a
// stand-in store for real, the same immutable-lower + writable-upper invariant the
// design turns on. The final switch_root cannot run inside a test (it would replace
// the test process's own root), so it is proven by booting, like the display backends.
#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use nix::mount::{umount2, MntFlags};
    use std::fs;

    #[test]
    fn assembles_an_immutable_base_with_a_writable_overlay_and_carries_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = dir.path().join("run");
        fs::create_dir_all(&scratch).unwrap();

        // A fresh tmpfs holds the whole assembly, so the overlay lower is not itself
        // an overlay (the container's own rootfs is overlay2) and the test is
        // isolated.
        let mount_tmpfs = |target: &std::path::Path| {
            let p = Plan {
                steps: vec![Step::Mount {
                    source: Source::tmpfs(),
                    target: target.to_path_buf(),
                }],
            };
            execute(&p)
        };
        if let Err(e) = mount_tmpfs(&scratch) {
            if is_unprivileged_error(&e) {
                eprintln!("skipping: mounting is not permitted here ({e})");
                return;
            }
            panic!("mount tmpfs: {e}");
        }

        let l = Layout::new(&scratch);
        let store_src = scratch.join("store_src");

        // The immutable base: one file standing in for the read-only OS.
        let mut steps = vec![
            Step::Mkdir(l.lower.clone()),
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
        // The carried store, a stand-in Key holding the marker boot looks for.
        let store_to = l.root.join("run/horizon/store");
        steps.push(Step::Mkdir(store_src.clone()));
        steps.push(Step::Mkdir(store_to.clone()));
        steps.push(Step::Bind {
            from: store_src.clone(),
            to: store_to.clone(),
        });

        // The lower file has to exist before the overlay is mounted; write it, and the
        // store marker, before executing the steps that consume them.
        fs::create_dir_all(&l.lower).unwrap();
        fs::write(l.lower.join("os-release"), b"horizon").unwrap();
        fs::create_dir_all(&store_src).unwrap();
        fs::write(store_src.join("keysalt"), b"key").unwrap();

        if let Err(e) = execute(&Plan { steps }) {
            if is_unprivileged_error(&e) {
                eprintln!("skipping: assembling the root is not permitted here ({e})");
                let _ = umount2(&scratch, MntFlags::MNT_DETACH);
                return;
            }
            let _ = umount2(&scratch, MntFlags::MNT_DETACH);
            panic!("assemble root: {e}");
        }

        // The immutable base is visible through the overlay.
        assert_eq!(
            fs::read_to_string(l.root.join("os-release")).unwrap(),
            "horizon"
        );
        // A write to the root lands in the writable upper, never in the immutable
        // lower: the base resets clean.
        fs::write(l.root.join("state"), b"session").unwrap();
        assert!(
            !l.lower.join("state").exists(),
            "the immutable lower must stay untouched"
        );
        assert!(
            l.upper.join("state").exists(),
            "the write must land in the writable upper"
        );
        // The Key's store was carried into the new root, where horizon boot finds it.
        assert_eq!(fs::read_to_string(store_to.join("keysalt")).unwrap(), "key");

        // Tear the mounts down inner-first; a detach is enough and never blocks.
        let _ = umount2(&store_to, MntFlags::MNT_DETACH);
        let _ = umount2(&l.root, MntFlags::MNT_DETACH);
        let _ = umount2(&l.over, MntFlags::MNT_DETACH);
        let _ = umount2(&scratch, MntFlags::MNT_DETACH);
    }
}
