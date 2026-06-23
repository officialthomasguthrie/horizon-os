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
//! - [`Mode::Home`] (a Known Surface): the writable layer is the LUKS2-encrypted Home
//!   partition, opened with the identity master (recovered from the store with a touch
//!   or a passphrase), so OS state survives a power-off but is encrypted at rest.
//! - [`Mode::Ghost`] (a Foreign Surface): the writable layer is tmpfs in RAM, so the
//!   machine writes nothing outside memory and the session is gone on power-off.
//!
//! The base is read-only in both modes; only the writable layer differs. The identity
//! store lives on its own plain partition (its confidentiality is the Lifestream's own
//! object encryption), read in both modes to boot the identity, read-only in Ghost so a
//! Foreign Surface is never written to. Splitting it off the encrypted layer is what lets
//! the master be recovered before the layer that master unlocks is opened.
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
pub use linux::{
    execute, is_unprivileged_error, load_modules, luks_close, luks_open, modules_dir, mount_proc,
    resolve, verity_close, verity_open,
};

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The default init to exec once the real root is mounted: the `horizon` binary in
/// the base image, which runs `boot` to unlock the identity and open the desktop.
pub const DEFAULT_INIT: &str = "/usr/bin/horizon";

/// The filesystem labels a Horizon Key carries: the rendezvous between the image
/// builder, which writes them onto the partitions, and this init, which finds those
/// partitions by label so no device path is ever hardcoded.
///
/// A Key has three: the immutable base, the plain data partition holding the identity
/// store (readable before unlock, because its confidentiality is the Lifestream's own
/// object encryption), and the LUKS2-encrypted Home layer holding the writable overlay
/// backing (opened with the master the store yields). Splitting the store off the
/// encrypted layer is what breaks the circularity: the store is read to recover the
/// master before the layer that master unlocks is opened.
pub const BASE_LABEL: &str = "HORIZON-BASE";
pub const DATA_LABEL: &str = "HORIZON-DATA";
pub const HOME_LABEL: &str = "HORIZON-HOME";

/// The partition label of the dm-verity hash device: a Merkle tree over the immutable
/// base, with no filesystem of its own. It is consulted only when the kernel command line
/// carries a `horizon.verity` root hash (the trust anchor the loader supplies); absent
/// that token the base is mounted unverified, the same "boots anywhere" degradation a
/// missing data or Home partition gets.
pub const VERITY_LABEL: &str = "HORIZON-VERITY";

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
    /// A Known Surface: the decrypted Home layer (the LUKS2 partition, already opened with
    /// the master) backs the writable overlay, so OS state survives a power-off encrypted
    /// at rest. The identity store sits on its own plain partition, not here.
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
/// and the binary reads the same layout to find the store on the data partition.
#[derive(Debug, Clone)]
pub struct Layout {
    pub scratch: PathBuf,
    /// The immutable base, mounted read-only (the overlay lower).
    pub lower: PathBuf,
    /// The plain data partition holding the identity store, mounted so the master can be
    /// recovered before the encrypted Home layer is opened.
    pub data: PathBuf,
    /// The writable layer's backing filesystem (the decrypted Home layer or tmpfs),
    /// holding the upper and work directories overlay requires to live on one filesystem.
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
            data: scratch.join("data"),
            upper: over.join("upper"),
            work: over.join("work"),
            root: scratch.join("root"),
            over,
            scratch,
        }
    }
}

/// Whether to boot Home (encrypted persistence): the request is not an explicit Ghost,
/// and both the store partition (to recover the master) and the encrypted Home layer (to
/// unlock with it) are present. Anything else runs stateless on tmpfs, the same
/// "boots anywhere" degradation [`choose_mode`] applies to a missing data device, now
/// extended to a missing Home layer. Pure, so the policy is tested with no devices.
pub fn home_wanted(choice: ModeChoice, has_store: bool, has_home: bool) -> bool {
    !matches!(choice, ModeChoice::Ghost) && has_store && has_home
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
    /// The plain data partition holding the identity store.
    pub data: Spec,
    pub datafs: String,
    /// The LUKS2-encrypted Home layer backing the writable overlay. Opened with the
    /// master in Home mode; untouched in Ghost mode.
    pub home: Spec,
    /// The filesystem inside the Home layer, mounted once the LUKS volume is open.
    pub homefs: String,
    /// The dm-verity root hash anchoring the immutable base, lowercase hex. `Some` opens a
    /// verified read-only base over the raw partition before it is mounted; `None` (the
    /// token absent) mounts the base unverified. It is a trust anchor, so it comes from the
    /// signed or measured loader config, never from the disk.
    pub verity: Option<String>,
    /// The dm-verity hash device (the Merkle tree). Consulted only when `verity` is `Some`.
    pub verity_dev: Spec,
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
            home: Spec::Label(HOME_LABEL.into()),
            homefs: "ext4".into(),
            verity: None,
            verity_dev: Spec::Label(VERITY_LABEL.into()),
            mode: ModeChoice::Auto,
            init: PathBuf::from(DEFAULT_INIT),
            init_args: vec!["boot".into()],
        }
    }
}

/// Parse the kernel command line into [`Params`]. Recognized tokens, all optional:
/// `horizon.base=`, `horizon.basefs=`, `horizon.data=`, `horizon.datafs=`,
/// `horizon.home=`, `horizon.homefs=`, `horizon.verity=<roothash>`, `horizon.veritydev=`,
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
        } else if let Some(v) = tok.strip_prefix("horizon.home=") {
            p.home = Spec::parse(v);
        } else if let Some(v) = tok.strip_prefix("horizon.homefs=") {
            p.homefs = v.to_string();
        } else if let Some(v) = tok.strip_prefix("horizon.verity=") {
            p.verity = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("horizon.veritydev=") {
            p.verity_dev = Spec::parse(v);
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

/// The raw master key length cryptsetup reads from stdin when opening the Home layer.
/// Fixed at 32 bytes (`--keyfile-size`) so a master containing a newline byte is not
/// truncated, the same handling keybuild's formatter uses.
pub const MASTER_KEY_SIZE: usize = 32;

/// The device-mapper name the opened Home layer is exposed under, `/dev/mapper/<this>`.
/// One fixed name: a boot opens exactly one Home layer.
pub const HOME_MAPPER: &str = "horizon-home";

/// The device-mapper name the dm-verity-verified base is exposed under,
/// `/dev/mapper/<this>`. One fixed name: a boot opens exactly one verity device over the
/// base, mounted read-only as the overlay lower in place of the raw partition.
pub const BASE_MAPPER: &str = "horizon-base";

/// The cryptsetup argv (after the program name) to open the encrypted Home layer at
/// `container`, reading the 32-byte master from stdin, exposing it at
/// `/dev/mapper/<mapper>`. Pure, so it is asserted with no cryptsetup; the inverse of the
/// keybuild formatter's key handling, so the master that formatted the layer opens it.
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

/// The cryptsetup argv to close the device-mapper node `mapper`.
pub fn luks_close_args(mapper: &str) -> Vec<String> {
    vec!["luksClose".into(), mapper.into()]
}

/// The veritysetup argv (after the program name) to open the dm-verity device over the
/// immutable base: verify `data_dev` (the base partition) against the Merkle tree on
/// `hash_dev` anchored by `root_hash`, exposing the verified read-only base at
/// `/dev/mapper/<mapper>`. The `veritysetup open <data> <name> <hash> <roothash>` form.
///
/// Pure, so it is asserted with no veritysetup, the same way [`luks_open_args`] is, and it
/// is the inverse of keybuild's `verity::format`: the lowercase-hex root hash that build
/// printed opens the tree it wrote. Unlike the LUKS master the root hash is a public trust
/// anchor (it comes from the signed or measured loader config), so it is passed as an
/// argument rather than fed on stdin.
pub fn verity_open_args(
    data_dev: &Path,
    hash_dev: &Path,
    mapper: &str,
    root_hash: &str,
) -> Vec<String> {
    vec![
        "open".into(),
        data_dev.to_string_lossy().into_owned(),
        mapper.into(),
        hash_dev.to_string_lossy().into_owned(),
        root_hash.into(),
    ]
}

/// The veritysetup argv to close the device-mapper node `mapper` (tear down the verified
/// base mapping). Paired with [`verity_open_args`].
pub fn verity_close_args(mapper: &str) -> Vec<String> {
    vec!["close".into(), mapper.into()]
}

/// The path the kernel exposes an opened LUKS volume at.
pub fn mapper_path(mapper: &str) -> PathBuf {
    Path::new("/dev/mapper").join(mapper)
}

/// Parse a kernel `modules.dep` into a map from each module's path (relative to the modules
/// directory) to the modules it depends on. The init reads the closure-consistent `modules.dep`
/// keybuild wrote into the initramfs; each line is `<module>: <dep> <dep> ...`, paths relative to
/// the modules directory, blank and colon-less lines skipped. A module with no dependencies still
/// appears, with an empty list, so the map is the full set the initramfs carries. Pure text
/// handling, unit-tested on every host; the [`load_modules`] that consumes it is Linux-only. (The
/// keybuild producer has the same parser over the source kernel tree; init reparses the trimmed
/// closure it shipped, so the two share a format, not a dependency.)
pub fn parse_modules_dep(text: &str) -> BTreeMap<PathBuf, Vec<PathBuf>> {
    let mut deps = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((target, rest)) = line.split_once(':') else {
            continue;
        };
        let target = target.trim();
        if target.is_empty() {
            continue;
        }
        let needs = rest.split_whitespace().map(PathBuf::from).collect();
        deps.insert(PathBuf::from(target), needs);
    }
    deps
}

/// The order to load a set of kernel modules so every module's dependencies load before it: a
/// post-order walk of the `modules.dep` graph. Modules are visited in sorted order and each is
/// emitted once, so the boot loads the same deterministic sequence every time and a dependency
/// two modules share is loaded a single time. A dependency named in `modules.dep` but absent as a
/// key (it has its own line in a well-formed file, so this is only a malformed input) is still
/// emitted before its dependent. Pure, so the ordering is unit-tested with no kernel.
pub fn module_load_order(deps: &BTreeMap<PathBuf, Vec<PathBuf>>) -> Vec<PathBuf> {
    let mut order = Vec::new();
    let mut done = BTreeSet::new();
    for m in deps.keys() {
        visit_module(m, deps, &mut done, &mut order);
    }
    order
}

// Post-order DFS: mark on entry so a malformed dependency cycle terminates, push after the
// dependencies so they precede the dependent in the load order.
fn visit_module(
    m: &Path,
    deps: &BTreeMap<PathBuf, Vec<PathBuf>>,
    done: &mut BTreeSet<PathBuf>,
    order: &mut Vec<PathBuf>,
) {
    if !done.insert(m.to_path_buf()) {
        return;
    }
    if let Some(needs) = deps.get(m) {
        for d in needs {
            visit_module(d, deps, done, order);
        }
    }
    order.push(m.to_path_buf());
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
    fn parse_cmdline_reads_the_home_layer() {
        let p = parse_cmdline("horizon.home=LABEL=ENC horizon.homefs=btrfs");
        assert_eq!(p.home, Spec::Label("ENC".into()));
        assert_eq!(p.homefs, "btrfs");
    }

    #[test]
    fn parse_cmdline_reads_the_verity_root_and_device() {
        // The loader supplies the root hash (the trust anchor) and, optionally, where the
        // hash device lives; the root hash present is what turns verification on.
        let p = parse_cmdline(
            "ro horizon.verity=deadbeefcafe horizon.veritydev=UUID=1234 console=tty0",
        );
        assert_eq!(p.verity.as_deref(), Some("deadbeefcafe"));
        assert_eq!(p.verity_dev, Spec::Uuid("1234".into()));
    }

    #[test]
    fn parse_cmdline_defaults_to_the_horizon_labels() {
        let p = parse_cmdline("ro quiet console=tty0");
        assert_eq!(p.base, Spec::Label("HORIZON-BASE".into()));
        assert_eq!(p.data, Spec::Label("HORIZON-DATA".into()));
        // The encrypted Home layer defaults to its own label, so a Key boots with no
        // explicit command line.
        assert_eq!(p.home, Spec::Label("HORIZON-HOME".into()));
        assert_eq!(p.homefs, "ext4");
        // No verity token: the base is mounted unverified, but the hash device still
        // defaults to its own label for when a loader does supply a root hash.
        assert_eq!(p.verity, None);
        assert_eq!(p.verity_dev, Spec::Label("HORIZON-VERITY".into()));
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
    fn luks_open_args_read_an_exact_32_byte_key_from_stdin() {
        let args = luks_open_args(Path::new("/dev/disk/by-label/HORIZON-HOME"), HOME_MAPPER);
        assert_eq!(args[0], "luksOpen");
        let pos = |s: &str| args.iter().position(|a| a == s).unwrap();
        // The master comes from stdin, exactly 32 bytes, never a key file on disk.
        assert_eq!(args[pos("--key-file") + 1], "-");
        assert_eq!(args[pos("--keyfile-size") + 1], "32");
        // The container then the mapper name are the trailing positional args.
        assert_eq!(args[args.len() - 2], "/dev/disk/by-label/HORIZON-HOME");
        assert_eq!(args[args.len() - 1], "horizon-home");
        assert_eq!(luks_close_args("m"), vec!["luksClose", "m"]);
        assert_eq!(
            mapper_path("horizon-home"),
            Path::new("/dev/mapper/horizon-home")
        );
    }

    #[test]
    fn verity_open_args_pass_the_root_hash_as_a_public_argument() {
        let args = verity_open_args(
            Path::new("/dev/disk/by-label/HORIZON-BASE"),
            Path::new("/dev/disk/by-partlabel/HORIZON-VERITY"),
            BASE_MAPPER,
            "abc123",
        );
        // `veritysetup open <data> <name> <hash> <roothash>`: the root hash is the trailing
        // positional argument, a public trust anchor, never fed on stdin the way the LUKS
        // master is. The verified base is exposed at the fixed base mapper name.
        assert_eq!(
            args,
            vec![
                "open",
                "/dev/disk/by-label/HORIZON-BASE",
                "horizon-base",
                "/dev/disk/by-partlabel/HORIZON-VERITY",
                "abc123",
            ]
        );
        assert_eq!(
            verity_close_args("horizon-base"),
            vec!["close", "horizon-base"]
        );
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

    #[test]
    fn home_wanted_needs_the_store_the_layer_and_not_ghost() {
        // Encrypted Home needs both partitions and a non-Ghost request.
        assert!(home_wanted(ModeChoice::Auto, true, true));
        assert!(home_wanted(ModeChoice::Home, true, true));
        // An explicit Ghost never persists, even with both present.
        assert!(!home_wanted(ModeChoice::Ghost, true, true));
        // Missing either partition degrades to a stateless boot.
        assert!(!home_wanted(ModeChoice::Auto, true, false));
        assert!(!home_wanted(ModeChoice::Auto, false, true));
        assert!(!home_wanted(ModeChoice::Home, false, false));
    }

    #[test]
    fn module_load_order_puts_dependencies_first() {
        // A slice of a real modules.dep: ext4 needs mbcache and jbd2, dm-crypt needs dm-mod,
        // squashfs needs nothing. The initramfs carries the closure keybuild trimmed, and the
        // init must load each module after the ones it depends on.
        let text = "\
kernel/fs/ext4/ext4.ko: kernel/fs/mbcache.ko kernel/fs/jbd2/jbd2.ko
kernel/fs/mbcache.ko:
kernel/fs/jbd2/jbd2.ko:
kernel/fs/squashfs/squashfs.ko:
kernel/drivers/md/dm-crypt.ko: kernel/drivers/md/dm-mod.ko
kernel/drivers/md/dm-mod.ko:
";
        let deps = parse_modules_dep(text);
        let order = module_load_order(&deps);
        let pos = |name: &str| {
            order
                .iter()
                .position(|p| p.to_string_lossy().contains(name))
                .unwrap_or_else(|| panic!("{name} not in load order"))
        };
        // Every dependency loads before the module that needs it.
        assert!(pos("mbcache") < pos("ext4.ko"));
        assert!(pos("jbd2") < pos("ext4.ko"));
        assert!(pos("dm-mod") < pos("dm-crypt"));
        // Six distinct modules, each loaded exactly once (a shared dependency is not repeated).
        assert_eq!(order.len(), 6);
        let unique: std::collections::BTreeSet<_> = order.iter().collect();
        assert_eq!(unique.len(), 6);
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
