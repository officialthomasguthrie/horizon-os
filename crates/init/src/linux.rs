// The Linux executor: walk a Plan against the real kernel. Each Step maps to a
// mount/overlay/bind/move/switch_root syscall. Everything here is gated to Linux so
// the workspace still builds on darwin; the plan that drives it is pure and lives in
// lib.rs.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use nix::errno::Errno;
use nix::mount::{mount, MsFlags};
use nix::unistd::{chdir, chroot, execv};

use crate::{Error, MountFlags, Plan, Source, Spec, Step};

// A typed None for the source/fstype/data arguments mount does not need.
const NONE: Option<&Path> = None;

fn io(e: Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e as i32)
}

fn flags(f: MountFlags) -> MsFlags {
    let mut m = MsFlags::empty();
    if f.rdonly {
        m |= MsFlags::MS_RDONLY;
    }
    if f.nosuid {
        m |= MsFlags::MS_NOSUID;
    }
    if f.nodev {
        m |= MsFlags::MS_NODEV;
    }
    if f.noexec {
        m |= MsFlags::MS_NOEXEC;
    }
    m
}

// The kernel virtual filesystems; re-mounting one is harmless (the binary mounts proc
// before reading the command line, then the plan mounts it again), so EBUSY on these
// is ignored rather than failing the boot.
fn is_pseudo(fstype: &str) -> bool {
    matches!(fstype, "proc" | "sysfs" | "devtmpfs" | "tmpfs")
}

/// Run a whole plan. Returns only if it ends before the `switch_root` step (the
/// executor for a real boot does not return: `switch_root` execs the init).
pub fn execute(plan: &Plan) -> Result<(), Error> {
    for step in &plan.steps {
        run(step)?;
    }
    Ok(())
}

fn run(step: &Step) -> Result<(), Error> {
    match step {
        Step::Mkdir(p) => std::fs::create_dir_all(p).map_err(|e| Error::step("mkdir", p, e)),
        Step::Mount { source, target } => do_mount(source, target),
        Step::Overlay {
            lower,
            upper,
            work,
            target,
        } => do_overlay(lower, upper, work, target),
        Step::Bind { from, to } => bind(from, to),
        Step::Move { from, to } => move_mount(from, to),
        Step::SwitchRoot {
            new_root,
            init,
            args,
        } => switch_root(new_root, init, args),
    }
}

fn do_mount(s: &Source, target: &Path) -> Result<(), Error> {
    let res = mount(
        Some(s.dev.as_path()),
        target,
        Some(s.fstype.as_str()),
        flags(s.flags),
        NONE,
    );
    match res {
        Ok(()) => Ok(()),
        // A kernel filesystem already present is not an error in an init.
        Err(Errno::EBUSY) if is_pseudo(&s.fstype) => Ok(()),
        Err(e) => Err(Error::step("mount", target, io(e))),
    }
}

fn do_overlay(lower: &Path, upper: &Path, work: &Path, target: &Path) -> Result<(), Error> {
    let data = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    mount(
        Some("overlay"),
        target,
        Some("overlay"),
        MsFlags::empty(),
        Some(data.as_str()),
    )
    .map_err(|e| Error::step("overlay", target, io(e)))
}

fn bind(from: &Path, to: &Path) -> Result<(), Error> {
    mount(
        Some(from),
        to,
        NONE,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        NONE,
    )
    .map_err(|e| Error::step("bind", to, io(e)))
}

fn move_mount(from: &Path, to: &Path) -> Result<(), Error> {
    mount(Some(from), to, NONE, MsFlags::MS_MOVE, NONE).map_err(|e| Error::step("move", to, io(e)))
}

// The initramfs switch_root: make the assembled root the new /, drop the initramfs
// rootfs, and exec the real init. pivot_root cannot be used on the initramfs rootfs,
// so the kernel-documented move-and-chroot sequence is used instead.
fn switch_root(new_root: &Path, init: &Path, args: &[String]) -> Result<(), Error> {
    chdir(new_root).map_err(|e| Error::step("chdir", new_root, io(e)))?;
    mount(Some(new_root), Path::new("/"), NONE, MsFlags::MS_MOVE, NONE)
        .map_err(|e| Error::step("move-root", new_root, io(e)))?;
    chroot(Path::new(".")).map_err(|e| Error::step("chroot", new_root, io(e)))?;
    chdir(Path::new("/")).map_err(|e| Error::step("chdir", Path::new("/"), io(e)))?;

    let prog = cstr(init.as_os_str().as_bytes(), init)?;
    let mut argv = vec![prog.clone()];
    for a in args {
        argv.push(cstr(a.as_bytes(), init)?);
    }
    // execv returns only on failure.
    let err = execv(&prog, &argv).unwrap_err();
    Err(Error::step("exec", init, io(err)))
}

fn cstr(bytes: &[u8], at: &Path) -> Result<CString, Error> {
    CString::new(bytes).map_err(|_| {
        Error::step(
            "exec",
            at,
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "interior nul byte"),
        )
    })
}

/// Mount proc at /proc, so the binary can read the kernel command line before it has
/// planned anything. Idempotent: the plan mounts proc again and the executor ignores
/// the resulting EBUSY.
pub fn mount_proc() -> Result<(), Error> {
    do_mount(
        &Source::new("proc", "proc", MountFlags::PSEUDO),
        Path::new("/proc"),
    )
}

/// Resolve a [`Spec`] to a [`Source`]: turn a label/UUID/path into a present block
/// device with the given filesystem type. A label or UUID is looked up under
/// `/dev/disk/by-*`, the symlinks udev maintains, so the image needs no device path
/// hardcoded. An absent device is an error the caller decides how to handle (a missing
/// base aborts the boot; a missing data device falls back to Ghost).
pub fn resolve(spec: &Spec, fstype: &str) -> Result<Source, Error> {
    let path = match spec {
        Spec::Path(p) => p.clone(),
        Spec::Label(l) => Path::new("/dev/disk/by-label").join(l),
        Spec::Uuid(u) => Path::new("/dev/disk/by-uuid").join(u),
    };
    if !path.exists() {
        return Err(Error::Resolve(format!("{spec:?}")));
    }
    Ok(Source::new(path, fstype, MountFlags::default()))
}
