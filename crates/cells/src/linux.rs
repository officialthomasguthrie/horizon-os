// The Linux confinement core. The caller (the supervisor) forks an init child A,
// which creates the namespaces and maps itself to root inside the new user
// namespace. A then forks the payload child B, which is PID 1 of the cell's pid
// namespace and builds the rest of the world: a tmpfs root holding only the
// granted binds, an optional minimal /dev and a private /proc, then it pivots
// into that root, sets no_new_privs, installs the seccomp filter, keeps only the
// granted fds, and runs the payload. The world is built by B rather than A
// because /proc must be mounted from inside the new pid namespace (A is not in
// it, only its children are) and the host device nodes /dev binds need are only
// reachable before the pivot detaches the host, so both belong to one process,
// which is B.
//
// Two pipes carry the outcome. B writes a (step, errno) pair to an error pipe
// only if a setup or exec step fails; a clean start closes it (CLOEXEC on exec,
// or an explicit close for a closure payload). A bridges that, plus B's wait
// status, into a 12-byte report the supervisor reads, so every failure comes
// back as a typed Error instead of a bare nonzero exit.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::statvfs::{statvfs, FsFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, execve, fork, pivot_root, sethostname, ForkResult};

use crate::{seccomp, Cell, Error, Payload, Result, Seccomp, Status};

// A new tmpfs root is staged at a unique, empty mountpoint under /tmp, so it
// shadows only itself (never a bind source that lives elsewhere under /tmp) and
// nothing inside it is ever visible on the host.
static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);
const PUT_OLD: &str = "oldroot";

fn stage_path() -> String {
    let n = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("/tmp/.horizon-cell.{}.{}", std::process::id(), n)
}

// Which setup step failed, reported back so the supervisor can name it.
const S_UNSHARE: i32 = 1;
const S_MAP: i32 = 2;
const S_PRIVATE: i32 = 3;
const S_TMPFS: i32 = 4;
const S_MKDIR: i32 = 5;
const S_BIND: i32 = 6;
const S_PIVOT: i32 = 7;
const S_HOSTNAME: i32 = 8;
const S_FORK: i32 = 9;
const S_NOPRIV: i32 = 11;
const S_SECCOMP: i32 = 12;
const S_EXEC: i32 = 13;
const S_DEV: i32 = 14;
const S_PROC: i32 = 15;

fn step_name(s: i32) -> &'static str {
    match s {
        S_UNSHARE => "unshare namespaces",
        S_MAP => "write uid/gid map",
        S_PRIVATE => "make mounts private",
        S_TMPFS => "mount tmpfs root",
        S_MKDIR => "create cell dir",
        S_BIND => "bind grant into cell",
        S_PIVOT => "pivot_root",
        S_HOSTNAME => "set hostname",
        S_FORK => "fork payload",
        S_NOPRIV => "set no_new_privs",
        S_SECCOMP => "install seccomp filter",
        S_EXEC => "exec payload",
        S_DEV => "set up /dev",
        S_PROC => "mount /proc",
        _ => "unknown step",
    }
}

// Report kinds, A -> supervisor.
const R_EXITED: i32 = 0;
const R_SIGNALED: i32 = 1;
const R_SETUP_ERR: i32 = 2;

pub(crate) fn available() -> bool {
    // The only honest probe is the real thing: build a throwaway empty cell and
    // see if it runs end to end. A host can allow unshare(CLONE_NEWUSER) yet
    // still refuse to write the uid map (Ubuntu's
    // apparmor_restrict_unprivileged_userns does exactly this), so any lighter
    // check would lie and make the tests run where they cannot.
    run(Cell::default(), Payload::Call(Box::new(|| 0)))
        .map(|s| s.code == Some(0))
        .unwrap_or(false)
}

pub(crate) struct ChildHandle {
    a_pid: nix::unistd::Pid,
    report_r: RawFd,
    stage: String,
}

pub(crate) fn spawn(cell: Cell, payload: Payload) -> Result<ChildHandle> {
    let stage = stage_path();
    let (report_r, report_w) = pipe_raw()?;
    match unsafe { fork() }.map_err(|e| Error::Confine(format!("fork init: {e}")))? {
        ForkResult::Child => {
            close(report_r);
            let code = cell_init(&stage, cell, payload, report_w);
            unsafe { libc::_exit(code) };
        }
        ForkResult::Parent { child } => {
            close(report_w);
            Ok(ChildHandle {
                a_pid: child,
                report_r,
                stage,
            })
        }
    }
}

pub(crate) fn wait(h: ChildHandle) -> Result<Status> {
    let out = read_report(h.report_r);
    close(h.report_r);
    let _ = waitpid(h.a_pid, None);
    // The cell's mount namespace is gone now, so the staging dir is an empty
    // leftover on the host; remove it.
    let _ = std::fs::remove_dir(&h.stage);
    out
}

pub(crate) fn run(cell: Cell, payload: Payload) -> Result<Status> {
    wait(spawn(cell, payload)?)
}

// Child A: create the namespaces and the uid/gid map, then fork B (PID 1 of the
// new pid namespace) to build the world and run the payload, and bridge B's
// outcome into the report pipe. Returns A's own exit code (the supervisor
// ignores it; it reads the pipe).
fn cell_init(stage: &str, cell: Cell, payload: Payload, report: RawFd) -> i32 {
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();

    let flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNET
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWCGROUP;
    if let Err(e) = unshare(flags) {
        return fail(report, S_UNSHARE, e as i32);
    }

    // Map the caller to root inside the new user namespace. setgroups must be
    // denied before gid_map can be written unprivileged.
    if let Err(c) = write_maps(uid, gid) {
        return fail(report, S_MAP, c);
    }

    // Error pipe B -> A: B writes (step, errno) only if a step fails.
    let (err_r, err_w) = match pipe_raw() {
        Ok(p) => p,
        Err(_) => return fail(report, S_FORK, 0),
    };

    // This first fork after unshare(CLONE_NEWPID) lands B as PID 1 of the new
    // pid namespace.
    match unsafe { fork() } {
        Err(e) => fail(report, S_FORK, e as i32),
        Ok(ForkResult::Child) => {
            close(err_r);
            close(report);
            build_world_and_run(stage, cell, payload, err_w)
        }
        Ok(ForkResult::Parent { child }) => {
            close(err_w);
            bridge(report, err_r, child)
        }
    }
}

// Child B: PID 1 of the cell. Build the world (tmpfs root, binds, optional /dev
// and /proc), pivot into it, lock down, and run the payload. Any setup failure
// is emitted as (step, errno) on the error pipe; a clean start closes it (an
// explicit close for a closure, CLOEXEC on a successful exec).
fn build_world_and_run(stage: &str, cell: Cell, payload: Payload, err: RawFd) -> ! {
    // Stop every mount change here from propagating back to the host.
    if let Err(e) = mount(NONE, "/", NONE, MsFlags::MS_REC | MsFlags::MS_PRIVATE, NONE) {
        emit_exit(err, S_PRIVATE, e as i32);
    }

    // A fresh tmpfs at a unique mountpoint becomes the cell's whole world.
    if let Err(c) = mkdirs(stage) {
        emit_exit(err, S_MKDIR, c);
    }
    if let Err(e) = mount(
        Some("tmpfs"),
        stage,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        NONE,
    ) {
        emit_exit(err, S_TMPFS, e as i32);
    }
    if let Err(c) = mkdirs(&format!("{stage}/{PUT_OLD}")) {
        emit_exit(err, S_MKDIR, c);
    }

    for b in &cell.binds {
        if let Err((step, c)) = bind_into(stage, b) {
            emit_exit(err, step, c);
        }
    }

    // /dev nodes are binds of the host's, so they must be set up before the
    // pivot detaches the host filesystem.
    if cell.mount_dev {
        if let Err((step, c)) = dev_into(stage) {
            emit_exit(err, step, c);
        }
    }

    // /proc is a virtual filesystem (no host source), so it can be mounted into
    // the new root before the pivot. It must be mounted here, by PID 1 of the
    // new pid namespace, so the procfs binds to that namespace and the cell sees
    // only its own processes.
    if cell.mount_proc {
        if let Err((step, c)) = proc_into(stage) {
            emit_exit(err, step, c);
        }
    }

    if let Err(c) = pivot(stage) {
        emit_exit(err, S_PIVOT, c);
    }

    if let Some(name) = &cell.hostname {
        if let Err(e) = sethostname(name) {
            emit_exit(err, S_HOSTNAME, e as i32);
        }
    }

    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        emit_exit(err, S_NOPRIV, errno());
    }

    if let Seccomp::Block(list) = &cell.seccomp {
        if seccomp::apply_block(list).is_err() {
            emit_exit(err, S_SECCOMP, -1);
        }
    }

    keep_only(&cell.keep_fds, err);

    match payload {
        Payload::Call(f) => {
            // Signal a clean start, then run the closure.
            close(err);
            let code = f();
            unsafe { libc::_exit(code) };
        }
        Payload::Exec { path, argv, env } => {
            set_cloexec(err); // a successful exec closes it, telling A we started
            let cpath = match CString::new(path.as_os_str().as_bytes()) {
                Ok(c) => c,
                Err(_) => emit_exit(err, S_EXEC, libc::EINVAL),
            };
            let cargv = cstrings(argv.iter().map(|a| a.as_bytes()));
            let env_bytes: Vec<Vec<u8>> = env
                .iter()
                .map(|(k, v)| join_kv(k.as_bytes(), v.as_bytes()))
                .collect();
            let cenv = cstrings(env_bytes.iter().map(|v| v.as_slice()));
            let _ = execve(&cpath, &cargv, &cenv);
            emit_exit(err, S_EXEC, errno())
        }
    }
}

// A waits on B and turns the error pipe + wait status into one report.
fn bridge(report: RawFd, err_r: RawFd, child: nix::unistd::Pid) -> i32 {
    let mut buf = [0u8; 8];
    let n = read_full(err_r, &mut buf);
    close(err_r);
    let status = waitpid(child, None);
    if n == 8 {
        let step = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let errno = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        write_report(report, R_SETUP_ERR, step, errno);
        return 1;
    }
    match status {
        Ok(WaitStatus::Exited(_, code)) => write_report(report, R_EXITED, code, 0),
        Ok(WaitStatus::Signaled(_, sig, _)) => write_report(report, R_SIGNALED, sig as i32, 0),
        _ => write_report(report, R_SETUP_ERR, S_FORK, 0),
    }
    0
}

fn read_report(fd: RawFd) -> Result<Status> {
    let mut buf = [0u8; 12];
    let n = read_full(fd, &mut buf);
    if n != 12 {
        return Err(Error::Confine("cell died before reporting".into()));
    }
    let kind = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let a = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let b = i32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    match kind {
        R_EXITED => Ok(Status {
            code: Some(a),
            signal: None,
        }),
        R_SIGNALED => Ok(Status {
            code: None,
            signal: Some(a),
        }),
        R_SETUP_ERR => {
            let what = step_name(a);
            if b > 0 {
                let os = std::io::Error::from_raw_os_error(b);
                Err(Error::Confine(format!("{what}: {os}")))
            } else {
                Err(Error::Confine(what.to_string()))
            }
        }
        _ => Err(Error::Confine("garbled cell report".into())),
    }
}

// --- small building blocks ---

const NONE: Option<&'static str> = None;

fn write_maps(uid: u32, gid: u32) -> std::result::Result<(), i32> {
    io_errno(std::fs::write("/proc/self/setgroups", "deny"))?;
    io_errno(std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")))?;
    io_errno(std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")))?;
    Ok(())
}

fn bind_into(stage: &str, b: &crate::Bind) -> std::result::Result<(), (i32, i32)> {
    let dst = b.dst.to_string_lossy();
    let dst = if dst.starts_with('/') {
        dst.to_string()
    } else {
        format!("/{dst}")
    };
    let target = format!("{stage}{dst}");

    let is_dir = std::fs::metadata(&b.src)
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if is_dir {
        mkdirs(&target).map_err(|c| (S_MKDIR, c))?;
    } else {
        if let Some(parent) = Path::new(&target).parent() {
            mkdirs(&parent.to_string_lossy()).map_err(|c| (S_MKDIR, c))?;
        }
        io_errno(std::fs::write(&target, b"")).map_err(|c| (S_MKDIR, c))?;
    }

    let flags = MsFlags::MS_BIND | MsFlags::MS_REC;
    mount(Some(b.src.as_path()), target.as_str(), NONE, flags, NONE)
        .map_err(|e| (S_BIND, e as i32))?;
    if !b.writable {
        // A read-only remount in a user namespace cannot drop the flags the
        // source mount already had locked on (nosuid, nodev, relatime, ...), so
        // they must be carried over or the remount is refused with EPERM. This
        // is the bubblewrap gotcha that bites binding host system dirs read-only.
        let flags =
            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY | locked_flags(&target);
        mount(NONE, target.as_str(), NONE, flags, NONE).map_err(|e| (S_BIND, e as i32))?;
    }
    Ok(())
}

// The mount flags the kernel will not let an unprivileged remount clear, read
// back from the just-created bind so the read-only remount can re-assert them.
fn locked_flags(target: &str) -> MsFlags {
    let mut flags = MsFlags::empty();
    let Ok(st) = statvfs(target) else {
        return flags;
    };
    let f = st.flags();
    if f.contains(FsFlags::ST_NOSUID) {
        flags |= MsFlags::MS_NOSUID;
    }
    if f.contains(FsFlags::ST_NODEV) {
        flags |= MsFlags::MS_NODEV;
    }
    if f.contains(FsFlags::ST_NOEXEC) {
        flags |= MsFlags::MS_NOEXEC;
    }
    if f.contains(FsFlags::ST_NOATIME) {
        flags |= MsFlags::MS_NOATIME;
    }
    if f.contains(FsFlags::ST_NODIRATIME) {
        flags |= MsFlags::MS_NODIRATIME;
    }
    if f.contains(FsFlags::ST_RELATIME) {
        flags |= MsFlags::MS_RELATIME;
    }
    flags
}

// A minimal /dev: the standard character devices, each bound from the host's
// node (an unprivileged user namespace cannot mknod its own), plus the usual
// symlinks into /proc. Runs before the pivot, while the host's /dev is reachable.
fn dev_into(stage: &str) -> std::result::Result<(), (i32, i32)> {
    let devdir = format!("{stage}/dev");
    mkdirs(&devdir).map_err(|c| (S_DEV, c))?;
    for name in ["null", "zero", "full", "random", "urandom", "tty"] {
        let node = crate::Bind {
            src: PathBuf::from(format!("/dev/{name}")),
            dst: PathBuf::from(format!("/dev/{name}")),
            writable: true,
        };
        bind_into(stage, &node).map_err(|(_, c)| (S_DEV, c))?;
    }
    for (link, dst) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        let _ = std::os::unix::fs::symlink(dst, format!("{devdir}/{link}"));
    }
    Ok(())
}

// A private /proc, mounted into the new root by PID 1 of the cell's pid
// namespace, so the procfs reflects that namespace and shows only the cell.
fn proc_into(stage: &str) -> std::result::Result<(), (i32, i32)> {
    let target = format!("{stage}/proc");
    mkdirs(&target).map_err(|c| (S_PROC, c))?;
    mount(
        Some("proc"),
        target.as_str(),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        NONE,
    )
    .map_err(|e| (S_PROC, e as i32))?;
    Ok(())
}

// Make the staged tmpfs the root and detach the host. Errors come back as an
// errno; the caller (B) names the step S_PIVOT and emits it.
fn pivot(stage: &str) -> std::result::Result<(), i32> {
    chdir(stage).map_err(|e| e as i32)?;
    pivot_root(".", PUT_OLD).map_err(|e| e as i32)?;
    chdir("/").map_err(|e| e as i32)?;
    let old = format!("/{PUT_OLD}");
    umount2(old.as_str(), MntFlags::MNT_DETACH).map_err(|e| e as i32)?;
    let _ = std::fs::remove_dir(&old);
    Ok(())
}

fn mkdirs(path: &str) -> std::result::Result<(), i32> {
    io_errno(std::fs::create_dir_all(path))
}

// Close every fd except 0,1,2, the kept fds, and the error fd.
fn keep_only(keep: &[RawFd], err: RawFd) {
    for &fd in keep {
        clear_cloexec(fd);
    }
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) } as RawFd;
    let max = if max <= 0 { 1024 } else { max.min(4096) };
    for fd in 3..max {
        if fd == err || keep.contains(&fd) {
            continue;
        }
        unsafe {
            libc::close(fd);
        }
    }
}

// --- raw fd helpers ---

fn pipe_raw() -> Result<(RawFd, RawFd)> {
    let mut fds = [0 as RawFd; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok((fds[0], fds[1]))
}

fn close(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

fn read_full(fd: RawFd, buf: &mut [u8]) -> usize {
    let mut got = 0;
    while got < buf.len() {
        let n = unsafe {
            libc::read(
                fd,
                buf[got..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - got,
            )
        };
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    got
}

fn write_all(fd: RawFd, buf: &[u8]) {
    let mut sent = 0;
    while sent < buf.len() {
        let n = unsafe {
            libc::write(
                fd,
                buf[sent..].as_ptr() as *const libc::c_void,
                buf.len() - sent,
            )
        };
        if n <= 0 {
            break;
        }
        sent += n as usize;
    }
}

fn write_report(fd: RawFd, kind: i32, a: i32, b: i32) {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&kind.to_le_bytes());
    buf[4..8].copy_from_slice(&a.to_le_bytes());
    buf[8..12].copy_from_slice(&b.to_le_bytes());
    write_all(fd, &buf);
}

// Used by A: report a setup error and return A's exit code.
fn fail(report: RawFd, step: i32, errno: i32) -> i32 {
    write_report(report, R_SETUP_ERR, step, errno);
    1
}

// Used by B: write (step, errno) to the error pipe.
fn emit(fd: RawFd, step: i32, errno: i32) {
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&step.to_le_bytes());
    buf[4..8].copy_from_slice(&errno.to_le_bytes());
    write_all(fd, &buf);
}

fn emit_exit(fd: RawFd, step: i32, errno: i32) -> ! {
    emit(fd, step, errno);
    unsafe { libc::_exit(127) };
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn io_errno<T>(r: std::io::Result<T>) -> std::result::Result<(), i32> {
    r.map(|_| ()).map_err(|e| e.raw_os_error().unwrap_or(-1))
}

fn clear_cloexec(fd: RawFd) {
    unsafe {
        let f = libc::fcntl(fd, libc::F_GETFD);
        if f >= 0 {
            libc::fcntl(fd, libc::F_SETFD, f & !libc::FD_CLOEXEC);
        }
    }
}

fn set_cloexec(fd: RawFd) {
    unsafe {
        let f = libc::fcntl(fd, libc::F_GETFD);
        if f >= 0 {
            libc::fcntl(fd, libc::F_SETFD, f | libc::FD_CLOEXEC);
        }
    }
}

fn cstrings<'a>(items: impl Iterator<Item = &'a [u8]>) -> Vec<CString> {
    items
        .map(|b| CString::new(b).unwrap_or_else(|_| CString::new("").unwrap()))
        .collect()
}

fn join_kv(k: &[u8], v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(k.len() + v.len() + 1);
    out.extend_from_slice(k);
    out.push(b'=');
    out.extend_from_slice(v);
    out
}
