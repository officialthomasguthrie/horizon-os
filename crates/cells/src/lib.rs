//! Cells: bubblewrap-class confinement for Horizon principals.
//!
//! No principal, app, service, or Aura, has authority by virtue of "running as
//! you". A Cell is the cage that makes that real: a process placed in fresh
//! Linux namespaces (user, mount, pid, net, ipc, uts, cgroup) with an empty
//! default world, no network, no filesystem, no devices, plus `no_new_privs`
//! and a seccomp filter. The only things inside are what was granted: read-only
//! [`Bind`]s into the mount tree and open file descriptors handed in with
//! [`Cell::keep_fd`]. That fd is how the Weave broker passes a brokered file or
//! socket to a confined principal (see the `weave` crate's `Lease`).
//!
//! Confinement is unprivileged: a user namespace maps the caller to root inside
//! the Cell, so no SUID helper and no real root are needed (the bubblewrap
//! design, chosen over Firejail's SUID-root model). It is a faithful userland
//! approximation of object-capabilities on a monolithic kernel; a kernel
//! exploit still bypasses it, which is why the model is kept microkernel-shaped
//! for later.

mod error;
pub use error::{Error, Result};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod seccomp;

use std::ffi::OsString;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

// A host path mounted into the cell's world. The default world has no files at
// all; every path a principal can see is a Bind placed here on purpose.
#[derive(Clone, Debug)]
pub struct Bind {
    pub src: PathBuf,
    pub dst: PathBuf,
    pub writable: bool,
}

// The seccomp posture installed just before the payload runs.
#[derive(Clone, Debug, Default)]
pub enum Seccomp {
    // No syscall filter.
    #[default]
    None,
    // Allow by default, refuse the listed syscalls with EPERM. Numbers are this
    // host arch's (use the `libc::SYS_*` constants).
    Block(Vec<i64>),
}

// What runs inside the Cell.
pub enum Payload {
    // Execute a program, resolved inside the cell's mount tree (so the binary
    // must be a Bind). argv[0] is whatever the caller puts first.
    Exec {
        path: PathBuf,
        argv: Vec<OsString>,
        env: Vec<(OsString, OsString)>,
    },
    // Run a closure in the confined child; its return is the exit code. Handy
    // for tests and in-process confined work. Keep it small: it runs right
    // after a fork, so avoid anything that might wait on a lock another thread
    // held at fork time (allocator, stdio).
    Call(Box<dyn FnOnce() -> i32>),
}

impl Payload {
    pub fn call(f: impl FnOnce() -> i32 + 'static) -> Payload {
        Payload::Call(Box::new(f))
    }
    pub fn exec(path: impl Into<PathBuf>, argv: Vec<OsString>) -> Payload {
        Payload::Exec {
            path: path.into(),
            argv,
            env: Vec::new(),
        }
    }
}

// A confinement spec: an empty world plus exactly what is granted into it.
#[derive(Default)]
pub struct Cell {
    pub(crate) binds: Vec<Bind>,
    pub(crate) keep_fds: Vec<RawFd>,
    pub(crate) seccomp: Seccomp,
    pub(crate) hostname: Option<String>,
}

impl Cell {
    pub fn new() -> Cell {
        Cell::default()
    }

    pub fn bind_ro(mut self, src: impl Into<PathBuf>, dst: impl Into<PathBuf>) -> Cell {
        self.binds.push(Bind {
            src: src.into(),
            dst: dst.into(),
            writable: false,
        });
        self
    }

    pub fn bind_rw(mut self, src: impl Into<PathBuf>, dst: impl Into<PathBuf>) -> Cell {
        self.binds.push(Bind {
            src: src.into(),
            dst: dst.into(),
            writable: true,
        });
        self
    }

    // Keep this fd open in the payload; every other fd is closed. This is the
    // channel the broker uses to hand a confined principal a brokered fd.
    pub fn keep_fd(mut self, fd: RawFd) -> Cell {
        self.keep_fds.push(fd);
        self
    }

    pub fn seccomp(mut self, s: Seccomp) -> Cell {
        self.seccomp = s;
        self
    }

    pub fn hostname(mut self, name: impl Into<String>) -> Cell {
        self.hostname = Some(name.into());
        self
    }

    // Spawn the payload confined, wait for it, and report how it exited.
    pub fn run(self, payload: Payload) -> Result<Status> {
        #[cfg(target_os = "linux")]
        {
            linux::run(self, payload)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, payload);
            Err(Error::Unsupported)
        }
    }
}

// How a Cell's payload ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl Status {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

// Whether this host can confine, that is, whether unprivileged user namespaces
// are usable here. Tests and the CLI call this to skip gracefully where the
// kernel forbids it: a hardened host, or a CI runner that restricts
// unprivileged userns.
pub fn available() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::available()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
