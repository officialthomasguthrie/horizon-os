// Errors from building or running a Cell. A confinement failure carries the
// kernel step that refused, so a denied unshare and a denied mount read
// differently in a log.

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    // The kernel would not confine: unprivileged user namespaces are off, or a
    // namespace, mount, or pivot step was refused. The string names the step.
    #[error("confine: {0}")]
    Confine(String),
    // Building or installing the seccomp filter failed.
    #[error("seccomp: {0}")]
    Seccomp(String),
    // Not Linux: a Cell needs the Linux kernel's namespaces and seccomp.
    #[error("cells need Linux; this host has no confinement")]
    Unsupported,
}

pub type Result<T> = std::result::Result<T, Error>;
