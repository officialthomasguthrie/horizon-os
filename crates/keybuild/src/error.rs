use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A userland binary path has no final component to install under /usr/bin.
    #[error("not a file: {0}")]
    NotAFile(PathBuf),
    /// A build tool ran but failed. The name and its stderr are what a build log needs.
    #[error("{name} failed (exit {code:?}): {stderr}")]
    Tool {
        name: &'static str,
        code: Option<i32>,
        stderr: String,
    },
    /// A build tool is not installed. Separate from a tool failure so a test can skip
    /// gracefully where the tool is absent (CI) while running for real where it is not.
    #[error("{0} is not installed")]
    Missing(&'static str),
    /// Requested modules that no file in the kernel's `modules.dep` matches. A base must
    /// not silently omit a driver it was told to carry, so an unresolved name fails.
    #[error("modules not found in the kernel's modules.dep: {}", .0.join(", "))]
    UnknownModules(Vec<String>),
    /// Modules were requested without naming the kernel version to harvest them from.
    #[error("a kernel version is required to install modules")]
    NoKernelVersion,
}

pub type Result<T> = std::result::Result<T, Error>;
