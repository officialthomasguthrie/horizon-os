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
    /// A partition image the disk assembly needs has not been built yet.
    #[error("partition image not found (build it first): {0}")]
    NoImage(PathBuf),
    /// A file or directory name placed in the ESP is not a valid 8.3 short name (the only
    /// form the minimal FAT writer emits): too long, an empty base, or an illegal character.
    #[error("not a valid 8.3 short name: {0}")]
    BadName(String),
    /// The ESP contents do not fit in the partition: more clusters are needed than it holds.
    #[error("ESP contents do not fit: need {needed} clusters, partition holds {available}")]
    EspFull { needed: u64, available: u64 },
    /// The ESP partition is too small to format as a valid FAT16/FAT32 filesystem.
    #[error("ESP is too small to format as FAT: {0} bytes")]
    EspTooSmall(u64),
    /// A cpio archive could not be built or parsed: a malformed path on write, or a
    /// corrupt header/field on read (the reader half that cross-checks the writer).
    #[error("cpio: {0}")]
    Cpio(&'static str),
    /// `build_initramfs` was called without naming the `/init` binary to install as PID 1.
    #[error("an init binary is required to build the initramfs")]
    NoInitBin,
}

pub type Result<T> = std::result::Result<T, Error>;
