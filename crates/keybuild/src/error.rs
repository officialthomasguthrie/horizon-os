use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
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
}

pub type Result<T> = std::result::Result<T, Error>;
