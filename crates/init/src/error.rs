use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// A boot step failed: the operation, the path it acted on, and the OS error.
    /// Naming the step is what turns an opaque init failure into something a console
    /// log can act on.
    #[error("{op} {path}: {source}")]
    Step {
        op: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// A device named on the kernel command line (a label, a UUID, a path) did not
    /// resolve to a present block device.
    #[error("resolve {0}: no such device")]
    Resolve(String),
}

#[cfg(target_os = "linux")]
impl Error {
    pub(crate) fn step(op: &'static str, path: &std::path::Path, source: std::io::Error) -> Error {
        Error::Step {
            op,
            path: path.display().to_string(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
