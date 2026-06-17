#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("lifestream: {0}")]
    Lifestream(#[from] lifestream::Error),
    // A request the broker refused. The reason is the same string written to
    // the audit log, so a denial in code and a denial in the log always read
    // the same way.
    #[error("denied: {0}")]
    Denied(String),
    #[error("corrupt audit record: {0}")]
    Corrupt(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn denied(reason: impl Into<String>) -> Error {
        Error::Denied(reason.into())
    }
}
