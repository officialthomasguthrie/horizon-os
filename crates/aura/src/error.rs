use std::fmt;

// Aura's failure modes. A bad plan, a missing argument, or a tool's own IO
// error are all surfaced as typed reasons rather than panics, so the executor
// can record a step as failed and carry on with the rest of the plan.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing argument: {0}")]
    MissingArg(&'static str),
    #[error("bad argument {0}: {1}")]
    BadArg(&'static str, String),
    #[error("unknown tool: {0}")]
    UnknownTool(String),
    #[error("io: {0}")]
    Io(String),
    #[error("weave: {0}")]
    Weave(#[from] weave::Error),
    #[error("lifestream: {0}")]
    Lifestream(String),
    #[error("malformed index: {0}")]
    Index(&'static str),
    #[error("planning failed: {0}")]
    Plan(String),
    #[error("model: {0}")]
    Model(String),
}

impl Error {
    pub fn io(e: impl fmt::Display) -> Error {
        Error::Io(e.to_string())
    }
    pub fn lifestream(e: impl fmt::Display) -> Error {
        Error::Lifestream(e.to_string())
    }
    pub fn model(e: impl fmt::Display) -> Error {
        Error::Model(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
