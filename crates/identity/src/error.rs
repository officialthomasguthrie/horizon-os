use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Sealing the master under the wrap key failed (should not happen for a
    /// well-formed key).
    #[error("crypto error")]
    Crypto,
    /// The authenticator produced a secret that did not open this keyslot: a
    /// different device, a wrong software token, or a corrupted slot.
    #[error("could not unlock this keyslot (wrong authenticator or corrupted slot)")]
    Unlock,
    /// No enrolled keyslot could be unlocked by the authenticator presented.
    #[error("no enrolled keyslot matched the authenticator")]
    NoMatchingKeyslot,
    /// The on-disk keyslot bytes did not parse.
    #[error("malformed keyslot data: {0}")]
    Malformed(String),
    /// The underlying authenticator (a real FIDO2 device) failed.
    #[error("authenticator error: {0}")]
    Device(String),
}

pub type Result<T> = std::result::Result<T, Error>;
