//! The Weave: Horizon's object-capability broker and audited IPC.
//!
//! No principal, app, service, or Aura, has authority by virtue of "running as
//! you". It can only act through a [`Capability`]: an unforgeable handle that
//! both names a [`Resource`] and carries the [`Rights`] to it, scoped in time
//! and use and revocable at any moment. The [`Broker`] is the only path to a
//! resource, and every grant, use, denial, and revocation is appended to a
//! tamper-evident audit log persisted through the Lifestream, the same log
//! Glass renders live.

mod audit;
mod broker;
mod capability;
mod codec;
mod error;

pub use audit::{AuditEntry, Event};
pub use broker::{Broker, Policy, Rule};
pub use capability::{
    Capability, Grant, GrantId, GrantInfo, Lease, Limits, PrincipalId, Resource, Rights, Status,
};
pub use error::{Error, Result};
