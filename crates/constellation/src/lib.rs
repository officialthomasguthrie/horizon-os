//! Constellation: cloudless object sync of the Lifestream across your devices.
//!
//! Your Keys, phone, and home machine form a private mesh that replicates one
//! identity's Lifestream. Because every object is addressed by a keyed hash of
//! its plaintext, two stores of the same identity name the same data the same
//! way: syncing is just shipping the sealed records the other side is missing,
//! and shared history (most of the store) is already deduped on both ends.
//!
//! The records that cross a [`Transport`] are ciphertext. Only an endpoint that
//! holds the identity key can open them, so a peer that merely relays or backs
//! up your objects sees nothing but opaque blobs. The receiving endpoint, which
//! does hold the key, verifies each record before it commits it (see
//! [`lifestream::Lifestream::write_record`]).
//!
//! This is the in-process core. The network skin lives in [`net`] (enabled by
//! the default `net` feature): a QUIC + Noise link that implements the same
//! [`Transport`] trait, so the algorithm here does not change. Finding a peer to
//! dial on a LAN, without typing a host:port, lives in [`discovery`] (the default
//! `discovery` feature); finding one beyond the LAN, through a rendezvous server,
//! lives in [`net::rendezvous`]. Both use the same non-secret identity label from
//! [`label`].

mod error;
mod transport;

#[cfg(any(feature = "net", feature = "discovery"))]
mod label;

#[cfg(feature = "net")]
pub mod net;

#[cfg(feature = "discovery")]
pub mod discovery;

pub use error::{Error, Result};
pub use transport::{LocalTransport, Transport};

#[cfg(any(feature = "net", feature = "discovery"))]
pub use label::fingerprint;

#[cfg(feature = "net")]
pub use net::{NetworkTransport, Rendezvous, RendezvousClient, RendezvousRegistration, Server};

#[cfg(feature = "discovery")]
pub use discovery::{discover, Beacon};

use std::collections::HashSet;

use lifestream::ObjectId;

// What one sync run did. Counts are over the source store; transferred and bytes
// cover only records that were actually missing on the destination.
#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub source_objects: usize,
    pub dest_objects: usize,
    pub transferred: usize,
    pub bytes: u64,
    // Refs the destination did not have, set outright.
    pub refs_set: Vec<String>,
    // Refs fast-forwarded: the destination's target was an ancestor of ours.
    pub refs_advanced: Vec<String>,
    // Refs left untouched because advancing them would drop history.
    pub refs_conflicted: Vec<String>,
}

impl SyncReport {
    pub fn moved_anything(&self) -> bool {
        self.transferred > 0 || !self.refs_set.is_empty() || !self.refs_advanced.is_empty()
    }
}

// Push everything `from` holds that `to` is missing, then carry `from`'s refs
// onto `to`. One direction; a two-way sync is this run in each direction.
pub fn sync(from: &dyn Transport, to: &dyn Transport) -> Result<SyncReport> {
    let mut report = SyncReport::default();
    let source = from.have()?;
    let dest = to.have()?;
    report.source_objects = source.len();
    report.dest_objects = dest.len();

    // The diff is the whole point: only objects `to` lacks move. Sorted so a run
    // is deterministic and easy to follow in a log.
    let mut missing: Vec<ObjectId> = source.difference(&dest).copied().collect();
    missing.sort();
    for id in &missing {
        let record = from.read_record(id)?;
        if to.write_record(id, &record)? {
            report.transferred += 1;
            report.bytes += record.len() as u64;
        }
    }

    sync_refs(from, to, &mut report)?;
    Ok(report)
}

// Carry refs from `from` to `to`. A ref `to` lacks is set outright; its target
// is present now that objects have transferred. A ref both sides hold is moved
// only on a fast-forward, when `to`'s generation is an ancestor of ours, so no
// history is dropped. Anything else is a divergence we refuse to clobber and
// report instead.
fn sync_refs(from: &dyn Transport, to: &dyn Transport, report: &mut SyncReport) -> Result<()> {
    for (name, src_id) in from.refs()? {
        match to.get_ref(&name)? {
            None => {
                to.set_ref(&name, &src_id)?;
                report.refs_set.push(name);
            }
            Some(dst_id) if dst_id == src_id => {}
            Some(dst_id) => {
                if is_ancestor(to, &dst_id, &src_id)? {
                    to.set_ref(&name, &src_id)?;
                    report.refs_advanced.push(name);
                } else {
                    report.refs_conflicted.push(name);
                }
            }
        }
    }
    Ok(())
}

// Is `ancestor` reachable from `descendant` by following generation parents?
// Walked on `to`, which holds the full graph once objects have transferred.
fn is_ancestor(to: &dyn Transport, ancestor: &ObjectId, descendant: &ObjectId) -> Result<bool> {
    let mut seen = HashSet::new();
    let mut stack = vec![*descendant];
    while let Some(id) = stack.pop() {
        if id == *ancestor {
            return Ok(true);
        }
        if !seen.insert(id) {
            continue;
        }
        if let Some(parents) = to.parents(&id)? {
            stack.extend(parents);
        }
    }
    Ok(false)
}
