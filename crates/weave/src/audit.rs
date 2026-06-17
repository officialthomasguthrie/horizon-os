// The audit log: an append-only, tamper-evident record of every grant, use,
// denial, and revocation, persisted through the Lifestream.
//
// Each entry is stored as a small Lifestream Tree with two children: a "payload"
// File holding the encoded event, and (for all but the first) a "prev" pointing
// at the previous entry's Tree. That makes the log a hash-chained DAG: because
// every object is addressed by a keyed hash of its content, altering any past
// entry changes its id, which changes the next entry's "prev", and so on up to
// the head ref that pins the chain. Shaping it as a real DAG also means the
// existing mark-and-sweep gc keeps the whole history alive from that one ref.

use lifestream::{Lifestream, NodeKind, Object, ObjectId, TreeEntry};

use crate::capability::{GrantId, PrincipalId, Resource, Rights};
use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};

const PAYLOAD_VERSION: u8 = 1;

// One thing that happened. The log is a sequence of these.
#[derive(Clone, Debug)]
pub enum Event {
    Grant {
        grant: GrantId,
        principal: PrincipalId,
        resource: Resource,
        rights: Rights,
        expires_unix: Option<u64>,
        max_uses: Option<u32>,
    },
    Use {
        grant: GrantId,
        principal: PrincipalId,
        resource: Resource,
        rights: Rights,
    },
    Deny {
        principal: PrincipalId,
        resource: Resource,
        rights: Rights,
        reason: String,
    },
    Revoke {
        grant: GrantId,
    },
}

impl Event {
    pub fn kind(&self) -> &'static str {
        match self {
            Event::Grant { .. } => "grant",
            Event::Use { .. } => "use",
            Event::Deny { .. } => "deny",
            Event::Revoke { .. } => "revoke",
        }
    }
}

// A decoded entry plus the id of the object it lives at.
#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub id: ObjectId,
    pub seq: u64,
    pub time_unix: u64,
    pub event: Event,
}

const CHILD_PAYLOAD: &str = "payload";
const CHILD_PREV: &str = "prev";

// Append an event as a new chained entry, returning the new head id. `prev` is
// the current head (None for the first entry).
pub(crate) fn append(
    ls: &Lifestream,
    prev: Option<ObjectId>,
    seq: u64,
    time_unix: u64,
    event: &Event,
) -> Result<ObjectId> {
    let payload = encode_payload(seq, time_unix, event);
    let payload_id = ls.write_bytes(&payload)?;
    let mut entries = vec![TreeEntry {
        name: CHILD_PAYLOAD.to_string(),
        kind: NodeKind::File,
        id: payload_id,
        mode: 0,
    }];
    if let Some(p) = prev {
        entries.push(TreeEntry {
            name: CHILD_PREV.to_string(),
            kind: NodeKind::Tree,
            id: p,
            mode: 0,
        });
    }
    Ok(ls.put(&Object::Tree { entries })?)
}

// Walk the chain from `head` back to the first entry and return the entries in
// chronological order. Every get() along the way reverifies the object hash, so
// a walk that completes is also an integrity check.
pub(crate) fn read_chain(ls: &Lifestream, head: ObjectId) -> Result<Vec<AuditEntry>> {
    let mut out = Vec::new();
    let mut cur = Some(head);
    while let Some(id) = cur {
        let (entry, prev) = read_entry(ls, id)?;
        cur = prev;
        out.push(entry);
    }
    out.reverse();
    Ok(out)
}

fn read_entry(ls: &Lifestream, id: ObjectId) -> Result<(AuditEntry, Option<ObjectId>)> {
    let entries = match ls.get(&id)? {
        Object::Tree { entries } => entries,
        _ => return Err(Error::Corrupt("audit entry is not a tree".into())),
    };
    let payload_id = entries
        .iter()
        .find(|e| e.name == CHILD_PAYLOAD)
        .map(|e| e.id)
        .ok_or_else(|| Error::Corrupt("audit entry has no payload".into()))?;
    let prev = entries.iter().find(|e| e.name == CHILD_PREV).map(|e| e.id);
    let payload = ls.read_bytes(&payload_id)?;
    let (seq, time_unix, event) = decode_payload(&payload)?;
    Ok((
        AuditEntry {
            id,
            seq,
            time_unix,
            event,
        },
        prev,
    ))
}

fn encode_payload(seq: u64, time_unix: u64, event: &Event) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(PAYLOAD_VERSION);
    w.u64(seq);
    w.u64(time_unix);
    encode_event(&mut w, event);
    w.b
}

fn decode_payload(buf: &[u8]) -> Result<(u64, u64, Event)> {
    let mut r = Reader::new(buf);
    let v = r.u8()?;
    if v != PAYLOAD_VERSION {
        return Err(Error::Corrupt(format!("audit payload version {v}")));
    }
    let seq = r.u64()?;
    let time_unix = r.u64()?;
    let event = decode_event(&mut r)?;
    Ok((seq, time_unix, event))
}

fn encode_event(w: &mut Writer, event: &Event) {
    match event {
        Event::Grant {
            grant,
            principal,
            resource,
            rights,
            expires_unix,
            max_uses,
        } => {
            w.u8(1);
            w.raw(grant.bytes());
            w.str(&principal.0);
            encode_resource(w, resource);
            w.u32(rights.bits());
            w.opt_u64(*expires_unix);
            w.opt_u32(*max_uses);
        }
        Event::Use {
            grant,
            principal,
            resource,
            rights,
        } => {
            w.u8(2);
            w.raw(grant.bytes());
            w.str(&principal.0);
            encode_resource(w, resource);
            w.u32(rights.bits());
        }
        Event::Deny {
            principal,
            resource,
            rights,
            reason,
        } => {
            w.u8(3);
            w.str(&principal.0);
            encode_resource(w, resource);
            w.u32(rights.bits());
            w.str(reason);
        }
        Event::Revoke { grant } => {
            w.u8(4);
            w.raw(grant.bytes());
        }
    }
}

fn decode_event(r: &mut Reader) -> Result<Event> {
    let tag = r.u8()?;
    match tag {
        1 => Ok(Event::Grant {
            grant: GrantId::from_bytes(r.arr16()?),
            principal: PrincipalId(r.str()?),
            resource: decode_resource(r)?,
            rights: Rights::from_bits(r.u32()?),
            expires_unix: r.opt_u64()?,
            max_uses: r.opt_u32()?,
        }),
        2 => Ok(Event::Use {
            grant: GrantId::from_bytes(r.arr16()?),
            principal: PrincipalId(r.str()?),
            resource: decode_resource(r)?,
            rights: Rights::from_bits(r.u32()?),
        }),
        3 => Ok(Event::Deny {
            principal: PrincipalId(r.str()?),
            resource: decode_resource(r)?,
            rights: Rights::from_bits(r.u32()?),
            reason: r.str()?,
        }),
        4 => Ok(Event::Revoke {
            grant: GrantId::from_bytes(r.arr16()?),
        }),
        _ => Err(Error::Corrupt(format!("bad event tag {tag}"))),
    }
}

fn encode_resource(w: &mut Writer, r: &Resource) {
    match r {
        Resource::File { path } => {
            w.u8(1);
            w.str(&path.to_string_lossy());
        }
        Resource::Net { host, port } => {
            w.u8(2);
            w.str(host);
            w.u16(*port);
        }
        Resource::Device { name } => {
            w.u8(3);
            w.str(name);
        }
        Resource::Service { name, action } => {
            w.u8(4);
            w.str(name);
            w.str(action);
        }
    }
}

fn decode_resource(r: &mut Reader) -> Result<Resource> {
    let tag = r.u8()?;
    match tag {
        1 => Ok(Resource::file(r.str()?)),
        2 => Ok(Resource::net(r.str()?, r.u16()?)),
        3 => Ok(Resource::device(r.str()?)),
        4 => Ok(Resource::service(r.str()?, r.str()?)),
        _ => Err(Error::Corrupt(format!("bad resource tag {tag}"))),
    }
}
