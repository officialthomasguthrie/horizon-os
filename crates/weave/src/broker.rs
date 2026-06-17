// The Weave broker: the single gate to every resource. Nothing has authority by
// running "as you"; a principal can only act through a capability the broker
// handed it, and every grant, use, denial, and revocation lands in the audit
// log. This is the userland approximation of an object-capability kernel.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use lifestream::Lifestream;
use rand::RngCore;

use crate::audit::{self, AuditEntry, Event};
use crate::capability::{
    Capability, Grant, GrantId, GrantInfo, Lease, Limits, PrincipalId, Resource, Rights, Status,
};
use crate::error::{Error, Result};

// The audit head lives beside the Lifestream's own HEAD as a separate ref, so
// the capability log rides in the same store as the state it governs.
const AUDIT_REF: &str = "weave-audit";

// How the broker decides an unsolicited request. In the running OS a fourth
// arm, "prompt the user", sits here; for the headless core a request resolves
// to allow or deny without a human in the loop. Explicit grant() is the path a
// user prompt takes once the user says yes.
pub enum Policy {
    AllowAll,
    DenyAll,
    Rules(Vec<Rule>),
}

// A single allow rule. A request matches when the principal matches (or the
// rule names no principal), the rule's resource covers the requested one, and
// the requested rights fit inside the rule's rights.
pub struct Rule {
    pub principal: Option<String>,
    pub resource: Resource,
    pub rights: Rights,
    pub limits: Limits,
}

impl Policy {
    fn decide(
        &self,
        principal: &PrincipalId,
        resource: &Resource,
        rights: Rights,
    ) -> Option<(Rights, Limits)> {
        match self {
            Policy::AllowAll => Some((rights, Limits::none())),
            Policy::DenyAll => None,
            Policy::Rules(rules) => rules.iter().find_map(|r| {
                let principal_ok = r.principal.as_deref().is_none_or(|p| p == principal.0);
                if principal_ok && r.resource.covers(resource) && r.rights.contains(rights) {
                    Some((rights, r.limits))
                } else {
                    None
                }
            }),
        }
    }
}

// In-memory state for one grant. The secret is None for a grant replayed from
// the log: a returning holder must reissue() a fresh handle before using it,
// which mirrors how a file descriptor does not survive a reboot but the
// permission behind it does.
struct GrantState {
    grant: Grant,
    revoked: bool,
    uses: u32,
    secret: Option<[u8; 32]>,
}

pub struct Broker {
    ls: Lifestream,
    policy: Policy,
    head: Option<lifestream::ObjectId>,
    seq: u64,
    grants: HashMap<GrantId, GrantState>,
}

impl Broker {
    // Open a broker on a Lifestream store, rebuilding the live grant table by
    // replaying the audit log. The log is the source of truth; this is a fold.
    pub fn open(ls: Lifestream, policy: Policy) -> Result<Broker> {
        let head = ls.get_ref(AUDIT_REF)?;
        let entries = match head {
            Some(h) => audit::read_chain(&ls, h)?,
            None => Vec::new(),
        };
        let mut grants: HashMap<GrantId, GrantState> = HashMap::new();
        for e in &entries {
            match &e.event {
                Event::Grant {
                    grant,
                    principal,
                    resource,
                    rights,
                    expires_unix,
                    max_uses,
                } => {
                    grants.insert(
                        *grant,
                        GrantState {
                            grant: Grant {
                                id: *grant,
                                principal: principal.clone(),
                                resource: resource.clone(),
                                rights: *rights,
                                granted_unix: e.time_unix,
                                expires_unix: *expires_unix,
                                max_uses: *max_uses,
                            },
                            revoked: false,
                            uses: 0,
                            secret: None,
                        },
                    );
                }
                Event::Use { grant, .. } => {
                    if let Some(gs) = grants.get_mut(grant) {
                        gs.uses += 1;
                    }
                }
                Event::Revoke { grant } => {
                    if let Some(gs) = grants.get_mut(grant) {
                        gs.revoked = true;
                    }
                }
                Event::Deny { .. } => {}
            }
        }
        Ok(Broker {
            ls,
            policy,
            head,
            seq: entries.len() as u64,
            grants,
        })
    }

    // Issue a capability directly. This is the user-approved path: the broker
    // already has a yes, so it records the grant and mints a live handle.
    pub fn grant(
        &mut self,
        principal: PrincipalId,
        resource: Resource,
        rights: Rights,
        limits: Limits,
    ) -> Result<Capability> {
        let id = GrantId::random();
        let secret = random_secret();
        let now = now();
        self.log(Event::Grant {
            grant: id,
            principal: principal.clone(),
            resource: resource.clone(),
            rights,
            expires_unix: limits.expires_unix,
            max_uses: limits.max_uses,
        })?;
        self.grants.insert(
            id,
            GrantState {
                grant: Grant {
                    id,
                    principal,
                    resource,
                    rights,
                    granted_unix: now,
                    expires_unix: limits.expires_unix,
                    max_uses: limits.max_uses,
                },
                revoked: false,
                uses: 0,
                secret: Some(secret),
            },
        );
        Ok(Capability { grant: id, secret })
    }

    // A principal asks for access. Policy decides; an allow becomes a grant, a
    // deny is logged and refused. The principal never gets ambient authority,
    // only the handle the broker chooses to return.
    pub fn request(
        &mut self,
        principal: PrincipalId,
        resource: Resource,
        rights: Rights,
    ) -> Result<Capability> {
        match self.policy.decide(&principal, &resource, rights) {
            Some((granted, limits)) => self.grant(principal, resource, granted, limits),
            None => {
                self.log(Event::Deny {
                    principal,
                    resource,
                    rights,
                    reason: "policy".into(),
                })?;
                Err(Error::denied("policy"))
            }
        }
    }

    // Exercise a capability. The broker checks the handle, the grant's scope,
    // rights, expiry, and use budget, then records the result. A success logs a
    // use and returns a lease; a failure logs a denial and returns the reason.
    pub fn access(
        &mut self,
        cap: &Capability,
        resource: &Resource,
        rights: Rights,
    ) -> Result<Lease> {
        match self.check(cap, resource, rights) {
            Ok(()) => {
                let principal = self.grants[&cap.grant].grant.principal.clone();
                if let Some(gs) = self.grants.get_mut(&cap.grant) {
                    gs.uses += 1;
                }
                self.log(Event::Use {
                    grant: cap.grant,
                    principal,
                    resource: resource.clone(),
                    rights,
                })?;
                Ok(Lease {
                    grant: cap.grant,
                    resource: resource.clone(),
                    rights,
                })
            }
            Err(Error::Denied(reason)) => {
                let principal = self
                    .grants
                    .get(&cap.grant)
                    .map(|g| g.grant.principal.clone())
                    .unwrap_or_else(|| PrincipalId("unknown".into()));
                self.log(Event::Deny {
                    principal,
                    resource: resource.clone(),
                    rights,
                    reason: reason.clone(),
                })?;
                Err(Error::Denied(reason))
            }
            Err(e) => Err(e),
        }
    }

    fn check(&self, cap: &Capability, resource: &Resource, rights: Rights) -> Result<()> {
        let gs = self
            .grants
            .get(&cap.grant)
            .ok_or_else(|| Error::denied("no such grant"))?;
        match gs.secret {
            Some(s) if s == cap.secret => {}
            _ => return Err(Error::denied("forged handle")),
        }
        if gs.revoked {
            return Err(Error::denied("revoked"));
        }
        if let Some(exp) = gs.grant.expires_unix {
            if now() >= exp {
                return Err(Error::denied("expired"));
            }
        }
        if let Some(max) = gs.grant.max_uses {
            if gs.uses >= max {
                return Err(Error::denied("use limit reached"));
            }
        }
        if !gs.grant.resource.covers(resource) {
            return Err(Error::denied("out of scope"));
        }
        if !gs.grant.rights.contains(rights) {
            return Err(Error::denied("insufficient rights"));
        }
        Ok(())
    }

    // Revoke a grant. Idempotent: revoking an already-revoked grant is a no-op
    // and does not add a second log entry.
    pub fn revoke(&mut self, grant: GrantId) -> Result<()> {
        match self.grants.get(&grant) {
            None => return Err(Error::denied("no such grant")),
            Some(gs) if gs.revoked => return Ok(()),
            _ => {}
        }
        self.grants.get_mut(&grant).unwrap().revoked = true;
        self.log(Event::Revoke { grant })?;
        Ok(())
    }

    // Mint a fresh handle for a grant that is still live. Used when a holder
    // reconnects after a restart, where the original session secret is gone.
    pub fn reissue(&mut self, grant: GrantId) -> Result<Capability> {
        let gs = self
            .grants
            .get(&grant)
            .ok_or_else(|| Error::denied("no such grant"))?;
        if gs.revoked {
            return Err(Error::denied("revoked"));
        }
        if let Some(exp) = gs.grant.expires_unix {
            if now() >= exp {
                return Err(Error::denied("expired"));
            }
        }
        let secret = random_secret();
        self.grants.get_mut(&grant).unwrap().secret = Some(secret);
        Ok(Capability { grant, secret })
    }

    // Every grant the broker knows, newest last, for listing in the CLI or Glass.
    pub fn grants(&self) -> Vec<GrantInfo> {
        let now = now();
        let mut v: Vec<GrantInfo> = self
            .grants
            .values()
            .map(|gs| {
                let status = if gs.revoked {
                    Status::Revoked
                } else if gs.grant.expires_unix.is_some_and(|e| now >= e) {
                    Status::Expired
                } else {
                    Status::Active
                };
                GrantInfo {
                    id: gs.grant.id,
                    principal: gs.grant.principal.clone(),
                    resource: gs.grant.resource.clone(),
                    rights: gs.grant.rights,
                    granted_unix: gs.grant.granted_unix,
                    expires_unix: gs.grant.expires_unix,
                    max_uses: gs.grant.max_uses,
                    uses: gs.uses,
                    status,
                }
            })
            .collect();
        v.sort_by_key(|g| g.granted_unix);
        v
    }

    // The full audit log, oldest first.
    pub fn audit(&self) -> Result<Vec<AuditEntry>> {
        match self.head {
            Some(h) => audit::read_chain(&self.ls, h),
            None => Ok(Vec::new()),
        }
    }

    // Walk the chain and confirm it is intact and contiguous, returning the
    // entry count. The walk itself reverifies every object hash; the seq check
    // catches a truncated or reordered chain.
    pub fn verify(&self) -> Result<usize> {
        let entries = self.audit()?;
        for (i, e) in entries.iter().enumerate() {
            if e.seq != i as u64 {
                return Err(Error::Corrupt(format!(
                    "audit seq gap at position {i}: entry says {}",
                    e.seq
                )));
            }
        }
        Ok(entries.len())
    }

    fn log(&mut self, event: Event) -> Result<()> {
        let id = audit::append(&self.ls, self.head, self.seq, now(), &event)?;
        self.ls.set_ref(AUDIT_REF, &id)?;
        self.head = Some(id);
        self.seq += 1;
        Ok(())
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut s);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn broker() -> Broker {
        let d = tempdir().unwrap();
        let ls = Lifestream::init(d.path(), &[9u8; 32]).unwrap();
        // keep the tempdir alive for the broker's lifetime
        std::mem::forget(d);
        Broker::open(ls, Policy::DenyAll).unwrap()
    }

    // A handle with the wrong secret is refused even though the grant is live.
    // This can only be tested from inside the crate, where Capability's private
    // fields are reachable; from outside, the type itself is unforgeable.
    #[test]
    fn forged_handle_is_refused() {
        let mut b = broker();
        let cap = b
            .grant(
                "app".into(),
                Resource::file("/data"),
                Rights::READ,
                Limits::none(),
            )
            .unwrap();
        let forged = Capability {
            grant: cap.grant_id(),
            secret: [0u8; 32],
        };
        let err = b
            .access(&forged, &Resource::file("/data"), Rights::READ)
            .unwrap_err();
        assert!(matches!(err, Error::Denied(r) if r == "forged handle"));
    }
}
