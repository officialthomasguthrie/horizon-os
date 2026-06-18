//! Glass: the live transparency surface over the Weave audit log.
//!
//! Every grant and every use a principal makes lands in the Weave's audit log.
//! Glass is the pane that makes that legible: a per-principal map of what each
//! app, service, or Aura can reach, which channels are live, what was used, and
//! what was refused, with a one-tap kill switch (severing a capability) and a
//! timeline over a window.
//!
//! This crate is the model layer, the part that can be built and proven without
//! a display. [`build`] folds the broker's grant table and audit log into a
//! [`Model`]; [`report::text`] renders that model as text (the headless stand-in
//! for the drawn surface); [`Glass`] wraps a live [`Broker`] to read the model
//! and pull a kill switch. The compositor surface that draws the same model
//! comes when there is a screen to draw it on.

mod model;
pub mod report;

pub use model::{
    build, Bucket, Channel, ChannelKind, ChannelStatus, Model, PrincipalView, Totals, Window,
    DAY_SECS, WEEK_SECS,
};

use std::time::{SystemTime, UNIX_EPOCH};

use weave::{Broker, GrantId, Result};

// How many timeline buckets the default view splits its window into (a week,
// one bucket per day).
pub const DEFAULT_BUCKETS: usize = 7;

// A live Glass over a broker: read the current model, or sever a channel. The
// broker is the source of truth; this holds no state of its own.
pub struct Glass<'b> {
    broker: &'b mut Broker,
}

impl<'b> Glass<'b> {
    pub fn new(broker: &'b mut Broker) -> Glass<'b> {
        Glass { broker }
    }

    // The model for the trailing week, as of now.
    pub fn model(&self) -> Result<Model> {
        self.model_within(Window::week(now()), DEFAULT_BUCKETS)
    }

    // The model for an explicit window and bucket count. Pure given the broker
    // state, so a caller can pin the window for a reproducible render.
    pub fn model_within(&self, window: Window, buckets: usize) -> Result<Model> {
        let entries = self.broker.audit()?;
        let grants = self.broker.grants();
        Ok(build(&entries, &grants, window, buckets))
    }

    // The kill switch: sever a capability by revoking its grant. Idempotent,
    // and the revocation lands in the audit log like every other broker action.
    pub fn sever(&mut self, grant: GrantId) -> Result<()> {
        self.broker.revoke(grant)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ChannelKind, ChannelStatus};
    use weave::{AuditEntry, Event, GrantId, GrantInfo, PrincipalId, Resource, Rights, Status};

    // Build a GrantInfo the way the broker would report one.
    fn grant_info(
        id: GrantId,
        principal: &str,
        resource: Resource,
        rights: Rights,
        granted: u64,
        uses: u32,
        status: Status,
    ) -> GrantInfo {
        GrantInfo {
            id,
            principal: principal.into(),
            resource,
            rights,
            granted_unix: granted,
            expires_unix: None,
            max_uses: None,
            uses,
            status,
        }
    }

    fn entry(seq: u64, time: u64, event: Event) -> AuditEntry {
        // The id is irrelevant to the model, so a throwaway all-zero one is fine.
        AuditEntry {
            id: lifestream::ObjectId::from_hex(&"00".repeat(32)).unwrap(),
            seq,
            time_unix: time,
            event,
        }
    }

    #[test]
    fn empty_inputs_make_an_empty_model() {
        let m = build(&[], &[], Window::week(1_000_000), DEFAULT_BUCKETS);
        assert!(m.is_empty());
        assert_eq!(m.totals.principals, 0);
        assert_eq!(m.timeline.len(), DEFAULT_BUCKETS);
        assert!(m.timeline.iter().all(|b| b.total() == 0));
    }

    #[test]
    fn a_grant_and_a_use_become_a_live_channel() {
        let now = 1_000_000;
        let gid = GrantId::random();
        let grants = vec![grant_info(
            gid,
            "mail",
            Resource::net("api.example", 443),
            Rights::READ | Rights::WRITE,
            now - 100,
            1,
            Status::Active,
        )];
        let log = vec![
            entry(
                0,
                now - 100,
                Event::Grant {
                    grant: gid,
                    principal: "mail".into(),
                    resource: Resource::net("api.example", 443),
                    rights: Rights::READ | Rights::WRITE,
                    expires_unix: None,
                    max_uses: None,
                },
            ),
            entry(
                1,
                now - 50,
                Event::Use {
                    grant: gid,
                    principal: "mail".into(),
                    resource: Resource::net("api.example", 443),
                    rights: Rights::WRITE,
                },
            ),
        ];
        let m = build(&log, &grants, Window::week(now), DEFAULT_BUCKETS);
        assert_eq!(m.totals.principals, 1);
        assert_eq!(m.totals.live, 1);
        assert_eq!(m.totals.network, 1);
        let p = &m.principals[0];
        assert_eq!(p.principal, PrincipalId("mail".into()));
        let c = &p.channels[0];
        assert_eq!(c.kind, ChannelKind::Network);
        assert_eq!(c.status, ChannelStatus::Live);
        assert_eq!(c.uses, 1);
        assert_eq!(c.grant, Some(gid));
        assert!(c.can_sever());
        assert_eq!(c.last_unix, Some(now - 50));
    }

    #[test]
    fn a_denial_with_no_grant_is_a_blocked_channel() {
        let now = 2_000_000;
        let log = vec![entry(
            0,
            now - 10,
            Event::Deny {
                principal: "spy".into(),
                resource: Resource::file("/etc/shadow"),
                rights: Rights::READ,
                reason: "policy".into(),
            },
        )];
        let m = build(&log, &[], Window::week(now), DEFAULT_BUCKETS);
        assert_eq!(m.totals.blocked, 1);
        let c = &m.principals[0].channels[0];
        assert_eq!(c.status, ChannelStatus::Blocked);
        assert_eq!(c.grant, None);
        assert!(!c.can_sever());
        assert_eq!(c.denials, 1);
        assert_eq!(c.last_reason.as_deref(), Some("policy"));
    }

    #[test]
    fn a_use_after_revoke_folds_into_the_severed_channel() {
        let now = 3_000_000;
        let gid = GrantId::random();
        let grants = vec![grant_info(
            gid,
            "app",
            Resource::file("/data"),
            Rights::READ,
            now - 200,
            1,
            Status::Revoked,
        )];
        let log = vec![
            entry(
                0,
                now - 200,
                Event::Grant {
                    grant: gid,
                    principal: "app".into(),
                    resource: Resource::file("/data"),
                    rights: Rights::READ,
                    expires_unix: None,
                    max_uses: None,
                },
            ),
            entry(
                1,
                now - 150,
                Event::Use {
                    grant: gid,
                    principal: "app".into(),
                    resource: Resource::file("/data/a"),
                    rights: Rights::READ,
                },
            ),
            entry(2, now - 100, Event::Revoke { grant: gid }),
            // attempted again after revoke: denied, same scope as the grant
            entry(
                3,
                now - 50,
                Event::Deny {
                    principal: "app".into(),
                    resource: Resource::file("/data/a"),
                    rights: Rights::READ,
                    reason: "revoked".into(),
                },
            ),
        ];
        let m = build(&log, &grants, Window::week(now), DEFAULT_BUCKETS);
        // One channel only: the denial folded into the severed grant, not a new row.
        assert_eq!(m.principals.len(), 1);
        assert_eq!(m.principals[0].channels.len(), 1);
        let c = &m.principals[0].channels[0];
        assert_eq!(c.status, ChannelStatus::Severed);
        assert_eq!(c.uses, 1);
        assert_eq!(c.denials, 1);
        // the touched sub-resource shows under the directory grant
        assert_eq!(c.accessed.len(), 1);
        assert_eq!(c.accessed[0], Resource::file("/data/a"));
        assert_eq!(m.totals.severed, 1);
        assert_eq!(m.totals.live, 0);
    }

    #[test]
    fn an_out_of_scope_denial_is_its_own_blocked_row() {
        let now = 4_000_000;
        let gid = GrantId::random();
        let grants = vec![grant_info(
            gid,
            "app",
            Resource::file("/home/me/docs"),
            Rights::READ,
            now - 100,
            0,
            Status::Active,
        )];
        let log = vec![
            entry(
                0,
                now - 100,
                Event::Grant {
                    grant: gid,
                    principal: "app".into(),
                    resource: Resource::file("/home/me/docs"),
                    rights: Rights::READ,
                    expires_unix: None,
                    max_uses: None,
                },
            ),
            entry(
                1,
                now - 30,
                Event::Deny {
                    principal: "app".into(),
                    resource: Resource::file("/etc/passwd"),
                    rights: Rights::READ,
                    reason: "out of scope".into(),
                },
            ),
        ];
        let m = build(&log, &grants, Window::week(now), DEFAULT_BUCKETS);
        // The live grant and the out-of-scope denial are two distinct channels.
        assert_eq!(m.principals.len(), 1);
        assert_eq!(m.principals[0].channels.len(), 2);
        assert_eq!(m.totals.live, 1);
        assert_eq!(m.totals.blocked, 1);
    }

    #[test]
    fn dead_history_outside_the_window_is_dropped_but_live_stays() {
        let now = 5_000_000;
        let live = GrantId::random();
        let old = GrantId::random();
        let grants = vec![
            grant_info(
                live,
                "app",
                Resource::net("a", 1),
                Rights::READ,
                now - 10 * DAY_SECS, // granted long ago but still live
                0,
                Status::Active,
            ),
            grant_info(
                old,
                "app",
                Resource::net("b", 2),
                Rights::READ,
                now - 30 * DAY_SECS,
                0,
                Status::Revoked, // dead and old: should drop
            ),
        ];
        let m = build(
            &grants_log(&grants),
            &grants,
            Window::week(now),
            DEFAULT_BUCKETS,
        );
        let chans = &m.principals[0].channels;
        assert_eq!(chans.len(), 1);
        assert_eq!(chans[0].grant, Some(live));
        assert_eq!(m.totals.live, 1);
        assert_eq!(m.totals.severed, 0);
    }

    // A matching log of Grant events for a set of grants, timed at their grant time.
    fn grants_log(grants: &[GrantInfo]) -> Vec<AuditEntry> {
        grants
            .iter()
            .enumerate()
            .map(|(i, g)| {
                entry(
                    i as u64,
                    g.granted_unix,
                    Event::Grant {
                        grant: g.id,
                        principal: g.principal.clone(),
                        resource: g.resource.clone(),
                        rights: g.rights,
                        expires_unix: g.expires_unix,
                        max_uses: g.max_uses,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn timeline_buckets_count_events_in_window() {
        let now = 6_000_000;
        let gid = GrantId::random();
        // two uses a day apart, both inside the week
        let log = vec![
            entry(
                0,
                now - 2 * DAY_SECS,
                Event::Use {
                    grant: gid,
                    principal: "x".into(),
                    resource: Resource::net("h", 1),
                    rights: Rights::READ,
                },
            ),
            entry(
                1,
                now - DAY_SECS,
                Event::Use {
                    grant: gid,
                    principal: "x".into(),
                    resource: Resource::net("h", 1),
                    rights: Rights::READ,
                },
            ),
            // outside the window: ignored by the timeline
            entry(
                2,
                now - 30 * DAY_SECS,
                Event::Use {
                    grant: gid,
                    principal: "x".into(),
                    resource: Resource::net("h", 1),
                    rights: Rights::READ,
                },
            ),
        ];
        let m = build(&log, &[], Window::week(now), DEFAULT_BUCKETS);
        assert_eq!(sum_uses(&m), 2);
        // the two in-window uses land in different daily buckets
        assert!(m.timeline.iter().filter(|b| b.uses > 0).count() >= 2);
    }

    fn sum_uses(m: &Model) -> u32 {
        m.timeline.iter().map(|b| b.uses).sum()
    }
}
