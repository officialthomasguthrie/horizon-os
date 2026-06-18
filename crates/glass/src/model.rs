// The Glass view model: a per-principal map of the Weave audit log.
//
// The broker hands out two flat things: the live grant table (`GrantInfo`) and
// the chronological audit log (`AuditEntry`). Neither is what a human watches.
// Glass folds them into a per-principal set of channels, one row per thing a
// principal can reach (a network host, a file, a device, a service), each
// carrying its live/severed/blocked status, how often it was used, and the
// grant behind it, which is the kill switch. On top of that sits a timeline of
// activity over a window (the 7-day view) and a few header totals.
//
// `build` is a pure fold over those two inputs plus a clock reading, so the
// whole model is reproducible and tested without a display.

use std::collections::BTreeSet;

use weave::{AuditEntry, Event, GrantId, GrantInfo, PrincipalId, Resource, Rights, Status};

pub const DAY_SECS: u64 = 24 * 60 * 60;
pub const WEEK_SECS: u64 = 7 * DAY_SECS;

// The slice of time the model summarizes. Live authority is always shown; dead
// history (severed, expired, blocked) is shown only when it falls in here, and
// the timeline buckets cover exactly this span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub start_unix: u64,
    pub end_unix: u64,
}

impl Window {
    pub fn ending(now: u64, span: u64) -> Window {
        Window {
            start_unix: now.saturating_sub(span),
            end_unix: now,
        }
    }
    pub fn week(now: u64) -> Window {
        Window::ending(now, WEEK_SECS)
    }
    pub fn days(now: u64, days: u64) -> Window {
        Window::ending(now, days.saturating_mul(DAY_SECS))
    }
    pub fn span(&self) -> u64 {
        self.end_unix.saturating_sub(self.start_unix)
    }
    fn contains(&self, t: u64) -> bool {
        t >= self.start_unix && t <= self.end_unix
    }
}

// What a channel reaches, derived from the grant's resource. This is the axis a
// human reads first: a network connection is the thing Glass exists to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelKind {
    Network,
    Data,
    Device,
    Service,
}

impl ChannelKind {
    pub fn of(r: &Resource) -> ChannelKind {
        match r {
            Resource::Net { .. } => ChannelKind::Network,
            Resource::File { .. } => ChannelKind::Data,
            Resource::Device { .. } => ChannelKind::Device,
            Resource::Service { .. } => ChannelKind::Service,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            ChannelKind::Network => "net",
            ChannelKind::Data => "data",
            ChannelKind::Device => "dev",
            ChannelKind::Service => "svc",
        }
    }
}

// A channel's standing. Live and severed map straight onto a grant; blocked is a
// denial with no live grant behind it, the "something tried and was refused"
// signal Glass is built to surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelStatus {
    Live,
    Severed,
    Expired,
    Blocked,
}

impl ChannelStatus {
    pub fn label(self) -> &'static str {
        match self {
            ChannelStatus::Live => "live",
            ChannelStatus::Severed => "severed",
            ChannelStatus::Expired => "expired",
            ChannelStatus::Blocked => "blocked",
        }
    }
}

impl From<Status> for ChannelStatus {
    fn from(s: Status) -> ChannelStatus {
        match s {
            Status::Active => ChannelStatus::Live,
            Status::Revoked => ChannelStatus::Severed,
            Status::Expired => ChannelStatus::Expired,
        }
    }
}

// One thing a principal can reach. A grant-backed channel carries the grant id,
// which is the kill switch; a blocked channel carries none (there is nothing to
// sever, the access was already refused).
#[derive(Clone, Debug)]
pub struct Channel {
    pub principal: PrincipalId,
    pub resource: Resource,
    pub kind: ChannelKind,
    pub rights: Rights,
    pub grant: Option<GrantId>,
    pub status: ChannelStatus,
    pub uses: u32,
    pub denials: u32,
    pub first_unix: Option<u64>,
    pub last_unix: Option<u64>,
    // Distinct sub-resources actually touched under a directory-style grant, so
    // a "read ~/docs" grant shows which files were opened, not just the scope.
    pub accessed: Vec<Resource>,
    pub last_reason: Option<String>,
}

impl Channel {
    pub fn is_live(&self) -> bool {
        self.status == ChannelStatus::Live
    }
    // A channel can be severed when it has a live grant behind it. Severing an
    // already-dead one is pointless; a blocked one has nothing to sever.
    pub fn can_sever(&self) -> bool {
        self.grant.is_some() && self.status == ChannelStatus::Live
    }
}

// One slice of the timeline. Counts the four event kinds in its span.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bucket {
    pub start_unix: u64,
    pub end_unix: u64,
    pub grants: u32,
    pub uses: u32,
    pub denials: u32,
    pub revokes: u32,
}

impl Bucket {
    pub fn total(&self) -> u32 {
        self.grants + self.uses + self.denials + self.revokes
    }
}

// Header counts for the surface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub principals: u32,
    pub live: u32,
    pub network: u32,
    pub blocked: u32,
    pub severed: u32,
}

// Every channel of one principal, plus its rolled-up counts.
#[derive(Clone, Debug)]
pub struct PrincipalView {
    pub principal: PrincipalId,
    pub channels: Vec<Channel>,
    pub live: u32,
    pub blocked: u32,
    pub last_unix: Option<u64>,
}

// The whole Glass model for a window: who reached what, the activity timeline,
// and the header totals. This is what a renderer (the text report here, the
// compositor surface later) draws.
#[derive(Clone, Debug)]
pub struct Model {
    pub window: Window,
    pub principals: Vec<PrincipalView>,
    pub timeline: Vec<Bucket>,
    pub totals: Totals,
}

impl Model {
    pub fn is_empty(&self) -> bool {
        self.principals.is_empty()
    }
}

// Fold the grant table and the audit log into the model for a window. `grants`
// is the broker's live view (it already counts uses and resolves status); the
// log supplies activity times, the touched sub-resources, denials, and the
// timeline.
pub fn build(
    entries: &[AuditEntry],
    grants: &[GrantInfo],
    window: Window,
    buckets: usize,
) -> Model {
    let mut channels: Vec<Channel> = Vec::new();
    let mut seen: Vec<BTreeSet<String>> = Vec::new();
    // grant id -> channel index, for attributing uses and revoke-time denials.
    let mut by_grant: Vec<(GrantId, usize)> = Vec::new();
    // (principal, resource) -> channel index, for coalescing repeated denials.
    let mut by_deny: Vec<(String, usize)> = Vec::new();

    // Seed one channel per known grant. The grant table is authoritative for
    // rights, status, and the use count; the log only enriches these below.
    for g in grants {
        let idx = channels.len();
        by_grant.push((g.id, idx));
        channels.push(Channel {
            principal: g.principal.clone(),
            resource: g.resource.clone(),
            kind: ChannelKind::of(&g.resource),
            rights: g.rights,
            grant: Some(g.id),
            status: ChannelStatus::from(g.status),
            uses: g.uses,
            denials: 0,
            first_unix: Some(g.granted_unix),
            last_unix: Some(g.granted_unix),
            accessed: Vec::new(),
            last_reason: None,
        });
        seen.push(BTreeSet::new());
    }

    let mut timeline = make_buckets(window, buckets);

    for e in entries {
        if window.contains(e.time_unix) {
            if let Some(b) = bucket_index(&window, buckets, e.time_unix) {
                let slot = &mut timeline[b];
                match &e.event {
                    Event::Grant { .. } => slot.grants += 1,
                    Event::Use { .. } => slot.uses += 1,
                    Event::Deny { .. } => slot.denials += 1,
                    Event::Revoke { .. } => slot.revokes += 1,
                }
            }
        }

        match &e.event {
            // Grants are already seeded from the table; nothing to add.
            Event::Grant { .. } => {}
            Event::Use {
                grant, resource, ..
            } => {
                if let Some(i) = grant_index(&by_grant, grant) {
                    advance(&mut channels[i], e.time_unix);
                    note_access(&mut channels[i], &mut seen[i], resource);
                }
            }
            Event::Deny {
                principal,
                resource,
                rights,
                reason,
            } => {
                // A denial of something a grant covers (a use after revoke, an
                // expired or over-budget grant) belongs to that grant's row.
                // `covers` is the same predicate the broker used to decide, so
                // this attribution matches the authorization that was refused.
                let folded = channels.iter().position(|c| {
                    c.grant.is_some() && &c.principal == principal && c.resource.covers(resource)
                });
                let i = match folded {
                    Some(i) => i,
                    None => deny_channel(
                        &mut channels,
                        &mut seen,
                        &mut by_deny,
                        principal,
                        resource,
                        *rights,
                    ),
                };
                let c = &mut channels[i];
                c.denials += 1;
                c.last_reason = Some(reason.clone());
                advance(c, e.time_unix);
            }
            Event::Revoke { .. } => {}
        }
    }

    // Keep current authority always; bound dead history to the window.
    let mut kept: Vec<Channel> = channels
        .into_iter()
        .filter(|c| c.is_live() || c.last_unix.is_some_and(|t| window.contains(t)))
        .collect();
    for c in &mut kept {
        c.accessed.sort_by_key(|r| r.to_string());
    }

    let principals = group(kept);
    let totals = totals(&principals);
    Model {
        window,
        principals,
        timeline,
        totals,
    }
}

fn grant_index(by_grant: &[(GrantId, usize)], g: &GrantId) -> Option<usize> {
    by_grant.iter().find(|(id, _)| id == g).map(|(_, i)| *i)
}

fn deny_channel(
    channels: &mut Vec<Channel>,
    seen: &mut Vec<BTreeSet<String>>,
    by_deny: &mut Vec<(String, usize)>,
    principal: &PrincipalId,
    resource: &Resource,
    rights: Rights,
) -> usize {
    let key = format!("{}\u{0}{}", principal.0, resource);
    if let Some((_, i)) = by_deny.iter().find(|(k, _)| *k == key) {
        let i = *i;
        channels[i].rights = channels[i].rights | rights;
        return i;
    }
    let idx = channels.len();
    channels.push(Channel {
        principal: principal.clone(),
        resource: resource.clone(),
        kind: ChannelKind::of(resource),
        rights,
        grant: None,
        status: ChannelStatus::Blocked,
        uses: 0,
        denials: 0,
        first_unix: None,
        last_unix: None,
        accessed: Vec::new(),
        last_reason: None,
    });
    seen.push(BTreeSet::new());
    by_deny.push((key, idx));
    idx
}

fn advance(c: &mut Channel, t: u64) {
    c.first_unix = Some(c.first_unix.map_or(t, |f| f.min(t)));
    c.last_unix = Some(c.last_unix.map_or(t, |l| l.max(t)));
}

fn note_access(c: &mut Channel, seen: &mut BTreeSet<String>, resource: &Resource) {
    let d = resource.to_string();
    if d == c.resource.to_string() {
        return;
    }
    if seen.insert(d) {
        c.accessed.push(resource.clone());
    }
}

fn make_buckets(w: Window, buckets: usize) -> Vec<Bucket> {
    let span = w.span();
    (0..buckets)
        .map(|i| {
            let s = w.start_unix + scale(span, i as u64, buckets as u64);
            let e = w.start_unix + scale(span, i as u64 + 1, buckets as u64);
            Bucket {
                start_unix: s,
                end_unix: e,
                ..Bucket::default()
            }
        })
        .collect()
}

fn scale(span: u64, num: u64, den: u64) -> u64 {
    if den == 0 {
        return 0;
    }
    (span as u128 * num as u128 / den as u128) as u64
}

fn bucket_index(w: &Window, buckets: usize, t: u64) -> Option<usize> {
    if buckets == 0 || !w.contains(t) {
        return None;
    }
    let span = w.span();
    if span == 0 {
        return Some(0);
    }
    let off = t - w.start_unix;
    let i = (off as u128 * buckets as u128 / span as u128) as usize;
    Some(i.min(buckets - 1))
}

fn group(channels: Vec<Channel>) -> Vec<PrincipalView> {
    let mut views: Vec<PrincipalView> = Vec::new();
    for c in channels {
        match views.iter_mut().find(|v| v.principal == c.principal) {
            Some(v) => v.channels.push(c),
            None => views.push(PrincipalView {
                principal: c.principal.clone(),
                channels: vec![c],
                live: 0,
                blocked: 0,
                last_unix: None,
            }),
        }
    }
    for v in &mut views {
        v.live = v.channels.iter().filter(|c| c.is_live()).count() as u32;
        v.blocked = v
            .channels
            .iter()
            .filter(|c| c.status == ChannelStatus::Blocked)
            .count() as u32;
        v.last_unix = v.channels.iter().filter_map(|c| c.last_unix).max();
        // Live first, then most recent, then a stable resource order.
        v.channels.sort_by(|a, b| {
            b.is_live()
                .cmp(&a.is_live())
                .then(b.last_unix.cmp(&a.last_unix))
                .then(a.resource.to_string().cmp(&b.resource.to_string()))
        });
    }
    // Busiest principal first, ties broken by name.
    views.sort_by(|a, b| {
        b.last_unix
            .cmp(&a.last_unix)
            .then(a.principal.0.cmp(&b.principal.0))
    });
    views
}

fn totals(views: &[PrincipalView]) -> Totals {
    let mut t = Totals {
        principals: views.len() as u32,
        ..Totals::default()
    };
    for c in views.iter().flat_map(|v| &v.channels) {
        if c.is_live() {
            t.live += 1;
            if c.kind == ChannelKind::Network {
                t.network += 1;
            }
        }
        match c.status {
            ChannelStatus::Blocked => t.blocked += 1,
            ChannelStatus::Severed => t.severed += 1,
            _ => {}
        }
    }
    t
}
