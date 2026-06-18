// End-to-end: drive a real Weave broker (grant, use, deny, revoke) and confirm
// Glass renders the live state and that its kill switch actually severs.

use std::time::{SystemTime, UNIX_EPOCH};

use glass::{ChannelStatus, Glass, Window};
use lifestream::Lifestream;
use tempfile::tempdir;
use weave::{Broker, Policy, Resource, Rights};

const KEY: [u8; 32] = [7u8; 32];

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn glass_reflects_the_broker_and_severs() {
    let d = tempdir().unwrap();
    let mut b = Broker::open(Lifestream::init(d.path(), &KEY).unwrap(), Policy::DenyAll).unwrap();

    // mail gets a live network capability and uses it twice.
    let cap = b
        .grant(
            "mail".into(),
            Resource::net("api.mail.example", 443),
            Rights::READ | Rights::WRITE,
            weave::Limits::none(),
        )
        .unwrap();
    b.access(&cap, &Resource::net("api.mail.example", 443), Rights::WRITE)
        .unwrap();
    b.access(&cap, &Resource::net("api.mail.example", 443), Rights::READ)
        .unwrap();

    // an unknown principal is refused a file it never had: a blocked channel.
    let _ = b.request("spy".into(), Resource::file("/etc/shadow"), Rights::READ);

    let win = Window::week(now());
    let gid = cap.grant_id();

    let mut g = Glass::new(&mut b);
    let m = g.model_within(win, glass::DEFAULT_BUCKETS).unwrap();

    assert_eq!(m.totals.principals, 2, "mail and spy");
    assert_eq!(m.totals.live, 1);
    assert_eq!(m.totals.network, 1);
    assert_eq!(m.totals.blocked, 1);

    // mail's live channel reflects two uses and offers the kill switch.
    let mail = m
        .principals
        .iter()
        .find(|p| p.principal.0 == "mail")
        .unwrap();
    let chan = &mail.channels[0];
    assert_eq!(chan.status, ChannelStatus::Live);
    assert_eq!(chan.uses, 2);
    assert_eq!(chan.grant, Some(gid));
    assert!(chan.can_sever());

    // spy's channel is blocked and cannot be severed (nothing was granted).
    let spy = m
        .principals
        .iter()
        .find(|p| p.principal.0 == "spy")
        .unwrap();
    assert_eq!(spy.channels[0].status, ChannelStatus::Blocked);
    assert!(!spy.channels[0].can_sever());

    let report = glass::report::text(&m);
    assert!(report.contains("mail"));
    assert!(report.contains("live"));
    assert!(report.contains("blocked"));

    // pull the kill switch.
    g.sever(gid).unwrap();
    let after = g.model_within(win, glass::DEFAULT_BUCKETS).unwrap();
    assert_eq!(after.totals.live, 0);
    assert_eq!(after.totals.severed, 1);
    let mail = after
        .principals
        .iter()
        .find(|p| p.principal.0 == "mail")
        .unwrap();
    assert_eq!(mail.channels[0].status, ChannelStatus::Severed);
    assert!(!mail.channels[0].can_sever());
    assert!(glass::report::text(&after).contains("severed"));
}

#[test]
fn severing_survives_a_reopen() {
    let d = tempdir().unwrap();
    let gid;
    {
        let mut b =
            Broker::open(Lifestream::init(d.path(), &KEY).unwrap(), Policy::DenyAll).unwrap();
        let cap = b
            .grant(
                "app".into(),
                Resource::file("/data"),
                Rights::READ,
                weave::Limits::none(),
            )
            .unwrap();
        gid = cap.grant_id();
        let mut g = Glass::new(&mut b);
        g.sever(gid).unwrap();
    }
    // reopen: the revocation was logged, so the channel is still severed.
    let mut b = Broker::open(Lifestream::open(d.path(), &KEY).unwrap(), Policy::DenyAll).unwrap();
    let g = Glass::new(&mut b);
    let m = g
        .model_within(Window::week(now()), glass::DEFAULT_BUCKETS)
        .unwrap();
    assert_eq!(m.totals.severed, 1);
    assert_eq!(m.totals.live, 0);
}
