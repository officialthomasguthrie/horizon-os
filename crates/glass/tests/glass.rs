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

// A click on the drawn `sever` button resolves, through the scene's hit targets,
// to the same kill switch the text view exposes as a grant id, and pulling it
// severs the channel. This is the seam the compositor routes a pointer press
// through: it hands the click position to the owner, Scene::action_at maps it to
// an Action, and Glass::sever applies it. Proven here without a display.
#[test]
fn a_click_on_the_sever_button_severs_the_channel() {
    let d = tempdir().unwrap();
    let mut b = Broker::open(Lifestream::init(d.path(), &KEY).unwrap(), Policy::DenyAll).unwrap();

    // mail gets a live, severable network capability and uses it once.
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
    let gid = cap.grant_id();

    let win = Window::week(now());
    let mut g = Glass::new(&mut b);
    let model = g.model_within(win, glass::DEFAULT_BUCKETS).unwrap();

    // Lay the model out and find the sever button for mail's live channel: it is
    // the only severable one, so the scene carries exactly one hit target.
    let scene = glass::layout(&model, &glass::Palette::new(), 1200, 800, 2);
    let hit = scene
        .hits
        .iter()
        .find(|h| h.action == glass::Action::Sever(gid))
        .expect("the live channel offers a sever button");

    // A click at the button's center resolves back to the sever action; a click
    // off any target (the top-left corner) resolves to nothing, which is what the
    // compositor would hand over for empty chrome.
    let (cx, cy) = (hit.x + hit.w / 2, hit.y + hit.h / 2);
    assert_eq!(scene.action_at(cx, cy), Some(&glass::Action::Sever(gid)));
    assert_eq!(scene.action_at(0, 0), None);

    // Resolve the click the way the shell does, then pull the switch.
    match scene.action_at(cx, cy).cloned() {
        Some(glass::Action::Sever(grant)) => g.sever(grant).unwrap(),
        other => panic!("expected a sever action at the button, got {other:?}"),
    }

    // The channel is now severed, exactly as `glass sever --grant` would leave it.
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
}

// A line typed into the Aura command palette resolves, against the live model, to
// the same kill switch, and running it severs the channel. This is the other seam
// the compositor routes input through: keystrokes build a line, glass::parse and
// glass::resolve turn it into a PaletteAction, and Glass::sever applies it. Proven
// here without a display, the way the click path above is.
#[test]
fn a_palette_sever_command_severs_the_matching_channel() {
    let d = tempdir().unwrap();
    let mut b = Broker::open(Lifestream::init(d.path(), &KEY).unwrap(), Policy::DenyAll).unwrap();

    // Two live capabilities for "mail": both should fall to one `sever mail`.
    for res in [
        Resource::net("api.mail.example", 443),
        Resource::file("/home/user/mail"),
    ] {
        b.grant("mail".into(), res, Rights::READ, weave::Limits::none())
            .unwrap();
    }
    // A second principal whose channel must be left untouched.
    b.grant(
        "music".into(),
        Resource::net("api.music.example", 443),
        Rights::READ,
        weave::Limits::none(),
    )
    .unwrap();

    let win = Window::week(now());
    let mut g = Glass::new(&mut b);
    let model = g.model_within(win, glass::DEFAULT_BUCKETS).unwrap();
    assert_eq!(model.totals.live, 3);

    // Type "sever mail": it resolves to severing both of mail's live channels and
    // previews the view filtered to "mail". A bare query just filters, no action.
    assert_eq!(
        glass::resolve(&glass::parse("mail"), &model).action,
        glass::PaletteAction::None
    );
    let resolved = glass::resolve(&glass::parse("sever mail"), &model);
    assert_eq!(resolved.filter.as_deref(), Some("mail"));
    let grants = match resolved.action {
        glass::PaletteAction::Sever(grants) => grants,
        other => panic!("expected a sever action, got {other:?}"),
    };
    assert_eq!(grants.len(), 2);

    // Run it the way the shell does on Enter.
    for grant in grants {
        g.sever(grant).unwrap();
    }

    // Both of mail's channels are severed; music's stays live.
    let after = g.model_within(win, glass::DEFAULT_BUCKETS).unwrap();
    assert_eq!(after.totals.severed, 2);
    assert_eq!(after.totals.live, 1);
    let music = after
        .principals
        .iter()
        .find(|p| p.principal.0 == "music")
        .unwrap();
    assert!(music.channels[0].can_sever(), "music was left untouched");
}

// A long-lived Glass holds one broker open, so its model does not reflect appends
// another process makes to the store until the broker reloads. Open a store,
// append through a second broker, and confirm the model only changes after the
// reload: open a store, append externally, re-summarize, assert the model
// changed. This is what the live shell does on each tick.
#[test]
fn model_reflects_external_appends_after_reload() {
    let d = tempdir().unwrap();
    let mut a = Broker::open(Lifestream::init(d.path(), &KEY).unwrap(), Policy::DenyAll).unwrap();

    let win = Window::week(now());
    let before = Glass::new(&mut a)
        .model_within(win, glass::DEFAULT_BUCKETS)
        .unwrap();
    assert!(before.is_empty());

    // Another process grants and uses a network capability on the same store.
    {
        let mut b =
            Broker::open(Lifestream::open(d.path(), &KEY).unwrap(), Policy::DenyAll).unwrap();
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
    }

    // A has not looked again, so its model is still the stale, empty one.
    let stale = Glass::new(&mut a)
        .model_within(win, glass::DEFAULT_BUCKETS)
        .unwrap();
    assert!(stale.is_empty());
    assert_eq!(stale.totals, before.totals);

    // After the broker reloads, the model folds in the live network channel.
    assert!(a.reload().unwrap());
    let after = Glass::new(&mut a)
        .model_within(win, glass::DEFAULT_BUCKETS)
        .unwrap();
    assert!(!after.is_empty());
    assert_ne!(after.totals, before.totals);
    assert_eq!(after.totals.principals, 1);
    assert_eq!(after.totals.network, 1);
    assert_eq!(after.totals.live, 1);
    let channel = &after.principals[0].channels[0];
    assert_eq!(channel.status, ChannelStatus::Live);
    assert_eq!(channel.uses, 1);
}
