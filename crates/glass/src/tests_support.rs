// Sample models shared by the surface and raster unit tests, so both draw the
// same fixtures. Built through the real `build` fold from crafted grants and log
// entries, the way the broker would report them.

use lifestream::ObjectId;
use weave::{AuditEntry, Event, GrantId, GrantInfo, Resource, Rights, Status};

use crate::model::{build, Model, Window};
use crate::DEFAULT_BUCKETS;

pub const NOW: u64 = 1_700_000_000;

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
    AuditEntry {
        id: ObjectId::from_hex(&"00".repeat(32)).unwrap(),
        seq,
        time_unix: time,
        event,
    }
}

// One principal with one live network channel: the smallest non-empty model.
pub fn one_live_model() -> Model {
    let gid = GrantId::random();
    let res = Resource::net("api.example", 443);
    let grants = vec![grant_info(
        gid,
        "mail",
        res.clone(),
        Rights::READ | Rights::WRITE,
        NOW - 100,
        1,
        Status::Active,
    )];
    let log = vec![
        entry(
            0,
            NOW - 100,
            Event::Grant {
                grant: gid,
                principal: "mail".into(),
                resource: res.clone(),
                rights: Rights::READ | Rights::WRITE,
                expires_unix: None,
                max_uses: None,
            },
        ),
        entry(
            1,
            NOW - 40,
            Event::Use {
                grant: gid,
                principal: "mail".into(),
                resource: res,
                rights: Rights::WRITE,
            },
        ),
    ];
    build(&log, &grants, Window::week(NOW), DEFAULT_BUCKETS)
}

// A richer model: a live network channel, a live directory grant with touched
// files and an out-of-scope blocked attempt, and a severed channel. Exercises
// every status color and the kill switch.
pub fn demo_model() -> Model {
    let net = GrantId::random();
    let docs = GrantId::random();
    let peer = GrantId::random();

    let net_res = Resource::net("api.example", 443);
    let docs_res = Resource::file("/home/user/docs");
    let peer_res = Resource::net("peer.local", 7777);

    let grants = vec![
        grant_info(
            net,
            "mail",
            net_res.clone(),
            Rights::READ | Rights::WRITE,
            NOW - 100,
            4,
            Status::Active,
        ),
        grant_info(
            docs,
            "aura",
            docs_res.clone(),
            Rights::READ,
            NOW - 3 * 3600,
            2,
            Status::Active,
        ),
        grant_info(
            peer,
            "sync",
            peer_res.clone(),
            Rights::READ | Rights::WRITE,
            NOW - 2 * 86_400,
            3,
            Status::Revoked,
        ),
    ];

    let mut log = vec![
        entry(
            0,
            NOW - 100,
            Event::Grant {
                grant: net,
                principal: "mail".into(),
                resource: net_res.clone(),
                rights: Rights::READ | Rights::WRITE,
                expires_unix: None,
                max_uses: None,
            },
        ),
        entry(
            1,
            NOW - 30,
            Event::Use {
                grant: net,
                principal: "mail".into(),
                resource: net_res,
                rights: Rights::WRITE,
            },
        ),
        entry(
            2,
            NOW - 3 * 3600,
            Event::Grant {
                grant: docs,
                principal: "aura".into(),
                resource: docs_res.clone(),
                rights: Rights::READ,
                expires_unix: None,
                max_uses: None,
            },
        ),
    ];
    for (i, f) in ["/home/user/docs/notes.md", "/home/user/docs/todo.txt"]
        .iter()
        .enumerate()
    {
        log.push(entry(
            3 + i as u64,
            NOW - 2 * 3600 + i as u64,
            Event::Use {
                grant: docs,
                principal: "aura".into(),
                resource: Resource::file(f),
                rights: Rights::READ,
            },
        ));
    }
    log.push(entry(
        5,
        NOW - 1800,
        Event::Deny {
            principal: "aura".into(),
            resource: Resource::file("/etc/passwd"),
            rights: Rights::READ,
            reason: "out of scope".into(),
        },
    ));
    log.push(entry(
        6,
        NOW - 2 * 86_400,
        Event::Grant {
            grant: peer,
            principal: "sync".into(),
            resource: peer_res.clone(),
            rights: Rights::READ | Rights::WRITE,
            expires_unix: None,
            max_uses: None,
        },
    ));
    log.push(entry(
        7,
        NOW - 86_400,
        Event::Use {
            grant: peer,
            principal: "sync".into(),
            resource: peer_res,
            rights: Rights::WRITE,
        },
    ));
    log.push(entry(8, NOW - 3600, Event::Revoke { grant: peer }));

    build(&log, &grants, Window::week(NOW), DEFAULT_BUCKETS)
}
