use std::path::Path;

use lifestream::Lifestream;
use tempfile::{tempdir, TempDir};
use weave::{Broker, Error, Limits, Policy, Resource, Rights, Rule, Status};

const KEY: [u8; 32] = [7u8; 32];

fn store() -> TempDir {
    tempdir().unwrap()
}

fn init(path: &Path, policy: Policy) -> Broker {
    Broker::open(Lifestream::init(path, &KEY).unwrap(), policy).unwrap()
}

fn reopen(path: &Path, policy: Policy) -> Broker {
    Broker::open(Lifestream::open(path, &KEY).unwrap(), policy).unwrap()
}

#[test]
fn grant_then_access_logs_use() {
    let d = store();
    let mut b = init(d.path(), Policy::DenyAll);
    let cap = b
        .grant(
            "aura".into(),
            Resource::file("/home/user/docs"),
            Rights::READ,
            Limits::none(),
        )
        .unwrap();
    let lease = b
        .access(
            &cap,
            &Resource::file("/home/user/docs/report.txt"),
            Rights::READ,
        )
        .unwrap();
    assert_eq!(lease.rights, Rights::READ);

    let log = b.audit().unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].event.kind(), "grant");
    assert_eq!(log[1].event.kind(), "use");
    assert_eq!(b.verify().unwrap(), 2);
}

#[test]
fn access_outside_scope_is_denied() {
    let d = store();
    let mut b = init(d.path(), Policy::DenyAll);
    let cap = b
        .grant(
            "aura".into(),
            Resource::file("/home/user/docs"),
            Rights::READ,
            Limits::none(),
        )
        .unwrap();
    // a sibling directory is not covered by the grant
    let err = b
        .access(&cap, &Resource::file("/home/user/secret"), Rights::READ)
        .unwrap_err();
    assert!(matches!(err, Error::Denied(r) if r == "out of scope"));
    // the denial is on the record
    let log = b.audit().unwrap();
    assert_eq!(log.last().unwrap().event.kind(), "deny");
}

#[test]
fn insufficient_rights_is_denied() {
    let d = store();
    let mut b = init(d.path(), Policy::DenyAll);
    let cap = b
        .grant(
            "app".into(),
            Resource::file("/x"),
            Rights::READ,
            Limits::none(),
        )
        .unwrap();
    let err = b
        .access(&cap, &Resource::file("/x"), Rights::WRITE)
        .unwrap_err();
    assert!(matches!(err, Error::Denied(r) if r == "insufficient rights"));
    // asking for more than granted (read+write when only read was given) also fails
    assert!(b
        .access(&cap, &Resource::file("/x"), Rights::READ | Rights::WRITE)
        .is_err());
}

#[test]
fn use_limit_is_enforced() {
    let d = store();
    let mut b = init(d.path(), Policy::DenyAll);
    let cap = b
        .grant(
            "app".into(),
            Resource::service("mail", "send"),
            Rights::EXEC,
            Limits::uses(2),
        )
        .unwrap();
    let r = Resource::service("mail", "send");
    assert!(b.access(&cap, &r, Rights::EXEC).is_ok());
    assert!(b.access(&cap, &r, Rights::EXEC).is_ok());
    let err = b.access(&cap, &r, Rights::EXEC).unwrap_err();
    assert!(matches!(err, Error::Denied(m) if m == "use limit reached"));
}

#[test]
fn expired_grant_is_denied() {
    let d = store();
    let mut b = init(d.path(), Policy::DenyAll);
    // expires at the epoch, so it is already past
    let cap = b
        .grant(
            "app".into(),
            Resource::device("microphone"),
            Rights::READ,
            Limits::until(1),
        )
        .unwrap();
    let err = b
        .access(&cap, &Resource::device("microphone"), Rights::READ)
        .unwrap_err();
    assert!(matches!(err, Error::Denied(m) if m == "expired"));
    assert_eq!(b.grants()[0].status, Status::Expired);
}

#[test]
fn revoke_blocks_further_use() {
    let d = store();
    let mut b = init(d.path(), Policy::DenyAll);
    let r = Resource::net("api.example.com", 443);
    let cap = b
        .grant("aura".into(), r.clone(), Rights::EXEC, Limits::none())
        .unwrap();
    assert!(b.access(&cap, &r, Rights::EXEC).is_ok());

    let id = cap.grant_id();
    b.revoke(id).unwrap();
    let err = b.access(&cap, &r, Rights::EXEC).unwrap_err();
    assert!(matches!(err, Error::Denied(m) if m == "revoked"));

    // revoke is idempotent and the grant now reads as revoked
    b.revoke(id).unwrap();
    assert_eq!(b.grants()[0].status, Status::Revoked);

    let kinds: Vec<_> = b.audit().unwrap().iter().map(|e| e.event.kind()).collect();
    assert_eq!(kinds, ["grant", "use", "revoke", "deny"]);
}

#[test]
fn audit_persists_and_replays_across_reopen() {
    let d = store();
    let id = {
        let mut b = init(d.path(), Policy::DenyAll);
        let cap = b
            .grant(
                "aura".into(),
                Resource::file("/home/user"),
                Rights::READ | Rights::WRITE,
                Limits::uses(5),
            )
            .unwrap();
        b.access(&cap, &Resource::file("/home/user/a"), Rights::READ)
            .unwrap();
        b.access(&cap, &Resource::file("/home/user/b"), Rights::WRITE)
            .unwrap();
        cap.grant_id()
    };

    // a fresh broker rebuilds its whole grant table from the persisted log
    let b = reopen(d.path(), Policy::DenyAll);
    assert_eq!(b.verify().unwrap(), 3);
    let g = b.grants();
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].id, id);
    assert_eq!(g[0].uses, 2);
    assert_eq!(g[0].status, Status::Active);
}

#[test]
fn reissue_lets_a_returning_holder_act() {
    let d = store();
    let id = {
        let mut b = init(d.path(), Policy::DenyAll);
        b.grant(
            "app".into(),
            Resource::file("/data"),
            Rights::READ,
            Limits::none(),
        )
        .unwrap()
        .grant_id()
    };
    // after a restart the old session handle is gone; reissue mints a new one
    let mut b = reopen(d.path(), Policy::DenyAll);
    let cap = b.reissue(id).unwrap();
    assert!(b
        .access(&cap, &Resource::file("/data/x"), Rights::READ)
        .is_ok());

    // a revoked grant cannot be reissued
    b.revoke(id).unwrap();
    assert!(matches!(b.reissue(id), Err(Error::Denied(m)) if m == "revoked"));
}

#[test]
fn request_consults_policy() {
    let d = store();
    let rules = vec![Rule {
        principal: Some("aura".into()),
        resource: Resource::net("api.example.com", 443),
        rights: Rights::EXEC,
        limits: Limits::none(),
    }];
    let mut b = init(d.path(), Policy::Rules(rules));

    // allowed: matching principal, resource, and rights
    let cap = b
        .request(
            "aura".into(),
            Resource::net("api.example.com", 443),
            Rights::EXEC,
        )
        .unwrap();
    assert!(b
        .access(&cap, &Resource::net("api.example.com", 443), Rights::EXEC)
        .is_ok());

    // denied: a different host
    assert!(b
        .request(
            "aura".into(),
            Resource::net("evil.example.com", 443),
            Rights::EXEC
        )
        .is_err());
    // denied: a different principal
    assert!(b
        .request(
            "spotify".into(),
            Resource::net("api.example.com", 443),
            Rights::EXEC,
        )
        .is_err());

    let kinds: Vec<_> = b.audit().unwrap().iter().map(|e| e.event.kind()).collect();
    assert_eq!(kinds, ["grant", "use", "deny", "deny"]);
}

#[test]
fn gc_by_refs_preserves_the_audit_chain() {
    let d = store();
    let ls = Lifestream::init(d.path(), &KEY).unwrap();
    // an object no ref points at: gc should reclaim it
    let junk = ls.write_bytes(b"unreferenced junk data").unwrap();

    let n = {
        let mut b = Broker::open(ls, Policy::DenyAll).unwrap();
        let cap = b
            .grant(
                "aura".into(),
                Resource::file("/p"),
                Rights::READ,
                Limits::none(),
            )
            .unwrap();
        b.access(&cap, &Resource::file("/p/q"), Rights::READ)
            .unwrap();
        b.access(&cap, &Resource::file("/p/r"), Rights::READ)
            .unwrap();
        b.verify().unwrap()
    };

    // gc the way the CLI does: roots are exactly the ref targets
    let ls = Lifestream::open(d.path(), &KEY).unwrap();
    assert!(ls.has(&junk));
    let mut roots = Vec::new();
    for name in ls.list_refs().unwrap() {
        if let Some(id) = ls.get_ref(&name).unwrap() {
            roots.push(id);
        }
    }
    let removed = ls.gc(&roots).unwrap();
    assert!(removed >= 1);
    assert!(!ls.has(&junk));

    // the whole audit history is still intact and verifiable
    let b = Broker::open(ls, Policy::DenyAll).unwrap();
    assert_eq!(b.verify().unwrap(), n);
}
