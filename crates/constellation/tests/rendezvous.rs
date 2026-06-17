// The rendezvous, exercised over loopback. Unlike mDNS, which needs real LAN
// multicast, the rendezvous is plain QUIC, so the whole find-then-dial path runs
// in CI: a Rendezvous, a serving Server that registers under its identity
// fingerprint, and a second peer that looks the fingerprint up and dials the
// address it gets back. The dial itself is the same QUIC + Noise sync the net
// tests already cover; here we prove discovery hands it a working address.
#![cfg(feature = "net")]

use std::net::SocketAddr;

use constellation::{
    fingerprint, sync, LocalTransport, NetworkTransport, Rendezvous, RendezvousClient, Server,
};
use lifestream::{Lifestream, NodeKind, Object, ObjectId, TreeEntry};
use tempfile::{tempdir, TempDir};

const KEY: [u8; 32] = [21u8; 32];
const OTHER_KEY: [u8; 32] = [22u8; 32];

fn store(dir: &TempDir, key: &[u8; 32]) -> Lifestream {
    Lifestream::init(dir.path(), key).unwrap()
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn varied(n: usize) -> Vec<u8> {
    (0..n as u32)
        .map(|i| {
            let z = i.wrapping_mul(2_654_435_761);
            (z ^ (z >> 13)) as u8
        })
        .collect()
}

fn tree_with(ls: &Lifestream, entries: &[(&str, ObjectId)]) -> ObjectId {
    let entries = entries
        .iter()
        .map(|(name, id)| TreeEntry {
            name: (*name).to_string(),
            kind: NodeKind::File,
            id: *id,
            mode: 0o644,
        })
        .collect();
    ls.put(&Object::Tree { entries }).unwrap()
}

// The headline path: a peer that knows only the rendezvous address and the
// shared identity finds a serving peer and pulls its objects, no host:port for
// the peer typed anywhere.
#[test]
fn register_then_look_up_and_sync() {
    // The meeting point.
    let rz = Rendezvous::start(loopback()).unwrap();
    let rz_addr = rz.local_addr();

    // A serving peer with real content, listening on an OS-chosen port.
    let ds = tempdir().unwrap();
    let source = store(&ds, &KEY);
    let payload = varied(200_000);
    let f = source.write_bytes(&payload).unwrap();
    let gen = source
        .commit(tree_with(&source, &[("data", f)]), vec![], "src")
        .unwrap();
    let server = Server::start(loopback(), KEY, source).unwrap();
    let serve_addr = server.local_addr();

    // It registers under its identity fingerprint at the rendezvous.
    let announcer = RendezvousClient::connect(rz_addr).unwrap();
    let observed = announcer
        .register(&fingerprint(&KEY), serve_addr.port())
        .unwrap();
    // The rendezvous saw us on loopback; the dialable address pairs that with the
    // listen port, which is exactly where the server is.
    assert_eq!(observed.ip(), serve_addr.ip());

    // A second peer of the same identity looks the fingerprint up.
    let finder = RendezvousClient::connect(rz_addr).unwrap();
    let found = finder.lookup(&fingerprint(&KEY)).unwrap();
    assert_eq!(
        found,
        vec![serve_addr],
        "rendezvous returns the serve address"
    );

    // And dialing what it found runs a normal sync: the content arrives.
    let dd = tempdir().unwrap();
    let local = LocalTransport::new(store(&dd, &KEY));
    let remote = NetworkTransport::connect(found[0], KEY).unwrap();
    let report = sync(&remote, &local).unwrap();
    assert!(report.transferred > 0);
    assert_eq!(local.lifestream().head().unwrap(), Some(gen));

    let root = match local.lifestream().get(&gen).unwrap() {
        Object::Generation(g) => g.root,
        _ => panic!("not a generation"),
    };
    let entries = match local.lifestream().get(&root).unwrap() {
        Object::Tree { entries } => entries,
        _ => panic!("not a tree"),
    };
    assert_eq!(
        local.lifestream().read_bytes(&entries[0].id).unwrap(),
        payload
    );

    remote.close().ok();
    drop(server);
    drop(rz);
}

// The fingerprint scopes the lookup: a peer of a different identity finds
// nothing, even though a peer of another identity is registered. (And it could
// not connect even if it learned the address: that is the Noise handshake's job,
// covered in net.rs.)
#[test]
fn a_different_identity_finds_nothing() {
    let rz = Rendezvous::start(loopback()).unwrap();
    let rz_addr = rz.local_addr();

    let announcer = RendezvousClient::connect(rz_addr).unwrap();
    announcer.register(&fingerprint(&KEY), 7777).unwrap();

    let stranger = RendezvousClient::connect(rz_addr).unwrap();
    assert!(stranger
        .lookup(&fingerprint(&OTHER_KEY))
        .unwrap()
        .is_empty());
    // The original identity is still there.
    assert!(!stranger.lookup(&fingerprint(&KEY)).unwrap().is_empty());

    drop(rz);
}

// Unregister takes a peer off the map at once, rather than waiting for its lease
// to lapse.
#[test]
fn unregister_clears_the_listing() {
    let rz = Rendezvous::start(loopback()).unwrap();
    let rz_addr = rz.local_addr();

    let peer = RendezvousClient::connect(rz_addr).unwrap();
    let fp = fingerprint(&KEY);
    peer.register(&fp, 7777).unwrap();
    assert_eq!(peer.lookup(&fp).unwrap().len(), 1);

    peer.unregister(&fp, 7777).unwrap();
    assert!(peer.lookup(&fp).unwrap().is_empty());

    drop(rz);
}

// keepalive registers and hands back a handle whose observed address matches a
// plain register. Dropping the handle stops the heartbeat; the lease then ages
// out on the rendezvous (not waited on here).
#[test]
fn keepalive_registers_and_reports_observed() {
    let rz = Rendezvous::start(loopback()).unwrap();
    let rz_addr = rz.local_addr();

    let client = RendezvousClient::connect(rz_addr).unwrap();
    let reg = client.keepalive(fingerprint(&KEY), 7777).unwrap();
    assert_eq!(reg.observed().ip(), loopback().ip());

    let finder = RendezvousClient::connect(rz_addr).unwrap();
    assert_eq!(
        finder.lookup(&fingerprint(&KEY)).unwrap(),
        vec![SocketAddr::new(loopback().ip(), 7777)]
    );

    drop(reg);
    drop(rz);
}
