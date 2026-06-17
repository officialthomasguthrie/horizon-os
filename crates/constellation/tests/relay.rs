// The relay, exercised over loopback. Like the rendezvous, the relay is plain
// QUIC, so the whole bind-then-tunnel-then-sync path runs in CI: a Relay, a
// serving Server that binds under its identity fingerprint, and a second peer
// that tunnels to it through the relay and runs a normal sync. The tunnel carries
// the same QUIC + Noise sync the net tests cover; here we prove the relay splices
// two peers together without ever holding their identity.
#![cfg(feature = "net")]

use std::net::SocketAddr;
use std::time::Duration;

use constellation::{sync, LocalTransport, NetworkTransport, Relay, Server};
use lifestream::{Lifestream, NodeKind, Object, ObjectId, TreeEntry};
use tempfile::{tempdir, TempDir};

const KEY: [u8; 32] = [41u8; 32];
const OTHER_KEY: [u8; 32] = [42u8; 32];

fn store(dir: &TempDir, key: &[u8; 32]) -> Lifestream {
    Lifestream::init(dir.path(), key).unwrap()
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

// Non-repeating bytes so a few records grow past the 64 KiB cut, which forces the
// channel to segment them under the Noise message limit and the relay to forward
// across those boundaries blindly.
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

// The headline path: a peer that knows only the relay address and the shared
// identity tunnels to a serving peer and pulls its objects, with no dialable
// address for the peer anywhere. Large content makes the server send
// multi-segment record frames the relay forwards and the client reassembles.
#[test]
fn tunnel_pull_replicates_through_the_relay() {
    let relay = Relay::start(loopback()).unwrap();
    let relay_addr = relay.local_addr();

    // A serving peer with real content. It listens directly too, but the dialer
    // never learns that address; it reaches it only through the relay.
    let ds = tempdir().unwrap();
    let source = store(&ds, &KEY);
    let payload = varied(200_000);
    let f = source.write_bytes(&payload).unwrap();
    let gen = source
        .commit(tree_with(&source, &[("data", f)]), vec![], "src")
        .unwrap();
    let server = Server::start(loopback(), KEY, source).unwrap();
    let _binding = server.bind_relay(relay_addr).unwrap();

    // A second peer of the same identity tunnels in and pulls everything.
    let dd = tempdir().unwrap();
    let local = LocalTransport::new(store(&dd, &KEY));
    let remote = NetworkTransport::connect_via_relay(relay_addr, KEY).unwrap();
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
    drop(relay);
}

// The tunnel is symmetric: a peer can push to the bound server through it too,
// not only pull. Large content here makes the client send multi-segment frames.
#[test]
fn tunnel_push_replicates_through_the_relay() {
    let relay = Relay::start(loopback()).unwrap();
    let relay_addr = relay.local_addr();

    // The far side starts empty and is reachable only through the relay.
    let db = tempdir().unwrap();
    let server = Server::start(loopback(), KEY, store(&db, &KEY)).unwrap();
    let _binding = server.bind_relay(relay_addr).unwrap();

    // The near side holds the content and pushes it across the tunnel.
    let da = tempdir().unwrap();
    let a = LocalTransport::new(store(&da, &KEY));
    let big = a.lifestream().write_bytes(&varied(150_000)).unwrap();
    let note = a.lifestream().write_bytes(b"pushed over a relay").unwrap();
    let gen = a
        .lifestream()
        .commit(
            tree_with(a.lifestream(), &[("big", big), ("note", note)]),
            vec![],
            "g1",
        )
        .unwrap();

    let remote = NetworkTransport::connect_via_relay(relay_addr, KEY).unwrap();
    let report = sync(&a, &remote).unwrap();
    assert_eq!(report.transferred, a.lifestream().object_count().unwrap());
    assert_eq!(report.refs_set, vec!["HEAD".to_string()]);
    remote.close().ok();

    // On the server's actual disk, a fresh handle decrypts the pushed generation.
    let b = Lifestream::open(db.path(), &KEY).unwrap();
    assert_eq!(
        b.object_count().unwrap(),
        a.lifestream().object_count().unwrap()
    );
    assert_eq!(b.head().unwrap(), Some(gen));
    drop(server);
    drop(relay);
}

// With no serving peer of this identity bound, a dialer is told there is no peer
// rather than left hanging.
#[test]
fn a_dialer_with_no_peer_is_refused() {
    let relay = Relay::start(loopback()).unwrap();
    let relay_addr = relay.local_addr();

    let err = NetworkTransport::connect_via_relay(relay_addr, KEY);
    assert!(err.is_err(), "no peer is bound, so the tunnel cannot form");
    drop(relay);
}

// A different identity cannot tunnel to a bound peer: the relay pairs by
// fingerprint, and a different identity has a different fingerprint, so the relay
// has no peer for it. (Even if a hostile relay forced the pairing, the Noise
// handshake would refuse it, as net.rs covers on a direct link; the relay only
// ever forwards ciphertext.)
#[test]
fn a_different_identity_is_refused() {
    let relay = Relay::start(loopback()).unwrap();
    let relay_addr = relay.local_addr();

    let db = tempdir().unwrap();
    let server = Server::start(loopback(), KEY, store(&db, &KEY)).unwrap();
    let _binding = server.bind_relay(relay_addr).unwrap();

    // A stranger of another identity finds no peer to tunnel to.
    assert!(NetworkTransport::connect_via_relay(relay_addr, OTHER_KEY).is_err());
    // The right identity still tunnels in.
    let ok = NetworkTransport::connect_via_relay(relay_addr, KEY).unwrap();
    ok.close().ok();

    drop(server);
    drop(relay);
}

// Dropping the binding withdraws the peer from the relay: a later dialer of the
// same identity then finds no peer. The relay learns the binding is gone when the
// serving peer's connection closes, so we give that close a moment to propagate.
#[test]
fn binding_withdraws_on_drop() {
    let relay = Relay::start(loopback()).unwrap();
    let relay_addr = relay.local_addr();

    let db = tempdir().unwrap();
    let server = Server::start(loopback(), KEY, store(&db, &KEY)).unwrap();
    let binding = server.bind_relay(relay_addr).unwrap();

    // While bound, a dialer tunnels in.
    let up = NetworkTransport::connect_via_relay(relay_addr, KEY).unwrap();
    up.close().ok();

    // After dropping the binding, the relay forgets the peer.
    drop(binding);
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        NetworkTransport::connect_via_relay(relay_addr, KEY).is_err(),
        "a withdrawn binding leaves no peer to tunnel to"
    );

    drop(server);
    drop(relay);
}
