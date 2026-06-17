//! A rendezvous server for finding a peer beyond the LAN.
//!
//! mDNS ([`crate::discovery`]) finds a peer of your identity on the same LAN,
//! where multicast reaches. It does not cross subnets or the open internet. A
//! rendezvous server is the meeting point that does: a device at a known address
//! that every device of an identity can reach. A serving peer registers under
//! its identity [`fingerprint`](crate::fingerprint); another peer of the same
//! identity looks the fingerprint up and gets the addresses to dial.
//!
//! The rendezvous holds no identity. It never sees the master, a Lifestream
//! object, or the Noise PSK; it sees only a non-secret fingerprint and the IP a
//! packet arrived from. So it can run on a cheap shared host without trusting it
//! with anything: the worst a hostile rendezvous can do is deny service, or hand
//! out a wrong address, and a wrong address simply fails the Noise NNpsk0
//! handshake when the dialing peer tries it (see [`super::noise`]). The link to
//! the rendezvous is QUIC with the same throwaway-cert envelope the sync uses
//! ([`super::tls`]); identity, as everywhere in the Constellation, lives only in
//! the Noise layer between the two real peers, never here.
//!
//! Registrations are presence, not state: each is a short lease the serving peer
//! refreshes with a heartbeat ([`RendezvousClient::keepalive`]), and the registry
//! lives only in memory. A peer that stops serving simply stops refreshing, and
//! its lease expires. Nothing is persisted, so a rendezvous restart just waits
//! for everyone to re-register.
//!
//! What this is not, yet: a relay (carrying bytes for peers that cannot reach
//! each other at all) or NAT hole punching. The rendezvous already records the
//! public address it observes a peer at, which is the input a hole punch needs,
//! but the punch itself wants real hosts behind real NATs to test, so it is left
//! for that setting.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

use super::noise::net;
use super::tls;
use super::wire::{put_str, put_u16, put_u32, Reader};

// How long a registration lives without a refresh, and how often a serving peer
// refreshes it. The lease outlasts a few missed beats, so a brief network hiccup
// does not drop a peer off the map; when a peer really stops, it is gone within
// one lease.
const LEASE: Duration = Duration::from_secs(90);
const HEARTBEAT: Duration = Duration::from_secs(30);

// A rendezvous message is a fingerprint and a handful of addresses, far under
// this. The cap just stops a peer from making the server buffer without bound.
const MAX_MSG: usize = 64 * 1024;

// The fingerprint -> live addresses map. Each address carries the instant its
// lease expires; lookups drop the expired ones, so the map self-cleans as it is
// used and a peer that vanished without unregistering ages out on its own.
#[derive(Default)]
struct Registry {
    by_fp: HashMap<String, HashMap<SocketAddr, Instant>>,
}

impl Registry {
    // Record (or refresh) that `fp` is reachable at `addr`, leased from `now`.
    // Re-registering the same address just extends its lease, which is what the
    // heartbeat does.
    fn register(&mut self, fp: String, addr: SocketAddr, now: Instant) {
        let bucket = self.by_fp.entry(fp).or_default();
        bucket.insert(addr, now + LEASE);
        bucket.retain(|_, &mut exp| exp > now);
    }

    fn unregister(&mut self, fp: &str, addr: &SocketAddr) {
        if let Some(bucket) = self.by_fp.get_mut(fp) {
            bucket.remove(addr);
            if bucket.is_empty() {
                self.by_fp.remove(fp);
            }
        }
    }

    // The live addresses for `fp`, sorted, with expired leases pruned in passing.
    fn lookup(&mut self, fp: &str, now: Instant) -> Vec<SocketAddr> {
        let mut out = Vec::new();
        if let Some(bucket) = self.by_fp.get_mut(fp) {
            bucket.retain(|_, &mut exp| exp > now);
            out.extend(bucket.keys().copied());
            if bucket.is_empty() {
                self.by_fp.remove(fp);
            }
        }
        out.sort();
        out
    }
}

// A listening rendezvous. It binds a QUIC endpoint and answers register, lookup
// and unregister requests on a background runtime it owns; dropping it stops
// serving. It is identity-agnostic: any peer can register or look up any
// fingerprint, because the fingerprint is public and authentication happens
// later, between the two real peers.
pub struct Rendezvous {
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
    // Kept alive so the spawned accept loop keeps running.
    _rt: tokio::runtime::Runtime,
}

impl Rendezvous {
    // Bind `bind` and start answering. Returns once the socket is bound; the
    // address it actually got (useful when binding port 0) is
    // [`Rendezvous::local_addr`].
    pub fn start(bind: SocketAddr) -> Result<Rendezvous> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(net)?;

        let endpoint = rt.block_on(async {
            quinn::Endpoint::server(tls::server_config()?, bind).map_err(net)
        })?;
        let local_addr = endpoint.local_addr().map_err(net)?;

        let registry = Arc::new(Mutex::new(Registry::default()));
        rt.spawn(accept_loop(endpoint.clone(), registry));

        Ok(Rendezvous {
            endpoint,
            local_addr,
            _rt: rt,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    // Block the calling thread while the rendezvous keeps answering in the
    // background. The CLI uses this; a SIGINT (ctrl-c) ends the process.
    pub fn wait(&self) -> ! {
        loop {
            std::thread::park();
        }
    }
}

impl Drop for Rendezvous {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"rendezvous closing");
    }
}

async fn accept_loop(endpoint: quinn::Endpoint, registry: Arc<Mutex<Registry>>) {
    while let Some(incoming) = endpoint.accept().await {
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                // The address we see the peer at: its real source IP, which a peer
                // cannot forge, and the source port the path mapped it to.
                let observed = conn.remote_address();
                // One request per stream; a peer reuses the connection for many.
                while let Ok((send, recv)) = conn.accept_bi().await {
                    let registry = registry.clone();
                    tokio::spawn(async move {
                        let _ = serve_stream(registry, observed, send, recv).await;
                    });
                }
            }
        });
    }
}

async fn serve_stream(
    registry: Arc<Mutex<Registry>>,
    observed: SocketAddr,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    let buf = recv.read_to_end(MAX_MSG).await.map_err(net)?;
    let resp = apply(&registry, observed, Req::decode(&buf)?)?;
    send.write_all(&resp.encode()).await.map_err(net)?;
    send.finish().map_err(net)?;
    Ok(())
}

// Run one request against the registry. A peer registers an address for its own
// observed IP and a port it names: it cannot register for someone else's IP
// (that comes from the packet, not the peer), only for a fingerprint it claims,
// which is public anyway. The dialable address pairs the observed IP with the
// peer's announced listen port; the response echoes the full observed address so
// the peer learns its own public mapping.
fn apply(registry: &Mutex<Registry>, observed: SocketAddr, req: Req) -> Result<Resp> {
    let now = Instant::now();
    let mut reg = registry.lock().map_err(|_| net("registry poisoned"))?;
    Ok(match req {
        Req::Register { fp, port } => {
            reg.register(fp, SocketAddr::new(observed.ip(), port), now);
            Resp::Registered(observed)
        }
        Req::Unregister { fp, port } => {
            reg.unregister(&fp, &SocketAddr::new(observed.ip(), port));
            Resp::Ok
        }
        Req::Lookup { fp } => Resp::Addrs(reg.lookup(&fp, now)),
    })
}

// The peer's view of a rendezvous: dial it once and make register/lookup/
// unregister calls over the connection. Like [`super::NetworkTransport`] it owns
// a tokio runtime and bridges each blocking call to the async QUIC stack, so the
// CLI stays synchronous.
pub struct RendezvousClient {
    rt: tokio::runtime::Runtime,
    conn: quinn::Connection,
    // Kept alive for the life of the client: dropping the endpoint tears down the
    // connection.
    _endpoint: quinn::Endpoint,
}

impl RendezvousClient {
    pub fn connect(addr: SocketAddr) -> Result<RendezvousClient> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(net)?;

        let (endpoint, conn) = rt.block_on(async {
            let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
            let mut endpoint = quinn::Endpoint::client(bind).map_err(net)?;
            endpoint.set_default_client_config(tls::client_config()?);
            let conn = endpoint
                .connect(addr, "horizon")
                .map_err(net)?
                .await
                .map_err(net)?;
            Ok::<_, Error>((endpoint, conn))
        })?;

        Ok(RendezvousClient {
            rt,
            conn,
            _endpoint: endpoint,
        })
    }

    // Register `fp` at the listen `port`, returning how the rendezvous sees this
    // host (its public IP and mapped source port). A single register without a
    // heartbeat lasts one lease; use [`RendezvousClient::keepalive`] to stay
    // listed while serving.
    pub fn register(&self, fp: &str, port: u16) -> Result<SocketAddr> {
        match self.call(Req::Register {
            fp: fp.to_string(),
            port,
        })? {
            Resp::Registered(a) => Ok(a),
            other => Err(unexpected(other)),
        }
    }

    // The addresses currently registered for `fp`, to dial in turn until one
    // completes the Noise handshake. Empty if no peer of that identity is listed.
    pub fn lookup(&self, fp: &str) -> Result<Vec<SocketAddr>> {
        match self.call(Req::Lookup { fp: fp.to_string() })? {
            Resp::Addrs(v) => Ok(v),
            other => Err(unexpected(other)),
        }
    }

    pub fn unregister(&self, fp: &str, port: u16) -> Result<()> {
        match self.call(Req::Unregister {
            fp: fp.to_string(),
            port,
        })? {
            Resp::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    // Register and keep the lease alive with a background heartbeat until the
    // returned handle is dropped. This is what a serving peer holds for as long
    // as it serves.
    pub fn keepalive(self, fp: String, port: u16) -> Result<RendezvousRegistration> {
        let observed = self.register(&fp, port)?;

        // Re-register on the client's own runtime so the lease never lapses while
        // serving. The task is cancelled when the runtime drops with the handle.
        let conn = self.conn.clone();
        let beat_fp = fp.clone();
        self.rt.spawn(async move {
            let mut tick = tokio::time::interval(HEARTBEAT);
            tick.tick().await; // fires at once; we already registered above
            loop {
                tick.tick().await;
                let req = Req::Register {
                    fp: beat_fp.clone(),
                    port,
                }
                .encode();
                let _ = roundtrip(&conn, &req).await;
            }
        });

        Ok(RendezvousRegistration {
            _client: self,
            observed,
        })
    }

    fn call(&self, req: Req) -> Result<Resp> {
        let bytes = req.encode();
        let resp = self.rt.block_on(roundtrip(&self.conn, &bytes))?;
        Resp::decode(&resp)
    }
}

impl Drop for RendezvousClient {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"bye");
    }
}

// A live registration with a rendezvous: held for as long as a peer serves.
// Dropping it stops the heartbeat and closes the link, and the lease ages out
// within [`LEASE`]. A serving process that is killed (ctrl-c) never runs this
// drop, which is fine: the lease expiry is what the rendezvous relies on, not a
// clean goodbye.
pub struct RendezvousRegistration {
    _client: RendezvousClient,
    observed: SocketAddr,
}

impl RendezvousRegistration {
    // How the rendezvous saw this host at registration: its public IP and the
    // source port the path mapped the rendezvous connection to.
    pub fn observed(&self) -> SocketAddr {
        self.observed
    }
}

// One round trip on its own stream: write the request, half-close, read the
// reply to end. A fresh bi-directional stream per call keeps requests
// independent; the connection underneath is reused.
async fn roundtrip(conn: &quinn::Connection, req: &[u8]) -> Result<Vec<u8>> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(net)?;
    send.write_all(req).await.map_err(net)?;
    send.finish().map_err(net)?;
    recv.read_to_end(MAX_MSG).await.map_err(net)
}

fn unexpected(r: Resp) -> Error {
    match r {
        Resp::Err(s) => Error::Net(s),
        _ => Error::Net("unexpected reply from rendezvous".into()),
    }
}

// The rendezvous wire: tiny request/response messages, distinct from the sync
// protocol in [`super::wire`] because a rendezvous speaks no identity and moves
// no objects. One request, one response, per stream.
enum Req {
    Register { fp: String, port: u16 },
    Unregister { fp: String, port: u16 },
    Lookup { fp: String },
}

enum Resp {
    // How the rendezvous observed the registrant (public IP and source port).
    Registered(SocketAddr),
    // Acknowledges an unregister.
    Ok,
    // The live addresses for a looked-up fingerprint.
    Addrs(Vec<SocketAddr>),
    Err(String),
}

impl Req {
    fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        match self {
            Req::Register { fp, port } => {
                o.push(1);
                put_str(&mut o, fp);
                put_u16(&mut o, *port);
            }
            Req::Unregister { fp, port } => {
                o.push(2);
                put_str(&mut o, fp);
                put_u16(&mut o, *port);
            }
            Req::Lookup { fp } => {
                o.push(3);
                put_str(&mut o, fp);
            }
        }
        o
    }

    fn decode(buf: &[u8]) -> Result<Req> {
        let mut r = Reader::new(buf);
        Ok(match r.u8()? {
            1 => Req::Register {
                fp: r.string()?,
                port: r.u16()?,
            },
            2 => Req::Unregister {
                fp: r.string()?,
                port: r.u16()?,
            },
            3 => Req::Lookup { fp: r.string()? },
            t => return Err(net(format!("bad rendezvous request tag {t}"))),
        })
    }
}

impl Resp {
    fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        match self {
            Resp::Registered(addr) => {
                o.push(1);
                put_addr(&mut o, addr);
            }
            Resp::Ok => o.push(2),
            Resp::Addrs(addrs) => {
                o.push(3);
                put_u32(&mut o, addrs.len() as u32);
                for a in addrs {
                    put_addr(&mut o, a);
                }
            }
            Resp::Err(s) => {
                o.push(4);
                put_str(&mut o, s);
            }
        }
        o
    }

    fn decode(buf: &[u8]) -> Result<Resp> {
        let mut r = Reader::new(buf);
        Ok(match r.u8()? {
            1 => Resp::Registered(get_addr(&mut r)?),
            2 => Resp::Ok,
            3 => {
                let n = r.u32()?;
                let mut addrs = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    addrs.push(get_addr(&mut r)?);
                }
                Resp::Addrs(addrs)
            }
            4 => Resp::Err(r.string()?),
            t => return Err(net(format!("bad rendezvous response tag {t}"))),
        })
    }
}

// A socket address: a family tag, the raw IP octets, then the port. Both
// families so a rendezvous works over IPv6 too.
fn put_addr(o: &mut Vec<u8>, a: &SocketAddr) {
    match a.ip() {
        IpAddr::V4(v4) => {
            o.push(4);
            o.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            o.push(6);
            o.extend_from_slice(&v6.octets());
        }
    }
    put_u16(o, a.port());
}

fn get_addr(r: &mut Reader) -> Result<SocketAddr> {
    let ip = match r.u8()? {
        4 => {
            let b = r.take(4)?;
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        }
        6 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(r.take(16)?);
            IpAddr::V6(Ipv6Addr::from(b))
        }
        t => return Err(net(format!("bad address family {t}"))),
    };
    Ok(SocketAddr::new(ip, r.u16()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    #[test]
    fn lease_lookup_and_expiry() {
        let mut reg = Registry::default();
        let t0 = Instant::now();
        let addr = v4(203, 0, 113, 7, 7777);

        reg.register("fp1".into(), addr, t0);
        assert_eq!(reg.lookup("fp1", t0), vec![addr]);

        // Still live just before the lease ends.
        let almost = t0 + LEASE - Duration::from_secs(1);
        assert_eq!(reg.lookup("fp1", almost), vec![addr]);

        // Gone once the lease passes, and the empty bucket is dropped.
        let after = t0 + LEASE + Duration::from_secs(1);
        assert!(reg.lookup("fp1", after).is_empty());
        assert!(reg.by_fp.is_empty());
    }

    #[test]
    fn heartbeat_extends_the_lease() {
        let mut reg = Registry::default();
        let t0 = Instant::now();
        let addr = v4(198, 51, 100, 4, 7777);

        reg.register("fp".into(), addr, t0);
        // A refresh part-way through the lease pushes expiry out from the new now.
        let mid = t0 + Duration::from_secs(60);
        reg.register("fp".into(), addr, mid);
        // Past the original expiry but inside the refreshed one: still listed.
        let past_first = t0 + LEASE + Duration::from_secs(1);
        assert_eq!(reg.lookup("fp", past_first), vec![addr]);
    }

    #[test]
    fn lookup_is_identity_scoped_and_sorted() {
        let mut reg = Registry::default();
        let t0 = Instant::now();
        let a1 = v4(192, 0, 2, 1, 7777);
        let a2 = v4(192, 0, 2, 2, 7777);

        reg.register("alice".into(), a2, t0);
        reg.register("alice".into(), a1, t0);
        reg.register("bob".into(), v4(192, 0, 2, 9, 7777), t0);

        // Only alice's addresses, sorted, never bob's.
        assert_eq!(reg.lookup("alice", t0), vec![a1, a2]);
        // An unknown fingerprint finds nothing.
        assert!(reg.lookup("carol", t0).is_empty());
    }

    #[test]
    fn unregister_removes_one_address() {
        let mut reg = Registry::default();
        let t0 = Instant::now();
        let a1 = v4(192, 0, 2, 1, 7777);
        let a2 = v4(192, 0, 2, 1, 8888);

        reg.register("fp".into(), a1, t0);
        reg.register("fp".into(), a2, t0);
        reg.unregister("fp", &a1);
        assert_eq!(reg.lookup("fp", t0), vec![a2]);

        reg.unregister("fp", &a2);
        assert!(reg.lookup("fp", t0).is_empty());
        assert!(reg.by_fp.is_empty());
    }

    #[test]
    fn request_and_response_round_trip() {
        // v4 register, with a port.
        let r = Req::Register {
            fp: "deadbeefcafef00d".into(),
            port: 7777,
        };
        match Req::decode(&r.encode()).unwrap() {
            Req::Register { fp, port } => {
                assert_eq!(fp, "deadbeefcafef00d");
                assert_eq!(port, 7777);
            }
            _ => panic!("wrong request"),
        }

        // Lookup, then a response carrying both address families.
        let look = Req::Lookup { fp: "abc".into() };
        assert!(matches!(Req::decode(&look.encode()).unwrap(), Req::Lookup { fp } if fp == "abc"));

        let v6: SocketAddr = "[2001:db8::1]:7777".parse().unwrap();
        let v4a = v4(203, 0, 113, 9, 8080);
        let resp = Resp::Addrs(vec![v4a, v6]);
        match Resp::decode(&resp.encode()).unwrap() {
            Resp::Addrs(addrs) => assert_eq!(addrs, vec![v4a, v6]),
            _ => panic!("wrong response"),
        }

        let reg = Resp::Registered(v4a);
        assert!(matches!(Resp::decode(&reg.encode()).unwrap(), Resp::Registered(a) if a == v4a));
    }

    #[test]
    fn a_short_or_bad_frame_is_an_error() {
        assert!(Req::decode(&[]).is_err());
        assert!(Req::decode(&[99]).is_err());
        // Tag says register but the fingerprint length runs off the end.
        assert!(Req::decode(&[1, 0, 0, 0, 8, b'x']).is_err());
    }
}
