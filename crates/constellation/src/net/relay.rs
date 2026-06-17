//! A relay for peers that cannot reach each other at all.
//!
//! The rendezvous ([`super::rendezvous`]) hands a peer an address to dial, and
//! that is enough when something can reach that address: a peer on the same LAN,
//! or one whose NAT a hole punch can open. But two peers can both sit behind
//! NATs that refuse every inbound packet, where no address either side learns is
//! dialable. A relay is the meeting point that still works: both peers make an
//! outbound connection to it (which a NAT does allow), and it forwards bytes
//! between the two. It is the path that always works, the fallback a direct dial
//! or a future hole punch is tried before.
//!
//! Like the rendezvous, the relay holds no identity. It pairs peers by the same
//! non-secret [`fingerprint`](crate::fingerprint) and then forwards opaque bytes;
//! it never sees the master, a Lifestream object, or the Noise PSK. The Noise
//! NNpsk0 handshake still runs end to end between the two real peers, through the
//! tunnel, so everything past the handshake is ciphertext to the relay and a
//! wrong identity is refused at the far peer exactly as on a direct link (see
//! [`super::noise`]). So a relay, too, can run on a cheap untrusted host: the
//! worst a hostile one can do is deny service or splice the wrong peers together,
//! and the wrong peers simply fail each other's handshake. The link to the relay
//! is QUIC with the same throwaway-cert envelope the sync uses ([`super::tls`]).
//!
//! Presence here is a live connection, not a lease. A serving peer dials the
//! relay and binds under its fingerprint ([`bind`]); the relay keeps that
//! connection and, when a peer asks to reach the fingerprint, opens a fresh
//! stream to the serving peer and splices it to the dialer. When the serving
//! peer's connection closes, the relay withdraws the binding. QUIC keep-alive
//! holds an otherwise idle binding open, so there is nothing to refresh; the
//! transport's own liveness is the heartbeat.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::label::fingerprint;
use crate::LocalTransport;

use super::tls;
use super::wire::{put_str, NoiseChannel, Reader};
use super::{noise::net, serve_stream, NetworkTransport};

// A control frame (one Bind or Connect request, or its reply) is a tag and at
// most a short fingerprint. The cap just stops a peer making the relay buffer
// without bound; it does not apply to the forwarded bytes, which are streamed.
const MAX_CTL: usize = 4 * 1024;

// Bytes moved per relayed copy step. The relay is content-blind, so this is only
// a buffer size, not a message boundary; Noise framing is preserved because the
// bytes are forwarded in order, whole.
const COPY_BUF: usize = 64 * 1024;

// The fingerprint -> bound serving connections map. A serving peer binds one
// connection under its fingerprint; a dialer asking for that fingerprint is
// spliced onto a fresh stream opened to one of them. Several devices of one
// identity can bind at once, so each fingerprint holds a list.
#[derive(Default)]
struct Registry {
    by_fp: HashMap<String, Vec<Bound>>,
}

// One serving peer's connection to the relay, kept so the relay can open a
// stream toward it when a dialer arrives. Identified by the connection's stable
// id so it can be withdrawn precisely when it closes.
struct Bound {
    id: usize,
    conn: quinn::Connection,
}

impl Registry {
    fn bind(&mut self, fp: String, conn: quinn::Connection) {
        let id = conn.stable_id();
        let bucket = self.by_fp.entry(fp).or_default();
        // A reconnect under the same id replaces the old entry rather than
        // doubling it.
        bucket.retain(|b| b.id != id);
        bucket.push(Bound { id, conn });
    }

    fn unbind(&mut self, fp: &str, id: usize) {
        if let Some(bucket) = self.by_fp.get_mut(fp) {
            bucket.retain(|b| b.id != id);
            if bucket.is_empty() {
                self.by_fp.remove(fp);
            }
        }
    }

    // Live serving connections for a fingerprint, as clonable handles to try in
    // turn. Empty if no peer of that identity is bound.
    fn peers(&self, fp: &str) -> Vec<quinn::Connection> {
        self.by_fp
            .get(fp)
            .map(|v| v.iter().map(|b| b.conn.clone()).collect())
            .unwrap_or_default()
    }
}

// A listening relay. It binds a QUIC endpoint and, on a background runtime it
// owns, accepts serving peers that bind under a fingerprint and dialers that ask
// to reach one, splicing the two together. Dropping it stops serving. It is
// identity-agnostic: any peer can bind or reach any fingerprint, because the
// fingerprint is public and authentication happens later, between the two real
// peers.
pub struct Relay {
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
    // Kept alive so the spawned accept loop keeps running.
    _rt: tokio::runtime::Runtime,
}

impl Relay {
    // Bind `bind` and start forwarding. Returns once the socket is bound; the
    // address it actually got (useful when binding port 0) is
    // [`Relay::local_addr`].
    pub fn start(bind: SocketAddr) -> Result<Relay> {
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

        Ok(Relay {
            endpoint,
            local_addr,
            _rt: rt,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    // Block the calling thread while the relay keeps forwarding in the
    // background. The CLI uses this; a SIGINT (ctrl-c) ends the process.
    pub fn wait(&self) -> ! {
        loop {
            std::thread::park();
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"relay closing");
    }
}

async fn accept_loop(endpoint: quinn::Endpoint, registry: Arc<Mutex<Registry>>) {
    while let Some(incoming) = endpoint.accept().await {
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                // The first stream on a connection carries one control request,
                // Bind or Connect; everything after is forwarded bytes.
                if let Ok((send, recv)) = conn.accept_bi().await {
                    let _ = serve_control(registry, conn, send, recv).await;
                }
            }
        });
    }
}

// Handle one peer's control request. A serving peer Binds and the relay holds
// its connection until it closes; a dialer Connects and the relay splices it to
// a bound serving peer (or tells it there is none).
async fn serve_control(
    registry: Arc<Mutex<Registry>>,
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    match Req::decode(&read_ctl(&mut recv).await?)? {
        Req::Bind { fp } => {
            let id = conn.stable_id();
            registry
                .lock()
                .map_err(|_| net("relay registry poisoned"))?
                .bind(fp.clone(), conn.clone());
            write_ctl(&mut send, &Resp::Bound.encode()).await?;
            // Hold the binding until the serving peer's connection closes. The
            // relay opens streams toward this connection for dialers (the serving
            // peer accepts them); we never read or write the control stream
            // again, and keep-alive holds the connection open meanwhile.
            let _ = conn.closed().await;
            registry
                .lock()
                .map_err(|_| net("relay registry poisoned"))?
                .unbind(&fp, id);
            Ok(())
        }
        Req::Connect { fp } => {
            let peers = registry
                .lock()
                .map_err(|_| net("relay registry poisoned"))?
                .peers(&fp);
            for peer in peers {
                // Open a fresh stream to the serving peer. If its connection is
                // gone, drop it from the map and try the next one.
                match peer.open_bi().await {
                    Ok((s_send, s_recv)) => {
                        write_ctl(&mut send, &Resp::Connected.encode()).await?;
                        splice(recv, send, s_send, s_recv).await;
                        return Ok(());
                    }
                    Err(_) => {
                        registry
                            .lock()
                            .map_err(|_| net("relay registry poisoned"))?
                            .unbind(&fp, peer.stable_id());
                    }
                }
            }
            write_ctl(&mut send, &Resp::NoPeer.encode()).await?;
            let _ = send.finish();
            Ok(())
        }
    }
}

// Forward bytes both ways between a dialer's stream and a serving peer's stream
// until either side ends. The relay reads nothing it forwards; both directions
// carry the peers' Noise-encrypted traffic.
async fn splice(
    d_recv: quinn::RecvStream,
    d_send: quinn::SendStream,
    s_send: quinn::SendStream,
    s_recv: quinn::RecvStream,
) {
    // Run both directions concurrently and wait for both to finish, so neither
    // side is cut off mid-frame.
    let to_server = tokio::spawn(pump(d_recv, s_send));
    let to_dialer = tokio::spawn(pump(s_recv, d_send));
    let _ = to_server.await;
    let _ = to_dialer.await;
}

// Copy one direction until the source ends or a write fails, then signal the end
// of the stream to the far side so the other direction unwinds too.
async fn pump(mut from: quinn::RecvStream, mut to: quinn::SendStream) {
    let mut buf = vec![0u8; COPY_BUF];
    // The loop ends when the source stream does: Ok(None) is a clean end, Err is
    // a reset or closed connection. A failed write ends it too.
    while let Ok(Some(n)) = from.read(&mut buf).await {
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = to.finish();
}

// Bind this identity's serving peer to a relay so dialers can reach it through
// the tunnel. Dials the relay, announces the fingerprint, then accepts the
// streams the relay opens per dialer and serves each with the same logic the
// direct endpoint uses. The returned handle keeps the binding live; dropping it
// closes the relay connection, which both stops the accept loop and makes the
// relay withdraw the binding.
pub(super) fn bind(
    relay_addr: SocketAddr,
    master: [u8; 32],
    transport: Arc<LocalTransport>,
) -> Result<RelayBinding> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(net)?;

    let (endpoint, conn) = rt.block_on(async {
        let fp = fingerprint(&master);
        let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut endpoint = quinn::Endpoint::client(bind).map_err(net)?;
        endpoint.set_default_client_config(tls::client_config()?);
        let conn = endpoint
            .connect(relay_addr, "horizon")
            .map_err(net)?
            .await
            .map_err(net)?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(net)?;
        write_ctl(&mut send, &Req::Bind { fp }.encode()).await?;
        match Resp::decode(&read_ctl(&mut recv).await?)? {
            Resp::Bound => {}
            other => return Err(unexpected(other)),
        }
        Ok::<_, Error>((endpoint, conn))
    })?;

    // Each stream the relay opens is one dialer's tunnel; serve it like any other
    // peer session. The loop ends when the relay connection closes.
    let accept_conn = conn.clone();
    rt.spawn(async move {
        while let Ok((send, recv)) = accept_conn.accept_bi().await {
            let transport = transport.clone();
            tokio::spawn(async move {
                let _ = serve_stream(send, recv, master, &*transport).await;
            });
        }
    });

    Ok(RelayBinding {
        conn,
        _rt: rt,
        _endpoint: endpoint,
    })
}

// Connect to a serving peer through a relay. Dials the relay, asks to reach this
// identity's fingerprint, and on success runs the Noise handshake over the
// tunnel the relay splices, returning a transport indistinguishable from a
// direct one. Used by [`super::NetworkTransport::connect_via_relay`].
pub(super) fn connect(relay_addr: SocketAddr, master: [u8; 32]) -> Result<NetworkTransport> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(net)?;

    let (endpoint, conn, ch) = rt.block_on(async {
        let fp = fingerprint(&master);
        let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let mut endpoint = quinn::Endpoint::client(bind).map_err(net)?;
        endpoint.set_default_client_config(tls::client_config()?);
        let conn = endpoint
            .connect(relay_addr, "horizon")
            .map_err(net)?
            .await
            .map_err(net)?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(net)?;
        write_ctl(&mut send, &Req::Connect { fp }.encode()).await?;
        match Resp::decode(&read_ctl(&mut recv).await?)? {
            Resp::Connected => {}
            Resp::NoPeer => return Err(net("relay has no peer of this identity")),
            other => return Err(unexpected(other)),
        }
        // The same stream is now a tunnel to the serving peer; the handshake runs
        // over it exactly as on a direct link, including refusing a wrong peer.
        let ch = NoiseChannel::initiator(send, recv, &master).await?;
        Ok::<_, Error>((endpoint, conn, ch))
    })?;

    Ok(NetworkTransport::from_parts(rt, endpoint, conn, ch))
}

// A live relay binding, held for as long as a peer serves through the relay.
// Dropping it closes the relay connection: the relay withdraws the binding and
// the accept loop ends, then the runtime drops with the handle, stopping any
// in-flight relayed sessions. A serving process that is killed (ctrl-c) never
// runs this drop, which is fine: the relay notices the connection drop and
// withdraws the binding regardless.
pub struct RelayBinding {
    conn: quinn::Connection,
    // Both kept alive for the life of the binding: the runtime runs the accept
    // loop, and dropping the endpoint would tear down the connection.
    _rt: tokio::runtime::Runtime,
    _endpoint: quinn::Endpoint,
}

impl Drop for RelayBinding {
    fn drop(&mut self) {
        // Close the relay connection, then let the close frame reach the relay
        // before the runtime stops, so the relay withdraws this binding promptly
        // rather than waiting for the connection to time out. Bounded so a dead
        // relay cannot stall the drop.
        self.conn.close(0u32.into(), b"unbind");
        let endpoint = self._endpoint.clone();
        let _ = self._rt.block_on(async move {
            tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await
        });
    }
}

// One length-prefixed control frame: a u32 byte count then the bytes. Used only
// for the Bind/Connect handshake; the forwarded traffic after it is unframed at
// this layer (the Noise channel frames itself).
async fn write_ctl(send: &mut quinn::SendStream, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(net)?;
    send.write_all(&len.to_be_bytes()).await.map_err(net)?;
    send.write_all(bytes).await.map_err(net)?;
    Ok(())
}

async fn read_ctl(recv: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    let mut lb = [0u8; 4];
    recv.read_exact(&mut lb).await.map_err(net)?;
    let len = u32::from_be_bytes(lb) as usize;
    if len > MAX_CTL {
        return Err(net("relay control frame too large"));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(net)?;
    Ok(buf)
}

fn unexpected(r: Resp) -> Error {
    match r {
        Resp::Err(s) => Error::Net(s),
        _ => Error::Net("unexpected reply from relay".into()),
    }
}

// The relay wire: tiny control messages, distinct from the sync protocol in
// [`super::wire`] because a relay speaks no identity and reads no objects.
enum Req {
    // A serving peer offering itself under a fingerprint.
    Bind { fp: String },
    // A dialer asking to reach a serving peer of a fingerprint.
    Connect { fp: String },
}

enum Resp {
    // Acknowledges a Bind: the serving peer is now reachable.
    Bound,
    // The tunnel is up; forwarded bytes follow on the same stream.
    Connected,
    // No serving peer of that fingerprint is bound.
    NoPeer,
    Err(String),
}

impl Req {
    fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        match self {
            Req::Bind { fp } => {
                o.push(1);
                put_str(&mut o, fp);
            }
            Req::Connect { fp } => {
                o.push(2);
                put_str(&mut o, fp);
            }
        }
        o
    }

    fn decode(buf: &[u8]) -> Result<Req> {
        let mut r = Reader::new(buf);
        Ok(match r.u8()? {
            1 => Req::Bind { fp: r.string()? },
            2 => Req::Connect { fp: r.string()? },
            t => return Err(net(format!("bad relay request tag {t}"))),
        })
    }
}

impl Resp {
    fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        match self {
            Resp::Bound => o.push(1),
            Resp::Connected => o.push(2),
            Resp::NoPeer => o.push(3),
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
            1 => Resp::Bound,
            2 => Resp::Connected,
            3 => Resp::NoPeer,
            4 => Resp::Err(r.string()?),
            t => return Err(net(format!("bad relay response tag {t}"))),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_response_round_trip() {
        let bind = Req::Bind {
            fp: "deadbeefcafef00d".into(),
        };
        assert!(matches!(
            Req::decode(&bind.encode()).unwrap(),
            Req::Bind { fp } if fp == "deadbeefcafef00d"
        ));

        let connect = Req::Connect { fp: "abc".into() };
        assert!(matches!(
            Req::decode(&connect.encode()).unwrap(),
            Req::Connect { fp } if fp == "abc"
        ));

        assert!(matches!(
            Resp::decode(&Resp::Bound.encode()).unwrap(),
            Resp::Bound
        ));
        assert!(matches!(
            Resp::decode(&Resp::Connected.encode()).unwrap(),
            Resp::Connected
        ));
        assert!(matches!(
            Resp::decode(&Resp::NoPeer.encode()).unwrap(),
            Resp::NoPeer
        ));
        assert!(matches!(
            Resp::decode(&Resp::Err("nope".into()).encode()).unwrap(),
            Resp::Err(s) if s == "nope"
        ));
    }

    #[test]
    fn a_short_or_bad_frame_is_an_error() {
        assert!(Req::decode(&[]).is_err());
        assert!(Req::decode(&[99]).is_err());
        // Tag says bind but the fingerprint length runs off the end.
        assert!(Req::decode(&[1, 0, 0, 0, 8, b'x']).is_err());
        assert!(Resp::decode(&[]).is_err());
        assert!(Resp::decode(&[42]).is_err());
    }

    // An empty registry returns no peers and tolerates withdrawing an unknown
    // binding. The registry stores live connections, so binding and splicing are
    // exercised by the loopback test in tests/relay.rs rather than here.
    #[test]
    fn empty_registry_has_no_peers() {
        let mut reg = Registry::default();
        assert!(reg.peers("alice").is_empty());
        reg.unbind("ghost", 1);
        assert!(reg.by_fp.is_empty());
    }
}
