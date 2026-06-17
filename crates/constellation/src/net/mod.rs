//! The QUIC + Noise network skin for the Constellation.
//!
//! Two halves implement the same [`Transport`](crate::Transport) trait the
//! in-process sync already runs on, so the algorithm in [`crate::sync`] does not
//! change:
//!
//! - [`Server`] holds one identity's Lifestream and listens on a QUIC endpoint.
//!   Each peer that connects authenticates with the Noise handshake, then reads
//!   and writes objects and refs through a small request/response protocol.
//! - [`NetworkTransport`] is the peer's view of that server: it implements
//!   `Transport` by sending one request per call and blocking for the reply.
//!
//! The trait is synchronous and the Lifestream is blocking file IO, so rather
//! than colour the whole sync engine async, the network transport keeps its own
//! tokio runtime and bridges each blocking call to the async QUIC stack with
//! `block_on`. The async surface stays contained inside this module.
//!
//! What crosses the link is exactly what crosses any `Transport`: sealed records
//! (ciphertext) and ref names. The Noise layer adds peer authentication and a
//! second AEAD over the framing; the QUIC/TLS layer below it is only the
//! transport envelope (see [`tls`]).

mod noise;
pub mod relay;
pub mod rendezvous;
mod tls;
mod wire;

pub use relay::{Relay, RelayBinding};
pub use rendezvous::{Rendezvous, RendezvousClient, RendezvousRegistration};

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use lifestream::{Lifestream, ObjectId};

use crate::error::{Error, Result};
use crate::{LocalTransport, Transport};
use noise::net;
use wire::{NoiseChannel, Req, Resp};

// A listening peer. It serves one identity's store to other devices of that
// identity over QUIC. Serving runs on a background runtime owned by the Server;
// dropping the Server stops it.
pub struct Server {
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
    // Held so the same store and identity can also be served through a relay
    // (see [`Server::bind_relay`]), not only on the direct endpoint above.
    master: [u8; 32],
    transport: Arc<LocalTransport>,
    // Kept alive so the spawned accept loop keeps running.
    _rt: tokio::runtime::Runtime,
}

impl Server {
    // Bind `bind` and start serving `ls` to peers that prove the same identity
    // (`master`). Returns once the socket is bound; the address it actually got
    // (useful when binding port 0) is [`Server::local_addr`].
    pub fn start(bind: SocketAddr, master: [u8; 32], ls: Lifestream) -> Result<Server> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(net)?;

        let endpoint = rt.block_on(async {
            quinn::Endpoint::server(tls::server_config()?, bind).map_err(net)
        })?;
        let local_addr = endpoint.local_addr().map_err(net)?;

        let transport = Arc::new(LocalTransport::new(ls));
        rt.spawn(accept_loop(endpoint.clone(), master, transport.clone()));

        Ok(Server {
            endpoint,
            local_addr,
            master,
            transport,
            _rt: rt,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    // Also serve this identity's store through a relay at `relay_addr`, for
    // peers that cannot reach the direct endpoint (both sides behind NATs, say).
    // The relay forwards opaque bytes between this server and a dialing peer; the
    // same Noise handshake still authenticates the peer end to end through it, so
    // the relay sees only ciphertext. The returned handle keeps the binding live;
    // dropping it stops accepting relayed peers and withdraws from the relay. The
    // direct endpoint keeps serving regardless.
    pub fn bind_relay(&self, relay_addr: SocketAddr) -> Result<RelayBinding> {
        relay::bind(relay_addr, self.master, self.transport.clone())
    }

    // Block the calling thread while the server keeps serving in the background.
    // The CLI uses this; a SIGINT (ctrl-c) ends the process.
    pub fn wait(&self) -> ! {
        loop {
            std::thread::park();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"server closing");
    }
}

async fn accept_loop(endpoint: quinn::Endpoint, master: [u8; 32], transport: Arc<LocalTransport>) {
    while let Some(incoming) = endpoint.accept().await {
        let transport = transport.clone();
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                let _ = serve_conn(conn, master, transport).await;
            }
        });
    }
}

// One peer session over a direct connection: take its single bi-directional
// stream and serve it. The relay path serves the same way over a stream the
// relay forwards instead (see [`serve_stream`]).
async fn serve_conn(
    conn: quinn::Connection,
    master: [u8; 32],
    transport: Arc<LocalTransport>,
) -> Result<()> {
    let (send, recv) = conn.accept_bi().await.map_err(net)?;
    serve_stream(send, recv, master, &*transport).await
}

// Serve one peer session over a bi-directional stream: the Noise handshake, then
// request/response frames until the peer says Bye or drops. The stream may be a
// direct QUIC stream or one a relay forwards on this peer's behalf; either way
// the Noise layer authenticates the peer here, before any object moves. Shared
// by the direct accept loop and the relay binding so serving is one code path.
pub(super) async fn serve_stream(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    master: [u8; 32],
    transport: &(dyn Transport + Sync),
) -> Result<()> {
    let mut ch = NoiseChannel::responder(send, recv, &master).await?;
    loop {
        // A read error here is the ordinary end of a session (peer closed), not
        // something to propagate.
        let frame = match ch.recv().await {
            Ok(f) => f,
            Err(_) => break,
        };
        let req = Req::decode(&frame)?;
        let done = matches!(req, Req::Bye);
        let resp = handle(transport, req);
        ch.send(&resp.encode()).await?;
        if done {
            break;
        }
    }
    Ok(())
}

// Run one request against the local store and shape the answer. A store error
// becomes Resp::Err so the caller sees the same message it would running the op
// itself, instead of the connection just dropping.
fn handle(t: &dyn Transport, req: Req) -> Resp {
    match req {
        Req::Have => match t.have() {
            Ok(s) => Resp::Have(s.into_iter().collect()),
            Err(e) => Resp::Err(e.to_string()),
        },
        Req::Read(id) => match t.read_record(&id) {
            Ok(r) => Resp::Record(r),
            Err(e) => Resp::Err(e.to_string()),
        },
        Req::Write(id, rec) => match t.write_record(&id, &rec) {
            Ok(b) => Resp::Wrote(b),
            Err(e) => Resp::Err(e.to_string()),
        },
        Req::Refs => match t.refs() {
            Ok(v) => Resp::Refs(v),
            Err(e) => Resp::Err(e.to_string()),
        },
        Req::GetRef(name) => match t.get_ref(&name) {
            Ok(o) => Resp::Ref(o),
            Err(e) => Resp::Err(e.to_string()),
        },
        Req::SetRef(name, id) => match t.set_ref(&name, &id) {
            Ok(()) => Resp::Did,
            Err(e) => Resp::Err(e.to_string()),
        },
        Req::Parents(id) => match t.parents(&id) {
            Ok(o) => Resp::Parents(o),
            Err(e) => Resp::Err(e.to_string()),
        },
        Req::Bye => Resp::Did,
    }
}

// The dialing peer: a Transport whose calls travel to a remote Server. One
// connection and one Noise channel are opened at connect time and reused for
// every call; sync drives the calls in sequence, so the channel needs no more
// than a mutex for interior mutability.
pub struct NetworkTransport {
    rt: tokio::runtime::Runtime,
    session: Mutex<NoiseChannel>,
    // Both kept alive for the life of the session: dropping the endpoint or the
    // connection would tear down the streams the channel holds.
    _conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
}

impl NetworkTransport {
    // Connect to a Server at `addr` and authenticate as `master`. A wrong
    // identity is refused here, during the Noise handshake, before any object
    // moves.
    pub fn connect(addr: SocketAddr, master: [u8; 32]) -> Result<NetworkTransport> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(net)?;

        let (endpoint, conn, ch) = rt.block_on(async {
            let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
            let mut endpoint = quinn::Endpoint::client(bind).map_err(net)?;
            endpoint.set_default_client_config(tls::client_config()?);
            let conn = endpoint
                .connect(addr, "horizon")
                .map_err(net)?
                .await
                .map_err(net)?;
            let (send, recv) = conn.open_bi().await.map_err(net)?;
            let ch = NoiseChannel::initiator(send, recv, &master).await?;
            Ok::<_, Error>((endpoint, conn, ch))
        })?;

        Ok(NetworkTransport::from_parts(rt, endpoint, conn, ch))
    }

    // Connect to a Server through a relay at `relay_addr` instead of dialing it
    // directly, for a peer that cannot be reached on any address (behind a NAT).
    // The relay tunnels bytes to a serving peer bound under the same identity
    // fingerprint; the Noise handshake then authenticates that peer end to end
    // through the tunnel, exactly as on a direct link. A wrong identity, or no
    // peer of this identity bound at the relay, fails here before any object
    // moves.
    pub fn connect_via_relay(relay_addr: SocketAddr, master: [u8; 32]) -> Result<NetworkTransport> {
        relay::connect(relay_addr, master)
    }

    // Assemble the transport from an established connection and Noise channel.
    // Shared by the direct [`NetworkTransport::connect`] and the relay path,
    // which differ only in how they obtain the stream the channel runs over.
    pub(super) fn from_parts(
        rt: tokio::runtime::Runtime,
        endpoint: quinn::Endpoint,
        conn: quinn::Connection,
        ch: NoiseChannel,
    ) -> NetworkTransport {
        NetworkTransport {
            rt,
            session: Mutex::new(ch),
            _conn: conn,
            _endpoint: endpoint,
        }
    }

    fn call(&self, req: Req) -> Result<Resp> {
        let mut guard = self.session.lock().map_err(|_| net("session poisoned"))?;
        let ch = &mut *guard;
        self.rt.block_on(async move {
            ch.send(&req.encode()).await?;
            let frame = ch.recv().await?;
            Resp::decode(&frame)
        })
    }

    // Graceful shutdown: tell the server we are done and wait for it to
    // acknowledge, so a clean sync ends a clean session. Best used right after
    // the last sync, while the peer is still up.
    pub fn close(self) -> Result<()> {
        match self.call(Req::Bye)? {
            Resp::Did => Ok(()),
            other => Err(unexpected(other)),
        }
    }
}

impl Drop for NetworkTransport {
    fn drop(&mut self) {
        // Synchronous and non-blocking: notify the server so its session loop
        // ends promptly. Unlike a Bye round-trip this never waits on a reply, so
        // a transport dropped after its peer is gone does not stall.
        self._conn.close(0u32.into(), b"bye");
    }
}

// Map an unexpected reply to an error. A Resp::Err carries the peer's own
// message; anything else means the protocol desynced.
fn unexpected(r: Resp) -> Error {
    match r {
        Resp::Err(s) => Error::Net(s),
        _ => Error::Net("unexpected reply from peer".into()),
    }
}

impl Transport for NetworkTransport {
    fn have(&self) -> Result<HashSet<ObjectId>> {
        match self.call(Req::Have)? {
            Resp::Have(v) => Ok(v.into_iter().collect()),
            other => Err(unexpected(other)),
        }
    }

    fn read_record(&self, id: &ObjectId) -> Result<Vec<u8>> {
        match self.call(Req::Read(*id))? {
            Resp::Record(r) => Ok(r),
            other => Err(unexpected(other)),
        }
    }

    fn write_record(&self, id: &ObjectId, record: &[u8]) -> Result<bool> {
        match self.call(Req::Write(*id, record.to_vec()))? {
            Resp::Wrote(b) => Ok(b),
            other => Err(unexpected(other)),
        }
    }

    fn refs(&self) -> Result<Vec<(String, ObjectId)>> {
        match self.call(Req::Refs)? {
            Resp::Refs(v) => Ok(v),
            other => Err(unexpected(other)),
        }
    }

    fn get_ref(&self, name: &str) -> Result<Option<ObjectId>> {
        match self.call(Req::GetRef(name.to_string()))? {
            Resp::Ref(o) => Ok(o),
            other => Err(unexpected(other)),
        }
    }

    fn set_ref(&self, name: &str, id: &ObjectId) -> Result<()> {
        match self.call(Req::SetRef(name.to_string(), *id))? {
            Resp::Did => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn parents(&self, id: &ObjectId) -> Result<Option<Vec<ObjectId>>> {
        match self.call(Req::Parents(*id))? {
            Resp::Parents(o) => Ok(o),
            other => Err(unexpected(other)),
        }
    }
}
