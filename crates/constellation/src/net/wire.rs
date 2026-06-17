//! The Constellation wire: a request/response protocol that mirrors the
//! [`Transport`](crate::Transport) trait, carried over a Noise-encrypted,
//! self-framing channel on top of a QUIC stream.
//!
//! Records can be up to a 64 KiB chunk plus sealing overhead, which is larger
//! than a single Noise transport message (capped at 65535 bytes). So a frame is
//! length-prefixed and then split into Noise-sized segments; the reader puts the
//! segments back together. Each segment is independently encrypted by the
//! channel's transport keys, so nothing on the wire is plaintext past the
//! handshake.

use lifestream::ObjectId;

use super::noise::{self, net};
use crate::error::Result;

// 65535 (max Noise message) minus the 16-byte ChaChaPoly tag.
const MAX_SEGMENT: usize = 65519;

// A request names one Transport operation. One request gets exactly one
// response, in order, over a single stream.
pub enum Req {
    Have,
    Read(ObjectId),
    Write(ObjectId, Vec<u8>),
    Refs,
    GetRef(String),
    SetRef(String, ObjectId),
    Parents(ObjectId),
    // Tear the session down cleanly so the server can stop reading.
    Bye,
}

pub enum Resp {
    Have(Vec<ObjectId>),
    Record(Vec<u8>),
    Wrote(bool),
    Refs(Vec<(String, ObjectId)>),
    Ref(Option<ObjectId>),
    // Acknowledges a SetRef or a Bye: the call had no value to return.
    Did,
    Parents(Option<Vec<ObjectId>>),
    // The peer hit an error serving the request. Carried as text so the caller
    // sees the same message it would have seen running the op locally.
    Err(String),
}

impl Req {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        match self {
            Req::Have => o.push(1),
            Req::Read(id) => {
                o.push(2);
                o.extend_from_slice(&id.0);
            }
            Req::Write(id, rec) => {
                o.push(3);
                o.extend_from_slice(&id.0);
                put_bytes(&mut o, rec);
            }
            Req::Refs => o.push(4),
            Req::GetRef(name) => {
                o.push(5);
                put_str(&mut o, name);
            }
            Req::SetRef(name, id) => {
                o.push(6);
                put_str(&mut o, name);
                o.extend_from_slice(&id.0);
            }
            Req::Parents(id) => {
                o.push(7);
                o.extend_from_slice(&id.0);
            }
            Req::Bye => o.push(8),
        }
        o
    }

    pub fn decode(buf: &[u8]) -> Result<Req> {
        let mut r = Reader::new(buf);
        Ok(match r.u8()? {
            1 => Req::Have,
            2 => Req::Read(r.id()?),
            3 => {
                let id = r.id()?;
                Req::Write(id, r.bytes()?.to_vec())
            }
            4 => Req::Refs,
            5 => Req::GetRef(r.string()?),
            6 => {
                let name = r.string()?;
                Req::SetRef(name, r.id()?)
            }
            7 => Req::Parents(r.id()?),
            8 => Req::Bye,
            t => return Err(net(format!("bad request tag {t}"))),
        })
    }
}

impl Resp {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        match self {
            Resp::Have(ids) => {
                o.push(1);
                put_ids(&mut o, ids);
            }
            Resp::Record(rec) => {
                o.push(2);
                put_bytes(&mut o, rec);
            }
            Resp::Wrote(b) => {
                o.push(3);
                o.push(*b as u8);
            }
            Resp::Refs(pairs) => {
                o.push(4);
                put_u32(&mut o, pairs.len() as u32);
                for (name, id) in pairs {
                    put_str(&mut o, name);
                    o.extend_from_slice(&id.0);
                }
            }
            Resp::Ref(opt) => {
                o.push(5);
                put_opt_id(&mut o, opt.as_ref());
            }
            Resp::Did => o.push(6),
            Resp::Parents(opt) => {
                o.push(7);
                match opt {
                    Some(ids) => {
                        o.push(1);
                        put_ids(&mut o, ids);
                    }
                    None => o.push(0),
                }
            }
            Resp::Err(s) => {
                o.push(8);
                put_str(&mut o, s);
            }
        }
        o
    }

    pub fn decode(buf: &[u8]) -> Result<Resp> {
        let mut r = Reader::new(buf);
        Ok(match r.u8()? {
            1 => Resp::Have(r.ids()?),
            2 => Resp::Record(r.bytes()?.to_vec()),
            3 => Resp::Wrote(r.u8()? != 0),
            4 => {
                let n = r.u32()?;
                let mut pairs = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let name = r.string()?;
                    pairs.push((name, r.id()?));
                }
                Resp::Refs(pairs)
            }
            5 => Resp::Ref(r.opt_id()?),
            6 => Resp::Did,
            7 => match r.u8()? {
                0 => Resp::Parents(None),
                _ => Resp::Parents(Some(r.ids()?)),
            },
            8 => Resp::Err(r.string()?),
            t => return Err(net(format!("bad response tag {t}"))),
        })
    }
}

// A Noise-secured, self-framing channel over one QUIC bi-directional stream.
// Construct it with the handshake, then trade whole frames; segmentation under
// the Noise message cap is hidden.
pub struct NoiseChannel {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    noise: snow::TransportState,
}

impl NoiseChannel {
    // Dialing side of the handshake: write message one, read message two.
    pub async fn initiator(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        master: &[u8; 32],
    ) -> Result<NoiseChannel> {
        let mut hs = noise::initiator(master)?;
        let mut buf = [0u8; 256];
        let n = hs.write_message(&[], &mut buf).map_err(net)?;
        write_seg(&mut send, &buf[..n]).await?;
        let msg2 = read_seg(&mut recv).await?;
        hs.read_message(&msg2, &mut buf).map_err(net)?;
        Ok(NoiseChannel {
            send,
            recv,
            noise: noise::into_transport(hs)?,
        })
    }

    // Listening side: read message one (this is where a wrong identity is
    // rejected, its tag will not verify), then write message two.
    pub async fn responder(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        master: &[u8; 32],
    ) -> Result<NoiseChannel> {
        let mut hs = noise::responder(master)?;
        let msg1 = read_seg(&mut recv).await?;
        let mut buf = [0u8; 256];
        hs.read_message(&msg1, &mut buf).map_err(net)?;
        let n = hs.write_message(&[], &mut buf).map_err(net)?;
        write_seg(&mut send, &buf[..n]).await?;
        Ok(NoiseChannel {
            send,
            recv,
            noise: noise::into_transport(hs)?,
        })
    }

    // Send one whole frame: a u32 length then the bytes, encrypted in
    // Noise-sized segments.
    pub async fn send(&mut self, frame: &[u8]) -> Result<()> {
        let mut payload = Vec::with_capacity(4 + frame.len());
        put_u32(&mut payload, frame.len() as u32);
        payload.extend_from_slice(frame);
        for seg in payload.chunks(MAX_SEGMENT) {
            let mut out = vec![0u8; seg.len() + 16];
            let n = self.noise.write_message(seg, &mut out).map_err(net)?;
            out.truncate(n);
            write_seg(&mut self.send, &out).await?;
        }
        Ok(())
    }

    // Read one whole frame, reassembling segments until the declared length is
    // in hand.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut plain: Vec<u8> = Vec::new();
        let mut total: Option<usize> = None;
        loop {
            let ct = read_seg(&mut self.recv).await?;
            let mut out = vec![0u8; ct.len()];
            let n = self.noise.read_message(&ct, &mut out).map_err(net)?;
            out.truncate(n);
            plain.extend_from_slice(&out);
            if total.is_none() && plain.len() >= 4 {
                let len = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]) as usize;
                total = Some(4 + len);
            }
            if let Some(t) = total {
                if plain.len() >= t {
                    plain.truncate(t);
                    plain.drain(0..4);
                    return Ok(plain);
                }
            }
        }
    }
}

// One length-prefixed wire segment: a u16 byte count then the bytes. The count
// covers a single Noise message, which never exceeds 65535 bytes.
async fn write_seg(s: &mut quinn::SendStream, data: &[u8]) -> Result<()> {
    let len = u16::try_from(data.len()).map_err(net)?;
    s.write_all(&len.to_be_bytes()).await.map_err(net)?;
    s.write_all(data).await.map_err(net)?;
    Ok(())
}

async fn read_seg(s: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    let mut lb = [0u8; 2];
    s.read_exact(&mut lb).await.map_err(net)?;
    let mut buf = vec![0u8; u16::from_be_bytes(lb) as usize];
    s.read_exact(&mut buf).await.map_err(net)?;
    Ok(buf)
}

pub(crate) fn put_u16(o: &mut Vec<u8>, v: u16) {
    o.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_u32(o: &mut Vec<u8>, v: u32) {
    o.extend_from_slice(&v.to_be_bytes());
}

fn put_bytes(o: &mut Vec<u8>, b: &[u8]) {
    put_u32(o, b.len() as u32);
    o.extend_from_slice(b);
}

pub(crate) fn put_str(o: &mut Vec<u8>, s: &str) {
    put_bytes(o, s.as_bytes());
}

fn put_ids(o: &mut Vec<u8>, ids: &[ObjectId]) {
    put_u32(o, ids.len() as u32);
    for id in ids {
        o.extend_from_slice(&id.0);
    }
}

fn put_opt_id(o: &mut Vec<u8>, id: Option<&ObjectId>) {
    match id {
        Some(id) => {
            o.push(1);
            o.extend_from_slice(&id.0);
        }
        None => o.push(0),
    }
}

pub(crate) struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, p: 0 }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.p + n > self.b.len() {
            return Err(net("short frame"));
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn id(&mut self) -> Result<ObjectId> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(ObjectId(a))
    }
    fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub(crate) fn string(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(net)
    }
    fn ids(&mut self) -> Result<Vec<ObjectId>> {
        let n = self.u32()?;
        let mut v = Vec::with_capacity(n as usize);
        for _ in 0..n {
            v.push(self.id()?);
        }
        Ok(v)
    }
    fn opt_id(&mut self) -> Result<Option<ObjectId>> {
        match self.u8()? {
            0 => Ok(None),
            _ => Ok(Some(self.id()?)),
        }
    }
}
