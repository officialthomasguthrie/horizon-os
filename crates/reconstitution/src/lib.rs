//! Reconstitution: split an identity secret into k-of-n recovery shares.
//!
//! Lose your Key and you should still be whole. Before that day you split the
//! master secret into n shares and spread them across people and places; any k
//! of them rebuild it, and any k-1 reveal nothing at all. That is Shamir's
//! scheme over GF(2^8): each secret byte is the constant term of a random
//! degree k-1 polynomial, a share is that polynomial sampled at a distinct x,
//! and recovery is Lagrange interpolation back to x = 0.
//!
//! Plain Shamir is malleable: feed it a corrupted or wrong-set share and it
//! hands back a wrong secret with no complaint. So every share also carries a
//! short tag derived from the real secret, and [`combine`] recomputes it from
//! what it rebuilt and refuses a mismatch. The tag is a commitment to the
//! secret; for a high-entropy secret like the master key it leaks nothing
//! useful, which is the intended use. Do not hand low-entropy secrets here
//! without a passphrase wrap.
//!
//! This crate is the portable core. Wiring shares to FIDO2 re-enrollment and the
//! unlock path lives in the `identity` crate, which seals the same master a
//! recovered set rebuilds into a security-key keyslot.

mod error;
mod gf;

pub use error::{Error, Result};

use gf::Gf;
use rand::RngCore;

const VERSION: u8 = 1;
const TAG_LEN: usize = 16;
const TAG_CONTEXT: &str = "horizon reconstitution tag v1";

// One recovery share: the split it belongs to (id), the threshold needed to
// recover (k), this share's evaluation point (x), the integrity tag shared by
// the whole set, and the per-byte y values.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Share {
    id: [u8; 4],
    k: u8,
    x: u8,
    tag: [u8; TAG_LEN],
    y: Vec<u8>,
}

impl Share {
    pub fn index(&self) -> u8 {
        self.x
    }

    pub fn threshold(&self) -> u8 {
        self.k
    }

    pub fn set_id(&self) -> [u8; 4] {
        self.id
    }

    // Portable byte form: version, id, k, x, tag, length-prefixed y.
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(8 + TAG_LEN + self.y.len());
        o.push(VERSION);
        o.extend_from_slice(&self.id);
        o.push(self.k);
        o.push(self.x);
        o.extend_from_slice(&self.tag);
        o.push(self.y.len() as u8);
        o.extend_from_slice(&self.y);
        o
    }

    pub fn decode(buf: &[u8]) -> Result<Share> {
        let head = 1 + 4 + 1 + 1 + TAG_LEN + 1;
        if buf.len() < head {
            return Err(Error::Malformed("too short".into()));
        }
        if buf[0] != VERSION {
            return Err(Error::Malformed(format!("unknown version {}", buf[0])));
        }
        let mut id = [0u8; 4];
        id.copy_from_slice(&buf[1..5]);
        let k = buf[5];
        let x = buf[6];
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&buf[7..7 + TAG_LEN]);
        let ylen = buf[7 + TAG_LEN] as usize;
        let y = &buf[head..];
        if y.len() != ylen {
            return Err(Error::Malformed("length does not match body".into()));
        }
        if k == 0 {
            return Err(Error::Malformed("threshold is zero".into()));
        }
        if x == 0 {
            return Err(Error::Malformed("index is zero".into()));
        }
        Ok(Share {
            id,
            k,
            x,
            tag,
            y: y.to_vec(),
        })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.encode())
    }

    pub fn from_hex(s: &str) -> Result<Share> {
        let bytes = hex::decode(s.trim()).map_err(|_| Error::Malformed("not hex".into()))?;
        Share::decode(&bytes)
    }
}

// Split a secret into n shares, any k of which recover it. Requires
// 1 <= k <= n <= 255 and a non-empty secret. k = 1 makes every share a copy of
// the secret (redundancy, no secrecy); use k >= 2 for real protection.
pub fn split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Share>> {
    if secret.is_empty() {
        return Err(Error::Params("secret is empty".into()));
    }
    if k == 0 || n == 0 {
        return Err(Error::Params("k and n must be at least 1".into()));
    }
    if k > n {
        return Err(Error::Params(format!("k ({k}) exceeds n ({n})")));
    }

    let gf = Gf::new();
    let mut rng = rand::rngs::OsRng;
    let mut id = [0u8; 4];
    rng.fill_bytes(&mut id);
    let tag = tag_of(secret);

    // One random polynomial per secret byte: coeffs[byte] = [secret_byte, r1..].
    let mut coeffs = Vec::with_capacity(secret.len());
    for &b in secret {
        let mut c = vec![0u8; k as usize];
        c[0] = b;
        if k > 1 {
            rng.fill_bytes(&mut c[1..]);
        }
        coeffs.push(c);
    }

    let mut shares = Vec::with_capacity(n as usize);
    for x in 1..=n {
        let y = coeffs.iter().map(|c| gf.eval(c, x)).collect();
        shares.push(Share { id, k, x, tag, y });
    }
    Ok(shares)
}

// Recover the secret from a set of shares. They must come from one split, carry
// distinct indices, and number at least the threshold. The rebuilt secret is
// checked against the shares' tag, so a corrupted or wrong-set share is caught
// rather than silently returning garbage.
pub fn combine(shares: &[Share]) -> Result<Vec<u8>> {
    let first = shares
        .first()
        .ok_or_else(|| Error::Params("no shares given".into()))?;
    let k = first.k;
    let ylen = first.y.len();

    let mut seen = std::collections::HashSet::new();
    for s in shares {
        if s.id != first.id || s.k != k || s.tag != first.tag || s.y.len() != ylen {
            return Err(Error::MixedSet);
        }
        if s.x == 0 {
            return Err(Error::Malformed("index is zero".into()));
        }
        if !seen.insert(s.x) {
            return Err(Error::Duplicate(s.x));
        }
    }
    if shares.len() < k as usize {
        return Err(Error::Insufficient {
            have: shares.len(),
            need: k,
        });
    }

    // Interpolate each byte at x = 0 from any k of the shares.
    let gf = Gf::new();
    let pts = &shares[..k as usize];
    let xs: Vec<u8> = pts.iter().map(|s| s.x).collect();
    let mut secret = vec![0u8; ylen];
    for (byte, out) in secret.iter_mut().enumerate() {
        let mut acc = 0u8;
        for i in 0..pts.len() {
            // Lagrange basis at 0: prod_{j!=i} x_j / (x_i - x_j), and in this
            // field subtraction is xor.
            let mut num = 1u8;
            let mut den = 1u8;
            for j in 0..pts.len() {
                if i != j {
                    num = gf.mul(num, xs[j]);
                    den = gf.mul(den, xs[i] ^ xs[j]);
                }
            }
            acc ^= gf.mul(pts[i].y[byte], gf.div(num, den));
        }
        *out = acc;
    }

    if tag_of(&secret) != first.tag {
        return Err(Error::Integrity);
    }
    Ok(secret)
}

// A commitment to the secret, carried on every share so recovery can verify it
// rebuilt the right thing. Domain-separated so it cannot be confused with any
// other use of the secret as key material.
fn tag_of(secret: &[u8]) -> [u8; TAG_LEN] {
    let full = blake3::derive_key(TAG_CONTEXT, secret);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}
