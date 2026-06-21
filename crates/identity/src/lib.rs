//! Identity: unlock a Horizon master key with a FIDO2 security key.
//!
//! Everything in Horizon turns on one 32-byte master key: the Lifestream derives
//! its addressing and cipher keys from it, the Constellation binds its Noise
//! handshake to it, and Reconstitution splits it into k-of-n recovery shares. The
//! standalone tools derive that master from a passphrase (Argon2id over the
//! store's salt). This crate adds a second way to recover the same master: a FIDO2
//! security key you touch, so a device can boot into its identity with a tap
//! instead of a typed secret, and the recovery shares become the way to enroll a
//! fresh key when the old one is lost.
//!
//! The key idea is a keyslot. A FIDO2 authenticator implements the CTAP2
//! hmac-secret extension: given a credential it holds and a salt, it returns a
//! deterministic 32-byte secret, gated by user presence (a touch) and never
//! leaving the device. A [`Keyslot`] seals the master under a wrap key derived
//! from that secret and stores only what is needed to ask for it again, the
//! credential id and the salt. The sealed master plus the keyslot reveal nothing
//! without the device: the wrap key only exists while the key is touched. A store
//! can hold several keyslots ([`Keyslots`]), one per enrolled device, each
//! independent, so a key can be added or dropped without re-sealing the others.
//!
//! This is additive. The master is still whatever the rest of the system already
//! uses (the Argon2id-derived key, or one rebuilt from recovery shares); a keyslot
//! only wraps it, so enrolling a FIDO2 key changes no existing store, Lifestream,
//! or Constellation state and is fully reversible. Recovery interoperates for
//! free: rebuild the master from shares, then [`enroll`] a new key against it,
//! which is the re-enrollment path for a lost device.
//!
//! On the same headless split the rest of Horizon uses, the security-critical part
//! is a pure core tested without hardware. The keyslot sealing, the file format,
//! and trying enrolled slots all sit behind the [`Authenticator`] trait, so they
//! are exercised against [`SoftwareAuthenticator`] (a deterministic token a holder
//! keeps in a file) with no device present. The real USB-HID FIDO2 authenticator
//! is a thin implementation of the same trait behind the `fido2` feature, Linux
//! only, compile-checked in CI and verified on a real key, exactly as the
//! compositor's display backends sit behind its tested compositing core.

mod error;

pub use error::{Error, Result};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;

#[cfg(feature = "fido2")]
mod hardware;
#[cfg(feature = "fido2")]
pub use hardware::HardwareKey;

const VERSION: u8 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;
// Domain separator so the wrap key derived from a device's hmac-secret cannot be
// confused with any other use of that secret.
const WRAP_CONTEXT: &str = "horizon identity fido2 wrap v1";

/// An opaque FIDO2 credential id, returned when a credential is created and needed
/// to ask the same authenticator for its hmac-secret again. Stored in the keyslot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CredentialId(pub Vec<u8>);

/// A device that produces a deterministic per-credential secret gated by user
/// presence: the CTAP2 hmac-secret extension. A real FIDO2 key is one
/// implementation ([`HardwareKey`], behind the `fido2` feature);
/// [`SoftwareAuthenticator`] is the test and dev one.
pub trait Authenticator {
    /// Create a fresh credential and return its opaque id.
    fn make_credential(&mut self) -> Result<CredentialId>;

    /// The hmac-secret for `(cred, salt)`: a deterministic 32-byte secret, gated by
    /// user presence on hardware. The same `(cred, salt)` always yields the same
    /// secret, which is what lets a keyslot be re-derived later to unlock. An
    /// authenticator that does not hold `cred` must fail rather than invent one.
    fn hmac_secret(&mut self, cred: &CredentialId, salt: &[u8; SALT_LEN]) -> Result<[u8; 32]>;
}

/// One enrolled device's sealing of the master key. Holds the credential id and
/// salt needed to re-derive the wrap key from the authenticator, plus the sealed
/// master. Knowing a keyslot without its authenticator reveals nothing: the wrap
/// key lives only on the device, behind a touch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Keyslot {
    cred: CredentialId,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    // XChaCha20-Poly1305 of the 32-byte master under the wrap key, the credential
    // id bound in as AAD.
    sealed: Vec<u8>,
}

impl Keyslot {
    /// The credential this keyslot is bound to.
    pub fn credential(&self) -> &CredentialId {
        &self.cred
    }

    // Seal the master under a wrap key derived from the device's hmac-secret.
    fn seal(
        cred: CredentialId,
        salt: [u8; SALT_LEN],
        master: &[u8; 32],
        secret: &[u8; 32],
    ) -> Result<Keyslot> {
        let wrap = blake3::derive_key(WRAP_CONTEXT, secret);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&wrap));
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let sealed = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: master,
                    aad: &cred.0,
                },
            )
            .map_err(|_| Error::Crypto)?;
        Ok(Keyslot {
            cred,
            salt,
            nonce,
            sealed,
        })
    }

    /// Unlock the master from this keyslot via the authenticator: re-derive the
    /// hmac-secret for the stored credential and salt, then unwrap. A different
    /// device (or wrong software token) yields a different secret and the unwrap
    /// fails with [`Error::Unlock`].
    pub fn unlock(&self, auth: &mut dyn Authenticator) -> Result<[u8; 32]> {
        let secret = auth.hmac_secret(&self.cred, &self.salt)?;
        let wrap = blake3::derive_key(WRAP_CONTEXT, &secret);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&wrap));
        let pt = cipher
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.sealed,
                    aad: &self.cred.0,
                },
            )
            .map_err(|_| Error::Unlock)?;
        pt.as_slice().try_into().map_err(|_| Error::Unlock)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.cred.0.len() as u8);
        out.extend_from_slice(&self.cred.0);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.push(self.sealed.len() as u8);
        out.extend_from_slice(&self.sealed);
    }

    // Decode one keyslot from the front of `buf`, returning it and how many bytes
    // it consumed, so a list can be parsed in sequence.
    fn decode_from(buf: &[u8]) -> Result<(Keyslot, usize)> {
        fn take<'a>(buf: &'a [u8], p: &mut usize, n: usize, what: &str) -> Result<&'a [u8]> {
            let s = buf
                .get(*p..*p + n)
                .ok_or_else(|| Error::Malformed(format!("truncated {what}")))?;
            *p += n;
            Ok(s)
        }
        let mut p = 0;
        let credlen = *take(buf, &mut p, 1, "credential length")?.first().unwrap() as usize;
        let cred = take(buf, &mut p, credlen, "credential")?.to_vec();
        let salt: [u8; SALT_LEN] = take(buf, &mut p, SALT_LEN, "salt")?.try_into().unwrap();
        let nonce: [u8; NONCE_LEN] = take(buf, &mut p, NONCE_LEN, "nonce")?.try_into().unwrap();
        let sealedlen = *take(buf, &mut p, 1, "sealed length")?.first().unwrap() as usize;
        let sealed = take(buf, &mut p, sealedlen, "sealed")?.to_vec();
        Ok((
            Keyslot {
                cred: CredentialId(cred),
                salt,
                nonce,
                sealed,
            },
            p,
        ))
    }
}

/// All the keyslots enrolled for one store, the on-disk `keyslots` file. Any one of
/// them unlocks the master from its own authenticator, so devices are independent:
/// enroll or drop one without touching the rest.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Keyslots {
    slots: Vec<Keyslot>,
}

impl Keyslots {
    pub fn new() -> Keyslots {
        Keyslots::default()
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn add(&mut self, slot: Keyslot) {
        self.slots.push(slot);
    }

    pub fn slots(&self) -> &[Keyslot] {
        &self.slots
    }

    /// Try the enrolled keyslots against the authenticator and return the first
    /// master one unlocks. A device unlocks its own slot; slots it does not hold
    /// fail and are skipped (a one-key store, the common case, is one attempt).
    pub fn unlock_any(&self, auth: &mut dyn Authenticator) -> Result<[u8; 32]> {
        for slot in &self.slots {
            if let Ok(master) = slot.unlock(auth) {
                return Ok(master);
            }
        }
        Err(Error::NoMatchingKeyslot)
    }

    /// Portable byte form: version, count, then each keyslot.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION, self.slots.len() as u8];
        for slot in &self.slots {
            slot.encode_into(&mut out);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Keyslots> {
        if buf.len() < 2 {
            return Err(Error::Malformed("too short".into()));
        }
        if buf[0] != VERSION {
            return Err(Error::Malformed(format!("unknown version {}", buf[0])));
        }
        let count = buf[1] as usize;
        let mut p = 2;
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            let (slot, used) = Keyslot::decode_from(&buf[p..])?;
            p += used;
            slots.push(slot);
        }
        Ok(Keyslots { slots })
    }
}

/// Enroll the master against an authenticator: create a credential, pick a random
/// salt, get the device's hmac-secret for it, and seal the master under a wrap key
/// derived from that secret. The returned keyslot later unlocks the master from
/// this device. The master is supplied by the caller (the Argon2id-derived key, or
/// one rebuilt from recovery shares), so enrollment never changes the master.
pub fn enroll(auth: &mut dyn Authenticator, master: &[u8; 32]) -> Result<Keyslot> {
    let cred = auth.make_credential()?;
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let secret = auth.hmac_secret(&cred, &salt)?;
    Keyslot::seal(cred, salt, master, &secret)
}

/// A software stand-in for a FIDO2 key, seeded by a 32-byte token the holder keeps
/// (a file: "something you have"). It is the test and dev seam, not hardware: the
/// seed is extractable, so it gives possession, not the tamper resistance of a real
/// key. The same seed reproduces the same hmac-secret, so a slot enrolled with a
/// token unlocks with that token and no other.
pub struct SoftwareAuthenticator {
    seed: [u8; 32],
}

impl SoftwareAuthenticator {
    pub fn new(seed: [u8; 32]) -> SoftwareAuthenticator {
        SoftwareAuthenticator { seed }
    }
}

impl Authenticator for SoftwareAuthenticator {
    fn make_credential(&mut self) -> Result<CredentialId> {
        // A random opaque id, like a real authenticator's credential handle; the
        // secret is the held seed, not the id, so a random id is fine.
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        Ok(CredentialId(id.to_vec()))
    }

    fn hmac_secret(&mut self, cred: &CredentialId, salt: &[u8; SALT_LEN]) -> Result<[u8; 32]> {
        // Deterministic in (seed, credential, salt). A different seed (a different
        // token) yields a different secret, so it cannot open another token's slot.
        let mut h = blake3::Hasher::new_derive_key("horizon identity software hmac v1");
        h.update(&self.seed);
        h.update(&cred.0);
        h.update(salt);
        Ok(*h.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    #[test]
    fn enroll_then_unlock_roundtrips_the_master() {
        let mut auth = SoftwareAuthenticator::new([9u8; 32]);
        let slot = enroll(&mut auth, &MASTER).unwrap();
        assert_eq!(slot.unlock(&mut auth).unwrap(), MASTER);
    }

    #[test]
    fn a_different_token_cannot_unlock() {
        let mut owner = SoftwareAuthenticator::new([1u8; 32]);
        let slot = enroll(&mut owner, &MASTER).unwrap();
        let mut other = SoftwareAuthenticator::new([2u8; 32]);
        assert!(matches!(slot.unlock(&mut other), Err(Error::Unlock)));
    }

    #[test]
    fn unlock_any_picks_the_matching_slot() {
        let mut a = SoftwareAuthenticator::new([10u8; 32]);
        let mut b = SoftwareAuthenticator::new([20u8; 32]);
        let mut slots = Keyslots::new();
        slots.add(enroll(&mut a, &MASTER).unwrap());
        slots.add(enroll(&mut b, &MASTER).unwrap());

        // Either enrolled token unlocks; an un-enrolled one matches nothing.
        assert_eq!(slots.unlock_any(&mut a).unwrap(), MASTER);
        assert_eq!(slots.unlock_any(&mut b).unwrap(), MASTER);
        let mut c = SoftwareAuthenticator::new([30u8; 32]);
        assert!(matches!(
            slots.unlock_any(&mut c),
            Err(Error::NoMatchingKeyslot)
        ));
    }

    #[test]
    fn keyslots_encode_decode_roundtrips_and_still_unlocks() {
        let mut a = SoftwareAuthenticator::new([7u8; 32]);
        let mut b = SoftwareAuthenticator::new([8u8; 32]);
        let mut slots = Keyslots::new();
        slots.add(enroll(&mut a, &MASTER).unwrap());
        slots.add(enroll(&mut b, &MASTER).unwrap());

        let decoded = Keyslots::decode(&slots.encode()).unwrap();
        assert_eq!(decoded, slots);
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.unlock_any(&mut a).unwrap(), MASTER);
    }

    #[test]
    fn a_tampered_keyslot_is_rejected() {
        let mut auth = SoftwareAuthenticator::new([5u8; 32]);
        let mut slot = enroll(&mut auth, &MASTER).unwrap();
        let last = slot.sealed.len() - 1;
        slot.sealed[last] ^= 0xff;
        assert!(matches!(slot.unlock(&mut auth), Err(Error::Unlock)));
    }

    #[test]
    fn decode_rejects_a_wrong_version() {
        let mut buf = Keyslots::new().encode();
        buf[0] = 0xfe;
        assert!(matches!(Keyslots::decode(&buf), Err(Error::Malformed(_))));
    }

    #[test]
    fn decode_rejects_truncated_input() {
        let mut a = SoftwareAuthenticator::new([3u8; 32]);
        let mut slots = Keyslots::new();
        slots.add(enroll(&mut a, &MASTER).unwrap());
        let buf = slots.encode();
        assert!(matches!(
            Keyslots::decode(&buf[..buf.len() - 4]),
            Err(Error::Malformed(_))
        ));
    }
}
