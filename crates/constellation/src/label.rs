//! The non-secret rendezvous label for an identity.
//!
//! Both ways of finding a peer use the same label: mDNS on the LAN
//! ([`crate::discovery`]) and a rendezvous server beyond it
//! ([`crate::net::rendezvous`]). It is a short fingerprint derived one-way from
//! the identity master under its own domain separator, so it reveals neither the
//! master nor any other key derived from it (the Lifestream keys, the Noise PSK).
//! The fingerprint only says "a device of identity X is here"; it grants
//! nothing. Authentication is always the Noise NNpsk0 handshake at connect time,
//! so broadcasting or registering the fingerprint never widens what an attacker
//! can do: a peer that reads it still cannot complete the handshake or open an
//! object without the master.

// A short, non-secret label for an identity, derived one-way from the master
// under its own domain so it reveals neither the master nor any other derived
// key. Stable across a device's restarts and identical on every device of the
// same identity, which is exactly what lets them recognise each other, whether
// over LAN multicast or through a rendezvous server.
pub fn fingerprint(master: &[u8; 32]) -> String {
    let tag = blake3::derive_key("horizon constellation discovery fingerprint v1", master);
    hex::encode(&tag[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_identity_specific() {
        let a = [7u8; 32];
        let b = [8u8; 32];
        assert_eq!(fingerprint(&a), fingerprint(&a));
        assert_ne!(fingerprint(&a), fingerprint(&b));
        // 8 bytes, hex encoded.
        assert_eq!(fingerprint(&a).len(), 16);
        assert!(fingerprint(&a).bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_is_not_the_auth_key() {
        // The label that gets broadcast must be a different derivation from the
        // Noise PSK, which is what actually authenticates a peer. Same master,
        // different domain separator, so the values must not coincide.
        let m = [42u8; 32];
        let psk = blake3::derive_key("horizon constellation noise psk v1", &m);
        assert_ne!(fingerprint(&m), hex::encode(&psk[..8]));
    }
}
