//! The real USB-HID FIDO2 authenticator: a thin [`Authenticator`](crate::Authenticator)
//! over `ctap-hid-fido2`'s CTAP2 hmac-secret. Built only under the `fido2` feature
//! (enabled on Linux), behind the same trait the keyslot core is tested against, so
//! this is device plumbing alone: create a non-resident credential with the
//! hmac-secret extension, and read the per-credential secret back for a salt.
//! Compile-checked in CI and verified on a real key, like the compositor's display
//! backends sit behind its tested compositing core.

use ctap_hid_fido2::fidokey::{AssertionExtension as Gext, CredentialExtension as Mext};
use ctap_hid_fido2::{Cfg, FidoKeyHid, FidoKeyHidFactory};

use crate::{Authenticator, CredentialId, Error, Result};

// A stable relying-party id. The credentials are non-resident and local to this
// device, so any fixed id works as long as enrollment and unlock agree on it.
const RP_ID: &str = "horizon-os";
// The hmac-secret output depends only on the credential and the salt, not the
// challenge, and we never verify the returned assertion, so a constant challenge
// is fine.
const CHALLENGE: &[u8] = b"horizon-identity-fido2";

/// A connected FIDO2 security key. Holds the device handle and, where the key gates
/// hmac-secret on user verification (most do), the PIN to present.
pub struct HardwareKey {
    device: FidoKeyHid,
    pin: Option<String>,
}

impl HardwareKey {
    /// Open the single connected FIDO2 authenticator. Fails if none, or more than
    /// one, is present. `pin` is the device PIN, needed when the key requires user
    /// verification for the hmac-secret extension.
    pub fn open(pin: Option<String>) -> Result<HardwareKey> {
        let device =
            FidoKeyHidFactory::create(&Cfg::init()).map_err(|e| Error::Device(e.to_string()))?;
        Ok(HardwareKey { device, pin })
    }
}

impl Authenticator for HardwareKey {
    fn make_credential(&mut self) -> Result<CredentialId> {
        // A non-resident credential with hmac-secret enabled; its id is carried in
        // the keyslot and handed back at unlock (so it consumes no resident slot).
        let ext = vec![Mext::HmacSecret(Some(true))];
        let attestation = self
            .device
            .make_credential_with_extensions(RP_ID, CHALLENGE, self.pin.as_deref(), Some(&ext))
            .map_err(|e| Error::Device(e.to_string()))?;
        Ok(CredentialId(attestation.credential_descriptor.id))
    }

    fn hmac_secret(&mut self, cred: &CredentialId, salt: &[u8; 32]) -> Result<[u8; 32]> {
        let ext = vec![Gext::HmacSecret(Some(*salt))];
        let assertion = self
            .device
            .get_assertion_with_extensios(
                RP_ID,
                CHALLENGE,
                std::slice::from_ref(&cred.0),
                self.pin.as_deref(),
                Some(&ext),
            )
            .map_err(|e| Error::Device(e.to_string()))?;
        assertion
            .extensions
            .iter()
            .find_map(|e| match e {
                Gext::HmacSecret(Some(secret)) => Some(*secret),
                _ => None,
            })
            .ok_or_else(|| Error::Device("authenticator returned no hmac-secret".into()))
    }
}
