//! macOS fill of the [`Keystore`](crate::keystore::Keystore) seam.
//!
//! Two layers:
//!
//! * **Blob storage** uses the login Keychain via `security-framework` generic
//!   password items (service `works.rainn.sigil`, account = blob label). This
//!   backs the daemon identity keys and the Mac threshold share `m`.
//! * **The presence gate** is a P-256 key generated *inside* the Secure Enclave
//!   with an access control of `.privateKeyUsage | .biometryCurrentSet`, so any
//!   private-key op on it demands a live Touch ID. [`verify_presence`] finds (or
//!   mints) that key and signs a throwaway nonce with it, purely to force the
//!   biometric prompt; the signature is discarded. Nothing is unwrapped or
//!   delivered, so the gate is independent of any at-rest secret (there is no
//!   DEK anymore: everything Sigil stores is threshold-sealed and opened
//!   per-approval with the phone's partial).
//!
//! NEEDS-VERIFICATION (on real Apple-silicon hardware, enrolled biometric):
//! this compiles but nothing here can exercise an actual Secure Enclave from a
//! build box. Confirm the presence prompt fires with the ignored round-trip test
//! at the bottom of this file.
//!
//! [`verify_presence`]: MacKeystore::verify_presence

use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
};

use crate::keystore::{Keystore, KeystoreError};

/// Keychain service under which all Sigil blobs are stored.
const SERVICE: &str = "works.rainn.sigil";
/// `kSecAttrLabel` of the Secure Enclave key used purely as a biometric presence
/// gate for authorizing a pairing. It seals nothing; a private-key op on it only
/// proves a live Touch ID. `verify_presence` re-finds it by this label across
/// process restarts (the daemon and every `sigil` CLI invocation are separate
/// processes).
const PRESENCE_KEY_LABEL: &str = "works.rainn.sigil.presence";

/// `errSecItemNotFound`: the Keychain has no item matching the query.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
/// `errSecAuthFailed` (SecBase.h): a biometric/authentication attempt failed.
const ERR_SEC_AUTH_FAILED: isize = -25293;
/// `errSecUserCanceled` (SecBase.h): the user cancelled the Touch ID prompt.
const ERR_SEC_USER_CANCELED: isize = -128;

/// macOS Keychain + Secure Enclave keystore. The presence-key label is
/// per-instance (not a bare constant) so tests can point a `MacKeystore` at a
/// throwaway label instead of the real one production uses -- see
/// [`MacKeystore::for_test`]. `new()` (the only public constructor) always uses
/// the real, production label.
pub struct MacKeystore {
    service: String,
    presence_key_label: String,
}

impl Default for MacKeystore {
    fn default() -> Self {
        Self::new()
    }
}

impl MacKeystore {
    pub fn new() -> Self {
        Self {
            service: SERVICE.to_string(),
            presence_key_label: PRESENCE_KEY_LABEL.to_string(),
        }
    }

    /// A `MacKeystore` scoped to a test-only presence-key label, so exercising the
    /// real `verify_presence` implementation can never mint or touch the
    /// production presence key. Test-only: production always goes through `new()`.
    #[cfg(test)]
    fn for_test(presence_key_label: &str) -> Self {
        Self {
            service: SERVICE.to_string(),
            presence_key_label: presence_key_label.to_string(),
        }
    }

    /// Find, or mint on first use, the biometric-gated Secure Enclave presence
    /// key. Minting is a public operation (no Touch ID); only the later signature
    /// in [`verify_presence`](Self::verify_presence) prompts.
    fn ensure_presence_key(&self) -> Result<SecKey, KeystoreError> {
        if let Ok(key) = find_se_private_key(&self.presence_key_label) {
            return Ok(key);
        }
        // A biometric-gated access control: only a live Touch ID can ever exercise
        // this key's private half (`.privateKeyUsage` marks it usable for a
        // private-key op at all; `.biometryCurrentSet` pins that to the currently
        // enrolled biometrics, so re-enrolling Touch ID invalidates the key).
        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
        )
        .map_err(|e| KeystoreError::Backend(format!("building the access control: {e}")))?;

        // Secure Enclave keys must live in the `DataProtectionKeychain`; setting a
        // location is also what makes the key permanent so it survives this
        // process and `verify_presence` can re-find it later by label.
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_label(&self.presence_key_label)
            .set_access_control(access_control);
        SecKey::generate(opts.to_dictionary())
            .map_err(|e| KeystoreError::Backend(format!("minting the presence key: {e}")))
    }

    /// Delete the presence Secure Enclave key this instance points at, if one
    /// exists. Test-only cleanup so a round-trip test never leaves a minted key
    /// behind.
    #[cfg(test)]
    fn delete_presence_key(&self) -> Result<(), KeystoreError> {
        match find_se_private_key(&self.presence_key_label) {
            Ok(key) => key
                .delete()
                .map_err(|e| KeystoreError::Backend(format!("deleting the presence key: {e}"))),
            Err(KeystoreError::NeedsVerification(_)) | Err(KeystoreError::Backend(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl Keystore for MacKeystore {
    fn store_blob(&self, label: &str, data: &[u8]) -> Result<(), KeystoreError> {
        set_generic_password(&self.service, label, data)
            .map_err(|e| KeystoreError::Backend(e.to_string()))
    }

    fn load_blob(&self, label: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        match get_generic_password(&self.service, label) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(KeystoreError::Backend(e.to_string())),
        }
    }

    fn delete_blob(&self, label: &str) -> Result<(), KeystoreError> {
        match delete_generic_password(&self.service, label) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(e) => Err(KeystoreError::Backend(e.to_string())),
        }
    }

    fn is_biometric(&self) -> bool {
        // The presence key is sealed to a Secure Enclave key with
        // `.biometryCurrentSet`, so a private-key op on it demands a live Touch ID.
        true
    }

    fn verify_presence(&self, _reason: &str) -> Result<(), KeystoreError> {
        // NEEDS-VERIFICATION: `_reason` does not yet reach the Touch ID prompt.
        // Threading it in needs an `LAContext` (LocalAuthentication.framework) set
        // as `kSecUseAuthenticationContext`; the access control below still
        // mandates a live Touch ID either way, only the prompt's copy is the
        // system default until that lands.
        let key = self.ensure_presence_key()?;
        // A private-key op on a `.biometryCurrentSet` key forces the Touch ID
        // prompt. We sign a fixed throwaway nonce and discard the result: nothing
        // is unwrapped or delivered, we only require the human to be present.
        match key.create_signature(
            Algorithm::ECDSASignatureMessageX962SHA256,
            b"sigil-presence",
        ) {
            Ok(_sig) => Ok(()),
            Err(e) => Err(cf_error_code_to_keystore(e.code())),
        }
    }
}

/// Re-find the Secure Enclave private key minted under `label` -- the only handle
/// a *new* process has on it, since the private key itself never leaves the
/// enclave.
///
/// NEEDS-VERIFICATION: confirm this query actually surfaces a key generated in
/// the `DataProtectionKeychain`.
fn find_se_private_key(label: &str) -> Result<SecKey, KeystoreError> {
    let results = ItemSearchOptions::new()
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true)
        .limit(1)
        .search()
        .map_err(|e| KeystoreError::Backend(format!("finding the presence key: {e}")))?;
    match results.into_iter().next() {
        Some(SearchResult::Ref(Reference::Key(key))) => Ok(key),
        _ => Err(KeystoreError::Backend("presence key not found".into())),
    }
}

/// Map a signature failure code to a [`KeystoreError`]. A declined/cancelled Touch
/// ID prompt must read as [`KeystoreError::Declined`] (the pairing gate treats
/// that as a refusal); anything else is a backend fault.
fn cf_error_code_to_keystore(code: isize) -> KeystoreError {
    match code {
        ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED => KeystoreError::Declined,
        other => KeystoreError::Backend(format!("secure enclave op failed (code {other})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keychain writes touch the real login Keychain and may raise an ACL
    // prompt, so this is opt-in.
    #[test]
    #[ignore = "writes to the real login Keychain; run manually on the Mac"]
    fn keychain_blob_roundtrip() {
        let ks = MacKeystore::new();
        let label = "test.blob.sigil";
        ks.delete_blob(label).unwrap();
        assert!(ks.load_blob(label).unwrap().is_none());
        ks.store_blob(label, b"enclave-envelope-bytes").unwrap();
        assert_eq!(
            ks.load_blob(label).unwrap().unwrap(),
            b"enclave-envelope-bytes"
        );
        ks.delete_blob(label).unwrap();
        assert!(ks.load_blob(label).unwrap().is_none());
    }

    // The real hardware round trip: mint the presence Secure Enclave key, then
    // prove presence through a live Touch ID prompt. Needs real Apple-silicon
    // hardware with an enrolled biometric and a human present, so it is opt-in.
    // Uses a `.selftest` label via `MacKeystore::for_test`, never the production
    // one, and deletes the key at the end.
    #[test]
    #[ignore = "mints a real Secure Enclave key and prompts Touch ID; run manually on the Mac"]
    fn presence_check_prompts_a_real_touch_id() {
        const TEST_PRESENCE_KEY_LABEL: &str = "works.rainn.sigil.presence.selftest";

        let ks = MacKeystore::for_test(TEST_PRESENCE_KEY_LABEL);
        ks.delete_presence_key().ok();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            eprintln!("expect a Touch ID prompt now...");
            ks.verify_presence("sigil: hardware presence test")
                .expect("presence check (approve the Touch ID prompt)");
        }));

        ks.delete_presence_key().ok();

        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }
}
