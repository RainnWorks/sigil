//! macOS fill of the [`Keystore`](crate::keystore::Keystore) seam.
//!
//! Two layers:
//!
//! * **Blob storage** uses the login Keychain via `security-framework` generic
//!   password items (service `works.rainn.sigil`, account = blob label). This
//!   backs the daemon identity keys and the Mac threshold share `m`. Generic
//!   passwords need no entitlement, so this works from the unsigned daemon.
//! * **The presence gate** ([`verify_presence`]) uses
//!   `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` via a
//!   tiny ObjC shim (`src/presence.m`, compiled by `build.rs`). It forces a live
//!   Touch ID prompt but needs NO keychain item, NO Secure Enclave key, and NO
//!   entitlement, so it too works from the unsigned, portable daemon. (An earlier
//!   design minted a persistent Secure Enclave keychain key here; that cannot be
//!   created by an unsigned binary -- errSecMissingEntitlement / amfid SIGKILL --
//!   so it broke pairing on the shipping posture.) The gate is independent of any
//!   at-rest secret: there is no DEK; everything Sigil stores is threshold-sealed
//!   and opened per-approval with the phone's partial.
//!
//! [`verify_presence`]: MacKeystore::verify_presence

use std::os::raw::{c_char, c_int};

use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

use crate::keystore::{Keystore, KeystoreError};

// The LocalAuthentication presence shim (src/presence.m). Returns 1 = present,
// 0 = declined/failed/cancelled, -1 = biometrics unavailable/unenrolled.
extern "C" {
    fn sigil_la_verify_presence(reason_utf8: *const c_char) -> c_int;
}

/// Keychain service under which all Sigil blobs are stored.
const SERVICE: &str = "works.rainn.sigil";

/// `errSecItemNotFound`: the Keychain has no item matching the query.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

/// macOS Keychain keystore: login-Keychain blob storage plus a LocalAuthentication
/// presence gate. Both work from the unsigned binary (no entitlement needed).
pub struct MacKeystore {
    service: String,
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
        }
    }
}

impl Keystore for MacKeystore {
    fn backend(&self) -> &'static str {
        "keychain"
    }

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
        // verify_presence forces a live biometric via LAContext.
        true
    }

    fn verify_presence(&self, reason: &str) -> Result<(), KeystoreError> {
        // LAContext.evaluatePolicy (src/presence.m): a live biometric with no
        // keychain/SE/entitlement, so it works from the unsigned daemon. The
        // `reason` reaches the prompt.
        let c_reason = std::ffi::CString::new(reason).unwrap_or_default();
        // SAFETY: the shim reads the NUL-terminated string, blocks on the system
        // biometric prompt, and returns a small int. No Rust state is shared.
        match unsafe { sigil_la_verify_presence(c_reason.as_ptr()) } {
            1 => Ok(()),
            0 => Err(KeystoreError::Declined),
            // A value below -999 encodes an LAError code from canEvaluatePolicy
            // (rc = -1000 + code): -6 biometryNotAvailable, -7 notEnrolled, etc.
            rc if rc <= -1000 => Err(KeystoreError::Backend(format!(
                "biometrics unavailable (LAError {})",
                rc + 1000
            ))),
            rc => Err(KeystoreError::Backend(format!(
                "presence check failed (code {rc})"
            ))),
        }
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

    // The real hardware round trip: prove presence through a live Touch ID prompt
    // via LAContext. Needs real hardware with an enrolled biometric and a human
    // present, so it is opt-in. Mints nothing (no key to clean up).
    #[test]
    #[ignore = "prompts a real Touch ID via LAContext; run manually on the Mac"]
    fn presence_check_prompts_a_real_touch_id() {
        let ks = MacKeystore::new();
        eprintln!("expect a Touch ID prompt now...");
        ks.verify_presence("sigil: hardware presence test")
            .expect("presence check (approve the Touch ID prompt)");
    }
}
