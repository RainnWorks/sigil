//! macOS fill of the [`Keystore`](crate::keystore::Keystore) seam.
//!
//! Two layers, deliberately split by what can be verified without Tom at the
//! Mac:
//!
//! * **Blob storage** uses the login Keychain via `security-framework` generic
//!   password items (service `com.rowm.latch`, account = blob label). This
//!   compiles and runs headlessly; the one caveat is the runtime Keychain ACL
//!   prompt, noted below.
//! * **The DEK envelope** is meant to be a P-256 key generated *inside* the
//!   Secure Enclave with an access control of `.privateKeyUsage |
//!   .biometryCurrentSet`, so unwrapping the DEK requires a live Touch ID via
//!   `LAContext`. That path cannot be exercised while Tom is away from the Mac,
//!   so it is isolated here and returns [`KeystoreError::NeedsVerification`]
//!   rather than shipping unverified enclave FFI that merely compiles. The
//!   exact `Security.framework` calls and the command to confirm each are in
//!   the NEEDS-VERIFICATION block on [`MacKeystore::ensure_dek`].

use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

use crate::keystore::{Keystore, KeystoreError};
use crate::secrets::Dek;

/// Keychain service under which all Latch blobs are stored.
const SERVICE: &str = "com.rowm.latch";
/// The blob label under which the Secure Enclave DEK envelope lives.
const DEK_ENVELOPE_LABEL: &str = "dek.se-envelope.v1";

/// `errSecItemNotFound`: the Keychain has no item matching the query.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

/// macOS Keychain + Secure Enclave keystore.
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
        // The DEK envelope is sealed to a Secure Enclave key with
        // `.biometryCurrentSet`, so unwrapping it demands a live Touch ID.
        true
    }

    fn has_dek(&self) -> bool {
        matches!(self.load_blob(DEK_ENVELOPE_LABEL), Ok(Some(_)))
    }

    fn ensure_dek(&self) -> Result<(), KeystoreError> {
        // NEEDS-VERIFICATION (Secure Enclave key creation on hardware).
        //
        // Intended implementation, none of which can run away from the Mac:
        //   1. SecAccessControlCreateWithFlags(kCFAllocatorDefault,
        //        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        //        kSecAccessControlPrivateKeyUsage
        //          | kSecAccessControlBiometryCurrentSet, &err)
        //   2. SecKeyCreateRandomKey({
        //        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        //        kSecAttrKeySizeInBits: 256,
        //        kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
        //        kSecPrivateKeyAttrs: { kSecAttrIsPermanent: true,
        //          kSecAttrApplicationTag: b"com.rowm.latch.dek",
        //          kSecAttrAccessControl: <the control above> }})
        //   3. Wrap the DEK to the SE public key with P-256 ECIES and
        //      store_blob(DEK_ENVELOPE_LABEL, sealed). The wrap uses Apple's
        //      kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM
        //      (the VariableIV variant se-selftest.swift verifies), so the
        //      daemon can produce the exact blob in Rust via
        //      latch_proto::wrap_dek_p256(&dek, se_pub_x963) -- byte-compatible
        //      with SecKeyCreateEncryptedData(pubkey, <that algorithm>, dek) --
        //      and never needs the DEK plaintext to touch Security.framework.
        //
        // Confirm on device with the companion mac-app agent, or a scratch
        // binary, then:
        //   cargo test -p latch --features macos-se se_unwrap_roundtrip \
        //     -- --ignored --nocapture     # (feature/test added with the fill)
        Err(KeystoreError::NeedsVerification(
            "SecKeyCreateRandomKey(kSecAttrTokenIDSecureEnclave) DEK provisioning",
        ))
    }

    fn unwrap_dek(&self, _reason: &str) -> Result<Dek, KeystoreError> {
        // NEEDS-VERIFICATION (Touch-ID-gated Secure Enclave decrypt).
        //
        // Intended implementation:
        //   1. Load the sealed envelope: load_blob(DEK_ENVELOPE_LABEL).
        //   2. Build an LAContext, set localizedReason = `reason`, and pass it
        //      as kSecUseAuthenticationContext when resolving the private key so
        //      the biometric prompt carries our reason string.
        //   3. SecItemCopyMatching for the private key by application tag, then
        //      SecKeyCreateDecryptedData(privkey,
        //        kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
        //        sealed) -> 32 raw bytes -> Zeroizing<[u8;32]>. This is the
        //      VariableIV variant matching latch_proto::wrap_dek_p256 and
        //      se-selftest.swift; the fixed-IV variant will NOT decrypt the blob.
        //   Touch ID fires inside SecKeyCreateDecryptedData because the key's
        //   access control demands `.biometryCurrentSet`; a declined or absent
        //   biometric returns errSecUserCanceled / errSecAuthFailed, which map
        //   to KeystoreError::Declined. Malware as the user cannot fake it.
        //
        // Confirm on device: run `latch daemon`, trigger one `op read`, and
        // watch for the system Touch ID sheet with our reason; a decline must
        // yield a fail-closed (exit 1) shim.
        Err(KeystoreError::NeedsVerification(
            "LAContext + SecKeyCreateDecryptedData Touch-ID DEK unwrap",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keychain writes touch the real login Keychain and may raise an ACL
    // prompt, so this is opt-in. Confirm blob storage on device with:
    //   cargo test -p latch --lib keystore_macos::tests::keychain_blob_roundtrip \
    //     -- --ignored --nocapture
    #[test]
    #[ignore = "writes to the real login Keychain; run manually on the Mac"]
    fn keychain_blob_roundtrip() {
        let ks = MacKeystore::new();
        let label = "test.blob.latch";
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

    #[test]
    fn se_paths_refuse_until_verified() {
        let ks = MacKeystore::new();
        assert!(matches!(
            ks.ensure_dek().unwrap_err(),
            KeystoreError::NeedsVerification(_)
        ));
        assert!(matches!(
            ks.unwrap_dek("open the DEK").unwrap_err(),
            KeystoreError::NeedsVerification(_)
        ));
    }
}
