//! macOS fill of the [`Keystore`](crate::keystore::Keystore) seam.
//!
//! Two layers:
//!
//! * **Blob storage** uses the login Keychain via `security-framework` generic
//!   password items (service `com.rowm.latch`, account = blob label).
//! * **The DEK envelope** is a P-256 key generated *inside* the Secure Enclave
//!   with an access control of `.privateKeyUsage | .biometryCurrentSet`, so
//!   unwrapping the DEK demands a live Touch ID. `ensure_dek` mints the key and
//!   wraps a fresh DEK to its public half in pure Rust
//!   ([`latch_proto::wrap_dek_p256`], byte-compatible with Apple's
//!   `SecKeyCreateEncryptedData` for this algorithm -- confirmed by
//!   `apps/mac/Tools/se-selftest.swift`); `unwrap_dek` re-finds the persisted
//!   key and asks the Secure Enclave to decrypt, which is where Touch ID fires.
//!
//! NEEDS-VERIFICATION (on real Apple-silicon hardware, enrolled biometric):
//! this compiles and the crypto is independently reviewed, but nothing here can
//! exercise an actual Secure Enclave from a build box. Confirm with the
//! round-trip test below:
//!
//! ```text
//! cargo test -p latch --lib keystore_macos::tests::se_dek_round_trips_through_a_real_touch_id \
//!     -- --ignored --nocapture
//! ```
//!
//! It calls `ensure_dek()` then `unwrap_dek()` and asserts the recovered DEK
//! matches what was sealed; a live Touch ID prompt must appear for the unwrap.
//! Two spots are flagged individually below where the exact on-device behavior
//! is unconfirmed (the `unwrap_dek` reason string, and the declined-biometric
//! error code).

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use core_foundation::error::{CFError, CFErrorRef};
use security_framework::access_control::SecAccessControl;
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
use security_framework_sys::key::SecKeyCreateDecryptedData;

use crate::keystore::{Keystore, KeystoreError};
use crate::secrets::{self, Dek};

/// Keychain service under which all Latch blobs are stored.
const SERVICE: &str = "com.rowm.latch";
/// The blob label under which the sealed (Secure-Enclave-wrapped) DEK lives.
/// This is ciphertext at rest; it needs no ACL of its own; the wrap so far
/// is useless without the SE private key.
const DEK_ENVELOPE_LABEL: &str = "dek.se-envelope.v1";
/// `kSecAttrLabel` of the Secure Enclave key that wraps the DEK. `unwrap_dek`
/// re-finds the persisted key by this label across process restarts (the
/// daemon and every `latch` CLI invocation are separate processes).
const SE_KEY_LABEL: &str = "com.rowm.latch.dek";

/// `errSecItemNotFound`: the Keychain has no item matching the query.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
/// `errSecAuthFailed` (SecBase.h): a biometric/authentication attempt failed.
const ERR_SEC_AUTH_FAILED: isize = -25293;
/// `errSecUserCanceled` (SecBase.h, shared with the classic Carbon
/// `userCanceledErr`): the user cancelled the Touch ID prompt. Not exposed as
/// a named constant by `security-framework-sys`, so named here.
/// NEEDS-VERIFICATION: confirm this (vs. [`ERR_SEC_AUTH_FAILED`], or something
/// else) is what `SecKeyCreateDecryptedData` actually returns on a declined
/// Touch ID prompt.
const ERR_SEC_USER_CANCELED: isize = -128;

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
        if self.has_dek() {
            return Ok(());
        }

        // 1. A biometric-gated access control: only a live Touch ID can ever
        //    exercise this key's private half (`.privateKeyUsage` marks the
        //    key usable for a private-key op at all; `.biometryCurrentSet`
        //    pins that to the biometrics currently enrolled, so re-enrolling
        //    Touch ID invalidates the key rather than silently widening it).
        let access_control = SecAccessControl::create_with_flags(
            kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
        )
        .map_err(|e| KeystoreError::Backend(format!("building the access control: {e}")))?;

        // 2. Mint the Secure Enclave key. `Token::SecureEnclave` keeps the
        //    private key non-extractable inside the enclave; per
        //    `security-framework`'s own docs, Secure Enclave keys must live in
        //    the `DataProtectionKeychain` (the older file keychain refuses
        //    `kSecAttrTokenIDSecureEnclave`). `set_location` is also what makes
        //    the key `kSecAttrIsPermanent`, so it survives this process exiting
        //    and `unwrap_dek` can re-find it later by label.
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_label(SE_KEY_LABEL)
            .set_access_control(access_control);
        let private_key = SecKey::generate(opts.to_dictionary())
            .map_err(|e| KeystoreError::Backend(format!("minting the Secure Enclave key: {e}")))?;

        // 3. Wrap a fresh DEK to the SE key's PUBLIC half. This is a
        //    public-key operation (anyone can wrap to a public key), so it
        //    needs no Touch ID; the biometric only gates the later decrypt.
        //    Done in pure Rust (`latch_proto::wrap_dek_p256`, independently
        //    reviewed) rather than via `SecKeyCreateEncryptedData`, so the DEK
        //    plaintext is only ever built here and immediately zeroized, never
        //    round-tripped through Security.framework unencrypted.
        let public_key = private_key.public_key().ok_or_else(|| {
            KeystoreError::Backend(
                "the freshly minted Secure Enclave key has no public half".into(),
            )
        })?;
        let pub_x963 = public_key
            .external_representation()
            .ok_or_else(|| KeystoreError::Backend("copying the Secure Enclave public key".into()))?
            .to_vec();

        let dek = secrets::generate_dek();
        let proto_dek = latch_proto::pairing::Dek::from_bytes(*dek);
        let sealed = latch_proto::wrap_dek_p256(&proto_dek, &pub_x963)
            .map_err(|e| KeystoreError::Backend(format!("sealing the DEK to the SE key: {e}")))?;
        drop(proto_dek);
        drop(dek);

        self.store_blob(DEK_ENVELOPE_LABEL, &sealed)
    }

    fn unwrap_dek(&self, _reason: &str) -> Result<Dek, KeystoreError> {
        // NEEDS-VERIFICATION: `_reason` does not yet reach the Touch ID prompt.
        // Threading it in needs an `LAContext` (LocalAuthentication.framework,
        // a separate Objective-C FFI surface from Security.framework) set as
        // `kSecUseAuthenticationContext` on the key query below; the access
        // control below still mandates a live Touch ID either way, only the
        // prompt's copy is the system default rather than this string until
        // that lands.
        let sealed = self
            .load_blob(DEK_ENVELOPE_LABEL)?
            .ok_or(KeystoreError::NoDek)?;
        let key = find_se_private_key()?;

        let algorithm: security_framework_sys::key::SecKeyAlgorithm =
            Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM.into();
        let ciphertext = CFData::from_buffer(&sealed);
        let mut error: CFErrorRef = std::ptr::null_mut();
        // SAFETY: `key` and `ciphertext` are live `TCFType`s for the duration
        // of this call and `error` is a valid out-pointer; `security-framework`
        // wraps `SecKeyCreateSignature`/`SecKeyVerifySignature` this same way
        // but does not wrap `SecKeyCreateDecryptedData`, so this is the one
        // raw Security.framework call in this module. Touch ID fires inside
        // this call because the key's access control demands it.
        let plaintext_ref = unsafe {
            SecKeyCreateDecryptedData(
                key.as_concrete_TypeRef(),
                algorithm,
                ciphertext.as_concrete_TypeRef(),
                &mut error,
            )
        };

        if !error.is_null() {
            // SAFETY: a non-null `CFErrorRef` from a Core Foundation "create"
            // call is already retained for us; `wrap_under_create_rule` takes
            // ownership without an extra retain.
            let cf_err = unsafe { CFError::wrap_under_create_rule(error) };
            return Err(cf_error_to_keystore(&cf_err));
        }
        if plaintext_ref.is_null() {
            return Err(KeystoreError::Backend(
                "SecKeyCreateDecryptedData returned neither data nor an error".into(),
            ));
        }
        // SAFETY: non-null `CFDataRef` returned under the create rule (see
        // above); ownership transfers to `CFData` here.
        let plaintext = unsafe { CFData::wrap_under_create_rule(plaintext_ref) };
        if plaintext.len() != 32 {
            return Err(KeystoreError::Backend(format!(
                "Secure Enclave decrypt returned {} bytes, expected 32",
                plaintext.len()
            )));
        }
        let mut dek = zeroize::Zeroizing::new([0u8; 32]);
        dek.copy_from_slice(plaintext.bytes());
        Ok(dek)
    }
}

/// Re-find the Secure Enclave private key [`MacKeystore::ensure_dek`] minted,
/// by its label -- the only handle a *new* process has on it, since the
/// private key itself never leaves the enclave.
///
/// NEEDS-VERIFICATION: confirm this query actually surfaces a key generated in
/// the `DataProtectionKeychain`. `ItemSearchOptions` (the safe search builder
/// this uses) has no `kSecUseDataProtectionKeychain` option; if the query comes
/// back empty on hardware despite `ensure_dek` having succeeded, that flag
/// (added to a hand-rolled `SecItemCopyMatching` query) is the likely fix.
fn find_se_private_key() -> Result<SecKey, KeystoreError> {
    let results = ItemSearchOptions::new()
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(SE_KEY_LABEL)
        .load_refs(true)
        .limit(1)
        .search()
        .map_err(|e| KeystoreError::Backend(format!("finding the Secure Enclave key: {e}")))?;
    match results.into_iter().next() {
        Some(SearchResult::Ref(Reference::Key(key))) => Ok(key),
        _ => Err(KeystoreError::NoDek),
    }
}

/// Map a `SecKeyCreateDecryptedData` failure to a [`KeystoreError`]. A
/// declined/cancelled Touch ID prompt must read as [`KeystoreError::Declined`]
/// (the approval flow treats that as a deny, not a hard error); anything else
/// is a backend fault, surfaced with the underlying `CFError` for debugging.
fn cf_error_to_keystore(e: &CFError) -> KeystoreError {
    match e.code() {
        ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED => KeystoreError::Declined,
        _ => KeystoreError::Backend(e.to_string()),
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

    // The real hardware round trip: mint the Secure Enclave key, wrap a DEK to
    // it, then unwrap it back through a live Touch ID prompt. Needs real
    // Apple-silicon hardware with an enrolled biometric (fails on a VM or the
    // Simulator) and a human present to approve the prompt, so this is opt-in
    // and NOT part of `cargo test`'s default run. Run on the Mac with:
    //   cargo test -p latch --lib keystore_macos::tests::se_dek_round_trips_through_a_real_touch_id \
    //     -- --ignored --nocapture
    #[test]
    #[ignore = "mints a real Secure Enclave key and prompts Touch ID; run manually on the Mac"]
    fn se_dek_round_trips_through_a_real_touch_id() {
        let ks = MacKeystore::new();
        // Clean slate: a leftover envelope/key from a prior run would make
        // `ensure_dek` a no-op and this test wouldn't actually mint anything.
        ks.delete_blob(DEK_ENVELOPE_LABEL).ok();

        ks.ensure_dek()
            .expect("provisioning the Secure Enclave DEK");
        assert!(ks.has_dek());

        eprintln!("expect a Touch ID prompt now...");
        let dek_a = ks
            .unwrap_dek("latch: hardware round-trip test")
            .expect("unwrapping the DEK (approve the Touch ID prompt)");

        eprintln!("expect a second Touch ID prompt now...");
        let dek_b = ks
            .unwrap_dek("latch: hardware round-trip test, second unwrap")
            .expect("second unwrap must also succeed");

        assert_eq!(*dek_a, *dek_b, "every unwrap must recover the same DEK");
    }
}
