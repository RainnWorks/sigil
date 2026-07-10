//! The keystore seam: secret-at-rest storage and biometric-gated DEK unwrap.
//!
//! This trait is the single platform boundary for everything the daemon keeps
//! at rest: opaque encrypted blobs (the SA-token ciphertext lives in the
//! account store, but the daemon identity keys and the Mac Secure Enclave DEK
//! envelope live here) and the one privileged operation, [`Keystore::unwrap_dek`],
//! which on macOS performs a Touch-ID-gated Secure Enclave decrypt.
//!
//! macOS is the first fill ([`crate::keystore_macos`]); Linux (libsecret / TPM)
//! and Windows (DPAPI / TPM) are later fills of the same trait. Every
//! non-biometric path (blob store/load, DEK generation) is exercised now
//! through [`MemoryKeystore`], which also stands in for the Secure Enclave in
//! headless tests and the dev-approval loop.

use crate::secrets::{self, Dek};

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// No DEK has been provisioned yet; call [`Keystore::ensure_dek`] first.
    #[error("no DEK provisioned in this keystore")]
    NoDek,
    /// The biometric prompt was declined or the enclave refused to decrypt.
    #[error("biometric unwrap declined")]
    Declined,
    /// A backend (Keychain, Secure Enclave, libsecret) call failed.
    #[error("keystore backend: {0}")]
    Backend(String),
    /// The Secure Enclave / Touch-ID path exists but has never been verified on
    /// hardware; it refuses rather than pretending to work. See the module
    /// NEEDS-VERIFICATION notes.
    #[error("secure enclave path not yet verified on hardware: {0}")]
    NeedsVerification(&'static str),
    #[error("secrets: {0}")]
    Secrets(#[from] secrets::SecretsError),
}

/// A short, actionable next step for a [`KeystoreError`] surfaced from
/// provisioning or unwrapping the DEK. The raw `KeystoreError` is a fine log
/// detail but a poor user-facing string on its own (it names no fix, and it
/// pipes verbatim into the Mac app's error panels); callers should lead with
/// this hint and demote the raw error to a trailing detail line, never the
/// headline.
pub fn dek_error_hint(e: &KeystoreError) -> &'static str {
    match e {
        KeystoreError::NeedsVerification(_) => {
            "this Mac's Secure Enclave path has not been confirmed working on this \
             hardware yet. For local development, set SIGIL_DEV_KEYSTORE=file. \
             Otherwise, a threshold account (sigil account add <label> --threshold) \
             does not need the DEK ceremony at all."
        }
        KeystoreError::Declined => "the Touch ID prompt was declined; try again and approve it.",
        KeystoreError::NoDek => {
            "no DEK has been provisioned yet; run: sigil account add <label> --token-stdin"
        }
        KeystoreError::Backend(_) => {
            "the Keychain backend failed; run `sigil doctor` and check Keychain access for Sigil."
        }
        KeystoreError::Secrets(_) => {
            "the stored DEK envelope is malformed; remove and re-provision it."
        }
    }
}

/// Storage of encrypted blobs plus biometric-gated DEK unwrap. Implementations
/// must be safe to share across daemon worker threads.
pub trait Keystore: Send + Sync {
    /// Persist an opaque blob under `label`, replacing any existing value.
    fn store_blob(&self, label: &str, data: &[u8]) -> Result<(), KeystoreError>;

    /// Load the blob stored under `label`, or `None` if absent.
    fn load_blob(&self, label: &str) -> Result<Option<Vec<u8>>, KeystoreError>;

    /// Remove the blob stored under `label`. Absent is not an error.
    fn delete_blob(&self, label: &str) -> Result<(), KeystoreError>;

    /// True if unwrapping the DEK is gated by a real hardware biometric (the
    /// Secure Enclave). The approver treats a successful unwrap as the approving
    /// factor **only** when this is true; a dev/in-memory keystore returns false
    /// so it can never masquerade as Touch ID.
    fn is_biometric(&self) -> bool {
        false
    }

    /// True once a DEK envelope has been provisioned.
    fn has_dek(&self) -> bool;

    /// Provision a fresh DEK envelope if none exists. On macOS this generates a
    /// Secure Enclave key and seals a fresh DEK to it; in the memory fill it
    /// just generates and holds the DEK.
    fn ensure_dek(&self) -> Result<(), KeystoreError>;

    /// Unwrap the DEK for one use. `reason` is shown to the user in the
    /// biometric prompt. The returned key is `Zeroizing`; the caller must drop
    /// it as soon as the token is decrypted.
    fn unwrap_dek(&self, reason: &str) -> Result<Dek, KeystoreError>;

    /// Prove a live hardware user-presence (Touch ID / Secure Enclave), as a gate
    /// **independent of unwrapping the DEK for delivery** (#48). Authorizing a new
    /// pairing calls this so accepting a device is gated on the human's biometric
    /// even on a path that never delivers a DEK, and so the gate does not rely on
    /// the pairing ceremony's incidental DEK unwrap staying in place.
    ///
    /// The default fails **closed**: any keystore that reports
    /// [`is_biometric`](Self::is_biometric) `== true` MUST override this with a
    /// real hardware check, or the pairing gate refuses. Non-biometric dev
    /// keystores keep this default and are simply never asked: the pairing gate
    /// calls this only when `is_biometric()` is true, so `SIGIL_DEV_KEYSTORE`
    /// (which makes `is_biometric()` false, behind its own loud warning) is the
    /// single switch that lets headless dev and tests through without a biometric.
    fn verify_presence(&self, reason: &str) -> Result<(), KeystoreError> {
        let _ = reason;
        Err(KeystoreError::Backend(
            "this keystore has no hardware user-presence check".into(),
        ))
    }
}

/// In-memory keystore. Holds blobs and a DEK in RAM, wiped on drop. It is the
/// unit-test and headless-dev backend, and the stand-in for the Secure Enclave
/// when Touch ID cannot be exercised. It is **not** an at-rest secure store:
/// nothing here survives a restart, which is exactly why it is dev/test-only.
#[derive(Default)]
pub struct MemoryKeystore {
    inner: std::sync::Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    blobs: std::collections::HashMap<String, Vec<u8>>,
    dek: Option<Dek>,
}

impl MemoryKeystore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A keystore with a DEK already provisioned. Convenience for the dev loop
    /// and tests that need a ready-to-unwrap key.
    pub fn with_dek() -> Self {
        let ks = Self::new();
        ks.ensure_dek()
            .expect("memory keystore ensure_dek is infallible");
        ks
    }
}

impl Keystore for MemoryKeystore {
    fn store_blob(&self, label: &str, data: &[u8]) -> Result<(), KeystoreError> {
        self.inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?
            .blobs
            .insert(label.to_string(), data.to_vec());
        Ok(())
    }

    fn load_blob(&self, label: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?
            .blobs
            .get(label)
            .cloned())
    }

    fn delete_blob(&self, label: &str) -> Result<(), KeystoreError> {
        self.inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?
            .blobs
            .remove(label);
        Ok(())
    }

    fn has_dek(&self) -> bool {
        self.inner.lock().map(|i| i.dek.is_some()).unwrap_or(false)
    }

    fn ensure_dek(&self) -> Result<(), KeystoreError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?;
        if inner.dek.is_none() {
            inner.dek = Some(secrets::generate_dek());
        }
        Ok(())
    }

    fn unwrap_dek(&self, _reason: &str) -> Result<Dek, KeystoreError> {
        self.inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?
            .dek
            .clone()
            .ok_or(KeystoreError::NoDek)
    }
}

/// A dev keystore that persists the DEK and blobs to a 0600 JSON file. It is
/// **not secure** (the DEK is on disk in the clear) and exists only to make the
/// full gated loop runnable headlessly, standing in for the Secure Enclave the
/// way the v0 plan calls for ("unwrap key stubbed behind local Touch ID"). It
/// is selected only by `SIGIL_DEV_KEYSTORE=file`, never by default.
pub struct DevFileKeystore {
    path: std::path::PathBuf,
    inner: std::sync::Mutex<()>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct DevFileState {
    /// base64 of the 32-byte DEK.
    dek_b64: Option<String>,
    /// label -> base64 blob.
    blobs: std::collections::HashMap<String, String>,
}

impl DevFileKeystore {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self {
            path,
            inner: std::sync::Mutex::new(()),
        }
    }

    fn read(&self) -> Result<DevFileState, KeystoreError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| KeystoreError::Backend(e.to_string()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DevFileState::default()),
            Err(e) => Err(KeystoreError::Backend(e.to_string())),
        }
    }

    fn write(&self, state: &DevFileState) -> Result<(), KeystoreError> {
        use std::os::unix::fs::PermissionsExt;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| KeystoreError::Backend(e.to_string()))?;
        }
        let json =
            serde_json::to_vec_pretty(state).map_err(|e| KeystoreError::Backend(e.to_string()))?;
        std::fs::write(&self.path, json).map_err(|e| KeystoreError::Backend(e.to_string()))?;
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| KeystoreError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl Keystore for DevFileKeystore {
    fn store_blob(&self, label: &str, data: &[u8]) -> Result<(), KeystoreError> {
        use base64::Engine;
        let _g = self
            .inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?;
        let mut state = self.read()?;
        state.blobs.insert(
            label.to_string(),
            base64::engine::general_purpose::STANDARD.encode(data),
        );
        self.write(&state)
    }

    fn load_blob(&self, label: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        use base64::Engine;
        let _g = self
            .inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?;
        match self.read()?.blobs.get(label) {
            Some(b64) => Ok(Some(
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|e| KeystoreError::Backend(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    fn delete_blob(&self, label: &str) -> Result<(), KeystoreError> {
        let _g = self
            .inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?;
        let mut state = self.read()?;
        state.blobs.remove(label);
        self.write(&state)
    }

    fn has_dek(&self) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|_g| self.read().ok())
            .map(|s| s.dek_b64.is_some())
            .unwrap_or(false)
    }

    fn ensure_dek(&self) -> Result<(), KeystoreError> {
        use base64::Engine;
        let _g = self
            .inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?;
        let mut state = self.read()?;
        if state.dek_b64.is_none() {
            let dek = secrets::generate_dek();
            state.dek_b64 = Some(base64::engine::general_purpose::STANDARD.encode(&dek[..]));
            self.write(&state)?;
        }
        Ok(())
    }

    fn unwrap_dek(&self, _reason: &str) -> Result<Dek, KeystoreError> {
        use base64::Engine;
        let _g = self
            .inner
            .lock()
            .map_err(|_| KeystoreError::Backend("poisoned".into()))?;
        let state = self.read()?;
        let b64 = state.dek_b64.ok_or(KeystoreError::NoDek)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| KeystoreError::Backend(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(KeystoreError::Backend("dek length".into()));
        }
        let mut dek = zeroize::Zeroizing::new([0u8; 32]);
        dek.copy_from_slice(&bytes);
        Ok(dek)
    }
}

/// The loud, multi-line warning that must appear whenever `SIGIL_DEV_KEYSTORE`
/// is honored. Mirrors [`crate::factor::DEV_INSECURE_WARNING`] in shape: it
/// names the concrete risk (DEK, and for `file` the token-decryption key, in
/// plaintext on disk or in RAM with no biometric gate) so a dev config can
/// never be mistaken for a safe one. `mode` is `"file"` or `"memory"`; `path`
/// is the on-disk location for `file`, `None` for `memory`.
fn dev_keystore_warning(mode: &str, path: Option<&std::path::Path>) -> String {
    let where_line = match path {
        Some(p) => format!("!!  DEK on disk in the clear at: {}\n", p.display()),
        None => "!!  DEK held in plaintext RAM for this process only.\n".to_string(),
    };
    format!(
        "\n\
         !! ============================================================ !!\n\
         !!  SIGIL_DEV_KEYSTORE={mode} IS ACTIVE                          !!\n\
         !! ------------------------------------------------------------ !!\n\
         !!  The Secure Enclave / Keychain DEK envelope is bypassed.      !!\n\
         {where_line}\
         !!                                                              !!\n\
         !!  RISK: anyone with access to this machine (or the file,      !!\n\
         !!  for `file`) can read the DEK with no biometric gate, and     !!\n\
         !!  for v1 accounts that DEK decrypts every stored token.        !!\n\
         !!                                                              !!\n\
         !!  Use this ONLY for local development. Unset                  !!\n\
         !!  SIGIL_DEV_KEYSTORE for a real hardware-backed keystore.      !!\n\
         !! ============================================================ !!\n"
    )
}

/// Select the keystore for the daemon and CLI. Both must agree so a token
/// sealed by `sigil account add` unwraps in the daemon.
///
/// * `SIGIL_DEV_KEYSTORE=file` -> [`DevFileKeystore`] at `~/.sigil/dev-keystore.json`
///   (or `$SIGIL_HOME/dev-keystore.json`). Headless demo of the full loop.
/// * `SIGIL_DEV_KEYSTORE=memory` -> [`MemoryKeystore`] (ephemeral; single process).
/// * macOS default -> the Secure Enclave keystore (`MacKeystore`).
/// * other platforms default -> [`MemoryKeystore`] until their fill lands.
///
/// Honoring either dev override prints a loud stderr warning outside tests,
/// the same discipline `--dev-insecure` gets from
/// [`crate::factor::warn_dev_insecure`]: this is a silent escape hatch
/// otherwise, putting the DEK (and for `file`, the token-decryption key) in
/// plaintext with zero user-facing signal.
pub fn for_host() -> std::sync::Arc<dyn Keystore> {
    use std::sync::Arc;
    match std::env::var("SIGIL_DEV_KEYSTORE").ok().as_deref() {
        Some("file") => {
            let base = std::env::var_os("SIGIL_HOME")
                .map(std::path::PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".sigil"))
                })
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            let path = base.join("dev-keystore.json");
            #[cfg(not(test))]
            eprintln!("{}", dev_keystore_warning("file", Some(&path)));
            Arc::new(DevFileKeystore::new(path))
        }
        Some("memory") => {
            #[cfg(not(test))]
            eprintln!("{}", dev_keystore_warning("memory", None));
            Arc::new(MemoryKeystore::new())
        }
        _ => {
            #[cfg(target_os = "macos")]
            {
                Arc::new(crate::keystore_macos::MacKeystore::new())
            }
            #[cfg(not(target_os = "macos"))]
            {
                Arc::new(MemoryKeystore::new())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_store_load_delete() {
        let ks = MemoryKeystore::new();
        assert!(ks.load_blob("id.key").unwrap().is_none());
        ks.store_blob("id.key", b"\x01\x02\x03").unwrap();
        assert_eq!(ks.load_blob("id.key").unwrap().unwrap(), b"\x01\x02\x03");
        // Replace.
        ks.store_blob("id.key", b"\x04").unwrap();
        assert_eq!(ks.load_blob("id.key").unwrap().unwrap(), b"\x04");
        ks.delete_blob("id.key").unwrap();
        assert!(ks.load_blob("id.key").unwrap().is_none());
        // Deleting an absent blob is fine.
        ks.delete_blob("id.key").unwrap();
    }

    #[test]
    fn dek_lifecycle_and_stability() {
        let ks = MemoryKeystore::new();
        assert!(!ks.has_dek());
        assert!(matches!(
            ks.unwrap_dek("test").unwrap_err(),
            KeystoreError::NoDek
        ));

        ks.ensure_dek().unwrap();
        assert!(ks.has_dek());
        let a = ks.unwrap_dek("test").unwrap();
        let b = ks.unwrap_dek("test").unwrap();
        assert_eq!(*a, *b, "unwrap must return the same DEK each time");

        // ensure_dek is idempotent: it must not rotate an existing DEK.
        ks.ensure_dek().unwrap();
        assert_eq!(*ks.unwrap_dek("test").unwrap(), *a);
    }

    #[test]
    fn decrypts_a_token_sealed_under_the_unwrapped_dek() {
        let ks = MemoryKeystore::with_dek();
        let dek = ks.unwrap_dek("seal").unwrap();
        let ct = secrets::encrypt_token(&dek, b"ops_live_token").unwrap();
        // A fresh unwrap must open ciphertext sealed under the first one.
        let dek2 = ks.unwrap_dek("open").unwrap();
        let pt = secrets::decrypt_token(&dek2, &ct).unwrap();
        assert_eq!(&pt[..], b"ops_live_token");
    }

    #[test]
    fn memory_keystore_is_not_a_biometric_factor() {
        assert!(!MemoryKeystore::new().is_biometric());
    }

    #[test]
    fn dev_file_keystore_persists_dek_across_instances() {
        let dir = std::env::temp_dir().join(format!("sigil-ks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dev-keystore.json");

        let a = DevFileKeystore::new(path.clone());
        assert!(!a.has_dek());
        a.ensure_dek().unwrap();
        a.store_blob("id.key", b"blobby").unwrap();
        let dek_a = a.unwrap_dek("x").unwrap();

        // A fresh instance (as if a second process) sees the same DEK and blob.
        let b = DevFileKeystore::new(path.clone());
        assert!(b.has_dek());
        assert_eq!(*b.unwrap_dek("x").unwrap(), *dek_a);
        assert_eq!(b.load_blob("id.key").unwrap().unwrap(), b"blobby");
        assert!(!b.is_biometric());

        // File is 0600.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dek_error_hint_names_a_concrete_next_step_for_every_variant() {
        let variants = [
            KeystoreError::NeedsVerification("test"),
            KeystoreError::Declined,
            KeystoreError::NoDek,
            KeystoreError::Backend("test".into()),
        ];
        for e in &variants {
            let hint = dek_error_hint(e);
            assert!(!hint.is_empty());
            // Every hint reads like an instruction, not a bare error echo.
            assert_ne!(hint, e.to_string());
        }
    }

    #[test]
    fn dev_keystore_warning_names_the_concrete_risk() {
        let file = dev_keystore_warning("file", Some(std::path::Path::new("/tmp/x.json")));
        assert!(file.contains("SIGIL_DEV_KEYSTORE=file"));
        assert!(file.contains("/tmp/x.json"));
        assert!(file.contains("no biometric gate"));
        assert!(file.lines().count() > 5);

        let memory = dev_keystore_warning("memory", None);
        assert!(memory.contains("SIGIL_DEV_KEYSTORE=memory"));
        assert!(memory.contains("plaintext RAM"));
    }
}
