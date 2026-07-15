//! The keystore seam: secret-at-rest blob storage and a biometric presence gate.
//!
//! This trait is the single platform boundary for the opaque blobs the daemon
//! keeps at rest: the daemon identity keys and the Mac threshold share `m` (see
//! [`crate::threshold`]). It also exposes one privileged operation,
//! [`Keystore::verify_presence`], which on macOS performs a Touch-ID-gated
//! Secure Enclave op used to gate authorizing a new pairing.
//!
//! There is no data-encryption key here anymore: everything Sigil stores at rest
//! is threshold-sealed and opened per-approval with the phone's partial, so the
//! daemon holds no key that a compromise of this store could turn into a secret.
//!
//! macOS is the first fill ([`crate::keystore_macos`]); Linux (libsecret / TPM)
//! and Windows (DPAPI / TPM) are later fills of the same trait. Blob store/load
//! is exercised now through [`MemoryKeystore`], which also stands in for the
//! Secure Enclave in headless tests and the dev-approval loop.

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// The biometric prompt was declined or the enclave refused the op.
    #[error("biometric presence check declined")]
    Declined,
    /// A backend (Keychain, Secure Enclave, libsecret) call failed.
    #[error("keystore backend: {0}")]
    Backend(String),
    /// The Secure Enclave / Touch-ID path exists but has never been verified on
    /// hardware; it refuses rather than pretending to work. See the module
    /// NEEDS-VERIFICATION notes.
    #[error("secure enclave path not yet verified on hardware: {0}")]
    NeedsVerification(&'static str),
}

/// Storage of encrypted blobs plus a biometric presence gate. Implementations
/// must be safe to share across daemon worker threads.
pub trait Keystore: Send + Sync {
    /// Persist an opaque blob under `label`, replacing any existing value.
    fn store_blob(&self, label: &str, data: &[u8]) -> Result<(), KeystoreError>;

    /// Load the blob stored under `label`, or `None` if absent.
    fn load_blob(&self, label: &str) -> Result<Option<Vec<u8>>, KeystoreError>;

    /// Remove the blob stored under `label`. Absent is not an error.
    fn delete_blob(&self, label: &str) -> Result<(), KeystoreError>;

    /// True if [`verify_presence`](Self::verify_presence) is gated by a real
    /// hardware biometric (the Secure Enclave). The pairing gate only asks a
    /// keystore to prove presence when this is true; a dev/in-memory keystore
    /// returns false so it can never masquerade as Touch ID.
    fn is_biometric(&self) -> bool {
        false
    }

    /// Prove a live hardware user-presence (Touch ID / Secure Enclave).
    /// Authorizing a new pairing calls this so accepting a device is gated on the
    /// human's biometric. This is independent of any at-rest secret: nothing is
    /// unwrapped or delivered, the enclave op only proves the human is present.
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

/// In-memory keystore. Holds blobs in RAM, wiped on drop. It is the unit-test and
/// headless-dev backend, and the stand-in for the Secure Enclave when Touch ID
/// cannot be exercised. It is **not** an at-rest secure store: nothing here
/// survives a restart, which is exactly why it is dev/test-only.
#[derive(Default)]
pub struct MemoryKeystore {
    inner: std::sync::Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    blobs: std::collections::HashMap<String, Vec<u8>>,
}

impl MemoryKeystore {
    pub fn new() -> Self {
        Self::default()
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
}

/// A dev keystore that persists blobs to a 0600 JSON file. It is **not secure**
/// (the Mac threshold share `m` sits on disk in the clear) and exists only to make
/// the full gated loop runnable headlessly, standing in for the Secure Enclave.
/// It is selected only by `SIGIL_DEV_KEYSTORE=file`, never by default.
pub struct DevFileKeystore {
    path: std::path::PathBuf,
    inner: std::sync::Mutex<()>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct DevFileState {
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
}

/// The loud, multi-line warning that must appear whenever `SIGIL_DEV_KEYSTORE`
/// is honored. Mirrors [`crate::factor::DEV_INSECURE_WARNING`] in shape: it
/// names the concrete risk (the Mac threshold share `m`, and the daemon identity
/// keys, in plaintext on disk or in RAM with no biometric gate) so a dev config
/// can never be mistaken for a safe one. `mode` is `"file"` or `"memory"`; `path`
/// is the on-disk location for `file`, `None` for `memory`.
fn dev_keystore_warning(mode: &str, path: Option<&std::path::Path>) -> String {
    let where_line = match path {
        Some(p) => format!(
            "!!  Threshold share on disk in the clear at: {}\n",
            p.display()
        ),
        None => "!!  Blobs held in plaintext RAM for this process only.\n".to_string(),
    };
    format!(
        "\n\
         !! ============================================================ !!\n\
         !!  SIGIL_DEV_KEYSTORE={mode} IS ACTIVE                          !!\n\
         !! ------------------------------------------------------------ !!\n\
         !!  The Secure Enclave / Keychain-backed keystore is bypassed.   !!\n\
         {where_line}\
         !!                                                              !!\n\
         !!  RISK: anyone with access to this machine (or the file,      !!\n\
         !!  for `file`) can read the Mac threshold share and the daemon  !!\n\
         !!  identity keys with no biometric gate.                        !!\n\
         !!                                                              !!\n\
         !!  Use this ONLY for local development. Unset                  !!\n\
         !!  SIGIL_DEV_KEYSTORE for a real hardware-backed keystore.      !!\n\
         !! ============================================================ !!\n"
    )
}

/// Print the dev-keystore warning once per process, not once per
/// construction: the daemon resolves a keystore on hot paths (each relay poll
/// cycle re-resolves it), and the repeated banner amounted to tens of
/// megabytes of log per day while burying the lines that mattered. Once per
/// process is just as loud and stays honest. Silent under `cfg(test)`, like
/// the inline prints it replaces.
#[cfg(not(test))]
fn warn_dev_keystore_once(mode: &str, path: Option<&std::path::Path>) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| eprintln!("{}", dev_keystore_warning(mode, path)));
}

#[cfg(test)]
fn warn_dev_keystore_once(_mode: &str, _path: Option<&std::path::Path>) {}

/// Select the keystore for the daemon and CLI. Both must agree so the Mac
/// threshold share `m` a `sigil` command seals with is the same one the daemon
/// combines against.
///
/// * `SIGIL_DEV_KEYSTORE=file` -> [`DevFileKeystore`] at `~/.sigil/dev-keystore.json`
///   (or `$SIGIL_HOME/dev-keystore.json`). Headless demo of the full loop.
/// * `SIGIL_DEV_KEYSTORE=memory` -> [`MemoryKeystore`] (ephemeral; single process).
/// * macOS default -> the Secure Enclave keystore (`MacKeystore`).
/// * other platforms default -> [`MemoryKeystore`] until their fill lands.
///
/// Honoring either dev override prints a loud stderr warning outside tests, the
/// same discipline `--dev-insecure` gets from
/// [`crate::factor::warn_dev_insecure`].
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
            warn_dev_keystore_once("file", Some(&path));
            Arc::new(DevFileKeystore::new(path))
        }
        Some("memory") => {
            warn_dev_keystore_once("memory", None);
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
    fn memory_keystore_is_not_a_biometric_factor() {
        assert!(!MemoryKeystore::new().is_biometric());
        // And it never proves presence, so it can never masquerade as Touch ID.
        assert!(MemoryKeystore::new().verify_presence("x").is_err());
    }

    #[test]
    fn dev_file_keystore_persists_blobs_across_instances() {
        let dir = std::env::temp_dir().join(format!("sigil-ks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dev-keystore.json");

        let a = DevFileKeystore::new(path.clone());
        a.store_blob("id.key", b"blobby").unwrap();

        // A fresh instance (as if a second process) sees the same blob.
        let b = DevFileKeystore::new(path.clone());
        assert_eq!(b.load_blob("id.key").unwrap().unwrap(), b"blobby");
        assert!(!b.is_biometric());

        // File is 0600.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        std::fs::remove_dir_all(&dir).ok();
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
