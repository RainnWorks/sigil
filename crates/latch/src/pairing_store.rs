//! On-disk persistence of the daemon<->phone pairing that makes the phone the
//! approving factor across daemon restarts.
//!
//! # What is persisted, and why it stays inert at rest
//!
//! A paired daemon needs three things to run the phone factor: its own
//! long-term identity (to sign requests and open responses), the phone's pinned
//! **public** identity (to seal to and verify), and the relay URL. This module
//! persists exactly those, split by sensitivity:
//!
//! * The daemon's **private identity** (Ed25519 signing seed + X25519 agreement
//!   secret, 64 bytes) goes into the [`Keystore`] blob seam — the login Keychain
//!   on macOS. It never touches the plaintext config file.
//! * The **public** parts — the phone's pinned [`PeerIdentity`], the relay URL,
//!   the pairing time, and the six SAS words (for `list-paired-devices`) — go
//!   into `~/.latch/pairing.json`, mode 0600.
//!
//! Crucially, **no DEK is persisted.** The DEK lives only on the phone; it
//! arrives per-approval inside a sealed [`ApprovalResponse`] and is zeroized
//! after one use. This is what keeps the daemon inert at rest: the on-disk state
//! (even including the private identity) can *ask* the phone to approve a
//! request, but it cannot by itself decrypt any service-account token, because
//! the tokens are AES-256-GCM ciphertext under the DEK the daemon does not hold.
//! An attacker who steals the whole disk gains only the ability to send the
//! phone a request — which the phone answers only after Tom's hardware-gated
//! approval, exactly the gate Latch exists to enforce. Nothing releasable at
//! rest, by construction.
//!
//! Flagged to security-reviewer: the persisted set is `{daemon private identity
//! (keystore), phone public identity, relay URL, SAS words}` and deliberately
//! excludes any DEK or DEK envelope.

use serde::{Deserialize, Serialize};

use latch_proto::identity::DeviceIdentity;
use latch_proto::PeerIdentity;

use crate::daemon::RemotePairingConfig;
use crate::keystore::{Keystore, KeystoreError};
use crate::paths;

/// Keystore blob label under which the daemon's own 64-byte private identity is
/// sealed. Versioned so a future key-format change can migrate cleanly.
const DAEMON_IDENTITY_LABEL: &str = "pairing.daemon-identity.v1";

/// Current on-disk `pairing.json` schema version.
const PAIRING_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum PairingStoreError {
    #[error("HOME is not set, so ~/.latch has no location")]
    NoHome,
    #[error("pairing config io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pairing config json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("keystore: {0}")]
    Keystore(#[from] KeystoreError),
    #[error("unsupported pairing config version {0} (this build understands {PAIRING_VERSION})")]
    Version(u32),
    #[error("the daemon identity is missing from the keystore; re-pair with `latch pair`")]
    MissingIdentity,
    #[error("the stored daemon identity is corrupt; re-pair with `latch pair`")]
    CorruptIdentity,
}

/// The public half of a persisted pairing: everything safe to keep in a
/// plaintext 0600 file. The private daemon identity lives in the keystore, keyed
/// by [`DAEMON_IDENTITY_LABEL`], never here.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedPairing {
    version: u32,
    /// The relay base URL the daemon attaches to for approvals.
    relay_url: String,
    /// The phone's pinned public identity (verify + seal targets).
    phone: PeerIdentity,
    /// When pairing completed, unix ms.
    paired_at: u64,
    /// The six SAS words this pairing confirmed, kept for display only.
    sas_words: Vec<String>,
}

/// The inputs a completed pairing hands this module to persist.
pub struct NewPairing {
    /// The daemon's own long-term identity (private; sealed into the keystore).
    pub daemon_identity: DeviceIdentity,
    /// The phone's pinned public identity.
    pub phone: PeerIdentity,
    /// The relay base URL.
    pub relay_url: String,
    /// The confirmed SAS words, for `list-paired-devices`.
    pub sas_words: [String; 6],
    /// Pairing completion time, unix ms.
    pub paired_at: u64,
}

/// A read-only summary of the persisted pairing, for `list-paired-devices`. Uses
/// only the public config file, so it needs no keystore access.
#[derive(Debug, Clone)]
pub struct PairingSummary {
    pub relay_url: String,
    pub phone: PeerIdentity,
    pub paired_at: u64,
    pub sas_words: Vec<String>,
}

fn config_path() -> Result<std::path::PathBuf, PairingStoreError> {
    paths::pairing_path().ok_or(PairingStoreError::NoHome)
}

/// True if a pairing config file is present (does not validate it or the
/// keystore identity).
pub fn exists() -> bool {
    config_path().map(|p| p.exists()).unwrap_or(false)
}

/// Persist a completed pairing: seal the daemon identity into the keystore, then
/// write the public config file 0600.
pub fn save(ks: &dyn Keystore, p: &NewPairing) -> Result<(), PairingStoreError> {
    use std::os::unix::fs::PermissionsExt;

    // 1. Seal the private daemon identity into the keystore blob seam. The bytes
    //    are Zeroizing and are wiped when `secret` drops at the end of this call.
    let secret = p.daemon_identity.to_secret_bytes();
    ks.store_blob(DAEMON_IDENTITY_LABEL, &secret[..])?;

    // 2. Write the public config 0600.
    let persisted = PersistedPairing {
        version: PAIRING_VERSION,
        relay_url: p.relay_url.clone(),
        phone: p.phone,
        paired_at: p.paired_at,
        sas_words: p.sas_words.to_vec(),
    };
    let path = config_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let json = serde_json::to_vec_pretty(&persisted)?;
    std::fs::write(&path, json)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Load the persisted pairing into a [`RemotePairingConfig`] the daemon can arm
/// the phone factor with, or `None` when no pairing is configured.
///
/// Reconstructs the daemon identity from the keystore and pins the phone from
/// the config file. Returns an error (rather than `None`) when a config file is
/// present but unreadable or its keystore identity is missing/corrupt, so a
/// half-broken pairing surfaces loudly instead of silently failing closed.
pub fn load(ks: &dyn Keystore) -> Result<Option<RemotePairingConfig>, PairingStoreError> {
    let path = config_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let persisted: PersistedPairing = serde_json::from_slice(&bytes)?;
    if persisted.version != PAIRING_VERSION {
        return Err(PairingStoreError::Version(persisted.version));
    }

    let blob = ks
        .load_blob(DAEMON_IDENTITY_LABEL)?
        .ok_or(PairingStoreError::MissingIdentity)?;
    let daemon_identity =
        DeviceIdentity::from_secret_bytes(&blob).ok_or(PairingStoreError::CorruptIdentity)?;

    Ok(Some(RemotePairingConfig {
        relay_url: persisted.relay_url,
        daemon_identity,
        phone: persisted.phone,
    }))
}

/// The public summary of the persisted pairing, for display. `None` when no
/// pairing is configured.
pub fn summary() -> Result<Option<PairingSummary>, PairingStoreError> {
    let path = config_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let persisted: PersistedPairing = serde_json::from_slice(&bytes)?;
    Ok(Some(PairingSummary {
        relay_url: persisted.relay_url,
        phone: persisted.phone,
        paired_at: persisted.paired_at,
        sas_words: persisted.sas_words,
    }))
}

/// Remove the pairing: delete the keystore identity blob and the config file.
/// Returns `true` if anything was removed. Idempotent.
pub fn remove(ks: &dyn Keystore) -> Result<bool, PairingStoreError> {
    let mut removed = false;
    ks.delete_blob(DAEMON_IDENTITY_LABEL)?;
    let path = config_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => removed = true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MemoryKeystore;

    /// A private LATCH_HOME for one test, plus a guard that restores the env.
    /// Holds the process-wide env lock so parallel tests do not clobber it.
    struct HomeGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        prev: Option<std::ffi::OsString>,
        dir: std::path::PathBuf,
    }
    impl HomeGuard {
        fn new(tag: &str) -> Self {
            let lock = crate::TEST_ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let dir = std::env::temp_dir().join(format!(
                "latch-pairstore-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let prev = std::env::var_os("LATCH_HOME");
            std::env::set_var("LATCH_HOME", &dir);
            Self {
                _lock: lock,
                prev,
                dir,
            }
        }
    }
    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("LATCH_HOME", v),
                None => std::env::remove_var("LATCH_HOME"),
            }
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    fn new_pairing() -> (DeviceIdentity, PeerIdentity, NewPairing) {
        let daemon = DeviceIdentity::generate();
        let phone = DeviceIdentity::generate().peer_identity();
        let daemon_pub = daemon.peer_identity();
        let np = NewPairing {
            daemon_identity: daemon,
            phone,
            relay_url: "https://relay.example".into(),
            sas_words: [
                "tide".into(),
                "brass".into(),
                "anchor".into(),
                "harbor".into(),
                "reef".into(),
                "mast".into(),
            ],
            paired_at: 1_720_000_000_000,
        };
        // Rebuild a daemon identity handle with the same public id for asserts.
        (DeviceIdentity::generate(), daemon_pub, np)
    }

    #[test]
    fn save_then_load_reconstructs_the_config_and_pins_the_phone() {
        let _home = HomeGuard::new("roundtrip");
        let ks = MemoryKeystore::new();
        let (_ignore, daemon_pub, np) = new_pairing();
        let phone = np.phone;
        let relay = np.relay_url.clone();

        save(&ks, &np).unwrap();
        assert!(exists());

        let cfg = load(&ks).unwrap().expect("a pairing was saved");
        assert_eq!(cfg.relay_url, relay);
        assert_eq!(cfg.phone, phone);
        // The reconstructed daemon identity has the same pinned public halves,
        // so the mailbox it derives matches what the phone computes.
        assert_eq!(cfg.daemon_identity.peer_identity(), daemon_pub);
    }

    #[test]
    fn no_config_file_loads_as_none() {
        let _home = HomeGuard::new("none");
        let ks = MemoryKeystore::new();
        assert!(!exists());
        assert!(load(&ks).unwrap().is_none());
        assert!(summary().unwrap().is_none());
    }

    #[test]
    fn config_present_but_identity_missing_is_a_loud_error() {
        let _home = HomeGuard::new("half");
        let ks = MemoryKeystore::new();
        let (_i, _p, np) = new_pairing();
        save(&ks, &np).unwrap();
        // Simulate a keystore that lost the identity (e.g. Keychain wiped).
        ks.delete_blob(DAEMON_IDENTITY_LABEL).unwrap();
        let err = match load(&ks) {
            Err(e) => e,
            Ok(_) => panic!("expected a MissingIdentity error"),
        };
        assert!(matches!(err, PairingStoreError::MissingIdentity));
    }

    #[test]
    fn config_file_is_0600_and_holds_no_dek() {
        use std::os::unix::fs::PermissionsExt;
        let _home = HomeGuard::new("perms");
        let ks = MemoryKeystore::new();
        let (_i, _p, np) = new_pairing();
        save(&ks, &np).unwrap();
        let path = config_path().unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Inert-at-rest: no DEK, no key material of any kind in the plaintext.
        let raw = std::fs::read_to_string(&path).unwrap().to_lowercase();
        assert!(!raw.contains("dek"), "no DEK field in the config");
        assert!(!raw.contains("secret"), "no secret in the config");
        assert!(!raw.contains("signing"), "no private key in the config");
    }

    #[test]
    fn summary_reads_public_parts_without_the_keystore() {
        let _home = HomeGuard::new("summary");
        let ks = MemoryKeystore::new();
        let (_i, _p, np) = new_pairing();
        let phone = np.phone;
        save(&ks, &np).unwrap();
        // No keystore passed: the summary comes from the config file alone.
        let s = summary().unwrap().expect("a pairing exists");
        assert_eq!(s.phone, phone);
        assert_eq!(s.sas_words.len(), 6);
        assert_eq!(s.relay_url, "https://relay.example");
    }

    #[test]
    fn remove_deletes_both_the_config_and_the_identity() {
        let _home = HomeGuard::new("remove");
        let ks = MemoryKeystore::new();
        let (_i, _p, np) = new_pairing();
        save(&ks, &np).unwrap();
        assert!(remove(&ks).unwrap());
        assert!(!exists());
        assert!(load(&ks).unwrap().is_none());
        // The identity blob is gone too.
        assert!(ks.load_blob(DAEMON_IDENTITY_LABEL).unwrap().is_none());
        // A second remove is a no-op, not an error.
        assert!(!remove(&ks).unwrap());
    }
}
