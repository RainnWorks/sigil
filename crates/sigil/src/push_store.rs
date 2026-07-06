//! Persistence of phone push-notification registrations, keyed by mailbox id.
//!
//! The phone sends a sealed [`PushRegister`](sigil_proto::PushRegister) over the
//! established session (see [`crate::remote`]); the daemon records the
//! `{token, platform}` here so it can later ring a best-effort APNs "doorbell"
//! ([`crate::apns`]) when it enqueues a new approval request. This survives a
//! daemon restart on the same seam the pairing uses (`~/.sigil`, mode 0600), so a
//! phone that registered once does not have to re-register after every relaunch.
//!
//! ## What this is (and is not)
//!
//! A push token is **not** a credential and unlocks nothing: the doorbell payload
//! is generic ("Approval requested"), so a leaked token lets a third party at
//! most make Tom's phone show that one static line. The real request still only
//! ever reaches the phone as a sealed envelope in the relay mailbox, gated by
//! hardware biometrics. We nonetheless keep the file 0600 beside the pairing and
//! store nothing request-specific, so the doorbell cannot become a side channel.
//!
//! Keyed by mailbox id (not a bare singleton) so multi-device pairing (task #36)
//! drops in without a format change. Re-registration overwrites in place.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::lease::hex32;
use crate::paths;

/// Current on-disk `push.json` schema version.
const PUSH_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum PushStoreError {
    #[error("HOME is not set, so ~/.sigil has no location")]
    NoHome,
    #[error("push store io: {0}")]
    Io(#[from] std::io::Error),
    #[error("push store json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported push store version {0} (this build understands {PUSH_VERSION})")]
    Version(u32),
}

/// One phone's push registration: the platform device token and which push
/// service it addresses, plus when it was recorded (diagnostics only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    /// The platform device token (APNs: lowercase hex). Opaque here.
    pub token: String,
    /// The push service the token addresses: `"apns"` or `"fcm"`.
    pub platform: String,
    /// When this registration was last written, unix ms. Display only.
    pub registered_at: u64,
}

/// The on-disk shape: a version tag plus a map keyed by mailbox hex.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Persisted {
    version: u32,
    #[serde(default)]
    registrations: BTreeMap<String, Registration>,
}

/// The push-registration store: an in-memory map cached behind a mutex, written
/// through to `~/.sigil/push.json` on every change (unless [`ephemeral`], for
/// tests). Cheap to read on the hot approval path; writes are rare (only on a
/// phone (re)registration).
///
/// [`ephemeral`]: PushStore::ephemeral
pub struct PushStore {
    inner: Mutex<BTreeMap<String, Registration>>,
    /// When false the store never touches disk (unit tests, and the default a
    /// `RemoteApprover` carries so the softphone loop needs no filesystem).
    persist: bool,
}

impl PushStore {
    /// Load the persisted registrations, or start empty. A missing file is not an
    /// error (no phone has registered yet); a corrupt or wrong-version file is
    /// logged and treated as empty so the daemon still arms and simply relies on
    /// the phone's poll backstop until the next registration overwrites it.
    pub fn load() -> Self {
        let inner = match Self::read_file() {
            Ok(map) => map,
            Err(e) => {
                eprintln!("sigil daemon: ignoring an unreadable push store: {e}");
                BTreeMap::new()
            }
        };
        Self {
            inner: Mutex::new(inner),
            persist: true,
        }
    }

    /// An in-memory-only store that never reads or writes disk. Used as the
    /// default a `RemoteApprover` holds and by tests.
    pub fn ephemeral() -> Self {
        Self {
            inner: Mutex::new(BTreeMap::new()),
            persist: false,
        }
    }

    /// Record (or overwrite) the registration for `mailbox`. Best-effort persist:
    /// a write failure is logged but never fails the caller, since the doorbell is
    /// itself best-effort and the in-memory copy is enough for this daemon's life.
    pub fn register(&self, mailbox: [u8; 32], token: &str, platform: &str, now_ms: u64) {
        let reg = Registration {
            token: token.to_string(),
            platform: platform.to_string(),
            registered_at: now_ms,
        };
        let snapshot = {
            let mut map = self.inner.lock().expect("push store poisoned");
            map.insert(hex32(&mailbox), reg);
            map.clone()
        };
        if self.persist {
            if let Err(e) = Self::write_file(&snapshot) {
                eprintln!("sigil daemon: could not persist push registration: {e}");
            }
        }
    }

    /// The current registration for `mailbox`, if any.
    pub fn get(&self, mailbox: [u8; 32]) -> Option<Registration> {
        self.inner
            .lock()
            .expect("push store poisoned")
            .get(&hex32(&mailbox))
            .cloned()
    }

    fn read_file() -> Result<BTreeMap<String, Registration>, PushStoreError> {
        let path = paths::push_path().ok_or(PushStoreError::NoHome)?;
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => return Err(e.into()),
        };
        let persisted: Persisted = serde_json::from_slice(&bytes)?;
        if persisted.version != PUSH_VERSION {
            return Err(PushStoreError::Version(persisted.version));
        }
        Ok(persisted.registrations)
    }

    fn write_file(map: &BTreeMap<String, Registration>) -> Result<(), PushStoreError> {
        use std::os::unix::fs::PermissionsExt;
        let path = paths::push_path().ok_or(PushStoreError::NoHome)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let persisted = Persisted {
            version: PUSH_VERSION,
            registrations: map.clone(),
        };
        let json = serde_json::to_vec_pretty(&persisted)?;
        std::fs::write(&path, json)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A private SIGIL_HOME for one test; restores the env on drop and holds the
    /// process-wide env lock so parallel tests do not clobber it.
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
                "sigil-pushstore-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let prev = std::env::var_os("SIGIL_HOME");
            std::env::set_var("SIGIL_HOME", &dir);
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
                Some(v) => std::env::set_var("SIGIL_HOME", v),
                None => std::env::remove_var("SIGIL_HOME"),
            }
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    #[test]
    fn register_then_get_round_trips_by_mailbox() {
        let store = PushStore::ephemeral();
        let mbx = [7u8; 32];
        assert!(store.get(mbx).is_none());
        store.register(mbx, "abc123", "apns", 42);
        let got = store.get(mbx).unwrap();
        assert_eq!(got.token, "abc123");
        assert_eq!(got.platform, "apns");
        assert_eq!(got.registered_at, 42);
        // A different mailbox is independent.
        assert!(store.get([8u8; 32]).is_none());
    }

    #[test]
    fn re_registration_overwrites_in_place() {
        let store = PushStore::ephemeral();
        let mbx = [1u8; 32];
        store.register(mbx, "old-token", "apns", 1);
        store.register(mbx, "new-token", "apns", 2);
        let got = store.get(mbx).unwrap();
        assert_eq!(got.token, "new-token");
        assert_eq!(got.registered_at, 2);
    }

    #[test]
    fn persists_across_a_reload_and_writes_0600() {
        use std::os::unix::fs::PermissionsExt;
        let _home = HomeGuard::new("persist");
        let mbx = [3u8; 32];
        {
            let store = PushStore::load();
            store.register(mbx, "persisted-token", "apns", 99);
        }
        // A fresh load sees the registration written by the previous instance.
        let store = PushStore::load();
        let got = store.get(mbx).expect("registration survived the reload");
        assert_eq!(got.token, "persisted-token");

        let path = paths::push_path().unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the push store is 0600 like the pairing");
    }

    #[test]
    fn a_corrupt_file_loads_as_empty_and_does_not_panic() {
        let _home = HomeGuard::new("corrupt");
        let path = paths::push_path().unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not json at all").unwrap();
        let store = PushStore::load();
        assert!(store.get([0u8; 32]).is_none());
    }
}
