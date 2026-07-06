//! The user-facing settings store: `<sigil_home>/settings.json`.
//!
//! These are the preferences the Mac app reads and writes over `sigil settings
//! get|set --json`: the approval timeout, notification and motion prefs, the
//! history retention window, the relay endpoint, and the `mac-approvals` mode.
//! None of it is secret; the file is 0600 only for tidiness alongside the rest
//! of `~/.sigil`.
//!
//! `set` is a *merge*: only the keys present in the incoming patch change, so
//! `sigil settings set relay_url https://…` never disturbs `mac_approvals`, and
//! the Mac app writing the five GUI fields never drops it either.

use serde::{Deserialize, Serialize};

use crate::json::SettingsJson;
use crate::paths;

/// The `mac-approvals` mode: whether a local Mac Secure Enclave envelope is
/// allowed to approve, or the daemon is hardened to require the phone.
pub const MAC_APPROVALS_ENABLED: &str = "enabled";
pub const MAC_APPROVALS_PHONE_ONLY: &str = "phone_only";

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("HOME is not set, so ~/.sigil has no location")]
    NoHome,
    #[error("settings io: {0}")]
    Io(#[from] std::io::Error),
    #[error("settings json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown setting {0:?}")]
    UnknownKey(String),
    #[error("value for {key:?} must be {expected}")]
    BadValue { key: String, expected: String },
}

/// The persisted settings. `serde(default)` on every field so an older or
/// partial file still loads, and new fields default cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_timeout")]
    pub approval_timeout_sec: u32,
    #[serde(default = "default_true")]
    pub notifications: bool,
    #[serde(default = "default_retention")]
    pub retention_days: u32,
    #[serde(default)]
    pub relay_url: String,
    #[serde(default)]
    pub reduce_motion: bool,
    #[serde(default = "default_mac_approvals")]
    pub mac_approvals: String,
}

fn default_timeout() -> u32 {
    120
}
fn default_true() -> bool {
    true
}
fn default_retention() -> u32 {
    30
}
fn default_mac_approvals() -> String {
    MAC_APPROVALS_ENABLED.to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            approval_timeout_sec: default_timeout(),
            notifications: default_true(),
            retention_days: default_retention(),
            relay_url: String::new(),
            reduce_motion: false,
            mac_approvals: default_mac_approvals(),
        }
    }
}

impl Settings {
    /// `<sigil_home>/settings.json`.
    pub fn path() -> Result<std::path::PathBuf, SettingsError> {
        paths::sigil_home()
            .map(|h| h.join("settings.json"))
            .ok_or(SettingsError::NoHome)
    }

    /// Load the settings, returning defaults if the file does not exist.
    pub fn load() -> Result<Self, SettingsError> {
        let path = Self::path()?;
        match std::fs::read(&path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Persist the settings, creating the parent dir 0700 and the file 0600.
    pub fn save(&self) -> Result<(), SettingsError> {
        use std::os::unix::fs::PermissionsExt;
        let path = Self::path()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(&path, json)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// The GUI-facing DTO (also carries `mac_approvals` so a round-trip never
    /// drops it).
    pub fn to_json(&self) -> SettingsJson {
        SettingsJson {
            approval_timeout_sec: self.approval_timeout_sec,
            notifications: self.notifications,
            retention_days: self.retention_days,
            relay_url: self.relay_url.clone(),
            reduce_motion: self.reduce_motion,
            mac_approvals: self.mac_approvals.clone(),
        }
    }

    /// Merge one `key value` pair, validating the type. Used by both the
    /// `settings set <key> <value>` argv form and the `--json` patch merge.
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), SettingsError> {
        let bad = |expected: &str| SettingsError::BadValue {
            key: key.to_string(),
            expected: expected.to_string(),
        };
        match key {
            "approval_timeout_sec" => {
                self.approval_timeout_sec = value.parse().map_err(|_| bad("a whole number"))?
            }
            "notifications" => {
                self.notifications = parse_bool(value).ok_or_else(|| bad("true or false"))?
            }
            "retention_days" => {
                self.retention_days = value.parse().map_err(|_| bad("a whole number"))?
            }
            "relay_url" => self.relay_url = value.to_string(),
            "reduce_motion" => {
                self.reduce_motion = parse_bool(value).ok_or_else(|| bad("true or false"))?
            }
            "mac_approvals" => {
                if value != MAC_APPROVALS_ENABLED && value != MAC_APPROVALS_PHONE_ONLY {
                    return Err(bad("enabled or phone_only"));
                }
                self.mac_approvals = value.to_string();
            }
            other => return Err(SettingsError::UnknownKey(other.to_string())),
        }
        Ok(())
    }

    /// Merge a JSON object patch: every present key is applied via [`set`], so
    /// the value types the GUI sends (numbers, bools, strings) are accepted and
    /// absent keys are left untouched.
    pub fn merge_json(&mut self, patch: &serde_json::Value) -> Result<(), SettingsError> {
        let Some(obj) = patch.as_object() else {
            return Err(SettingsError::BadValue {
                key: "<patch>".into(),
                expected: "a JSON object".into(),
            });
        };
        for (key, value) in obj {
            let as_str = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Null => continue,
                other => other.to_string(),
            };
            self.set(key, &as_str)?;
        }
        Ok(())
    }
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                "sigil-settings-{tag}-{}-{:?}",
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
    fn defaults_when_absent() {
        let _home = HomeGuard::new("defaults");
        let s = Settings::load().unwrap();
        assert_eq!(s, Settings::default());
        assert_eq!(s.approval_timeout_sec, 120);
        assert_eq!(s.mac_approvals, MAC_APPROVALS_ENABLED);
    }

    #[test]
    fn set_and_reload_round_trips() {
        let _home = HomeGuard::new("roundtrip");
        let mut s = Settings::load().unwrap();
        s.set("approval_timeout_sec", "45").unwrap();
        s.set("notifications", "false").unwrap();
        s.set("relay_url", "https://relay.example").unwrap();
        s.save().unwrap();

        let loaded = Settings::load().unwrap();
        assert_eq!(loaded.approval_timeout_sec, 45);
        assert!(!loaded.notifications);
        assert_eq!(loaded.relay_url, "https://relay.example");
        // Untouched fields kept their defaults.
        assert_eq!(loaded.retention_days, 30);
    }

    #[test]
    fn merge_json_leaves_absent_keys_untouched() {
        let mut s = Settings {
            mac_approvals: MAC_APPROVALS_PHONE_ONLY.to_string(),
            ..Settings::default()
        };
        // The GUI writes the five settings fields, not mac_approvals.
        let patch = serde_json::json!({
            "approval_timeout_sec": 90,
            "notifications": true,
            "retention_days": 14,
            "relay_url": "wss://r",
            "reduce_motion": true
        });
        s.merge_json(&patch).unwrap();
        assert_eq!(s.approval_timeout_sec, 90);
        assert_eq!(s.retention_days, 14);
        assert!(s.reduce_motion);
        // mac_approvals survived the GUI round-trip.
        assert_eq!(s.mac_approvals, MAC_APPROVALS_PHONE_ONLY);
    }

    #[test]
    fn unknown_key_and_bad_value_are_rejected() {
        let mut s = Settings::default();
        assert!(matches!(
            s.set("nope", "x"),
            Err(SettingsError::UnknownKey(_))
        ));
        assert!(matches!(
            s.set("approval_timeout_sec", "soon"),
            Err(SettingsError::BadValue { .. })
        ));
        assert!(matches!(
            s.set("mac_approvals", "sometimes"),
            Err(SettingsError::BadValue { .. })
        ));
    }
}
