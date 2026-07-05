//! The decision audit log: `<latch_home>/history.jsonl`.
//!
//! The daemon appends one line per resolved request (approved, denied, or the
//! lease-served fast path) so the History view has something to read; it is
//! exposed over the daemon control socket (`Frame::History`) and, for a headless
//! `latch history`, read directly from this file. Like every other Latch log, it
//! records **names
//! and metadata only** — the account label, the requested scope/item names, the
//! caller provenance, the decision, and how it was decided — and never a secret
//! value. It is the persisted sibling of the stderr `log_request` line.
//!
//! The file is append-only JSONL (one JSON object per line), mode 0600. Reads
//! return newest-first and are capped so a long-lived daemon does not hand the
//! GUI an unbounded array; a best-effort retention prune drops lines older than
//! the configured window on each append.

use serde::{Deserialize, Serialize};

use crate::json::{request_kind_str, HistoryJson};
use crate::paths;

/// How many entries `load` returns at most (newest-first). The GUI paginates
/// nothing today, so this bounds the response.
pub const HISTORY_READ_CAP: usize = 500;

/// One audit line. Metadata only, by construction: there is no field that can
/// hold a secret value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    /// A [`RequestKind`](latch_proto::RequestKind) snake_case spelling.
    pub kind: String,
    /// The brightest display label (item name, or SSH host).
    pub label: String,
    pub account: String,
    /// The rendered caller chain, e.g. `zsh -> claude -> op`.
    pub process: String,
    pub cwd: String,
    /// `approved` | `denied` | `expired`.
    pub decision: String,
    pub note: Option<String>,
    pub at_ms: u64,
    /// How it was decided: `phone` | `biometric` | `lease` | `dev`.
    pub via: String,
}

impl AuditEntry {
    /// The GUI-facing shape (identical fields; kept as a distinct type so the
    /// on-disk format and the wire format can diverge later).
    pub fn to_json(&self) -> HistoryJson {
        HistoryJson {
            id: self.id.clone(),
            kind: self.kind.clone(),
            label: self.label.clone(),
            account: self.account.clone(),
            process: self.process.clone(),
            cwd: self.cwd.clone(),
            decision: self.decision.clone(),
            note: self.note.clone(),
            at_ms: self.at_ms,
            via: self.via.clone(),
        }
    }
}

/// `<latch_home>/history.jsonl`.
pub fn path() -> Option<std::path::PathBuf> {
    paths::latch_home().map(|h| h.join("history.jsonl"))
}

/// Append one entry, best-effort. Never returns an error to the hot path: an
/// audit write must not fail a secret request. `retention_days` prunes lines
/// older than the window (0 disables pruning).
pub fn append(entry: &AuditEntry, retention_days: u32) {
    let Some(path) = path() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    // Prune first so the file stays bounded, then append the new line.
    if retention_days > 0 {
        prune(&path, retention_days, entry.at_ms);
    }

    let Ok(mut line) = serde_json::to_string(entry) else {
        return;
    };
    line.push('\n');
    write_append_0600(&path, line.as_bytes());
}

/// Load entries newest-first, capped at [`HISTORY_READ_CAP`]. Unparseable lines
/// are skipped rather than failing the whole read.
pub fn load() -> Vec<AuditEntry> {
    let Some(path) = path() else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut entries: Vec<AuditEntry> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    entries.reverse(); // newest-first
    entries.truncate(HISTORY_READ_CAP);
    entries
}

/// Rewrite the file dropping entries older than `retention_days` before `now_ms`.
/// Best-effort: any io error leaves the file as-is.
fn prune(path: &std::path::Path, retention_days: u32, now_ms: u64) {
    let cutoff = now_ms.saturating_sub(u64::from(retention_days) * 86_400_000);
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| match serde_json::from_str::<AuditEntry>(l) {
            Ok(e) => e.at_ms >= cutoff,
            Err(_) => false,
        })
        .collect();
    // Only rewrite when something was actually dropped.
    if kept.len() != text.lines().filter(|l| !l.trim().is_empty()).count() {
        let mut body = kept.join("\n");
        if !body.is_empty() {
            body.push('\n');
        }
        write_replace_0600(path, body.as_bytes());
    }
}

fn write_append_0600(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
    {
        let _ = f.write_all(bytes);
    }
}

fn write_replace_0600(path: &std::path::Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    if std::fs::write(path, bytes).is_ok() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

/// Build an audit entry from the parts the daemon has at a decision point.
#[allow(clippy::too_many_arguments)]
pub fn entry(
    id: &str,
    kind: latch_proto::RequestKind,
    label: &str,
    account: &str,
    process: &str,
    cwd: &str,
    decision: &str,
    note: Option<String>,
    at_ms: u64,
    via: &str,
) -> AuditEntry {
    AuditEntry {
        id: id.to_string(),
        kind: request_kind_str(kind).to_string(),
        label: label.to_string(),
        account: account.to_string(),
        process: process.to_string(),
        cwd: cwd.to_string(),
        decision: decision.to_string(),
        note,
        at_ms,
        via: via.to_string(),
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
                "latch-audit-{tag}-{}-{:?}",
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

    fn mk(id: &str, at_ms: u64, decision: &str) -> AuditEntry {
        entry(
            id,
            latch_proto::RequestKind::SecretRead,
            "Engineering/.env",
            "Rowm",
            "zsh \u{2192} op",
            "/work",
            decision,
            None,
            at_ms,
            "phone",
        )
    }

    #[test]
    fn append_then_load_is_newest_first() {
        let _home = HomeGuard::new("order");
        append(&mk("a", 1000, "approved"), 30);
        append(&mk("b", 2000, "denied"), 30);
        append(&mk("c", 3000, "approved"), 30);
        let all = load();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].id, "c");
        assert_eq!(all[2].id, "a");
        // Round-trips into the wire shape with the right spellings.
        let j = all[0].to_json();
        assert_eq!(j.kind, "secret_read");
        assert_eq!(j.decision, "approved");
    }

    #[test]
    fn retention_prunes_old_lines() {
        let _home = HomeGuard::new("prune");
        // An old entry, then a fresh one 10 days later with a 1-day window.
        let day = 86_400_000u64;
        append(&mk("old", 1_000_000, "approved"), 0); // no prune on this write
        append(&mk("new", 1_000_000 + 10 * day, "approved"), 1);
        let all = load();
        assert_eq!(all.len(), 1, "the old entry should have been pruned");
        assert_eq!(all[0].id, "new");
    }

    #[test]
    fn load_with_no_file_is_empty() {
        let _home = HomeGuard::new("empty");
        assert!(load().is_empty());
    }

    #[test]
    fn file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let _home = HomeGuard::new("perms");
        append(&mk("a", 1000, "approved"), 30);
        let mode = std::fs::metadata(path().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
