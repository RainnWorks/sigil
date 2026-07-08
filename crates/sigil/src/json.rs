//! The JSON DTOs shared by the daemon control protocol and the CLI mutation
//! commands.
//!
//! These are the payload shapes the Mac app decodes. They serve two surfaces
//! (see the least-privilege split in `crates/sigil/PROTOCOL.md`):
//!
//! * the **daemon control socket** carries the read/report shapes as
//!   [`Reply::Json`](crate::local::Reply)/[`Reply::Event`](crate::local::Reply)
//!   bodies: [`StatusJson`], [`CheckJson`], [`LeaseJson`], [`PendingJson`],
//!   [`HistoryJson`]; and
//! * the short-lived **CLI mutation commands** emit the rest on stdout under
//!   `--json`: [`AccountJson`], [`SettingsJson`], [`MacApprovalsJson`],
//!   [`PairListJson`]/[`PairedJson`], and [`ControlResult`].
//!
//! Field names, nesting, and value spellings match the Swift decoder in
//! `apps/mac/Sigil/Model/DaemonClient.swift` field-for-field. `PROTOCOL.md`
//! (socket) and `JSON.md` (CLI mutations) are the human indices; keep them in
//! sync with this file. Enum-like fields are plain `String` so the exact wire
//! spelling is explicit here; [`request_kind_str`] maps the proto enum to the
//! strings the Swift `RawValue` initializers expect. The lease policy is carried
//! flat as `leasable` + `max_lease_secs` for the Swift approve sheet.

use serde::{Deserialize, Serialize};

/// The `{"ok":bool,"lines":[str]}` shape every control verb returns (approve,
/// deny, lockdown, lease revoke, account remove, shim install, unpair, wipe).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResult {
    pub ok: bool,
    pub lines: Vec<String>,
}

impl ControlResult {
    pub fn ok(lines: Vec<String>) -> Self {
        Self { ok: true, lines }
    }
    pub fn failed(lines: Vec<String>) -> Self {
        Self { ok: false, lines }
    }
    /// A single-line result, the common case.
    pub fn line(ok: bool, msg: impl Into<String>) -> Self {
        Self {
            ok,
            lines: vec![msg.into()],
        }
    }
}

// --- status ----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimJson {
    /// `healthy` | `drift` | `not_installed` | `unknown`.
    pub kind: String,
    pub path: Option<String>,
    pub issue: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpJson {
    pub found: bool,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorJson {
    /// `phone` | `biometric` | `fail_closed`.
    pub kind: String,
    pub relay: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusJson {
    pub daemon_up: bool,
    pub socket: String,
    pub shim: ShimJson,
    pub op: OpJson,
    pub accounts: usize,
    pub factor: FactorJson,
    pub relay_reachable: Option<bool>,
    pub relay_url: Option<String>,
    pub locked_down: bool,
}

// --- doctor ----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckJson {
    pub label: String,
    pub ok: bool,
    pub hint: String,
}

// --- accounts --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountJson {
    /// The account id. The store keys accounts by their unique label, so
    /// `id == label` today (see JSON.md, "Known gaps").
    pub id: String,
    pub label: String,
    pub vaults: Vec<String>,
    /// `healthy` | `rotate` | `expiring`. Always `healthy`: the store keeps no
    /// token-expiry metadata (gap).
    pub health: String,
    pub detail: Option<String>,
    pub last_used_ms: Option<i64>,
}

// The rule/source config JSON is the serialized `crate::config` domain types
// (`Config`, `Source`, `Rule`), emitted directly by `sigil-config export` and
// the `--json` config verbs; there is no separate DTO here.

// --- leases ----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseJson {
    pub grant_hex: String,
    /// The calling process chain. Empty: leases retain the grant key, not the
    /// caller provenance that derived it (gap).
    pub caller: String,
    pub account: String,
    pub scope: String,
    pub granted_ms: u64,
    pub expires_ms: u64,
}

// --- history (audit) -------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryJson {
    pub id: String,
    /// A [`request_kind_str`] value.
    pub kind: String,
    pub label: String,
    pub account: String,
    pub process: String,
    pub cwd: String,
    /// `approved` | `denied` | `expired`.
    pub decision: String,
    pub note: Option<String>,
    pub at_ms: u64,
    /// How it was decided: `phone` | `biometric` | `lease` | `dev`.
    pub via: String,
}

// --- pending ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRefJson {
    pub provider: String,
    pub segments: Vec<String>,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshJson {
    pub key_label: String,
    pub host: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvJson {
    pub process_chain: Vec<String>,
    pub cwd: String,
    pub machine: String,
    pub requested_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingJson {
    pub id: String,
    pub kind: String,
    pub command: Vec<String>,
    pub secrets: Vec<SecretRefJson>,
    pub ssh: Option<SshJson>,
    pub provenance: ProvJson,
    /// Whether this request's matched rule permits a session lease. `false` =>
    /// run-once: a local approver must not offer "approve for N minutes", and the
    /// daemon refuses a lease even if one is requested.
    pub leasable: bool,
    /// The per-rule lease cap in seconds when [`leasable`](Self::leasable); `None`
    /// (omitted) for run-once. A local approver clamps any offered window to this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lease_secs: Option<u32>,
    pub reason: Option<String>,
    pub expires_ms: u64,
    pub timeout_ms: u64,
    /// Coalesced-request count. Always 0: the pending registry does not track
    /// how many identical requests wait behind one park (gap).
    pub coalesced: u32,
    /// Whether the paired phone has acknowledged receipt of this request (task
    /// #41). `false` until a sealed delivery receipt lands, and always `false` for
    /// a local (control-socket) request, which has no phone. DISPLAY ONLY: a
    /// missing receipt never changes the gating decision, only the requester's
    /// Sent -> Delivered readout ("couldn't confirm" = still `false` past a bound).
    #[serde(default)]
    pub delivered: bool,
    /// When the receipt landed, unix ms; omitted until then. Display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_at_ms: Option<u64>,
}

// --- pairing ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedJson {
    pub name: String,
    pub sas_words: Vec<String>,
    pub relay_url: String,
    pub paired_ms: u64,
}

/// One paired device in the multi-device list (#36). A superset of
/// [`PairedJson`] carrying the stable `device_id` (the `sigil pair remove`
/// handle) and the human `label`. Additive: the Swift decoder that only reads
/// `paired` ignores the `devices` array until it is taught this shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedDeviceJson {
    pub device_id: String,
    pub label: String,
    pub name: String,
    pub sas_words: Vec<String>,
    pub relay_url: String,
    pub paired_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairListJson {
    /// The primary device, for a single-device decoder (back-compat). `None` when
    /// nothing is paired.
    pub paired: Option<PairedJson>,
    /// Every paired device (#36 multi-device). Additive and omitted when empty, so
    /// an older decoder that reads only `paired` is unaffected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<PairedDeviceJson>,
}

// --- settings --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsJson {
    pub approval_timeout_sec: u32,
    pub notifications: bool,
    pub retention_days: u32,
    pub relay_url: String,
    pub reduce_motion: bool,
    /// `enabled` | `phone_only`. Not part of the Swift `SettingsDTO`; carried so
    /// `settings set` never clobbers the `mac-approvals` choice. Ignored by the
    /// GUI's decoder.
    pub mac_approvals: String,
}

// --- mac-approvals ---------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacApprovalsJson {
    pub ok: bool,
}

// --- helpers ---------------------------------------------------------------

/// The snake_case wire spelling of a [`RequestKind`](sigil_proto::RequestKind),
/// matching the phone/Swift `RequestKind` raw values.
pub fn request_kind_str(kind: sigil_proto::RequestKind) -> &'static str {
    use sigil_proto::RequestKind::*;
    match kind {
        SecretRead => "secret_read",
        SshSignature => "ssh_signature",
        Resume => "resume",
        LockdownClear => "lockdown_clear",
    }
}

/// Best-effort machine name for a request readout. Mirrors the derivation the
/// remote approver uses for the phone screen so the pending readout matches.
pub fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "this-mac".to_string())
}

/// Split a rendered provenance string (`zsh -> claude -> op`) back into its
/// root-first chain, the same way [`crate::remote`] rebuilds it for the phone.
pub fn split_provenance(provenance: &str) -> Vec<String> {
    provenance
        .split(" \u{2192} ")
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .collect()
}

/// Serialize any of the DTOs above to a single-line JSON string for stdout.
pub fn to_line<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

/// Serialize to a pretty multi-line JSON string (used for object outputs where
/// a human may also read the `--json`).
pub fn to_pretty<T: Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "null".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_result_shapes() {
        let r = ControlResult::line(true, "done");
        let v: serde_json::Value = serde_json::from_str(&to_line(&r)).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["lines"][0], "done");
    }

    #[test]
    fn request_kind_spellings_match_the_contract() {
        assert_eq!(
            request_kind_str(sigil_proto::RequestKind::SecretRead),
            "secret_read"
        );
        assert_eq!(
            request_kind_str(sigil_proto::RequestKind::SshSignature),
            "ssh_signature"
        );
        assert_eq!(
            request_kind_str(sigil_proto::RequestKind::LockdownClear),
            "lockdown_clear"
        );
    }

    #[test]
    fn provenance_round_trips_through_the_arrow_join() {
        assert_eq!(
            split_provenance("zsh \u{2192} claude \u{2192} op"),
            vec!["zsh", "claude", "op"]
        );
        assert!(split_provenance("").is_empty());
    }

    #[test]
    fn status_json_carries_the_contract_fields() {
        let s = StatusJson {
            daemon_up: true,
            socket: "/tmp/sigil/daemon.sock".into(),
            shim: ShimJson {
                kind: "healthy".into(),
                path: Some("/x/op".into()),
                issue: None,
            },
            op: OpJson {
                found: true,
                path: Some("/usr/bin/op".into()),
            },
            accounts: 2,
            factor: FactorJson {
                kind: "phone".into(),
                relay: Some("https://relay.example".into()),
            },
            relay_reachable: Some(true),
            relay_url: Some("https://relay.example".into()),
            locked_down: false,
        };
        let v: serde_json::Value = serde_json::from_str(&to_line(&s)).unwrap();
        assert_eq!(v["daemon_up"], true);
        assert_eq!(v["shim"]["kind"], "healthy");
        assert_eq!(v["op"]["found"], true);
        assert_eq!(v["factor"]["kind"], "phone");
        assert_eq!(v["factor"]["relay"], "https://relay.example");
        assert_eq!(v["locked_down"], false);
    }
}
