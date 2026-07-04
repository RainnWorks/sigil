//! The approval request/response payloads: the plaintext that rides *inside* a
//! sealed [`Envelope`](crate::Envelope).
//!
//! An [`ApprovalRequest`] carries only metadata to display (the op reference,
//! the daemon-verified provenance, a risk level); it never contains a
//! service-account token or a resolved secret. An [`ApprovalResponse`] carries
//! the decision and, on approve, the DEK the daemon needs to decrypt the one
//! token for this request. Both are serialized to JSON and sealed; the seal
//! (crypto_box to the peer's pinned agreement key, plus the sender's Ed25519
//! signature) is the confidentiality and authenticity layer, so these types are
//! plain data.
//!
//! ## Reconciliation with `apps/phone/src/protocol/requests.ts`
//!
//! The field names and shapes below are chosen to match the phone's proposed
//! TypeScript interfaces so the two sides interoperate with minimal change. All
//! structs serialize `camelCase` to line up with the TS field names. Two
//! deliberate divergences, both flagged for the phone team:
//!
//! 1. **`RequestKind`.** The design brief's request taxonomy is
//!    `op_read | op_item_get | ssh_sign | resume | lockdown_clear`, which is
//!    richer than the phone's `read_secret | ssh_signature`. The Rust enum is
//!    canonical (the brief is the constitution). The phone should map
//!    `read_secret -> op_read`/`op_item_get` and `ssh_signature -> ssh_sign`,
//!    and add `resume`/`lockdown_clear`. The optional `secret` / `ssh` payload
//!    fields are unchanged: `secret` is present for `op_read`/`op_item_get`,
//!    `ssh` for `ssh_sign`.
//! 2. **`wrappedDek`.** The phone's comment imagines a Secure-Enclave re-wrap of
//!    the DEK to the request's ephemeral key. This build does not do a second
//!    wrap: the whole `ApprovalResponse` is already sealed in an [`Envelope`] to
//!    the daemon's pinned agreement key (fresh ephemeral per response for
//!    forward secrecy against sender-key compromise, plus the phone's Ed25519
//!    signature), reusing the audited hostile-relay path. `wrappedDek` therefore
//!    carries the standard-base64 of the raw 32-byte DEK, confidential by virtue
//!    of the enclosing seal. See [`ApprovalResponse::approve`] / [`dek`].
//!
//! [`dek`]: ApprovalResponse::dek

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::pairing::Dek;

/// Risk level for the request. Scales the approve control on the phone only;
/// deny is always one tap.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Routine,
    Elevated,
    Critical,
}

/// What kind of operation the caller is asking the daemon to perform. Serializes
/// `snake_case` (`op_read`, `op_item_get`, `ssh_sign`, `resume`,
/// `lockdown_clear`).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    /// `op read op://vault/item/field` — a single secret field.
    OpRead,
    /// `op item get …` — a whole item.
    OpItemGet,
    /// An SSH signature over a challenge (see [`SshChallenge`]).
    SshSign,
    /// Resume a session after a lockdown or a lease lapse.
    Resume,
    /// Clear an active lockdown.
    LockdownClear,
}

/// A secret read, segmented for the phone's readout well.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    /// 1Password account label, e.g. "Rowm work".
    pub account: String,
    pub vault: String,
    /// The item name; rendered brightest in the well.
    pub item: String,
    /// Field within the item, e.g. "access-key". Empty for a whole-item get.
    pub field: String,
}

/// An SSH signature challenge: the two things worth verifying before signing.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SshChallenge {
    pub key_label: String,
    pub host: String,
    /// Challenge fingerprint, e.g. "SHA256:…".
    pub fingerprint: String,
}

/// Daemon-verified provenance. Never built from anything the client claimed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    /// Resolved ancestor chain, root-first, e.g. `["zsh", "claude", "op"]`.
    pub process_chain: Vec<String>,
    pub cwd: String,
    pub machine: String,
    /// When the daemon queued the request, unix ms.
    pub requested_at: u64,
}

/// The request the daemon seals to the phone.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequest {
    /// Correlates the response to the request. The phone echoes it back.
    pub request_id: String,
    pub kind: RequestKind,
    pub account_label: String,
    /// Present for `op_read` / `op_item_get`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub secret: Option<SecretRef>,
    /// Present for `ssh_sign`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ssh: Option<SshChallenge>,
    pub provenance: Provenance,
    pub risk: RiskLevel,
    /// One reason line for elevated / critical requests.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    /// Absolute expiry, unix ms.
    pub expires_at: u64,
    /// Full-scale window for the countdown gauge, ms.
    pub timeout_ms: u64,
}

/// The decision the phone seals back. Serializes `approved` / `denied`.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approved,
    Denied,
}

/// An "approve for this session" grant the daemon may install as a lease.
///
/// The daemon derives and trusts its *own* grant key from the kernel-verified
/// caller; `grant_key` here is echoed for the phone's display only and is not
/// trusted by the daemon when it installs the lease. `ttl_ms` is the requested
/// session length.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InstallLease {
    pub grant_key: String,
    pub ttl_ms: u64,
}

/// A "deny and block" directive: refuse and mute this process for a while.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BlockDirective {
    pub process: String,
    pub duration_ms: u64,
}

/// The response the phone seals to the daemon.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalResponse {
    pub request_id: String,
    pub decision: Decision,
    /// On approve: standard-base64 of the raw 32-byte DEK. Absent on deny.
    /// Confidential by virtue of the enclosing sealed [`Envelope`]; see the
    /// module divergence note.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub wrapped_dek: Option<String>,
    /// On "approve for this session": the requested lease, else absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lease: Option<InstallLease>,
    /// On "deny and block": the process to mute and for how long, else absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub block: Option<BlockDirective>,
    pub decided_at: u64,
}

impl ApprovalResponse {
    /// Build an approve response carrying the DEK (standard-base64).
    pub fn approve(request_id: &str, dek: &Dek, decided_at: u64) -> Self {
        Self {
            request_id: request_id.to_string(),
            decision: Decision::Approved,
            wrapped_dek: Some(B64.encode(dek.as_bytes())),
            lease: None,
            block: None,
            decided_at,
        }
    }

    /// Build a deny response. Carries no DEK, so a denial cannot release a token.
    pub fn deny(request_id: &str, decided_at: u64) -> Self {
        Self {
            request_id: request_id.to_string(),
            decision: Decision::Denied,
            wrapped_dek: None,
            lease: None,
            block: None,
            decided_at,
        }
    }

    /// Attach a session lease to an approve response.
    pub fn with_lease(mut self, lease: InstallLease) -> Self {
        self.lease = Some(lease);
        self
    }

    /// Decode the carried DEK, if any. Returns `None` on a denial or if the
    /// base64 does not decode to exactly 32 bytes (fail closed: a malformed DEK
    /// yields no key rather than a partial one).
    pub fn dek(&self) -> Option<Dek> {
        let b64 = self.wrapped_dek.as_ref()?;
        let bytes = B64.decode(b64).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(Dek::from_bytes(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serializes_camel_case_and_omits_absent_options() {
        let req = ApprovalRequest {
            request_id: "req-1".into(),
            kind: RequestKind::OpRead,
            account_label: "Rowm".into(),
            secret: Some(SecretRef {
                account: "Rowm".into(),
                vault: "Engineering".into(),
                item: ".env".into(),
                field: "password".into(),
            }),
            ssh: None,
            provenance: Provenance {
                process_chain: vec!["zsh".into(), "op".into()],
                cwd: "/p".into(),
                machine: "mac".into(),
                requested_at: 1_720_000_000_000,
            },
            risk: RiskLevel::Routine,
            reason: None,
            expires_at: 1_720_000_090_000,
            timeout_ms: 90_000,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"requestId\":\"req-1\""));
        assert!(json.contains("\"kind\":\"op_read\""));
        assert!(json.contains("\"accountLabel\":\"Rowm\""));
        assert!(json.contains("\"requestedAt\":1720000000000"));
        assert!(json.contains("\"risk\":\"routine\""));
        // Absent options are omitted, not serialized as null.
        assert!(!json.contains("\"ssh\""));
        assert!(!json.contains("\"reason\""));
        // Round-trips.
        let back: ApprovalRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn approve_carries_the_dek_and_deny_never_does() {
        let dek = Dek::from_bytes([7u8; 32]);
        let ok = ApprovalResponse::approve("req-1", &dek, 42);
        assert_eq!(ok.decision, Decision::Approved);
        assert_eq!(ok.dek().unwrap().as_bytes(), dek.as_bytes());

        let no = ApprovalResponse::deny("req-1", 42);
        assert_eq!(no.decision, Decision::Denied);
        assert!(no.dek().is_none());
    }

    #[test]
    fn response_round_trips_through_json() {
        let dek = Dek::from_bytes([3u8; 32]);
        let resp = ApprovalResponse::approve("r", &dek, 9).with_lease(InstallLease {
            grant_key: "abcd".into(),
            ttl_ms: 900_000,
        });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"wrappedDek\""));
        assert!(json.contains("\"ttlMs\":900000"));
        let back: ApprovalResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, resp);
        assert_eq!(back.dek().unwrap().as_bytes(), dek.as_bytes());
    }

    #[test]
    fn malformed_dek_base64_fails_closed_to_none() {
        let mut resp = ApprovalResponse::deny("r", 1);
        resp.wrapped_dek = Some("not-base64!!".into());
        assert!(resp.dek().is_none());
        // Right base64, wrong length.
        resp.wrapped_dek = Some(B64.encode([0u8; 16]));
        assert!(resp.dek().is_none());
    }
}
