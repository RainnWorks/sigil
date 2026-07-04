//! The approval request/response payloads: the plaintext that rides *inside* a
//! sealed [`Envelope`](crate::Envelope).
//!
//! **Provider-agnostic by design.** The daemon's core is generic: "run this
//! command with the approved credential injected so the command resolves its own
//! secrets." The *source* of secrets is a pluggable provider seam (1Password's
//! `op` is provider #1; bitwarden, aws-vault, doppler, an env-file are later
//! fills). This contract therefore bakes in **no** provider semantics:
//!
//! * [`ApprovalRequest::command`] is the raw argv the shim intercepted.
//! * [`ApprovalRequest::secrets`] are provider-agnostic [`SecretRef`]s: each
//!   carries an OPAQUE `reference` that only the owning provider understands,
//!   plus display-only `segments`/`label` for the approver's readout.
//! * [`RequestKind`] is a **display hint only** (how to render), never a
//!   mechanism switch (how to fulfill). The daemon's provider decides the latter.
//!
//! An [`ApprovalRequest`] never contains a credential or a resolved secret
//! value; an [`ApprovalResponse`] carries the decision and, on approve, the DEK
//! the daemon needs to decrypt the one stored credential for this request. Both
//! are serialized to JSON and sealed; the seal (crypto_box to the peer's pinned
//! agreement key, plus the sender's Ed25519 signature) is the confidentiality
//! and authenticity layer, so these types are plain data.
//!
//! ## Reconciliation with `apps/phone/src/protocol/requests.ts`
//!
//! Field names and shapes serialize `camelCase` to line up with the phone's
//! TypeScript. Three divergences from the phone's *original* op-shaped proposal,
//! all flagged for the phone team:
//!
//! 1. **`RequestKind`** is a provider-neutral display hint
//!    (`secret_read | ssh_signature | resume | lockdown_clear`), replacing the
//!    op-flavoured `read_secret | ssh_signature`. The approver switches rendering
//!    on it; it must not switch mechanism.
//! 2. **`SecretRef`** is provider-agnostic: `{ provider, reference, segments,
//!    label }` instead of the 1Password-specific `{ account, vault, item, field
//!    }`. The approver renders `segments`/`label` and stays blind to what
//!    `reference` means. `ApprovalRequest.secrets` is a *list* (a command may
//!    request several), and `command` (the argv) is now carried explicitly.
//! 3. **`wrappedDek`** is not a separate ephemeral re-wrap: the whole
//!    `ApprovalResponse` is already sealed in an [`Envelope`] to the daemon's
//!    pinned key (fresh ephemeral per response for forward secrecy against
//!    sender-key compromise, plus the phone's Ed25519 signature), reusing the
//!    audited hostile-relay path. `wrappedDek` carries the standard-base64 of the
//!    raw 32-byte DEK, confidential by virtue of the enclosing seal.

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

/// How the approver should *render* a request. A DISPLAY HINT ONLY: it tells the
/// phone which layout to show, never how the daemon fulfills the request (that
/// is the provider seam's job). Serializes `snake_case`.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    /// One or more secrets are about to be read/injected (the common case).
    SecretRead,
    /// An SSH signature over a challenge (see [`SshChallenge`]).
    SshSignature,
    /// Resume a session after a lockdown or a lease lapse.
    Resume,
    /// Clear an active lockdown.
    LockdownClear,
}

/// A provider-agnostic reference to one requested secret.
///
/// The core protocol and the approver treat `reference` as **opaque**: only the
/// daemon-side provider named by `provider` knows how to resolve it. `segments`
/// and `label` are for the approver's readout and carry no secret value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    /// The provider that resolves this reference, e.g. "1password", "aws-vault".
    pub provider: String,
    /// The opaque reference the provider understands, e.g.
    /// "op://Engineering/.env/password". The approver never parses this.
    pub reference: String,
    /// Human-readable path segments for the readout well, most-general first
    /// (e.g. `["Engineering", ".env", "password"]`). Display only.
    pub segments: Vec<String>,
    /// A short display label (e.g. the item name), rendered brightest.
    pub label: String,
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

/// The request the daemon seals to the phone. Provider-agnostic; see module docs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequest {
    /// Correlates the response to the request. The phone echoes it back.
    pub request_id: String,
    /// Display hint for the approver's layout.
    pub kind: RequestKind,
    /// The argv the shim intercepted, e.g. `["op", "read", "op://…"]`.
    pub command: Vec<String>,
    /// Provider-agnostic references to the secrets this command will resolve.
    /// Empty for kinds that read no secret (Resume, LockdownClear).
    #[serde(default)]
    pub secrets: Vec<SecretRef>,
    /// Present for `ssh_signature`.
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

/// The response the phone seals to the daemon. Provider-agnostic.
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

    fn secret_ref() -> SecretRef {
        SecretRef {
            provider: "1password".into(),
            reference: "op://Engineering/.env/password".into(),
            segments: vec!["Engineering".into(), ".env".into(), "password".into()],
            label: ".env".into(),
        }
    }

    #[test]
    fn request_serializes_camel_case_and_stays_provider_agnostic() {
        let req = ApprovalRequest {
            request_id: "req-1".into(),
            kind: RequestKind::SecretRead,
            command: vec![
                "op".into(),
                "read".into(),
                "op://Engineering/.env/password".into(),
            ],
            secrets: vec![secret_ref()],
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
        assert!(json.contains("\"kind\":\"secret_read\""));
        assert!(json.contains("\"command\":[\"op\",\"read\""));
        assert!(json.contains("\"provider\":\"1password\""));
        assert!(json.contains("\"segments\":[\"Engineering\",\".env\",\"password\"]"));
        // No op-specific field names on the wire.
        assert!(!json.contains("\"vault\""));
        assert!(!json.contains("\"accountLabel\""));
        // Absent options are omitted, not serialized as null.
        assert!(!json.contains("\"ssh\""));
        assert!(!json.contains("\"reason\""));
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
        resp.wrapped_dek = Some(B64.encode([0u8; 16]));
        assert!(resp.dek().is_none());
    }
}
