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

/// Per-rule **lease policy**: whether the approver may grant an auto-approve
/// window for this request, and its cap. This replaces the retired risk tier
/// (routine/elevated/critical), which only scaled approve-control friction and
/// gated nothing.
///
/// * [`RunOnce`](Self::RunOnce): every invocation needs a fresh phone approval;
///   a lease is NEVER offered or granted (and the daemon refuses one even if a
///   compromised approver tries to install it).
/// * [`Leasable`](Self::Leasable): the approver MAY grant an auto-approve window
///   up to `max_secs`; a longer request is clamped down to the cap by the daemon.
///
/// The **default is [`RunOnce`](Self::RunOnce)** — the safe default: a rule only
/// becomes leasable when explicitly set. It rides *inside* the sealed/signed
/// [`Envelope`](crate::Envelope): it is part of what the approver consents to, so
/// the phone can offer "approve for N minutes" only when the rule allows it.
///
/// One tap approves on the phone regardless of policy; policy governs only
/// whether that tap may *also* open a lease window, never the friction of the tap.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum LeasePolicy {
    /// Fresh approval every invocation; no lease is ever offered or granted. The
    /// default: a rule leases only when explicitly made leasable.
    #[default]
    RunOnce,
    /// The approver may grant a session lease up to `max_secs` seconds. The field
    /// is renamed explicitly (the enum-level `rename_all` renames only the variant
    /// tags, not struct-variant fields) so the wire spelling is `maxSecs`.
    Leasable {
        #[serde(rename = "maxSecs")]
        max_secs: u32,
    },
}

impl LeasePolicy {
    /// Whether this policy permits any lease at all.
    pub fn is_leasable(&self) -> bool {
        matches!(self, LeasePolicy::Leasable { .. })
    }

    /// Whether this is the run-once (never-lease) policy. Used as a
    /// `skip_serializing_if` predicate so the default omits from on-disk config.
    pub fn is_run_once(&self) -> bool {
        matches!(self, LeasePolicy::RunOnce)
    }

    /// The per-rule cap in seconds if leasable, else `None` (run-once).
    pub fn max_secs(&self) -> Option<u32> {
        match self {
            LeasePolicy::Leasable { max_secs } => Some(*max_secs),
            LeasePolicy::RunOnce => None,
        }
    }

    /// Clamp a *requested* lease duration (seconds) to what this policy allows:
    /// `None` for run-once (never lease), else `min(requested, cap)`. This is the
    /// single authority a granting daemon consults, so a run-once rule cannot be
    /// leased and a leasable rule cannot be over-leased past its cap.
    pub fn clamp_secs(&self, requested_secs: u32) -> Option<u32> {
        self.max_secs().map(|cap| requested_secs.min(cap))
    }
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

/// The per-request threshold challenge for a v2 account (`docs/design/threshold-v2.md`
/// §7). Absent on v1 requests and on kinds that read no secret. It carries the
/// base point the phone must key-agree its Secure-Enclave key `f` against, plus
/// the account binding the phone shows and consents to.
///
/// **R5 (bind consent to the account shown).** `account_id`/`label` name the
/// account being unlocked; the phone MUST display `label`, bind its Face-ID
/// consent to it, and cross-check it against the [`SecretRef`]s in the readout, so
/// a mis-issued challenge cannot decouple "what the human sees" from "what gets
/// unlocked". This is display/audit context only — `ephemeral_pub` is the sole
/// cryptographic input, and it is authenticated by the enclosing signed envelope.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdChallenge {
    /// Account whose token this unlocks; echoed in the response for correlation.
    pub account_id: String,
    /// Human label of that account, shown to and consented to by the approver (R5).
    pub label: String,
    /// The account's fixed ECDH base point `E = e·G`, ANSI X9.63 (65 bytes),
    /// standard-base64. The phone validates it on-curve, then computes
    /// `Z_F = x(f·E)` against it. (`sigil-proto`'s
    /// [`P256Point`](crate::threshold::P256Point) is the canonical validator; the
    /// phone MUST use the equivalent validating decoder — R2.)
    pub ephemeral_pub: String,
    /// Which pinned SE key `F` to use (a phone may hold more than one over re-pairs).
    pub se_key_id: String,
    /// Echoes the record's `Z_F` shape so the phone picks the matching SE
    /// algorithm: `"raw-x"` or `"x963-sha256"` (see
    /// [`EcdhAlgo`](crate::threshold::EcdhAlgo)).
    pub ecdh_algo: String,
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
    /// The rule's lease policy: whether this tap may also open an auto-approve
    /// window and its cap. Rides inside the seal so it is part of what the
    /// approver consents to; the phone offers "approve for N minutes" only when
    /// this is [`LeasePolicy::Leasable`]. Defaults to [`LeasePolicy::RunOnce`]
    /// when absent, so an older/omitting peer fails safe to run-once.
    #[serde(default)]
    pub lease_policy: LeasePolicy,
    /// One optional reason line the approver renders under the command.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    /// The v2 threshold challenge for a v2 account; absent on v1 requests and on
    /// kinds that read no secret, so a v1 peer never sees it. A command reading
    /// several v2 accounts in one approval generalizes this to a
    /// `Vec<ThresholdChallenge>` keyed by `account_id` (design Q7 / R5), enumerated
    /// in the readout so one Face ID is informed consent for the whole batch; the
    /// single-account form is implemented here.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub threshold: Option<ThresholdChallenge>,
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

/// An "approve for this session" grant: the auto-approve WINDOW the approver
/// chose, and nothing more.
///
/// The zero-knowledge phone picks only a window; it cannot compute the grant key
/// (a hash of the daemon-verified caller identity the phone never sees). The
/// DAEMON is the sole lease authority: given this window it clamps to the rule's
/// [`LeasePolicy`] (run-once refuses any lease; leasable caps at `max_secs`) and
/// mints/binds the grant itself. Nothing here is trusted as a key; `ttl_ms` is the
/// requested session length, always subject to the daemon's clamp.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InstallLease {
    pub ttl_ms: u64,
}

/// A "deny and block" directive: refuse and mute this process for a while.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BlockDirective {
    pub process: String,
    pub duration_ms: u64,
}

/// The phone's ECDH partial for a v2 account (`docs/design/threshold-v2.md` §7):
/// `Z_F = x(f·E)`, the value the Secure Enclave emits under Face ID. For v2
/// accounts it replaces `wrapped_dek` — the phone no longer holds a self-sufficient
/// DEK, only its share. Confidential ONLY by virtue of the enclosing sealed
/// [`Envelope`], exactly as v1's `wrapped_dek` was.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdPartial {
    /// Echoes the challenge's account id, correlating the partial to its request.
    pub account_id: String,
    /// The SE ECDH partial `Z_F`, 32 bytes, standard-base64.
    pub zf: String,
}

/// The response the phone seals to the daemon. Provider-agnostic.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalResponse {
    pub request_id: String,
    pub decision: Decision,
    /// On a v1 approve: standard-base64 of the raw 32-byte DEK. Absent on deny and
    /// on v2 approves. Confidential by virtue of the enclosing sealed [`Envelope`];
    /// see the module divergence note.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub wrapped_dek: Option<String>,
    /// On a v2 approve: the phone's threshold partial `Z_F`, replacing
    /// `wrapped_dek`. Absent on deny and on v1 approves. Exactly one of
    /// `wrapped_dek` / `partial` is populated per approve, selected by the
    /// account's record version (R3), never by a wire field.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub partial: Option<ThresholdPartial>,
    /// On "approve for this session": the requested lease, else absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lease: Option<InstallLease>,
    /// On "deny and block": the process to mute and for how long, else absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub block: Option<BlockDirective>,
    pub decided_at: u64,
}

impl ApprovalResponse {
    /// Build a v1 approve response carrying the DEK (standard-base64).
    pub fn approve(request_id: &str, dek: &Dek, decided_at: u64) -> Self {
        Self {
            request_id: request_id.to_string(),
            decision: Decision::Approved,
            wrapped_dek: Some(B64.encode(dek.as_bytes())),
            partial: None,
            lease: None,
            block: None,
            decided_at,
        }
    }

    /// Build a v2 approve response carrying the phone's threshold partial `Z_F`
    /// (32 bytes) instead of a DEK. `account_id` echoes the challenge for
    /// correlation. Carries no DEK, so a v2 approve can never release a v1 token.
    pub fn approve_v2(request_id: &str, account_id: &str, zf: &[u8; 32], decided_at: u64) -> Self {
        Self {
            request_id: request_id.to_string(),
            decision: Decision::Approved,
            wrapped_dek: None,
            partial: Some(ThresholdPartial {
                account_id: account_id.to_string(),
                zf: B64.encode(zf),
            }),
            lease: None,
            block: None,
            decided_at,
        }
    }

    /// Build a deny response. Carries neither a DEK nor a partial, so a denial can
    /// never release a token on either the v1 or the v2 path.
    pub fn deny(request_id: &str, decided_at: u64) -> Self {
        Self {
            request_id: request_id.to_string(),
            decision: Decision::Denied,
            wrapped_dek: None,
            partial: None,
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
        // The decoded bytes are raw DEK material: hold them in a Zeroizing
        // buffer so the plaintext key does not linger in a freed heap
        // allocation after it is copied into the zeroize-on-drop `Dek`.
        let bytes = zeroize::Zeroizing::new(B64.decode(b64).ok()?);
        let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
        Some(Dek::from_bytes(arr))
    }

    /// Decode the carried v2 partial `Z_F` and its account id, if any. Returns
    /// `None` on a denial, a v1 (DEK) response, or if the base64 does not decode to
    /// exactly 32 bytes (fail closed: a malformed partial yields no share rather
    /// than a truncated one, mirroring [`Self::dek`]). The 32 bytes are held in a
    /// `Zeroizing` buffer so the raw share is wiped after use.
    pub fn partial_zf(&self) -> Option<(String, zeroize::Zeroizing<[u8; 32]>)> {
        let partial = self.partial.as_ref()?;
        let bytes = zeroize::Zeroizing::new(B64.decode(&partial.zf).ok()?);
        let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
        Some((partial.account_id.clone(), zeroize::Zeroizing::new(arr)))
    }
}

/// A phone -> daemon push-registration: the phone hands the daemon the platform
/// device token so the daemon can ring a best-effort push "doorbell" when it
/// enqueues a new approval request. See `crates/sigil/src/apns.rs`.
///
/// **Wire contract (locked, shared with `apps/phone`).** Serializes with a
/// `"type":"pushRegister"` discriminator so it can be told apart from an
/// (untagged) [`ApprovalResponse`] on the same `ToDaemon` channel; `token` is the
/// platform device token (APNs: lowercase hex), `platform` names the push
/// service (`"apns"` implemented; `"fcm"` reserved for Android).
///
/// This rides the *established session box*, not the pairing ceremony: the phone
/// seals it exactly like an [`ApprovalResponse`], with the same monotonic
/// outbound counter, so it never enters the SAS/confirmation transcript and the
/// phone may re-register at will (token rotation). It carries no request-specific
/// or secret data; the token is not itself a credential (a stolen token lets a
/// third party at most ring Tom's phone with the generic doorbell copy).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PushRegister {
    /// The wire discriminator. Always [`PushRegister::TYPE`] on a conforming
    /// message; validated by [`ToDaemonMessage::from_value`] before dispatch.
    #[serde(rename = "type")]
    pub message_type: String,
    /// The platform device token (APNs: lowercase hex). Opaque to the daemon.
    pub token: String,
    /// The push service that token addresses: `"apns"` or `"fcm"`.
    pub platform: String,
}

impl PushRegister {
    /// The locked `type` discriminator value.
    pub const TYPE: &'static str = "pushRegister";

    /// Build a registration for `token` on `platform`, stamping the discriminator.
    pub fn new(token: impl Into<String>, platform: impl Into<String>) -> Self {
        Self {
            message_type: Self::TYPE.to_string(),
            token: token.into(),
            platform: platform.into(),
        }
    }
}

/// A phone -> daemon delivery receipt (task #41): the phone seals this the instant
/// it opens and verifies an inbound [`ApprovalRequest`], so the daemon can advance
/// the requester's readout from "Sent" to "Delivered".
///
/// **Wire contract (locked, shared with `apps/phone`).** Serializes with a
/// `"type":"delivered"` discriminator so the daemon's demux tells it apart from an
/// (untagged) [`ApprovalResponse`] and a [`PushRegister`] on the same ToDaemon
/// channel; `request_id` (wire: `requestId`) names the request it acknowledges.
///
/// It rides the established session box exactly like a [`PushRegister`], with the
/// same monotonic outbound counter, so it passes through the one shared
/// [`ReplayGuard`](crate::ReplayGuard) like every other inbound message. It is NOT
/// a decision and releases nothing: it carries no DEK, partial, or lease. A
/// duplicate, late, or unknown receipt is dropped and NEVER changes a gating
/// decision, only the requester's display.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryReceipt {
    /// The wire discriminator. Always [`DeliveryReceipt::TYPE`] on a conforming
    /// message; validated by [`ToDaemonMessage::from_value`] before dispatch.
    #[serde(rename = "type")]
    pub message_type: String,
    /// The request this acknowledges receipt of; correlates to a pending request.
    pub request_id: String,
}

impl DeliveryReceipt {
    /// The locked `type` discriminator value.
    pub const TYPE: &'static str = "delivered";

    /// Build a receipt for `request_id`, stamping the discriminator.
    pub fn new(request_id: impl Into<String>) -> Self {
        Self {
            message_type: Self::TYPE.to_string(),
            request_id: request_id.into(),
        }
    }
}

/// A phone -> daemon message on an established session's `ToDaemon` channel.
///
/// Three shapes share this channel: the (untagged, legacy) [`ApprovalResponse`],
/// the tagged [`PushRegister`], and the tagged [`DeliveryReceipt`]. This is the
/// single place the daemon decides which one an opened payload is. The
/// discriminator is the `type` field: `"pushRegister"` selects [`PushRegister`],
/// `"delivered"` selects [`DeliveryReceipt`]; anything else (in practice, its
/// absence) is an [`ApprovalResponse`]. A hand-rolled peek is used deliberately
/// instead of a `#[serde(untagged)]` enum so [`ApprovalResponse`]'s wire shape
/// stays byte-for-byte unchanged (the v2 pairing transcript must not shift).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ToDaemonMessage {
    /// A decision on a pending approval.
    Response(ApprovalResponse),
    /// A push-token (re)registration.
    Push(PushRegister),
    /// A receipt acknowledging the phone opened a request. Display only: it never
    /// releases a secret and never gates a decision.
    Delivered(DeliveryReceipt),
}

impl ToDaemonMessage {
    /// Classify an already-decrypted payload [`serde_json::Value`] (the plaintext
    /// an [`Envelope`](crate::Envelope) opened to). Fails closed: a value that is
    /// none of a valid registration, receipt, or response is an error the caller
    /// drops. Opening at the [`Value`](serde_json::Value) layer keeps the single
    /// envelope decrypt/verify/replay pass and lets the tag select the concrete
    /// type without a second parse of the ciphertext.
    pub fn from_value(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        let tag = value.get("type").and_then(serde_json::Value::as_str);
        match tag {
            Some(PushRegister::TYPE) => Ok(Self::Push(serde_json::from_value(value)?)),
            Some(DeliveryReceipt::TYPE) => Ok(Self::Delivered(serde_json::from_value(value)?)),
            _ => Ok(Self::Response(serde_json::from_value(value)?)),
        }
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
            lease_policy: LeasePolicy::RunOnce,
            reason: None,
            threshold: None,
            expires_at: 1_720_000_090_000,
            timeout_ms: 90_000,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"requestId\":\"req-1\""));
        // Run-once serializes as the tagged, camelCase discriminated union.
        assert!(json.contains("\"leasePolicy\":{\"kind\":\"runOnce\"}"));
        assert!(!json.contains("\"risk\""));
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
    fn lease_policy_defaults_to_run_once_and_clamps() {
        // The default is the safe one: run-once, never leasable.
        assert_eq!(LeasePolicy::default(), LeasePolicy::RunOnce);
        assert!(!LeasePolicy::RunOnce.is_leasable());
        assert_eq!(LeasePolicy::RunOnce.max_secs(), None);
        // Run-once refuses any lease, whatever the request asks for.
        assert_eq!(LeasePolicy::RunOnce.clamp_secs(60), None);

        let leasable = LeasePolicy::Leasable { max_secs: 900 };
        assert!(leasable.is_leasable());
        assert_eq!(leasable.max_secs(), Some(900));
        // Under the cap passes through; over the cap clamps down.
        assert_eq!(leasable.clamp_secs(300), Some(300));
        assert_eq!(leasable.clamp_secs(5_000), Some(900));
        assert_eq!(leasable.clamp_secs(900), Some(900));
    }

    #[test]
    fn lease_policy_round_trips_through_json_camel_case() {
        let once = LeasePolicy::RunOnce;
        let j1 = serde_json::to_string(&once).unwrap();
        assert_eq!(j1, "{\"kind\":\"runOnce\"}");
        assert_eq!(serde_json::from_str::<LeasePolicy>(&j1).unwrap(), once);

        let leas = LeasePolicy::Leasable { max_secs: 900 };
        let j2 = serde_json::to_string(&leas).unwrap();
        assert_eq!(j2, "{\"kind\":\"leasable\",\"maxSecs\":900}");
        assert_eq!(serde_json::from_str::<LeasePolicy>(&j2).unwrap(), leas);
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
        let resp =
            ApprovalResponse::approve("r", &dek, 9).with_lease(InstallLease { ttl_ms: 900_000 });
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

    #[test]
    fn v2_challenge_is_omitted_on_v1_requests_and_round_trips_when_present() {
        // A v1-shaped request omits `threshold` entirely (a v1 peer never sees it).
        let mut req = ApprovalRequest {
            request_id: "req-1".into(),
            kind: RequestKind::SecretRead,
            command: vec!["op".into(), "read".into()],
            secrets: vec![secret_ref()],
            ssh: None,
            provenance: Provenance {
                process_chain: vec!["op".into()],
                cwd: "/p".into(),
                machine: "mac".into(),
                requested_at: 1,
            },
            lease_policy: LeasePolicy::RunOnce,
            reason: None,
            threshold: None,
            expires_at: 2,
            timeout_ms: 90_000,
        };
        assert!(!serde_json::to_string(&req).unwrap().contains("threshold"));

        req.threshold = Some(ThresholdChallenge {
            account_id: "acct-1".into(),
            label: "Rowm work".into(),
            ephemeral_pub: B64.encode([0x04u8; 65]),
            se_key_id: "se-key-1".into(),
            ecdh_algo: "raw-x".into(),
        });
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"threshold\""));
        assert!(json.contains("\"accountId\":\"acct-1\""));
        assert!(json.contains("\"ephemeralPub\""));
        assert!(json.contains("\"ecdhAlgo\":\"raw-x\""));
        let back: ApprovalRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn v2_approve_carries_the_partial_and_deny_never_does() {
        let zf = [0x5Au8; 32];
        let ok = ApprovalResponse::approve_v2("req-1", "acct-1", &zf, 42);
        assert_eq!(ok.decision, Decision::Approved);
        // A v2 approve carries the partial, never a DEK.
        assert!(ok.dek().is_none());
        assert!(ok.wrapped_dek.is_none());
        let (acct, got) = ok.partial_zf().unwrap();
        assert_eq!(acct, "acct-1");
        assert_eq!(*got, zf);

        // Deny carries neither.
        let no = ApprovalResponse::deny("req-1", 42);
        assert!(no.partial_zf().is_none());
        assert!(no.dek().is_none());

        // Wire round-trip and camelCase.
        let json = serde_json::to_string(&ok).unwrap();
        assert!(json.contains("\"partial\""));
        assert!(json.contains("\"zf\""));
        assert!(!json.contains("wrappedDek"));
        let back: ApprovalResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ok);
    }

    #[test]
    fn push_register_serializes_the_locked_wire_contract() {
        let pr = PushRegister::new("a1b2c3", "apns");
        let json = serde_json::to_string(&pr).unwrap();
        assert!(json.contains("\"type\":\"pushRegister\""));
        assert!(json.contains("\"token\":\"a1b2c3\""));
        assert!(json.contains("\"platform\":\"apns\""));
        let back: PushRegister = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pr);
    }

    #[test]
    fn to_daemon_message_classifies_by_the_type_tag() {
        // A tagged registration is a Push; the same channel's untagged response is
        // a Response. This is the daemon's demux decision, proven here.
        let pr = PushRegister::new("deadbeef", "apns");
        let push_val = serde_json::to_value(&pr).unwrap();
        assert_eq!(
            ToDaemonMessage::from_value(push_val).unwrap(),
            ToDaemonMessage::Push(pr)
        );

        let dek = Dek::from_bytes([9u8; 32]);
        let resp = ApprovalResponse::approve("req-9", &dek, 7);
        let resp_val = serde_json::to_value(&resp).unwrap();
        // An ApprovalResponse carries no `type`, so it classifies as a Response.
        assert!(resp_val.get("type").is_none());
        assert_eq!(
            ToDaemonMessage::from_value(resp_val).unwrap(),
            ToDaemonMessage::Response(resp)
        );
    }

    #[test]
    fn to_daemon_message_fails_closed_on_a_bogus_type() {
        // A payload tagged as a push but missing the required fields is an error
        // the caller drops, never a half-built registration.
        let bogus = serde_json::json!({ "type": "pushRegister" });
        assert!(ToDaemonMessage::from_value(bogus).is_err());
    }

    #[test]
    fn delivery_receipt_serializes_the_locked_wire_contract() {
        // Matches apps/phone's `{ type: "delivered", requestId }`.
        let dr = DeliveryReceipt::new("req-7");
        let json = serde_json::to_string(&dr).unwrap();
        assert!(json.contains("\"type\":\"delivered\""));
        assert!(json.contains("\"requestId\":\"req-7\""));
        let back: DeliveryReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back, dr);
    }

    #[test]
    fn to_daemon_message_classifies_a_delivery_receipt() {
        // A `"delivered"`-tagged payload is a Delivered receipt, never mistaken for
        // an ApprovalResponse (which carries no `type`).
        let dr = DeliveryReceipt::new("req-42");
        let val = serde_json::to_value(&dr).unwrap();
        assert_eq!(
            ToDaemonMessage::from_value(val).unwrap(),
            ToDaemonMessage::Delivered(dr)
        );

        // An ApprovalResponse (no `type`) still classifies as a Response, so the
        // receipt tag can never shadow a real decision.
        let dek = Dek::from_bytes([4u8; 32]);
        let resp = ApprovalResponse::approve("req-42", &dek, 1);
        let resp_val = serde_json::to_value(&resp).unwrap();
        assert!(matches!(
            ToDaemonMessage::from_value(resp_val).unwrap(),
            ToDaemonMessage::Response(_)
        ));
    }

    #[test]
    fn delivery_receipt_missing_request_id_fails_closed() {
        // A receipt tag with no request id is an error the caller drops, never a
        // half-built receipt that could touch delivery state.
        let bogus = serde_json::json!({ "type": "delivered" });
        assert!(ToDaemonMessage::from_value(bogus).is_err());
    }

    #[test]
    fn malformed_partial_base64_fails_closed_to_none() {
        let mut resp = ApprovalResponse::approve_v2("r", "a", &[1u8; 32], 1);
        resp.partial = Some(ThresholdPartial {
            account_id: "a".into(),
            zf: "not-base64!!".into(),
        });
        assert!(resp.partial_zf().is_none());
        resp.partial = Some(ThresholdPartial {
            account_id: "a".into(),
            zf: B64.encode([0u8; 16]),
        });
        assert!(resp.partial_zf().is_none());
    }
}
