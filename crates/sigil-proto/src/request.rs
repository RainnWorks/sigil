//! The approval request/response payloads: the plaintext that rides *inside* a
//! sealed [`Envelope`](crate::Envelope).
//!
//! **Provider-agnostic by design.** The daemon's core is generic: "gate this
//! command, then run it, optionally injecting Sigil's own stored secrets." Sigil
//! does not broker other tools' credentials (`op` is a plain gated command that
//! does its own auth); the only injection is a Sigil-owned env secret, sealed at
//! rest under threshold. This contract therefore bakes in **no** provider
//! semantics:
//!
//! * [`ApprovalRequest::command`] is the raw argv the shim intercepted.
//! * [`ApprovalRequest::secrets`] are provider-agnostic [`SecretRef`]s: each
//!   carries an OPAQUE `reference` that only the owning provider understands,
//!   plus display-only `segments`/`label` for the approver's readout.
//! * [`RequestKind`] is a **display hint only** (how to render), never a
//!   mechanism switch (how to fulfill). The daemon's provider decides the latter.
//!
//! An [`ApprovalRequest`] never contains a credential or a resolved secret
//! value; an [`ApprovalResponse`] carries the decision and, for a request that
//! opens a threshold-sealed secret, the phone's per-request partial `Z_F` (which
//! is useless without the daemon's Mac share `m`). A plain gate carries no
//! partial. Both are serialized to JSON and sealed; the seal (crypto_box to the
//! peer's pinned agreement key, plus the sender's Ed25519 signature) is the
//! confidentiality and authenticity layer, so these types are plain data.
//!
//! ## Reconciliation with `apps/phone/src/protocol/requests.ts`
//!
//! Field names and shapes serialize `camelCase` to line up with the phone's
//! TypeScript. Three divergences from the phone's *original* op-shaped proposal,
//! all flagged for the phone team:
//!
//! 1. **`RequestKind`** is a provider-neutral display hint
//!    (`secret_read | ssh_signature | resume`), replacing the
//!    op-flavoured `read_secret | ssh_signature`. The approver switches rendering
//!    on it; it must not switch mechanism.
//! 2. **`SecretRef`** is provider-agnostic: `{ provider, reference, segments,
//!    label }` instead of the 1Password-specific `{ account, vault, item, field
//!    }`. The approver renders `segments`/`label` and stays blind to what
//!    `reference` means. `ApprovalRequest.secrets` is a *list* (a command may
//!    request several), and `command` (the argv) is now carried explicitly.
//! 3. **`partial`** (the threshold `Z_F`) is not a separate ephemeral re-wrap:
//!    the whole `ApprovalResponse` is already sealed in an [`Envelope`] to the
//!    daemon's pinned key (fresh ephemeral per response for forward secrecy
//!    against sender-key compromise, plus the phone's Ed25519 signature), reusing
//!    the audited hostile-relay path. `partial.zf` carries the standard-base64 of
//!    the raw 32-byte share, confidential by virtue of the enclosing seal and
//!    useless on its own (the daemon must combine it with its Mac share `m`).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum LeasePolicy {
    /// Fresh approval every invocation; no lease is ever offered or granted. The
    /// default: a rule leases only when explicitly made leasable.
    #[default]
    RunOnce,
    /// The approver may grant a session lease up to `max_secs` seconds. The fields
    /// are renamed explicitly (the enum-level `rename_all` renames only the variant
    /// tags, not struct-variant fields) so the wire spelling is `maxSecs`/`covers`.
    Leasable {
        #[serde(rename = "maxSecs")]
        max_secs: u32,
        /// **The coverage label**: a short, DISPLAY-ONLY sentence fragment naming
        /// how wide the window this tap may open is, e.g. `op read` or
        /// `op with --account rowmhq.1password.eu`.
        ///
        /// Rendered **by the daemon** from the matched rule's user-authored match
        /// conditions (rule name and match conditions are user config, not
        /// provider semantics, so this does not dent the approver's
        /// provider-blindness). It is never an argv, never a secret reference, and
        /// never a value the approver should parse or act on: it exists so the
        /// consent surface can state the breadth of the window exactly instead of
        /// hedging.
        ///
        /// Bounded to [`COVERS_MAX_CHARS`] characters and stripped of control
        /// characters by [`LeasePolicy::with_covers`], the only constructor the
        /// daemon uses. **Empty means "no label available"** (it is then omitted
        /// from the wire): a renderer must show no coverage clause rather than
        /// invent one.
        #[serde(rename = "covers", default, skip_serializing_if = "String::is_empty")]
        covers: String,
    },
}

/// The maximum length, in characters, of a [`LeasePolicy::Leasable`] coverage
/// label. It rides on a consent surface with a fixed caption line, so both the
/// renderer (daemon) and every reader (phone, Mac, CLI) hold to one bound.
pub const COVERS_MAX_CHARS: usize = 72;

/// Sanitize a coverage label for a consent surface: control characters become
/// spaces, whitespace runs collapse, and the result is bounded to
/// [`COVERS_MAX_CHARS`] characters (eliding with a single-character ellipsis, not
/// three dots, so the bound is exact).
fn sanitize_covers(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(COVERS_MAX_CHARS));
    let mut pending_space = false;
    for ch in raw.chars() {
        if ch.is_control() || ch.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(ch);
    }
    if out.chars().count() > COVERS_MAX_CHARS {
        out = out
            .chars()
            .take(COVERS_MAX_CHARS.saturating_sub(1))
            .collect::<String>()
            .trim_end()
            .to_string();
        out.push('\u{2026}');
    }
    out
}

impl LeasePolicy {
    /// A leasable policy capped at `max_secs`, with no coverage label yet. The
    /// label is attached by the daemon at resolve time via
    /// [`with_covers`](Self::with_covers); config on disk stores none.
    pub fn leasable(max_secs: u32) -> Self {
        LeasePolicy::Leasable {
            max_secs,
            covers: String::new(),
        }
    }

    /// Attach (or replace) the daemon-rendered coverage label, sanitized and
    /// bounded. A no-op on [`RunOnce`](Self::RunOnce): a run-once request opens no
    /// window, so it must carry no coverage label at all.
    pub fn with_covers(self, label: impl AsRef<str>) -> Self {
        match self {
            LeasePolicy::RunOnce => LeasePolicy::RunOnce,
            LeasePolicy::Leasable { max_secs, .. } => LeasePolicy::Leasable {
                max_secs,
                covers: sanitize_covers(label.as_ref()),
            },
        }
    }

    /// The coverage label, or `""` when there is none (run-once, or a peer that
    /// omitted it). Display only.
    pub fn covers(&self) -> &str {
        match self {
            LeasePolicy::Leasable { covers, .. } => covers,
            LeasePolicy::RunOnce => "",
        }
    }

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
            LeasePolicy::Leasable { max_secs, .. } => Some(*max_secs),
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
    /// Resume a session after a lease lapse.
    Resume,
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

/// How much the `host` field of an [`SshChallenge`] can be trusted. A STRUCTURED
/// discriminator so the approver keys "destination unverified" on structure, not
/// on parsing a sentinel string out of `host`.
///
/// The agent protocol carries no authenticated hostname (see the daemon's
/// `derive_host`), so even a [`Named`](Self::Named) binding is advisory context,
/// not a security boundary — a same-UID client can name any destination. This
/// only tells the phone which of the three honest states produced `host`.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum HostBinding {
    /// The `session-bind` host key matched a name in `~/.ssh/known_hosts`; `host`
    /// is that name.
    Named,
    /// A `session-bind` host key was captured but matched no known-hosts entry;
    /// `host` is the host key's `SHA256:…` fingerprint.
    Fingerprint,
    /// No `session-bind` was sent, so the destination is unverified; `host` is a
    /// plain marker only. The **default** so an older peer that omits the field
    /// (or any absent discriminator) is treated as unverified — fail-safe.
    #[default]
    Unbound,
}

/// An SSH signature challenge: the things worth verifying before signing.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SshChallenge {
    pub key_label: String,
    /// Best-effort destination string. Its trust level is [`Self::binding`];
    /// render "destination unverified" off that, never by parsing this string.
    pub host: String,
    /// Structured host-binding state. Additive and optional (serde `default` =
    /// [`HostBinding::Unbound`]) so an older phone that predates it ignores it and
    /// still sees `host`, per the durable-pairing principle.
    #[serde(default)]
    pub binding: HostBinding,
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
    /// Empty for kinds that read no secret (e.g. Resume).
    #[serde(default)]
    pub secrets: Vec<SecretRef>,
    /// Present for `ssh_signature`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ssh: Option<SshChallenge>,
    pub provenance: Provenance,
    /// The rule's lease policy: whether this tap may also open an auto-approve
    /// window, its cap, and (on a leasable rule) the daemon-rendered
    /// [`covers`](LeasePolicy::covers) label describing how wide that window is.
    /// Rides inside the seal so it is part of what the approver consents to; the
    /// phone offers "approve for N minutes" only when this is
    /// [`LeasePolicy::Leasable`]. Defaults to [`LeasePolicy::RunOnce`] when
    /// absent, so an older/omitting peer fails safe to run-once.
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

/// The phone's ECDH partial for a threshold-sealed secret
/// (`docs/design/threshold-v2.md` §7): `Z_F = x(f·E)`, the value the Secure
/// Enclave emits under Face ID. The phone holds only its share, never a
/// self-sufficient key. Confidential ONLY by virtue of the enclosing sealed
/// [`Envelope`].
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
    /// On an approve of a request that opens a threshold-sealed secret: the phone's
    /// threshold partial `Z_F`. Absent on deny and on approves that release no
    /// sealed secret (a plain gate). Confidential by virtue of the enclosing sealed
    /// [`Envelope`]; the daemon combines it with its Mac share `m` to open the one
    /// secret, then zeroizes both.
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
    /// Build an approve response carrying the phone's threshold partial `Z_F`
    /// (32 bytes). `account_id` echoes the challenge for correlation. This is the
    /// only approve shape: a plain gate uses [`approve_gate`](Self::approve_gate)
    /// (no secret to release), and everything sealed at rest is opened by
    /// combining this partial with the Mac share.
    pub fn approve_v2(request_id: &str, account_id: &str, zf: &[u8; 32], decided_at: u64) -> Self {
        Self {
            request_id: request_id.to_string(),
            decision: Decision::Approved,
            partial: Some(ThresholdPartial {
                account_id: account_id.to_string(),
                zf: B64.encode(zf),
            }),
            lease: None,
            block: None,
            decided_at,
        }
    }

    /// Build an approve response for a plain gate: a command Sigil gates but whose
    /// run releases no threshold-sealed secret, so no partial is carried.
    pub fn approve_gate(request_id: &str, decided_at: u64) -> Self {
        Self {
            request_id: request_id.to_string(),
            decision: Decision::Approved,
            partial: None,
            lease: None,
            block: None,
            decided_at,
        }
    }

    /// Build a deny response. Carries no partial, so a denial can never release a
    /// threshold-sealed secret.
    pub fn deny(request_id: &str, decided_at: u64) -> Self {
        Self {
            request_id: request_id.to_string(),
            decision: Decision::Denied,
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

    /// Decode the carried partial `Z_F` and its account id, if any. Returns
    /// `None` on a denial, a plain-gate approve, or if the base64 does not decode
    /// to exactly 32 bytes (fail closed: a malformed partial yields no share rather
    /// than a truncated one). The 32 bytes are held in a `Zeroizing` buffer so the
    /// raw share is wiped after use.
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

/// Why a ring-all request stopped being actionable, broadcast to the OTHER
/// paired devices so they dismiss their copy (#36 multi-device). Carries no
/// secret and no decision detail: a device learns only THAT the request is over,
/// never who resolved it or how a v1/v2 secret was released.
///
/// Serializes `snake_case` to match the phone's TypeScript union.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    /// A device approved or denied it (first-wins). The others dismiss it; the
    /// zero-knowledge broadcast deliberately does not say which of the two.
    Settled,
    /// The request timed out on the daemon before any device answered.
    Expired,
    /// The daemon withdrew it (restart, or the requester went away).
    Withdrawn,
}

/// A daemon -> phone resolution broadcast (#36 multi-device ring-all / first-wins).
///
/// When a gated request has been deposited to EVERY paired device and one of them
/// resolves it (or it expires / is withdrawn), the daemon seals this per-device to
/// the OTHER devices so their pending sheet dismisses instead of lingering until
/// its own timeout. It is the ToPhone-direction sibling of the phone's
/// [`DeliveryReceipt`]: metadata only, releases nothing, gates nothing.
///
/// **Wire contract (shared with `apps/phone`).** Serializes with a
/// `"type":"resolution"` discriminator so the phone's inbound demux tells it apart
/// from an (untagged) [`ApprovalRequest`] on the same ToPhone channel; `request_id`
/// (wire: `requestId`) names the request it settles, and `status` says why.
///
/// It is sealed, signed, and replay-protected exactly like every other envelope on
/// the daemon->phone counter, so a hostile relay can neither forge one (to dismiss
/// a real pending request the human should still see) nor replay one. Because it is
/// zero-knowledge, a forged-but-somehow-valid one could at worst hide a prompt, and
/// hiding a prompt only ever fails closed (the secret is not released); it can never
/// cause a release.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionBroadcast {
    /// The wire discriminator. Always [`ResolutionBroadcast::TYPE`] on a conforming
    /// message; validated by [`ToPhoneMessage::from_value`] before dispatch.
    #[serde(rename = "type")]
    pub message_type: String,
    /// The request this settles; correlates to a pending request on the phone.
    pub request_id: String,
    /// Why it is no longer actionable.
    pub status: ResolutionStatus,
}

impl ResolutionBroadcast {
    /// The locked `type` discriminator value.
    pub const TYPE: &'static str = "resolution";

    /// Build a broadcast for `request_id` with `status`, stamping the discriminator.
    pub fn new(request_id: impl Into<String>, status: ResolutionStatus) -> Self {
        Self {
            message_type: Self::TYPE.to_string(),
            request_id: request_id.into(),
            status,
        }
    }
}

/// A daemon -> phone message on an established session's `ToPhone` channel.
///
/// Two shapes share this channel: the (untagged, legacy) [`ApprovalRequest`] and
/// the tagged [`ResolutionBroadcast`]. This mirrors [`ToDaemonMessage`] on the
/// return path: the daemon's demux there tells a response from a tagged
/// registration/receipt; the phone's demux here tells a request from a tagged
/// resolution. The discriminator is the `type` field: `"resolution"` selects
/// [`ResolutionBroadcast`]; its absence is an [`ApprovalRequest`]. A hand-rolled
/// peek is used deliberately instead of a `#[serde(untagged)]` enum so
/// [`ApprovalRequest`]'s wire shape stays byte-for-byte unchanged (the pinned
/// vectors and the pairing transcript must not shift).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ToPhoneMessage {
    /// A fresh approval request to display.
    Request(Box<ApprovalRequest>),
    /// A resolution of an already-shown request: dismiss it. Never a decision and
    /// never a release; display only.
    Resolution(ResolutionBroadcast),
}

impl ToPhoneMessage {
    /// Classify an already-decrypted payload [`serde_json::Value`] (the plaintext an
    /// [`Envelope`](crate::Envelope) opened to). Fails closed: a value that is
    /// neither a valid resolution nor a valid request is an error the caller drops.
    /// A `ResolutionBroadcast` is boxed-free (small); an `ApprovalRequest` is boxed
    /// to keep the enum small.
    pub fn from_value(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        let tag = value.get("type").and_then(serde_json::Value::as_str);
        match tag {
            Some(ResolutionBroadcast::TYPE) => Ok(Self::Resolution(serde_json::from_value(value)?)),
            _ => Ok(Self::Request(Box::new(serde_json::from_value(value)?))),
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
    fn ssh_challenge_host_binding_is_additive_and_defaults_unbound() {
        // A new challenge carries the structured discriminator on the wire.
        let ch = SshChallenge {
            key_label: "GitHub".into(),
            host: "github.com".into(),
            binding: HostBinding::Named,
            fingerprint: "SHA256:abc".into(),
        };
        let json = serde_json::to_string(&ch).unwrap();
        assert!(json.contains("\"binding\":\"named\""));
        assert_eq!(serde_json::from_str::<SshChallenge>(&json).unwrap(), ch);

        // An OLDER phone's message predates `binding`: it must still deserialize,
        // defaulting to the fail-safe Unbound (durable-pairing principle).
        let legacy =
            r#"{"keyLabel":"GitHub","host":"(host not bound)","fingerprint":"SHA256:abc"}"#;
        let back: SshChallenge = serde_json::from_str(legacy).unwrap();
        assert_eq!(back.binding, HostBinding::Unbound);
        assert_eq!(HostBinding::default(), HostBinding::Unbound);
    }

    #[test]
    fn lease_policy_defaults_to_run_once_and_clamps() {
        // The default is the safe one: run-once, never leasable.
        assert_eq!(LeasePolicy::default(), LeasePolicy::RunOnce);
        assert!(!LeasePolicy::RunOnce.is_leasable());
        assert_eq!(LeasePolicy::RunOnce.max_secs(), None);
        // Run-once refuses any lease, whatever the request asks for.
        assert_eq!(LeasePolicy::RunOnce.clamp_secs(60), None);

        let leasable = LeasePolicy::leasable(900);
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

        // No coverage label: `covers` is omitted entirely, so the wire shape is
        // byte-identical to the pre-coverage protocol.
        let leas = LeasePolicy::leasable(900);
        let j2 = serde_json::to_string(&leas).unwrap();
        assert_eq!(j2, "{\"kind\":\"leasable\",\"maxSecs\":900}");
        assert_eq!(serde_json::from_str::<LeasePolicy>(&j2).unwrap(), leas);

        // With a label it rides alongside the cap, and an omitting peer decodes
        // to the empty label (fails safe to "no coverage clause", never invented).
        let covered = LeasePolicy::leasable(900).with_covers("op read");
        let j3 = serde_json::to_string(&covered).unwrap();
        assert_eq!(
            j3,
            "{\"kind\":\"leasable\",\"maxSecs\":900,\"covers\":\"op read\"}"
        );
        assert_eq!(serde_json::from_str::<LeasePolicy>(&j3).unwrap(), covered);
        assert_eq!(covered.covers(), "op read");
        assert_eq!(
            serde_json::from_str::<LeasePolicy>("{\"kind\":\"leasable\",\"maxSecs\":900}")
                .unwrap()
                .covers(),
            ""
        );
    }

    #[test]
    fn covers_is_sanitized_bounded_and_never_set_on_run_once() {
        // A run-once policy opens no window, so it can carry no coverage label.
        assert_eq!(
            LeasePolicy::RunOnce.with_covers("op read"),
            LeasePolicy::RunOnce
        );
        assert_eq!(LeasePolicy::RunOnce.covers(), "");

        // Control characters and whitespace runs cannot deform the consent
        // surface: they collapse to single spaces and the ends are trimmed.
        let messy = LeasePolicy::leasable(60).with_covers("  op\n\tread   with\r\n--vault  ");
        assert_eq!(messy.covers(), "op read with --vault");

        // The bound is exact, counted in characters, and marked with an ellipsis.
        let long = LeasePolicy::leasable(60).with_covers("x".repeat(500));
        assert_eq!(long.covers().chars().count(), COVERS_MAX_CHARS);
        assert!(long.covers().ends_with('\u{2026}'));

        // Multi-byte characters are truncated on a char boundary, not a byte one.
        let wide = LeasePolicy::leasable(60).with_covers("\u{e9}".repeat(500));
        assert_eq!(wide.covers().chars().count(), COVERS_MAX_CHARS);

        // A label exactly at the bound is left alone.
        let exact = "y".repeat(COVERS_MAX_CHARS);
        assert_eq!(
            LeasePolicy::leasable(60).with_covers(&exact).covers(),
            exact
        );
    }

    #[test]
    fn plain_gate_approve_carries_no_partial_and_deny_never_does() {
        let ok = ApprovalResponse::approve_gate("req-1", 42);
        assert_eq!(ok.decision, Decision::Approved);
        assert!(ok.partial_zf().is_none());

        let no = ApprovalResponse::deny("req-1", 42);
        assert_eq!(no.decision, Decision::Denied);
        assert!(no.partial_zf().is_none());
    }

    #[test]
    fn response_round_trips_through_json() {
        let resp =
            ApprovalResponse::approve_gate("r", 9).with_lease(InstallLease { ttl_ms: 900_000 });
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ttlMs\":900000"));
        let back: ApprovalResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, resp);
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
        let (acct, got) = ok.partial_zf().unwrap();
        assert_eq!(acct, "acct-1");
        assert_eq!(*got, zf);

        // Deny carries no partial.
        let no = ApprovalResponse::deny("req-1", 42);
        assert!(no.partial_zf().is_none());

        // Wire round-trip and camelCase.
        let json = serde_json::to_string(&ok).unwrap();
        assert!(json.contains("\"partial\""));
        assert!(json.contains("\"zf\""));
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

        let resp = ApprovalResponse::approve_gate("req-9", 7);
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
        let resp = ApprovalResponse::approve_gate("req-42", 1);
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
    fn resolution_broadcast_serializes_the_locked_wire_contract() {
        // Matches apps/phone's `{ type: "resolution", requestId, status }`.
        let rb = ResolutionBroadcast::new("req-7", ResolutionStatus::Settled);
        let json = serde_json::to_string(&rb).unwrap();
        assert!(json.contains("\"type\":\"resolution\""));
        assert!(json.contains("\"requestId\":\"req-7\""));
        assert!(json.contains("\"status\":\"settled\""));
        let back: ResolutionBroadcast = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rb);

        // Every status round-trips with its snake_case wire spelling.
        for (status, wire) in [
            (ResolutionStatus::Settled, "settled"),
            (ResolutionStatus::Expired, "expired"),
            (ResolutionStatus::Withdrawn, "withdrawn"),
        ] {
            let j = serde_json::to_string(&ResolutionBroadcast::new("r", status)).unwrap();
            assert!(j.contains(&format!("\"status\":\"{wire}\"")));
        }
    }

    #[test]
    fn to_phone_message_classifies_by_the_type_tag() {
        // A tagged resolution is a Resolution; an untagged ApprovalRequest is a
        // Request. This is the phone's inbound demux decision, proven here.
        let rb = ResolutionBroadcast::new("req-9", ResolutionStatus::Withdrawn);
        let rb_val = serde_json::to_value(&rb).unwrap();
        assert_eq!(
            ToPhoneMessage::from_value(rb_val).unwrap(),
            ToPhoneMessage::Resolution(rb)
        );

        let req = ApprovalRequest {
            request_id: "req-9".into(),
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
        let req_val = serde_json::to_value(&req).unwrap();
        // An ApprovalRequest carries no `type`, so it classifies as a Request.
        assert!(req_val.get("type").is_none());
        assert_eq!(
            ToPhoneMessage::from_value(req_val).unwrap(),
            ToPhoneMessage::Request(Box::new(req))
        );
    }

    #[test]
    fn to_phone_message_fails_closed_on_a_bogus_resolution() {
        // A payload tagged as a resolution but missing the required fields is an
        // error the caller drops, never a half-built dismissal that could hide a
        // real pending prompt.
        let bogus = serde_json::json!({ "type": "resolution" });
        assert!(ToPhoneMessage::from_value(bogus).is_err());
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
