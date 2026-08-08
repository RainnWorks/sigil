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
        /// `op with --account "rowmhq.1password.eu"`.
        ///
        /// Rendered **by the daemon** from the matched rule's user-authored match
        /// conditions (rule name and match conditions are user config, not
        /// provider semantics, so this does not dent the approver's
        /// provider-blindness). It is never an argv, never a secret reference, and
        /// never a value the approver should parse or act on: it exists so the
        /// consent surface can state the breadth of the window exactly instead of
        /// hedging.
        ///
        /// Bounded to [`COVERS_MAX_CHARS`] characters and reduced to the
        /// printable-ASCII allowlist by [`LeasePolicy::with_covers`] (see
        /// [`sanitize_label`]), the only constructor the daemon uses. **Empty
        /// means "no label available"** (it is then omitted from the wire): a
        /// renderer must show no coverage clause rather than invent one.
        #[serde(rename = "covers", default, skip_serializing_if = "String::is_empty")]
        covers: String,
    },
}

/// The maximum length, in characters, of a [`LeasePolicy::Leasable`] coverage
/// label. It rides on a consent surface with a fixed caption line, so both the
/// renderer (daemon) and every reader (phone, Mac, CLI) hold to one bound.
pub const COVERS_MAX_CHARS: usize = 72;

/// The single character a label may carry from outside printable ASCII: the
/// elision mark the bound below and `Match::coverage`'s token elider both emit.
/// Permitting it is what lets an already-bounded label pass the filter unchanged.
pub const LABEL_ELLIPSIS: char = '\u{2026}';

/// What one run of rejected characters becomes. A visible marker, never a silent
/// drop: a label that had something in it must not read as though it never did,
/// and the human comparing the caption against their own rule should see that the
/// daemon would not render part of it.
///
/// **`U+FFFD REPLACEMENT CHARACTER`, because the marker has to be unforgeable.**
/// A marker drawn from the permitted alphabet cannot carry that message: an ASCII
/// `?` is `is_ascii_graphic`, so it passes the filter as ordinary content, and a
/// rule written as `argv_contains ["?"]` renders `op containing "?"` while a rule
/// pinning a Japanese vault renders `op with --vault "?"` — same glyph, same
/// position, and no way for the reader to tell "a character was removed here"
/// from "the rule really does contain a question mark". `U+FFFD` is outside
/// `is_ascii_graphic`, so it can never survive the filter as content; it is the
/// standard, self-describing mark for exactly this ("something was here that I
/// cannot show you"); and it is present in SF Pro and SF Mono, the faces every
/// surface that renders a label uses.
///
/// Stated exactly: the only input that can put this character in a label without
/// having been rejected is the character itself (it is permitted, so the filter
/// stays idempotent), and a config value that literally contains `U+FFFD` already
/// asserts what the marker asserts. Every other input either survives as ASCII or
/// becomes this mark, so a reader never has to decide which of the two happened.
pub const LABEL_REJECTED: char = '\u{fffd}';

/// Sanitize a display label for a consent surface, bounded to `max_chars`
/// characters (elided with a single-character ellipsis, not three dots, so the
/// bound is exact).
///
/// **An allowlist, deliberately, not a list of known-bad characters.** A label
/// may contain printable ASCII (`U+0021`..=`U+007E`), runs of whitespace
/// collapsed to one space, and exactly the two non-ASCII marks the daemon itself
/// emits: [`LABEL_ELLIPSIS`] and [`LABEL_REJECTED`]. Everything else becomes one
/// [`LABEL_REJECTED`] per run.
///
/// Permitting the daemon's own two marks is what makes this function **exactly
/// idempotent**: `sanitize_label(sanitize_label(x))` is `sanitize_label(x)`. That
/// is load-bearing rather than tidy, because an already-sanitized label really is
/// re-filtered at a second boundary (`sigil lease list` re-runs it over a label
/// the daemon already produced). Without the marker in the permitted set, every
/// marker would be re-marked on that path; neither mark can be forged into a
/// label from outside, so permitting them lets nothing new through.
///
/// The blocklist this replaces filtered `char::is_control` (general category
/// `Cc`) and `char::is_whitespace`, which let two families through onto the
/// phone's consent caption, where the label shares a sentence with the fixed
/// clause stating how wide the window is:
///
/// * **Category `Cf`.** An unterminated `U+202E RIGHT-TO-LEFT OVERRIDE` inside a
///   rule's flag value reorders the caption, including the half that states the
///   breadth. Zero-width characters (`U+200B`, `U+2060`, the `U+E0020` tag block)
///   hide text or split a word invisibly.
/// * **Combining marks (`Mn`/`Me`).** A pile of them on one base character
///   obscures the line it lands on while counting as one character each against
///   any length bound.
///
/// An allowlist closes both, and closes what a `Cc`/`Cf`/`Mn` blocklist would
/// still miss: characters that are neither control nor mark yet render as
/// nothing (`U+3164 HANGUL FILLER` is a letter, `U+2800 BRAILLE PATTERN BLANK`
/// is a symbol), plus whatever a future Unicode revision adds. Unknown input is
/// rejected rather than passed, which is the direction a consent surface has to
/// fail in.
///
/// The cost, stated plainly: a legitimately non-ASCII rule token (a 1Password
/// vault named `Ingénierie`) renders as `Ing\u{fffd}nierie` here, and a token
/// with no ASCII in it at all renders as one bare marker. That is accepted: this
/// string is a statement of BREADTH on a consent surface, not a faithful echo of
/// config, and the marker states where the gap is instead of leaving a hole.
///
/// It is accepted **without** pointing at another surface as the faithful one.
/// The human this filter exists for is holding a phone and cannot run a Mac CLI
/// to see what the caption elided, so the marker has to carry the whole message
/// unaided — which is exactly why it must be unforgeable. Every human-rendered
/// surface filters, `sigil-config list` included (it is a terminal, the one place
/// where an unfiltered escape does real damage). `config.json` on disk and
/// `sigil-config list --json` are the verbatim record, and `list` says so on the
/// spot whenever the filter had to change a line it drew.
pub fn sanitize_label(raw: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(raw.len().min(max_chars));
    let mut pending_space = false;
    let mut prev_rejected = false;
    for ch in raw.chars() {
        if ch.is_control() || ch.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        // The daemon's own two marks are permitted so a second pass over an
        // already-filtered label is a no-op (see the idempotence note above).
        let permitted = ch.is_ascii_graphic() || ch == LABEL_ELLIPSIS || ch == LABEL_REJECTED;
        // A run of rejected characters collapses to one marker, the same way a
        // run of whitespace collapses to one space: forty combining marks are one
        // piece of information ("something here would not render"), and repeating
        // the marker forty times would itself deform the line.
        if !permitted && prev_rejected && !pending_space {
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(if permitted { ch } else { LABEL_REJECTED });
        prev_rejected = !permitted;
    }
    if out.chars().count() > max_chars {
        out = out
            .chars()
            .take(max_chars.saturating_sub(1))
            .collect::<String>()
            .trim_end()
            .to_string();
        out.push(LABEL_ELLIPSIS);
    }
    out
}

/// [`sanitize_label`] at the coverage label's own bound. The single choke point
/// every coverage label passes through: [`LeasePolicy::with_covers`] is the only
/// constructor that sets one, and the daemon's `Config::resolve` is the only
/// caller of that.
fn sanitize_covers(raw: &str) -> String {
    sanitize_label(raw, COVERS_MAX_CHARS)
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

// --- Phone lease control: list and revoke live windows from the approver ------
//
// Four messages let the paired approver see and close the auto-approve windows
// its own taps opened. They are the second controller over a store whose first
// controller is `sigil lease revoke <prefix>` on the Mac, which is unchanged.
//
// Three properties of the surrounding system drive every design choice here, and
// none of them is obvious:
//
// 1. **The envelope counter is not a replay gate.** It was retired (see
//    [`crate::replay`]) because an in-memory counter reset on either side and
//    dropped genuine approvals. It still rides inside the signed bytes and gates
//    nothing. What protects replay is the Ed25519 signature, a
//    [`REPLAY_WINDOW_MS`](crate::REPLAY_WINDOW_MS) freshness window, and a
//    single-use uuidv7 set -- the last two in a RAM-only guard on BOTH ends, so
//    both are empty again after any restart on either side.
// 2. **A grant key is deterministic AND non-unique.** It is a hash of the
//    caller's ancestor code-identity chain plus the rule, so it recurs tomorrow;
//    and several windows with different `LeaseBinding`s share one. It is
//    therefore useless as a wire identifier in both directions at once, and it
//    never appears here.
// 3. **A reply that cannot be tied to its request is an affirmative lie waiting
//    to happen.** A relay that captured a genuine `revoked: true` can, after the
//    phone's RAM guard is gone, suppress a fresh revoke and deliver the capture
//    instead. So every reply names the envelope that asked for it.

/// The exact character width of a lease id rendered as lowercase hex (16 bytes).
pub const LEASE_ID_CHARS: usize = 32;

/// The bound every human-readable field of a [`LeaseRow`] is sanitized to. The
/// same bound as [`COVERS_MAX_CHARS`], because these strings render on the same
/// consent surface as the coverage label and must hold to one rule.
pub const LEASE_LABEL_MAX_CHARS: usize = COVERS_MAX_CHARS;

/// The fixed length bucket every lease-control plaintext is padded up to, in
/// bytes of serialized JSON.
///
/// Without it, ciphertext length is a function of how many windows are live and
/// of the exact rule names in them, all of which an attacker who has seen the
/// config can fingerprint; and a revoke is trivially shorter than any list. With
/// it, zero rows, one row and five rows are one length, and a revoke is
/// indistinguishable from a list.
///
/// **1024, not the 512 the review specified**, because 512 does not buy the
/// property the review asked for. Measured on this wire: a row is 115 bytes with
/// short labels, 169 with realistic ones (`op with --account "rowmhq.1password.eu"`),
/// and 318 with all three labels at the 72-character bound. So a 512-byte bucket
/// holds two realistic rows and rolls to a second bucket at three, which would
/// leak the row count in exactly the range that matters. 1024 holds five.
///
/// **What it does not hide, stated plainly:** the relay still learns THAT lease
/// control was used and when (a 1024-byte-bucket envelope is not an approval),
/// and a list long enough to overflow the bucket reveals that it did -- six
/// realistic rows, or four with maximal labels. Widening the bucket only moves
/// that boundary; it cannot remove it.
pub const LEASE_PAD_BUCKET: usize = 1024;

/// The filler character [`LeaseControlMessage::padded`] uses. Printable ASCII
/// that never escapes in JSON, so the padded length is exactly predictable.
const LEASE_PAD_FILL: char = '.';

/// Normalize an ASCII-hex field of exactly `chars` characters to lowercase, or
/// `None` if it is not exactly that.
///
/// The exact-width check is load-bearing, not tidiness. The store's OTHER revoke
/// entry point is prefix-matched for the CLI, and `"".starts_with(p)` holds for
/// every string, so a short or empty identifier reaching a prefix API would be a
/// silent global lease wipe reported as a success. Nothing from this module can
/// reach that API (see [`LeaseRevoke`]), and this is the second lock on the same
/// door.
fn hex_field(raw: &str, chars: usize) -> Option<String> {
    if raw.len() != chars || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(raw.to_ascii_lowercase())
}

/// The four lease-control payloads, which all pad to [`LEASE_PAD_BUCKET`].
///
/// The `pad` field is meaningless filler and a receiver MUST ignore it: never
/// display it, never sanitize it, never let its size decide anything. It exists
/// only so the ciphertext length carries no information.
///
/// Padding is a **sender** obligation and is deliberately not verified on
/// receipt. Rejecting an unpadded message would make a version skew between the
/// two halves fail silently and closed, and a revoke that vanishes is the exact
/// failure this whole feature exists to end. The residual is stated where it
/// belongs: a peer that does not pad leaks its own lengths, nobody else's.
pub trait LeaseControlMessage: Serialize + Sized {
    /// Overwrite the padding field.
    fn set_pad(&mut self, pad: String);

    /// Return this message with `pad` sized so the serialized JSON is exactly a
    /// multiple of [`LEASE_PAD_BUCKET`] bytes.
    ///
    /// Exact because `pad` always serializes (never skipped when empty), so the
    /// zero-padding measurement already includes the field's own overhead and the
    /// filler never escapes.
    fn padded(mut self) -> Self {
        self.set_pad(String::new());
        let len = serde_json::to_vec(&self).map(|v| v.len()).unwrap_or(0);
        let target = len.div_ceil(LEASE_PAD_BUCKET) * LEASE_PAD_BUCKET;
        self.set_pad(std::iter::repeat_n(LEASE_PAD_FILL, target - len).collect());
        self
    }
}

/// A phone -> daemon request to enumerate the daemon's live lease windows.
///
/// **Wire contract (locked, shared with `apps/phone`).**
/// `{"type":"leaseList","pad":"…"}`. It carries no body: the daemon lists
/// everything it holds, exactly as `sigil lease list` does, because the phone is
/// the same single human. Correlation is the ENVELOPE's uuidv7 request id, which
/// the daemon echoes as [`LeaseListReply::in_reply_to`]; there is no
/// application-level id, so there is one fewer peer-chosen string to validate and
/// echo.
///
/// It rides the established session box with the same seal, signature, and
/// [`ReplayGuard`](crate::ReplayGuard) as an [`ApprovalResponse`]. It grants
/// nothing and releases nothing: a (cryptographically impossible) forged one
/// would at most make the daemon seal a list to the pinned phone that asked.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct LeaseQuery {
    /// The wire discriminator. Always [`LeaseQuery::TYPE`] on a conforming
    /// message; validated by [`ToDaemonMessage::from_value`] before dispatch.
    #[serde(rename = "type")]
    pub message_type: String,
    /// Length-hiding filler. Ignore it; see [`LeaseControlMessage`].
    #[serde(default)]
    pub pad: String,
}

impl LeaseQuery {
    /// The locked `type` discriminator value.
    pub const TYPE: &'static str = "leaseList";

    /// Build a padded query.
    pub fn new() -> Self {
        Self {
            message_type: Self::TYPE.to_string(),
            pad: String::new(),
        }
        .padded()
    }
}

impl LeaseControlMessage for LeaseQuery {
    fn set_pad(&mut self, pad: String) {
        self.pad = pad;
    }
}

/// A phone -> daemon request to kill ONE live lease window.
///
/// **Wire contract (locked, shared with `apps/phone`).**
/// `{"type":"leaseRevoke","leaseId":"<32 hex>","pad":"…"}`.
///
/// # Why the target is an opaque lease id and never a grant key
///
/// The obvious identifier is the grant key, and it is wrong on three counts, each
/// of which alone would sink it:
///
/// * **It is not unique.** Several live windows can share one grant key with
///   different bindings, so revoking "the row I tapped" would kill unseen
///   siblings, and the reply would describe a wider action than the human
///   consented to.
/// * **It reaches a prefix-matched API.** The store's CLI revoke is prefix
///   matched, and every string starts with `""`. A truncated or empty grant key
///   arriving from the network would be a silent global lease wipe reported as a
///   success.
/// * **It is a durable correlator.** A hash of the caller's ancestor
///   code-identity chain plus the rule outlives the window it describes and would
///   sit in phone storage across re-pairs, describing the shape of the human's
///   machine.
///
/// So the wire carries a [`LeaseRow::lease_id`]: 128 opaque bits minted from the
/// platform CSPRNG when a window opens, RAM-only, dying with the window. It
/// names ONE window and asserts nothing about any other. A captured revoke
/// re-flown after a daemon restart -- authentic, in-window, and against a fresh
/// empty guard -- names an id that no longer exists and is inert.
///
/// **This message never gains a duration field.** It exists to take a window
/// away. A revoke that could also set a TTL would be a grant path reachable from
/// the network, and the daemon is structurally prevented from reaching one from
/// here (its handle exposes list and revoke only).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LeaseRevoke {
    /// The wire discriminator. Always [`LeaseRevoke::TYPE`] on a conforming
    /// message; validated by [`ToDaemonMessage::from_value`] before dispatch.
    #[serde(rename = "type")]
    pub message_type: String,
    /// The window to close, lowercase hex, exactly [`LEASE_ID_CHARS`]. Taken
    /// verbatim from a [`LeaseRow`].
    pub lease_id: String,
    /// Length-hiding filler. Ignore it; see [`LeaseControlMessage`].
    #[serde(default)]
    pub pad: String,
}

impl LeaseRevoke {
    /// The locked `type` discriminator value.
    pub const TYPE: &'static str = "leaseRevoke";

    /// Build a padded revoke for one listed window.
    pub fn new(lease_id: impl Into<String>) -> Self {
        Self {
            message_type: Self::TYPE.to_string(),
            lease_id: lease_id.into(),
            pad: String::new(),
        }
        .padded()
    }

    /// The lease id this names, validated and normalized, or `None`.
    ///
    /// Fail closed as ONE decision: a message whose target the daemon cannot parse
    /// is dropped whole, with no reply. Replying to a malformed target would echo
    /// peer-chosen bytes back onto a screen, and there is nothing useful to say --
    /// a phone that sends an id it did not read off a [`LeaseRow`] has a bug, not
    /// a window.
    pub fn target(&self) -> Option<String> {
        hex_field(&self.lease_id, LEASE_ID_CHARS)
    }
}

impl LeaseControlMessage for LeaseRevoke {
    fn set_pad(&mut self, pad: String) {
        self.pad = pad;
    }
}

/// One live lease window, as the daemon describes it to the approver.
///
/// **Everything here is display-safe by construction.** The three human-readable
/// fields go through [`sanitize_label`] at [`LEASE_LABEL_MAX_CHARS`] in
/// [`LeaseRow::new`], the only constructor the daemon uses. That is not
/// belt-and-braces: `covers` is rendered by the daemon and already filtered, but
/// `scope` is the RAW rule name out of `config.json` and `account` is the raw
/// source label, and config validation only rejects duplicates and empty matches.
/// Without this they would be the first unfiltered config text on a
/// consent-adjacent phone surface -- the exact class the coverage-label allowlist
/// was written for.
///
/// None of them is ever a raw argv, a secret reference, or a secret value:
/// `scope` is the matched RULE's name and `covers` is the coverage label, both
/// already on the consent surface the human said yes to.
///
/// A renderer must still re-filter (the phone ports this same allowlist): this
/// type describes what the daemon promises to send, not what a screen may assume
/// it received.
///
/// **No age.** A refresh extends a window without re-stamping when it was first
/// granted, so an age would read "an hour" beside a full remaining for a window
/// re-approved thirty seconds ago. A number that misleads on the common path is
/// worse than no number; `remaining_ms` against [`LeaseListReply::as_of_ms`] is
/// what a countdown actually needs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LeaseRow {
    /// This window's opaque id, lowercase hex, [`LEASE_ID_CHARS`] wide. 128 bits
    /// from the platform CSPRNG, minted when the window opens, preserved when a
    /// later approval REFRESHES it (a refresh extends one window, it does not
    /// start another), never reused, and gone when the window is. It is the row's
    /// whole identity and the only thing a [`LeaseRevoke`] may name.
    pub lease_id: String,
    /// The matched rule's name. Display must make the breadth plain: the window
    /// covers anything that rule matches for that caller chain, not the one
    /// command that opened it.
    pub scope: String,
    /// The daemon-rendered coverage label for that rule (`op read`, `op with
    /// --account "…"`). **Empty means no label was rendered**: show no coverage
    /// clause rather than inventing one, and never read empty as "narrow".
    pub covers: String,
    /// The source/account label the window injects from. Empty for a plain gate,
    /// which injects nothing.
    pub account: String,
    /// Milliseconds left before the window lapses on its own, as measured at
    /// [`LeaseListReply::as_of_ms`].
    pub remaining_ms: u64,
}

impl LeaseRow {
    /// Build a row, sanitizing every display field and validating the id. `None`
    /// when `lease_id` is not exactly-width ASCII hex, so a row the phone could
    /// not act on is never sent at all.
    pub fn new(
        lease_id: &str,
        scope: &str,
        covers: &str,
        account: &str,
        remaining_ms: u64,
    ) -> Option<Self> {
        Some(Self {
            lease_id: hex_field(lease_id, LEASE_ID_CHARS)?,
            scope: sanitize_label(scope, LEASE_LABEL_MAX_CHARS),
            covers: sanitize_label(covers, LEASE_LABEL_MAX_CHARS),
            account: sanitize_label(account, LEASE_LABEL_MAX_CHARS),
            remaining_ms,
        })
    }
}

/// The daemon's answer to a [`LeaseQuery`]: every live window, newest first.
///
/// **Wire contract (locked, shared with `apps/phone`).**
/// `{"type":"leaseListReply","inReplyTo":"<uuid>","asOfMs":int,"leases":[LeaseRow,…],"pad":"…"}`.
/// `leases` is always present and may be empty (no live windows).
///
/// See [`LeaseRevokeReply::in_reply_to`] for why the correlation is mandatory
/// and what the phone must do with it. `as_of_ms` is when the daemon measured
/// the window clocks: a renderer counts down from it and, once it is old enough
/// to distrust, must show the list as stale rather than as current.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LeaseListReply {
    /// The wire discriminator. Always [`LeaseListReply::TYPE`].
    #[serde(rename = "type")]
    pub message_type: String,
    /// The uuidv7 request id of the envelope that asked. See
    /// [`LeaseRevokeReply::in_reply_to`].
    pub in_reply_to: String,
    /// Daemon wall clock, unix ms, when these windows were measured.
    pub as_of_ms: u64,
    /// The live windows. Empty is a complete, meaningful answer: no windows.
    pub leases: Vec<LeaseRow>,
    /// Length-hiding filler. Ignore it; see [`LeaseControlMessage`].
    #[serde(default)]
    pub pad: String,
}

impl LeaseListReply {
    /// The locked `type` discriminator value.
    pub const TYPE: &'static str = "leaseListReply";

    /// Build a padded reply to the envelope `in_reply_to`, measured at `as_of_ms`.
    pub fn new(in_reply_to: impl Into<String>, as_of_ms: u64, leases: Vec<LeaseRow>) -> Self {
        Self {
            message_type: Self::TYPE.to_string(),
            in_reply_to: in_reply_to.into(),
            as_of_ms,
            leases,
            pad: String::new(),
        }
        .padded()
    }
}

impl LeaseControlMessage for LeaseListReply {
    fn set_pad(&mut self, pad: String) {
        self.pad = pad;
    }
}

/// The daemon's answer to a [`LeaseRevoke`].
///
/// **Wire contract (locked, shared with `apps/phone`).**
/// `{"type":"leaseRevokeReply","inReplyTo":"<uuid>","leaseId":"<echoed>","revoked":bool,"pad":"…"}`.
///
/// `revoked` is `true` **only** when a live window with that exact id was found
/// and zeroized. It is `false` -- never an error, never a distinguishable failure
/// -- for every other case: the window already lapsed, it was already revoked
/// (from here or from `sigil lease revoke`), or the id names nothing. The three
/// are deliberately indistinguishable, so a `false` is not an oracle for what
/// this daemon holds.
///
/// A revoke is therefore **idempotent**: sending it twice is `true` then `false`,
/// and both are successful outcomes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LeaseRevokeReply {
    /// The wire discriminator. Always [`LeaseRevokeReply::TYPE`].
    #[serde(rename = "type")]
    pub message_type: String,
    /// **The uuidv7 request id of the envelope that asked for this.**
    ///
    /// Without it, a suppressed revoke becomes an affirmative lie. The attack is
    /// routine, not exotic: a relay captures a genuine `revoked: true`; the phone
    /// is later killed or backgrounded, which empties its RAM replay guard; the
    /// human reopens the app and taps revoke; the relay swallows that request and
    /// delivers the capture instead. Genuine signature, unseen id, inside the
    /// freshness window -- and the human is told the window closed while it is
    /// open.
    ///
    /// The phone MUST therefore accept a reply only when it names a request the
    /// phone has **outstanding right now**, and must retire that request the
    /// moment it does (single-use at the application layer). That check survives
    /// what the replay guard does not: after a restart nothing is outstanding, so
    /// every captured reply is dropped. A revoke with no matching reply is
    /// **unconfirmed** -- never rendered as success, never as failure -- and the
    /// recovery is to re-list.
    pub in_reply_to: String,
    /// Echoes the revoke's normalized `leaseId`, so a phone tracking several rows
    /// attributes the answer to the right one.
    pub lease_id: String,
    /// Whether a live window with that exact id was found and killed.
    pub revoked: bool,
    /// Length-hiding filler. Ignore it; see [`LeaseControlMessage`].
    #[serde(default)]
    pub pad: String,
}

impl LeaseRevokeReply {
    /// The locked `type` discriminator value.
    pub const TYPE: &'static str = "leaseRevokeReply";

    /// Build a padded reply to the envelope `in_reply_to`.
    pub fn new(in_reply_to: impl Into<String>, lease_id: impl Into<String>, revoked: bool) -> Self {
        Self {
            message_type: Self::TYPE.to_string(),
            in_reply_to: in_reply_to.into(),
            lease_id: lease_id.into(),
            revoked,
            pad: String::new(),
        }
        .padded()
    }
}

impl LeaseControlMessage for LeaseRevokeReply {
    fn set_pad(&mut self, pad: String) {
        self.pad = pad;
    }
}

/// A daemon -> phone message on an established session's `ToPhone` channel.
///
/// Four shapes share this channel: the (untagged, legacy) [`ApprovalRequest`] and
/// the tagged [`ResolutionBroadcast`], [`LeaseListReply`], and
/// [`LeaseRevokeReply`]. This mirrors [`ToDaemonMessage`] on the return path: the
/// daemon's demux there tells a response from a tagged
/// registration/receipt/lease-control message; the phone's demux here tells a
/// request from a tagged resolution or lease reply. The discriminator is the
/// `type` field; its absence is an [`ApprovalRequest`]. A hand-rolled peek is used
/// deliberately instead of a `#[serde(untagged)]` enum so [`ApprovalRequest`]'s
/// wire shape stays byte-for-byte unchanged (the pinned vectors and the pairing
/// transcript must not shift).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ToPhoneMessage {
    /// A fresh approval request to display.
    Request(Box<ApprovalRequest>),
    /// A resolution of an already-shown request: dismiss it. Never a decision and
    /// never a release; display only.
    Resolution(ResolutionBroadcast),
    /// The live lease windows this daemon holds. Display only.
    LeaseList(LeaseListReply),
    /// The outcome of one revoke. Reports what happened; changes nothing itself.
    LeaseRevoke(LeaseRevokeReply),
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
            Some(LeaseListReply::TYPE) => Ok(Self::LeaseList(serde_json::from_value(value)?)),
            Some(LeaseRevokeReply::TYPE) => Ok(Self::LeaseRevoke(serde_json::from_value(value)?)),
            _ => Ok(Self::Request(Box::new(serde_json::from_value(value)?))),
        }
    }
}

/// A phone -> daemon message on an established session's `ToDaemon` channel.
///
/// Five shapes share this channel: the (untagged, legacy) [`ApprovalResponse`],
/// and the tagged [`PushRegister`], [`DeliveryReceipt`], [`LeaseQuery`], and
/// [`LeaseRevoke`]. This is the single place the daemon decides which one an
/// opened payload is. The discriminator is the `type` field: `"pushRegister"`,
/// `"delivered"`, `"leaseList"`, and `"leaseRevoke"` select their tagged types;
/// anything else (in practice, its absence) is an [`ApprovalResponse`]. A
/// hand-rolled peek is used deliberately instead of a `#[serde(untagged)]` enum so
/// [`ApprovalResponse`]'s wire shape stays byte-for-byte unchanged (the v2 pairing
/// transcript must not shift).
///
/// **None of the tagged shapes can be mistaken for a decision.** An
/// [`ApprovalResponse`] is the one payload with no `type` at all, so a lease
/// message can never be routed to a waiting approval, and a lease message that
/// fails to parse is an error the caller drops rather than a half-built one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ToDaemonMessage {
    /// A decision on a pending approval.
    Response(ApprovalResponse),
    /// A push-token (re)registration.
    Push(PushRegister),
    /// A receipt acknowledging the phone opened a request. Display only: it never
    /// releases a secret and never gates a decision.
    Delivered(DeliveryReceipt),
    /// A request to enumerate the daemon's live lease windows. Reads state; grants
    /// nothing.
    LeaseList(LeaseQuery),
    /// A request to kill ONE live lease window, named by grant key AND instance.
    /// It can only ever narrow what is authorized, never widen it.
    LeaseRevoke(LeaseRevoke),
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
            Some(LeaseQuery::TYPE) => Ok(Self::LeaseList(serde_json::from_value(value)?)),
            Some(LeaseRevoke::TYPE) => Ok(Self::LeaseRevoke(serde_json::from_value(value)?)),
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
        // The ellipsis is the one non-ASCII character the allowlist admits, so it
        // is what proves the truncation is counted and cut in characters.
        let wide = LeasePolicy::leasable(60).with_covers("\u{2026}".repeat(500));
        assert_eq!(wide.covers().chars().count(), COVERS_MAX_CHARS);

        // A label exactly at the bound is left alone.
        let exact = "y".repeat(COVERS_MAX_CHARS);
        assert_eq!(
            LeasePolicy::leasable(60).with_covers(&exact).covers(),
            exact
        );
    }

    /// R4-F4, the reviewer's own vectors. The choke point used to filter general
    /// category `Cc` plus whitespace, so bidi controls, zero-width characters and
    /// combining marks reached the phone's consent caption, where the label and
    /// the fixed clause stating how wide the window is share one sentence.
    #[test]
    fn covers_cannot_carry_a_character_that_reorders_or_hides_the_caption() {
        // The caption the label rides in. If the label cannot introduce a
        // direction override, a zero-width character or a combining mark, the
        // rendered sentence cannot be reordered or obscured either.
        let caption = |p: &LeasePolicy| {
            format!(
                "Covers {}: every command and secret that rule matches, from anywhere on this Mac.",
                p.covers()
            )
        };

        // Vector 1: RIGHT-TO-LEFT OVERRIDE and ZERO WIDTH SPACE inside a rule's
        // flag value. Both are category Cf, which `char::is_control` does not
        // report, and the RLO is unterminated: it reordered everything after it.
        let rlo = LeasePolicy::leasable(900)
            .with_covers("op with --account \"\u{202e}terces-on\u{200b}\"");
        assert_eq!(
            rlo.covers(),
            "op with --account \"\u{fffd}terces-on\u{fffd}\""
        );

        // Vector 2: forty combining acute accents, which survived the old filter
        // whole and sat under the bound.
        let marks =
            LeasePolicy::leasable(900).with_covers(format!("op read{}", "\u{301}".repeat(40)));
        assert_eq!(marks.covers(), "op read\u{fffd}");

        // Nothing that can move text direction, join or split a word invisibly,
        // or stack on a neighbour survives, on either vector or in the sentence
        // they render into.
        for p in [&rlo, &marks] {
            let rendered = caption(p);
            for ch in rendered.chars() {
                assert!(
                    ch.is_ascii_graphic()
                        || ch == ' '
                        || ch == LABEL_ELLIPSIS
                        || ch == LABEL_REJECTED,
                    "{ch:?} reached the consent caption: {rendered}"
                );
            }
        }

        // The rest of the families an allowlist closes and a Cc/Cf/Mn blocklist
        // would not: characters that are neither control nor mark and still
        // render as nothing, and the tag block used to smuggle whole sentences.
        let invisible = LeasePolicy::leasable(900).with_covers(
            "op\u{3164}read\u{2800}\u{e0041}\u{e0042}", // HANGUL FILLER, BRAILLE BLANK, tags
        );
        assert_eq!(invisible.covers(), "op\u{fffd}read\u{fffd}");

        // A run collapses to one marker, so a rejected pile cannot spend the
        // whole bound either.
        let pile = LeasePolicy::leasable(900).with_covers("\u{202e}".repeat(500));
        assert_eq!(pile.covers(), "\u{fffd}");

        // Ordinary labels are untouched, including the quoting and the elision
        // mark `Match::coverage` emits.
        for plain in [
            "op read",
            "op with --account \"rowmhq.1password.eu\"",
            "op with --vault \"Shared Eng\" and --account \"a\u{2026}\"",
            "op containing \"prod\", matching a pattern",
        ] {
            assert_eq!(
                LeasePolicy::leasable(900).with_covers(plain).covers(),
                plain
            );
        }
    }

    /// The exported filter is what the CLI re-runs at its own render boundary
    /// (R4-F6), so it has to hold at any bound, not just the coverage one.
    #[test]
    fn sanitize_label_holds_its_bound_at_any_width() {
        assert_eq!(sanitize_label("", 40), "");
        assert_eq!(sanitize_label("anything", 0), "");
        assert_eq!(sanitize_label("  op   read  ", 40), "op read");
        // Bounded exactly, in characters, with the elision mark inside the bound.
        let cut = sanitize_label(&"z".repeat(99), 10);
        assert_eq!(cut.chars().count(), 10);
        assert!(cut.ends_with(LABEL_ELLIPSIS));
        // A trailing space is trimmed before the mark, never elided into "x …".
        assert_eq!(sanitize_label("abcde fghij", 7), "abcde\u{2026}");
        // Control bytes never reach a terminal through it.
        assert_eq!(sanitize_label("a\u{1b}[31mb\u{7}", 40), "a [31mb");
    }

    /// The marker must mean one thing and only one thing: "the daemon would not
    /// render what was here". A marker drawn from the permitted alphabet cannot,
    /// because content could spell it. This pins the property that makes the
    /// message unambiguous — a marker in the output was PUT there by the filter.
    #[test]
    fn the_rejected_marker_cannot_be_spelled_by_a_label() {
        // It is outside the permitted set by construction, so nothing that goes
        // in as content can come out looking like the filter's own mark.
        assert!(!LABEL_REJECTED.is_ascii_graphic());

        // The old marker (`?`) is ordinary content and stays ordinary content: a
        // rule that really matches on a question mark is distinguishable, in the
        // same position, from a rule whose value would not render.
        let literal = sanitize_label("op containing \"?\"", COVERS_MAX_CHARS);
        let elided = sanitize_label("op with --vault \"\u{65e5}\u{672c}\"", COVERS_MAX_CHARS);
        assert_eq!(literal, "op containing \"?\"");
        assert_eq!(elided, "op with --vault \"\u{fffd}\"");
        assert!(!literal.contains(LABEL_REJECTED));
        assert!(elided.contains(LABEL_REJECTED));

        // The mark appears in the output exactly when the input held something the
        // filter would not render, so its presence is never ambiguous. The one
        // input that puts the mark there without being rejected is the mark
        // itself, which already means what the filter means by it.
        for (raw, marked) in [
            ("?", false),
            ("op read", false),
            ("op with --account \"a-b.c\"", false),
            ("\u{fe0f}", true),
            ("\u{202e}", true),
            ("a\u{300}b", true),
            ("\u{fffd}", true),
        ] {
            assert_eq!(
                sanitize_label(raw, COVERS_MAX_CHARS).contains(LABEL_REJECTED),
                marked,
                "marker presence is wrong for {raw:?}"
            );
        }
    }

    /// Exactly idempotent, because `sigil lease list` re-filters a label the
    /// daemon already filtered (R4-F6). Today that holds by construction: the two
    /// marks the filter emits are the two non-ASCII characters it permits. It used
    /// to hold only by the accident of the marker being ASCII.
    #[test]
    fn sanitize_label_is_idempotent() {
        for raw in [
            "",
            "op read",
            "op with --account \"\u{202e}terces-on\u{200b}\"",
            "op with --vault \"Ing\u{e9}nierie\"",
            &"\u{301}".repeat(40),
            &format!("op {}", "z".repeat(200)),
            "\u{fffd}\u{2026}",
            "op containing \"?\"",
        ] {
            for bound in [7, 40, COVERS_MAX_CHARS] {
                let once = sanitize_label(raw, bound);
                assert_eq!(
                    sanitize_label(&once, bound),
                    once,
                    "not idempotent at {bound} for {raw:?}"
                );
            }
        }
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

    // --- phone lease control -------------------------------------------------

    const LEASE_ID: &str = "fedcba9876543210fedcba9876543210";
    const REQ_ID: &str = "01920000-0000-7000-8000-00000000c0de";

    /// The JSON key set of a serialized value, for pinning what is and is not on
    /// the wire.
    fn keys<T: Serialize>(v: &T) -> Vec<String> {
        let value = serde_json::to_value(v).unwrap();
        let mut k: Vec<String> = value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
        k.sort();
        k
    }

    #[test]
    fn the_phone_to_daemon_messages_serialize_the_locked_wire_contract() {
        let q = LeaseQuery::new();
        assert_eq!(keys(&q), vec!["pad", "type"]);
        let json = serde_json::to_string(&q).unwrap();
        assert!(json.starts_with("{\"type\":\"leaseList\""));
        assert_eq!(serde_json::from_str::<LeaseQuery>(&json).unwrap(), q);

        let r = LeaseRevoke::new(LEASE_ID);
        assert_eq!(keys(&r), vec!["leaseId", "pad", "type"]);
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"type\":\"leaseRevoke\""));
        assert!(json.contains(&format!("\"leaseId\":\"{LEASE_ID}\"")));
        assert_eq!(serde_json::from_str::<LeaseRevoke>(&json).unwrap(), r);
        assert_eq!(r.target(), Some(LEASE_ID.to_string()));
    }

    /// F2/F9: a grant key must not appear anywhere on this wire, and a revoke
    /// must never gain a way to CREATE or extend a window. Both are pinned by
    /// key set rather than by review, so a future field has to break a test.
    #[test]
    fn no_lease_control_message_carries_a_grant_key_or_a_duration() {
        let row = LeaseRow::new(LEASE_ID, "op", "op read", "rowm", 60_000).unwrap();
        let payloads = [
            serde_json::to_value(LeaseQuery::new()).unwrap(),
            serde_json::to_value(LeaseRevoke::new(LEASE_ID)).unwrap(),
            serde_json::to_value(LeaseListReply::new(REQ_ID, 1, vec![row])).unwrap(),
            serde_json::to_value(LeaseRevokeReply::new(REQ_ID, LEASE_ID, true)).unwrap(),
        ];
        for p in &payloads {
            let text = serde_json::to_string(p).unwrap();
            for forbidden in [
                "grant",
                "grantHex",
                "ttl",
                "ttlMs",
                "duration",
                "durationMs",
                "secs",
                "maxSecs",
                "prefix",
                "expires",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{forbidden} must not appear in {text}"
                );
            }
        }
    }

    #[test]
    fn a_revoke_target_must_be_an_exactly_wide_hex_lease_id() {
        // The width check is what keeps a truncated or empty identifier away from
        // the store's prefix-matched CLI revoke, where "" matches everything.
        for bad in [
            "",
            &LEASE_ID[..31],
            &format!("{LEASE_ID}0"),
            &LEASE_ID.replace('0', "z"),
            &"0".repeat(64), // a grant-key-width string is not a lease id
        ] {
            assert!(
                LeaseRevoke::new(bad).target().is_none(),
                "{bad:?} must not parse as a target"
            );
        }
        // Either hex case normalizes to lowercase.
        assert_eq!(
            LeaseRevoke::new(LEASE_ID.to_uppercase()).target(),
            Some(LEASE_ID.to_string())
        );
    }

    /// F4: `scope` is the RAW rule name out of config and `account` the raw
    /// source label, so both must pass the same allowlist `covers` already does.
    #[test]
    fn a_lease_row_sanitizes_every_display_field_and_validates_the_id() {
        let row = LeaseRow::new(
            LEASE_ID,
            "op\u{202e}prod",
            "  op   read  ",
            "rowm\u{200b}hq",
            60_000,
        )
        .expect("a well-formed id");
        assert_eq!(row.scope, "op\u{fffd}prod");
        assert_eq!(row.covers, "op read");
        assert_eq!(row.account, "rowm\u{fffd}hq");
        for field in [&row.scope, &row.covers, &row.account] {
            for ch in field.chars() {
                assert!(
                    ch.is_ascii_graphic()
                        || ch == ' '
                        || ch == LABEL_ELLIPSIS
                        || ch == LABEL_REJECTED,
                    "{ch:?} reached the lease list"
                );
            }
            assert!(field.chars().count() <= LEASE_LABEL_MAX_CHARS);
        }

        // Every field is bounded, so no single row can spend an unbounded screen.
        let long = LeaseRow::new(
            LEASE_ID,
            &"s".repeat(500),
            &"c".repeat(500),
            &"a".repeat(500),
            1,
        )
        .expect("a well-formed id");
        for field in [&long.scope, &long.covers, &long.account] {
            assert_eq!(field.chars().count(), LEASE_LABEL_MAX_CHARS);
            assert!(field.ends_with(LABEL_ELLIPSIS));
        }

        // A row the phone could not act on is never built at all.
        assert!(LeaseRow::new("nope", "s", "c", "a", 1).is_none());
    }

    #[test]
    fn lease_replies_serialize_the_locked_wire_contract() {
        let row = LeaseRow::new(LEASE_ID, "op", "op read", "rowm", 60_000).unwrap();
        assert_eq!(
            keys(&row),
            vec!["account", "covers", "leaseId", "remainingMs", "scope"],
            "no grantHex and no ageMs"
        );

        let list = LeaseListReply::new(REQ_ID, 1_720_000_000_000, vec![row]);
        assert_eq!(
            keys(&list),
            vec!["asOfMs", "inReplyTo", "leases", "pad", "type"]
        );
        let json = serde_json::to_string(&list).unwrap();
        assert!(json.contains("\"type\":\"leaseListReply\""));
        assert!(json.contains(&format!("\"inReplyTo\":\"{REQ_ID}\"")));
        assert!(json.contains("\"asOfMs\":1720000000000"));
        assert!(json.contains("\"remainingMs\":60000"));
        assert_eq!(serde_json::from_str::<LeaseListReply>(&json).unwrap(), list);

        // An empty list is a complete answer, not a missing one.
        assert!(
            serde_json::to_string(&LeaseListReply::new(REQ_ID, 1, Vec::new()))
                .unwrap()
                .contains("\"leases\":[]")
        );

        let rev = LeaseRevokeReply::new(REQ_ID, LEASE_ID, true);
        assert_eq!(
            keys(&rev),
            vec!["inReplyTo", "leaseId", "pad", "revoked", "type"]
        );
        let json = serde_json::to_string(&rev).unwrap();
        assert!(json.contains("\"type\":\"leaseRevokeReply\""));
        assert!(json.contains("\"revoked\":true"));
        assert_eq!(
            serde_json::from_str::<LeaseRevokeReply>(&json).unwrap(),
            rev
        );
    }

    /// F7: every lease-control plaintext pads to a bucket boundary, so within a
    /// bucket the length carries neither the row count nor which message it is.
    /// The bounded half (what happens when a list outgrows its bucket) is asserted
    /// at the end, and proved at the ciphertext layer by the hostile-relay suite's
    /// `lease_control_is_one_ciphertext_length_within_a_bucket`.
    #[test]
    fn lease_control_plaintexts_pad_to_a_bucket_boundary() {
        let row = |n: usize| LeaseRow::new(LEASE_ID, &"s".repeat(n), "op read", "rowm", 60_000);
        let len = |v: &serde_json::Value| serde_json::to_vec(v).unwrap().len();

        // Zero, one and five REALISTIC rows are one length. Realistic is the
        // measurement the bucket was sized against: a rule name and a coverage
        // label of the shape `op with --account "rowmhq.1password.eu"`.
        let lists: Vec<serde_json::Value> = [0usize, 1, 3, 5]
            .iter()
            .map(|&n| {
                let rows = (0..n)
                    .map(|_| {
                        LeaseRow::new(
                            LEASE_ID,
                            "op-account-rowmhq",
                            "op with --account \"rowmhq.1password.eu\"",
                            "Rowm work",
                            60_000,
                        )
                        .unwrap()
                    })
                    .collect();
                serde_json::to_value(LeaseListReply::new(REQ_ID, 1, rows)).unwrap()
            })
            .collect();
        let sizes: Vec<usize> = lists.iter().map(len).collect();
        assert_eq!(
            sizes,
            vec![LEASE_PAD_BUCKET; 4],
            "row count must not move the length"
        );

        // And a revoke is indistinguishable from a list, in both directions.
        for v in [
            serde_json::to_value(LeaseQuery::new()).unwrap(),
            serde_json::to_value(LeaseRevoke::new(LEASE_ID)).unwrap(),
            serde_json::to_value(LeaseRevokeReply::new(REQ_ID, LEASE_ID, true)).unwrap(),
            serde_json::to_value(LeaseRevokeReply::new(REQ_ID, LEASE_ID, false)).unwrap(),
        ] {
            assert_eq!(len(&v), LEASE_PAD_BUCKET, "{v}");
        }

        // A list too long for one bucket rolls to the next WHOLE bucket, never to
        // an arbitrary length. This is the stated residual, pinned: overflow is
        // visible, but only as a bucket count, never as a row count.
        let big: Vec<LeaseRow> = (0..40).map(|_| row(60).unwrap()).collect();
        let overflow = serde_json::to_value(LeaseListReply::new(REQ_ID, 1, big)).unwrap();
        assert!(len(&overflow) > LEASE_PAD_BUCKET);
        assert_eq!(len(&overflow) % LEASE_PAD_BUCKET, 0);

        // The filler is inert: it never escapes, so the padded length is exact.
        let padded = LeaseQuery::new();
        assert!(padded.pad.chars().all(|c| c == '.'));

        // Padding is IDEMPOTENT, which matters for more than tidiness: a message
        // padded twice must not grow, or a resend would be a different size from
        // the original and the relay could spot it as a resend. It holds because
        // `padded` clears the field before measuring.
        for once in [
            serde_json::to_value(LeaseQuery::new().padded()).unwrap(),
            serde_json::to_value(LeaseRevoke::new(LEASE_ID).padded()).unwrap(),
            serde_json::to_value(LeaseRevokeReply::new(REQ_ID, LEASE_ID, true).padded()).unwrap(),
            serde_json::to_value(LeaseListReply::new(REQ_ID, 1, vec![row(20).unwrap()]).padded())
                .unwrap(),
        ] {
            assert_eq!(len(&once), LEASE_PAD_BUCKET, "re-padding must not grow it");
        }
    }

    #[test]
    fn lease_control_messages_classify_and_never_shadow_a_decision() {
        // Phone -> daemon: both tags select their type.
        let q = LeaseQuery::new();
        assert_eq!(
            ToDaemonMessage::from_value(serde_json::to_value(&q).unwrap()).unwrap(),
            ToDaemonMessage::LeaseList(q)
        );
        let r = LeaseRevoke::new(LEASE_ID);
        assert_eq!(
            ToDaemonMessage::from_value(serde_json::to_value(&r).unwrap()).unwrap(),
            ToDaemonMessage::LeaseRevoke(r)
        );
        // An ApprovalResponse is the only untagged payload, so a lease message can
        // never be routed to a waiting approval.
        let resp = ApprovalResponse::approve_gate("req-1", 1);
        assert!(matches!(
            ToDaemonMessage::from_value(serde_json::to_value(&resp).unwrap()).unwrap(),
            ToDaemonMessage::Response(_)
        ));

        // Daemon -> phone: both reply tags select their type.
        let list = LeaseListReply::new(REQ_ID, 1, Vec::new());
        assert_eq!(
            ToPhoneMessage::from_value(serde_json::to_value(&list).unwrap()).unwrap(),
            ToPhoneMessage::LeaseList(list)
        );
        let rev = LeaseRevokeReply::new(REQ_ID, LEASE_ID, false);
        assert_eq!(
            ToPhoneMessage::from_value(serde_json::to_value(&rev).unwrap()).unwrap(),
            ToPhoneMessage::LeaseRevoke(rev)
        );
    }

    #[test]
    fn half_built_lease_control_messages_fail_closed() {
        // A tag with missing required fields is an error the caller drops, never a
        // half-built message that could reach the lease store or a screen. `pad` is
        // the one optional field: an older peer that omits it still decodes.
        for bogus in [
            serde_json::json!({ "type": "leaseRevoke" }),
            serde_json::json!({ "type": "leaseRevoke", "pad": "" }),
        ] {
            assert!(ToDaemonMessage::from_value(bogus).is_err());
        }
        assert!(ToDaemonMessage::from_value(serde_json::json!({ "type": "leaseList" })).is_ok());
        for bogus in [
            serde_json::json!({ "type": "leaseListReply" }),
            serde_json::json!({ "type": "leaseListReply", "inReplyTo": "r" }),
            serde_json::json!({ "type": "leaseRevokeReply", "inReplyTo": "r" }),
        ] {
            assert!(ToPhoneMessage::from_value(bogus).is_err());
        }
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
