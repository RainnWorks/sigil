/**
 * The approval request/response payloads: the plaintext that rides *inside* a
 * sealed envelope. This byte-matches crates/sigil-proto/src/request.rs (camelCase
 * serde on the Rust side); keep the two in lockstep.
 *
 * **Provider-agnostic by design.** The daemon's core is generic: "run this
 * command with the approved credential injected so the command resolves its own
 * secrets." The *source* of secrets is a pluggable provider seam (1Password's
 * `op` is provider #1; bitwarden, aws-vault, doppler, an env-file are later
 * fills). This contract bakes in no provider semantics: `command` is the raw
 * argv, `secrets` are opaque provider references with display-only readout data,
 * and `kind` is a DISPLAY HINT ONLY (how to render), never a mechanism switch
 * (how to fulfill).
 *
 * The phone never sees a service-account token or a resolved secret value. A
 * request carries only metadata to display; a response carries the decision and,
 * on an approve that opens a threshold-sealed secret, the phone's per-request
 * partial `Z_F`. The whole response is sealed in an envelope, so `partial.zf` is
 * confidential by virtue of the enclosing seal. A plain gate carries no partial.
 */

/**
 * How the approver should *render* a request. A DISPLAY HINT ONLY: it selects a
 * layout, never how the daemon fulfills the request (that is the provider seam's
 * job). Serializes snake_case to match the Rust enum.
 */
export type RequestKind = "secret_read" | "ssh_signature" | "resume";

/**
 * A provider-agnostic reference to one requested secret. `reference` is OPAQUE:
 * only the daemon-side provider named by `provider` knows how to resolve it, and
 * the approver never parses it. The readout well is rendered from `segments` and
 * `label`, never from `reference`.
 */
export interface SecretRef {
  /** The provider that resolves this reference, e.g. "1password", "aws-vault". */
  provider: string;
  /** The opaque reference the provider understands. Never parsed on the phone. */
  reference: string;
  /**
   * Human-readable path segments for the readout well, most-general first
   * (e.g. ["Engineering", ".env", "password"]). Display only.
   */
  segments: string[];
  /** A short display label (e.g. the item name), rendered brightest. */
  label: string;
}

/**
 * A grant the daemon has marked leasable. When present on a request, the
 * approver may either approve once or approve and keep the grant approved for a
 * window up to `maxSecs`; when absent the request is run-once (approve-once
 * only). This is an OFFER the daemon extends, never a provider/account concept
 * the phone interprets: the phone shows a duration and, on an approve-with-a-
 * window, echoes back the chosen window (never a grant key it cannot compute).
 *
 * Mirrors proto `LeasePolicy` (serde `{"kind":"leasable","maxSecs":N}`). See the
 * daemon-side counterpart note at the bottom of this file.
 */
export interface LeasePolicy {
  kind: "leasable";
  /** The longest lease window the daemon will honor for this grant, in seconds. */
  maxSecs: number;
  /**
   * The daemon's own one-line description of how wide the window is, e.g.
   * `op read`, `op with --account "rowmhq.1password.eu"`, or
   * `any command with the subcommand read`. Rendered by the daemon from the
   * user's rule match conditions, so the phone can state the breadth exactly
   * instead of guessing it from argv.
   *
   * DISPLAY ONLY, and strictly so: render it, never parse it, never branch
   * behavior on it. It is never an argv, never a secret reference, and never
   * client-supplied; it arrives inside the sealed, signed request like every
   * other display field.
   *
   * Absent on run-once and omitted when empty. Absent/empty means the sheet has
   * no daemon-stated breadth to show (an older daemon), never that the window is
   * narrow. The daemon guarantees at most `COVERS_MAX_CHARS` characters, no
   * control characters or newlines, whitespace already collapsed, and a single
   * "…" for any elision; `coverageLabel` (src/lib/format.ts) re-applies that
   * bound for layout rather than trusting it.
   */
  covers?: string;
}

/**
 * The longest coverage label the daemon will send, mirroring proto
 * `COVERS_MAX_CHARS`. The phone treats it as a layout bound it re-applies, not
 * as a promise it depends on.
 */
export const COVERS_MAX_CHARS = 72;

/**
 * The trust level of an SSH challenge's `host`, mirroring proto `HostBinding`
 * (serde snake_case). Additive and defaulted to `unbound` so an older daemon
 * that omits it is treated as unverified (fail-safe). Render the destination's
 * trust off THIS, never by parsing the `host` string.
 *   named       - a session-bind host key matched ~/.ssh/known_hosts; `host` is that name.
 *   fingerprint - a host key was captured but matched nothing; `host` is its SHA256:… fingerprint.
 *   unbound     - no session-bind was sent; the destination is unverified and `host` is a marker only.
 */
export type HostBinding = "named" | "fingerprint" | "unbound";

/** An SSH signature: the things worth verifying before signing. */
export interface SshChallenge {
  keyLabel: string;
  /**
   * Best-effort destination string. Its trust level is {@link binding}; render
   * "destination unverified" off that, never by parsing this string.
   */
  host: string;
  /**
   * Structured host-binding state. Optional/defaulted to `"unbound"` so a request
   * that predates the field is treated as unverified.
   */
  binding?: HostBinding;
  /** Challenge fingerprint, e.g. "SHA256:….". */
  fingerprint: string;
}

/** Which shape the Secure Enclave's ECDH output takes; mirrors proto EcdhAlgo. */
export type EcdhAlgo = "raw-x" | "x963-sha256";

/**
 * The per-request v2 threshold challenge (docs/design/threshold-v2.md §7),
 * mirroring proto `ThresholdChallenge`. Absent on v1 requests and on kinds that
 * read no secret. It carries the base point the phone key-agrees its
 * Secure-Enclave key `f` against, plus an opaque routing tag the crypto needs.
 *
 * The phone is a zero-knowledge approver: `accountId` is treated purely as an
 * opaque tag telling the enclave which pinned key `f` to agree with (and is
 * echoed back for correlation), never as an account concept the phone displays
 * or reasons about. `label` is retained for wire-compatibility with the daemon /
 * proto but is NOT shown or interpreted here. `ephemeralPub` is the only
 * cryptographic input and is authenticated by the enclosing signed envelope.
 */
export interface ThresholdChallenge {
  /** Opaque routing tag: selects the pinned SE key to agree with; echoed for correlation. */
  accountId: string;
  /** Retained for wire-compatibility with proto; the provider-blind phone ignores it. */
  label: string;
  /**
   * The account's fixed ECDH base point `E = e·G`, ANSI X9.63 (65 bytes),
   * standard-base64. The phone validates it on-curve (R2), then computes
   * `Z_F = x(f·E)` against it.
   */
  ephemeralPub: string;
  /** Which pinned SE key `F` to use (a phone may hold more than one over re-pairs). */
  seKeyId: string;
  /** Echoes the record's `Z_F` shape so the phone picks the matching SE algorithm. */
  ecdhAlgo: EcdhAlgo;
}

/**
 * The phone's ECDH partial for a v2 account, mirroring proto `ThresholdPartial`:
 * `Z_F = x(f·E)`, the value the Secure Enclave emits under Face ID. The phone
 * holds no self-sufficient at-rest key, only this per-request share; the daemon
 * combines it with its Mac share `m` to open the one secret. Confidential ONLY by
 * virtue of the enclosing sealed envelope.
 */
export interface ThresholdPartial {
  /** Echoes the challenge's account id, correlating the partial to its request. */
  accountId: string;
  /** The SE ECDH partial `Z_F`, 32 bytes, standard-base64. */
  zf: string;
}

/** Daemon-verified provenance. Rendered in SF Mono, hairline-separated. */
export interface Provenance {
  /** Resolved ancestor chain, root-first, e.g. ["zsh", "claude", "op"]. */
  processChain: string[];
  cwd: string;
  machine: string;
  /** When the daemon queued it, unix ms. */
  requestedAt: number;
}

export interface ApprovalRequest {
  /** Matches the enclosing envelope's request id. */
  requestId: string;
  /** Display hint for the approver's layout. */
  kind: RequestKind;
  /** The argv the shim intercepted, e.g. ["op", "read", "op://…"]. */
  command: string[];
  /**
   * Provider-agnostic references to the secrets this command will resolve.
   * Empty for kinds that read no secret (resume).
   */
  secrets: SecretRef[];
  /** Present for "ssh_signature". */
  ssh?: SshChallenge;
  provenance: Provenance;
  /** One optional display-only heads-up line (e.g. "Production vault."). */
  reason?: string;
  /**
   * The threshold challenge for a request that opens a threshold-sealed secret;
   * absent on plain gates and on kinds that read no secret. Present => this approve
   * must produce a `ThresholdPartial` (Z_F); absent => a plain gate approve that
   * carries no partial.
   */
  threshold?: ThresholdChallenge;
  /**
   * Present when the daemon marks this grant leasable: the approver may approve
   * once, or approve and keep it approved for a window up to `maxSecs`. Absent
   * => run-once, so the sheet offers approve-once only. Offer/display only; the
   * daemon mints and binds the actual lease from the response's chosen window.
   */
  leasePolicy?: LeasePolicy;
  /** Absolute expiry, unix ms. The gauge depletes to this. */
  expiresAt: number;
  /** Full-scale window for the gauge, ms (expiresAt - queuedAt). */
  timeoutMs: number;
}

export type Decision = "approved" | "denied";

export interface ApprovalResponse {
  requestId: string;
  decision: Decision;
  /**
   * On an approve of a request that opens a threshold-sealed secret: the phone's
   * threshold partial `Z_F`. Absent on deny and on a plain gate approve (which
   * releases no sealed secret), so a denial can never release a token. The daemon
   * combines it with its Mac share `m` to open the one secret. Confidential by
   * virtue of the enclosing seal.
   */
  partial?: ThresholdPartial | null;
  /**
   * On approve-with-a-window: the lease duration the approver chose, in ms
   * (<= `leasePolicy.maxSecs * 1000`). The daemon binds this to the grant it
   * already resolved for the request; the zero-knowledge phone cannot compute
   * the grant key, so it sends only the chosen window, never a key. Absent/null
   * on approve-once and on deny.
   */
  lease?: { ttlMs: number } | null;
  /** On deny-and-block: the process name to block, and for how long, else null. */
  block?: { process: string; durationMs: number } | null;
  decidedAt: number;
}

/**
 * Phone -> daemon push-token registration. Sealed over the live session like
 * any other envelope payload, but outside the request/response flow: it is
 * not part of the pairing ceremony's SAS transcript, and it carries no
 * request id. `type` is the discriminant that lets the daemon tell this
 * apart from an `ApprovalResponse` arriving in the same envelope slot. Sent
 * once after arming and again on every APNs token rotation.
 *
 * Content-free by design: this is the only thing the daemon learns about
 * this phone's push channel. `platform` is fixed to `"apns"` today; a future
 * Android/FCM doorbell would add a distinct platform value, never overload
 * this one.
 */
export interface PushRegisterMessage {
  type: "pushRegister";
  /** The APNs device token, lowercase hex. */
  token: string;
  platform: "apns";
}

/**
 * Phone -> daemon delivery acknowledgement (task #41). Sealed over the live
 * session like {@link PushRegisterMessage}, outside the request/response flow:
 * the instant the phone opens and verifies an inbound {@link ApprovalRequest},
 * it seals this back so the daemon can advance the requester's UI from "Sent"
 * to "Delivered". It carries only the `requestId` (opaque to the powerless
 * relay, which cannot read the seal); it is NOT a decision and never releases
 * anything. Best-effort: if it cannot be posted the daemon simply keeps showing
 * "Sent" and falls back to "couldn't confirm", so delivery is never blocked on
 * the ack.
 *
 * DAEMON-SIDE COUNTERPART NEEDED (crates/sigil-proto + daemon, NOT edited here):
 *   - Add `DeliveryReceipt { request_id }` to the daemon's inbound message enum
 *     (the same tagged union that already carries `PushRegisterMessage`), keyed
 *     on `type: "delivered"`.
 *   - On receipt, flip that request's requester-facing state Sent -> Delivered.
 *   - If no receipt arrives within a bound, show "couldn't confirm" (the phone
 *     may be offline or the ack lost); a later approve/deny still resolves it.
 */
export interface DeliveryReceiptMessage {
  type: "delivered";
  /** The request this acknowledges receipt of; matches the envelope's request id. */
  requestId: string;
}

/**
 * Why a ring-all request stopped being actionable (#36 multi-device). Mirrors
 * proto `ResolutionStatus` (serde snake_case). The zero-knowledge broadcast
 * deliberately does NOT say which device resolved it or whether it was an approve
 * or a deny: a phone learns only THAT its copy is over.
 */
export type ResolutionStatus = "settled" | "expired" | "withdrawn";

/**
 * Daemon -> phone resolution broadcast (#36 multi-device ring-all / first-wins).
 * Mirrors proto `ResolutionBroadcast`. When a gated request has been rung to every
 * paired device and one of them resolves it (or it expires / is withdrawn), the
 * daemon seals this to the OTHER devices so their pending sheet dismisses instead
 * of lingering until its own timeout.
 *
 * It is the ToPhone-direction sibling of {@link DeliveryReceiptMessage}: sealed
 * over the live session, metadata only. It carries only `requestId` + `status`,
 * releases nothing, and gates nothing. `type` is the discriminant that lets the
 * inbound demux tell it apart from an {@link ApprovalRequest} (which carries no
 * `type`) arriving in the same envelope slot.
 */
export interface ResolutionBroadcastMessage {
  type: "resolution";
  /** The request this settles; matches a pending request's `requestId`. */
  requestId: string;
  /** Why it is no longer actionable. */
  status: ResolutionStatus;
}

/**
 * The exact width of a lease id rendered as lowercase hex: 128 opaque random
 * bits, mirroring the daemon's own constant.
 *
 * A lease id and NOT a grant key, deliberately, and this is the one thing about
 * lease control the phone must never get wrong. A grant key is a hash of the
 * caller chain plus the rule: it is not unique to a window, it is a stable
 * correlator that would outlive the window in anything the phone kept and would
 * survive a re-pair, and the daemon's CLI revoke is PREFIX matched, so a
 * truncated or empty one would silently revoke every window while reporting
 * success. The phone therefore never handles, stores, renders or logs a grant
 * key; it echoes back the opaque per-window id it was handed and nothing else.
 */
export const LEASE_ID_CHARS = 32;

/**
 * The bound every human-readable field of a {@link LeaseRow} is sanitized to,
 * mirroring the daemon's `LEASE_LABEL_MAX_CHARS`. The same number as
 * {@link COVERS_MAX_CHARS}, because it is the same allowlist doing the same job
 * on the same kind of surface.
 */
export const LEASE_LABEL_MAX_CHARS = COVERS_MAX_CHARS;

/**
 * Every lease-control plaintext is padded to a multiple of this before sealing,
 * mirroring the daemon's `LEASE_PAD_BUCKET`.
 *
 * Ciphertext length would otherwise carry the row count straight to the relay: a
 * realistic row is around 169 bytes, so an unpadded reply says how many windows
 * are open, and a revoke is trivially shorter than a list. 1024 rather than 512
 * because 512 holds only two realistic rows and rolls at three, leaking the count
 * in exactly the range that matters.
 *
 * Padding is a SENDER obligation and is deliberately not verified on receipt. A
 * peer that does not pad leaks its own lengths and nobody else's, whereas
 * rejecting an unpadded message would make a version skew between the two halves
 * fail silently and closed, and a revoke that vanishes is the failure this whole
 * feature exists to end.
 */
export const LEASE_PAD_BUCKET = 1024;

/** The inert filler. ASCII, so one character is one byte and needs no escaping. */
const LEASE_PAD_FILL = ".";

/** A lease-control payload, which always carries its own padding field. */
interface Padded {
  pad: string;
}

/**
 * Size `pad` so the serialized JSON is exactly a multiple of
 * {@link LEASE_PAD_BUCKET} bytes. Mirrors the daemon's
 * `LeaseControlMessage::padded`.
 *
 * Exact rather than approximate because `pad` always serializes, even when empty,
 * so measuring with it empty already accounts for the field's own overhead and
 * the filler can never spill into a further bucket. Measured in BYTES, matching
 * `serde_json::to_vec().len()` on the daemon and the `TextEncoder` in `seal`.
 *
 * Key order differs from the daemon's struct order and that is fine: only the
 * length is load-bearing, and nothing on either side parses the padding.
 */
export function padLeaseControl<T extends Padded>(payload: T): T {
  const encoder = new TextEncoder();
  const bare = { ...payload, pad: "" };
  const len = encoder.encode(JSON.stringify(bare)).length;
  const target = Math.ceil(len / LEASE_PAD_BUCKET) * LEASE_PAD_BUCKET;
  return { ...bare, pad: LEASE_PAD_FILL.repeat(target - len) };
}

/**
 * Phone -> daemon: list the daemon's live lease windows (PHONE LEASE CONTROL).
 *
 * Sealed over the live session like {@link PushRegisterMessage}, outside the
 * request/response flow, and carrying no body: the correlation id is the
 * ENVELOPE's single-use uuidv7 request id, which the daemon echoes as
 * {@link LeaseListReplyMessage.inReplyTo}.
 *
 * Unlike the rest of the read path this one IS gated on a local biometric before
 * it is issued (design review F5). Listing releases nothing, but it changes what
 * a stolen or coerced phone can produce on demand: a complete schedule of which
 * auto-approve windows are live, on which rules, and how many seconds each has
 * left, which is a map of what will release with no human tap. Revoking stays
 * completely ungated, because a revoke is a deny and a deny is never made heavier
 * than an approve.
 */
export interface LeaseListMessage {
  type: "leaseList";
  /** Length-hiding filler; see {@link padLeaseControl}. Never read by anyone. */
  pad: string;
}

/**
 * Phone -> daemon: end ONE live lease window, named by its opaque id.
 *
 * `leaseId` comes verbatim from a {@link LeaseRow} the daemon itself sent. The
 * phone cannot compute one and never invents one. See {@link LEASE_ID_CHARS} for
 * why this is not a grant key.
 *
 * Revoking only ever NARROWS authority, so like a deny it needs no biometric and
 * no confirmation.
 */
export interface LeaseRevokeMessage {
  type: "leaseRevoke";
  leaseId: string;
  /** Length-hiding filler; see {@link padLeaseControl}. Never read by anyone. */
  pad: string;
}

/**
 * One live lease window as the daemon reports it. Display only, in every field:
 * nothing here is parsed, matched on, or branched upon, and `leaseId` is an
 * opaque handle to hand back on a revoke.
 *
 * The daemon sanitizes `scope`, `covers`, and `account` through its own label
 * allowlist before sending, because all three are raw config text the user wrote.
 * The phone re-runs that allowlist anyway (`safeLabel` in src/lib/format.ts),
 * exactly as the approval sheet's coverage caption does: this type describes what
 * the daemon promises, not what a screen may assume it received.
 *
 * There is no age field. It was dropped from the wire because it lies across a
 * refresh: a window extended by a later approval is one window, and an age
 * measured from the first approval would describe something the human never
 * agreed to as a single span.
 */
export interface LeaseRow {
  /** The opaque per-window id, lowercase hex, {@link LEASE_ID_CHARS} wide. The
   *  row's identity, and the only thing a revoke names. */
  leaseId: string;
  /**
   * The matched RULE's name. One window covers ANY command that rule matches for
   * the caller chain that opened it, so no renderer may let this read as a
   * single command line.
   */
  scope: string;
  /**
   * The daemon's one-line description of the rule's breadth, the same string the
   * approval sheet's caption consented to. **Empty means no label was
   * rendered**: show no coverage clause rather than inventing one, and never read
   * empty as "narrow".
   */
  covers: string;
  /** The source label the window injects from. Empty for a plain gate, which
   *  injects nothing. */
  account: string;
  /** Milliseconds left when the daemon took the snapshot. */
  remainingMs: number;
}

/**
 * Daemon -> phone: the answer to a {@link LeaseListMessage}.
 *
 * A SNAPSHOT, and the type says so: `asOfMs` is when the daemon measured it, and
 * the screen renders that timestamp and goes visibly stale rather than sitting
 * there looking like a live view of the Mac.
 *
 * An empty `leases` array is a POSITIVE statement that nothing is open, and it
 * is the only thing that entitles the phone to say so. The absence of a reply is
 * not an empty list, and the settings screen must never render one as the other.
 */
export interface LeaseListReplyMessage {
  type: "leaseListReply";
  /** The envelope request id of the {@link LeaseListMessage} this answers. */
  inReplyTo: string;
  /** When the daemon took this snapshot, unix ms on the daemon's clock. */
  asOfMs: number;
  leases: LeaseRow[];
}

/**
 * Daemon -> phone: the answer to a {@link LeaseRevokeMessage}.
 *
 * `revoked: true` means a live window with that id was found and zeroized;
 * `false` means there was none, and the daemon deliberately does not distinguish
 * already-lapsed from already-revoked from never-held. Every `false` is a
 * SUCCESS: the window is closed either way, and the UI says so plainly rather
 * than dressing it as a failure.
 *
 * The only real failure is no reply at all, and that one is never reported as a
 * success: see {@link inReplyTo}.
 */
export interface LeaseRevokeReplyMessage {
  type: "leaseRevokeReply";
  /**
   * The envelope request id of the {@link LeaseRevokeMessage} this answers, and
   * the whole defence against the attack that made this feature worse than the
   * badge it replaced (design review F3).
   *
   * The envelope layer's replay guard is a 150 second freshness window
   * (`REPLAY_WINDOW_MS`) plus a single-use id set held in RAM, and that set is
   * empty again after any restart.
   * The phone being killed or backgrounded is routine. So a relay can capture a
   * genuine `revoked: true`, wait for a restart, suppress the human's next
   * outgoing revoke, and deliver the captured reply into a fresh guard: unseen
   * id, valid signature, inside the freshness window, because the message really
   * is genuine. The phone would tell the human a window closed while it is open.
   *
   * The correlation is what closes it. The phone applies a reply ONLY if this
   * matches a request it issued in THIS session and has not yet answered, and it
   * consumes that entry on the match. A captured reply replayed after a restart
   * matches nothing, because the outstanding set died with the process, and is
   * dropped. This is single-use at the application layer and is load-bearing on
   * its own, not belt-and-braces over the envelope guard.
   */
  inReplyTo: string;
  /** Echoes the revoked lease id. */
  leaseId: string;
  revoked: boolean;
}

/** Exactly-width lowercase hex, normalized. Anything else is not an identifier. */
function hexField(v: unknown, chars: number): string | null {
  if (typeof v !== "string" || v.length !== chars) return null;
  return /^[0-9a-fA-F]+$/.test(v) ? v.toLowerCase() : null;
}

/** A uuid correlation id: the shape `seal` mints for an envelope request id. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function uuidField(v: unknown): string | null {
  return typeof v === "string" && UUID.test(v) ? v.toLowerCase() : null;
}

function isMs(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0;
}

/**
 * Validate one wire lease row. Shape only: the display hygiene (the daemon's
 * label allowlist, re-applied here as defence in depth) happens where the row is
 * turned into something renderable, in src/domain/leases.ts.
 */
function parseLeaseRow(v: unknown): LeaseRow | null {
  if (typeof v !== "object" || v === null) return null;
  const r = v as Record<string, unknown>;
  const leaseId = hexField(r.leaseId, LEASE_ID_CHARS);
  if (!leaseId) return null;
  if (typeof r.scope !== "string" || typeof r.covers !== "string") return null;
  if (typeof r.account !== "string") return null;
  if (!isMs(r.remainingMs)) return null;
  return {
    leaseId,
    scope: r.scope,
    covers: r.covers,
    account: r.account,
    remainingMs: r.remainingMs,
  };
}

/**
 * Validate a lease-list reply, returning null for anything malformed.
 *
 * **One bad row voids the whole answer, deliberately.** Skipping the bad row and
 * keeping the rest would under-report open windows, and under-reporting is the
 * one direction this surface must never fail in: the human would read a shorter
 * list as "that is everything". Voiding the answer lands the screen in "cannot
 * check right now", which is a true statement about what the phone knows.
 */
export function parseLeaseListReply(payload: unknown): LeaseListReplyMessage | null {
  if (typeof payload !== "object" || payload === null) return null;
  const p = payload as Record<string, unknown>;
  const inReplyTo = uuidField(p.inReplyTo);
  if (!inReplyTo || !isMs(p.asOfMs)) return null;
  if (!Array.isArray(p.leases)) return null;
  const leases: LeaseRow[] = [];
  for (const raw of p.leases) {
    const row = parseLeaseRow(raw);
    if (!row) return null;
    leases.push(row);
  }
  // `pad` is deliberately not read, not copied, and not sanitized: it is inert
  // filler, and letting its size or content reach anything would hand a relay a
  // lever it does not otherwise have.
  return { type: "leaseListReply", inReplyTo, asOfMs: p.asOfMs, leases };
}

/** Validate a revoke reply. Fails closed: a malformed one confirms nothing. */
export function parseLeaseRevokeReply(payload: unknown): LeaseRevokeReplyMessage | null {
  if (typeof payload !== "object" || payload === null) return null;
  const p = payload as Record<string, unknown>;
  const inReplyTo = uuidField(p.inReplyTo);
  const leaseId = hexField(p.leaseId, LEASE_ID_CHARS);
  if (!inReplyTo || !leaseId) return null;
  if (typeof p.revoked !== "boolean") return null;
  return { type: "leaseRevokeReply", inReplyTo, leaseId, revoked: p.revoked };
}

/**
 * An opened daemon -> phone payload: a fresh {@link ApprovalRequest} to display
 * (untagged, legacy), a tagged {@link ResolutionBroadcastMessage} to dismiss one,
 * or a tagged answer to a lease-control question. Mirrors proto `ToPhoneMessage`.
 * {@link classifyToPhone} is the single place the phone decides which one an
 * opened envelope is.
 */
export type ToPhoneMessage =
  | { kind: "request"; request: ApprovalRequest }
  | { kind: "resolution"; resolution: ResolutionBroadcastMessage }
  | { kind: "leaseList"; reply: LeaseListReplyMessage }
  | { kind: "leaseRevoke"; reply: LeaseRevokeReplyMessage };

/**
 * Classify an opened (decrypted, verified) ToPhone payload by its `type` tag,
 * mirroring proto `ToPhoneMessage::from_value`. `"resolution"` selects a
 * dismissal, `"leaseListReply"` / `"leaseRevokeReply"` select a lease-control
 * answer; the absence of a tag is an approval request. Fails closed: a tagged
 * payload that does not validate returns `null` so the caller drops it rather
 * than acting on a half-read message. Kept a pure function so it is unit
 * testable without a live session.
 */
export function classifyToPhone(payload: unknown): ToPhoneMessage | null {
  if (typeof payload !== "object" || payload === null) return null;
  const tag = (payload as { type?: unknown }).type;
  if (tag === "leaseListReply") {
    const reply = parseLeaseListReply(payload);
    return reply ? { kind: "leaseList", reply } : null;
  }
  if (tag === "leaseRevokeReply") {
    const reply = parseLeaseRevokeReply(payload);
    return reply ? { kind: "leaseRevoke", reply } : null;
  }
  if (tag === "resolution") {
    const p = payload as Partial<ResolutionBroadcastMessage>;
    if (typeof p.requestId !== "string" || p.requestId.length === 0) return null;
    if (p.status !== "settled" && p.status !== "expired" && p.status !== "withdrawn") return null;
    return { kind: "resolution", resolution: { type: "resolution", requestId: p.requestId, status: p.status } };
  }
  // No `type` (or an unknown one): treat as an approval request. The session's
  // envelope open already validated the crypto; shape errors surface downstream.
  return { kind: "request", request: payload as ApprovalRequest };
}
