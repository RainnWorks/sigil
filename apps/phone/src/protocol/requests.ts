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
 * on approve, the DEK the daemon needs to decrypt the one stored credential.
 * The whole response is sealed in an envelope, so `wrappedDek` is the plain
 * base64 of the raw 32-byte DEK, confidential by virtue of the enclosing seal.
 */

/**
 * How the approver should *render* a request. A DISPLAY HINT ONLY: it selects a
 * layout, never how the daemon fulfills the request (that is the provider seam's
 * job). Serializes snake_case to match the Rust enum.
 */
export type RequestKind = "secret_read" | "ssh_signature" | "resume" | "lockdown_clear";

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
}

/** An SSH signature: the two things worth verifying. */
export interface SshChallenge {
  keyLabel: string;
  host: string;
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
 * `Z_F = x(f·E)`, the value the Secure Enclave emits under Face ID. For v2
 * accounts it replaces `wrappedDek` — the phone no longer holds a self-sufficient
 * DEK, only its share. Confidential ONLY by virtue of the enclosing sealed
 * envelope, exactly as v1's `wrappedDek` was.
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
   * Empty for kinds that read no secret (resume, lockdown_clear).
   */
  secrets: SecretRef[];
  /** Present for "ssh_signature". */
  ssh?: SshChallenge;
  provenance: Provenance;
  /** One optional display-only heads-up line (e.g. "Production vault."). */
  reason?: string;
  /**
   * The v2 threshold challenge for a v2 account; absent on v1 requests and on
   * kinds that read no secret, so a v1 peer never sees it. Present => this
   * approve must produce a `ThresholdPartial` (Z_F) instead of a DEK.
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
   * On a v1 approve: standard-base64 of the raw 32-byte DEK. Absent on deny and
   * on v2 approves, so a denial cannot release a token. Confidential by virtue of
   * the enclosing seal.
   */
  wrappedDek?: string;
  /**
   * On a v2 approve: the phone's threshold partial `Z_F`, replacing `wrappedDek`.
   * Absent on deny and on v1 approves. Exactly one of `wrappedDek` / `partial` is
   * populated per approve, selected by the account's record version (R3), never by
   * a wire field.
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
 * An opened daemon -> phone payload: either a fresh {@link ApprovalRequest} to
 * display (untagged, legacy) or a tagged {@link ResolutionBroadcastMessage} to
 * dismiss one. Mirrors proto `ToPhoneMessage`. {@link classifyToPhone} is the
 * single place the phone decides which one an opened envelope is.
 */
export type ToPhoneMessage =
  | { kind: "request"; request: ApprovalRequest }
  | { kind: "resolution"; resolution: ResolutionBroadcastMessage };

/**
 * Classify an opened (decrypted, verified) ToPhone payload by its `type` tag,
 * mirroring proto `ToPhoneMessage::from_value`. `"resolution"` selects a
 * dismissal; its absence is an approval request. Fails closed: a `"resolution"`
 * tag with a missing/blank `requestId` returns `null` so the caller drops it
 * rather than dismissing an unknown request. Kept a pure function so it is unit
 * testable without a live session.
 */
export function classifyToPhone(payload: unknown): ToPhoneMessage | null {
  if (typeof payload !== "object" || payload === null) return null;
  const tag = (payload as { type?: unknown }).type;
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
