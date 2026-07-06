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

/** Risk scales the approve control only. Deny is always one tap. */
export type RiskLevel = "routine" | "elevated" | "critical";

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
  risk: RiskLevel;
  /** One reason line for elevated / critical (e.g. "Production vault."). */
  reason?: string;
  /**
   * The v2 threshold challenge for a v2 account; absent on v1 requests and on
   * kinds that read no secret, so a v1 peer never sees it. Present => this
   * approve must produce a `ThresholdPartial` (Z_F) instead of a DEK.
   */
  threshold?: ThresholdChallenge;
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
  /** On approve with "for this session": a lease grant, else null. */
  lease?: { grantKey: string; ttlMs: number } | null;
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
