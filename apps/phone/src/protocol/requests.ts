/**
 * The approval request/response payloads: the plaintext that rides *inside* a
 * sealed envelope. This byte-matches crates/proto/src/request.rs (camelCase
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
   * On approve: standard-base64 of the raw 32-byte DEK. Absent on deny, so a
   * denial cannot release a token. Confidential by virtue of the enclosing seal.
   */
  wrappedDek?: string;
  /** On approve with "for this session": a lease grant, else null. */
  lease?: { grantKey: string; ttlMs: number } | null;
  /** On deny-and-block: the process name to block, and for how long, else null. */
  block?: { process: string; durationMs: number } | null;
  decidedAt: number;
}
