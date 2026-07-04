/**
 * The approval request/response payloads: the plaintext that rides *inside* a
 * sealed envelope. crates/proto does not yet define these (envelope, pairing,
 * identity, fingerprint, and replay are landed; the request payload is still
 * being finalized on the rust-core side). This module is the phone's proposed
 * shape and MUST be reconciled when the Rust type lands. Keep it in this one
 * file so the reconciliation is a single diff.
 *
 * The phone never sees a service-account token or a resolved secret value. A
 * request carries only metadata to display; a response carries the decision and,
 * on approve, the DEK re-wrapped to this request's ephemeral key.
 */

/** Risk scales the approve control only. Deny is always one tap. */
export type RiskLevel = "routine" | "elevated" | "critical";

export type RequestKind = "read_secret" | "ssh_signature";

/** A secret read: the op:// reference, segmented for the readout well. */
export interface SecretRef {
  /** 1Password account label, e.g. "Rowm work". */
  account: string;
  vault: string;
  /** The item name; rendered brightest in the well. */
  item: string;
  /** Field within the item, e.g. "access-key". */
  field: string;
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
  /** Resolved ancestor chain, e.g. ["zsh", "claude", "op read"]. */
  processChain: string[];
  cwd: string;
  machine: string;
  /** When the daemon queued it, unix ms. */
  requestedAt: number;
}

export interface ApprovalRequest {
  /** Matches the enclosing envelope's request id. */
  requestId: string;
  kind: RequestKind;
  accountLabel: string;
  /** Present iff kind === "read_secret". */
  secret?: SecretRef;
  /** Present iff kind === "ssh_signature". */
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
  /** On approve: the DEK re-wrapped to this request's ephemeral key, base64. */
  wrappedDek?: string;
  /** On approve with "for this session": a lease grant, else null. */
  lease?: { grantKey: string; ttlMs: number } | null;
  /** On deny-and-block: the process name to block, and for how long, else null. */
  block?: { process: string; durationMs: number } | null;
  decidedAt: number;
}
