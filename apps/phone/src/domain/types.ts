/**
 * App-facing domain types. These wrap the protocol's ApprovalRequest with the
 * local UI state a request moves through, plus the secondary screens' models
 * (history, accounts, leases, settings). The phone stores names and metadata,
 * never secret values.
 */
import { type ApprovalRequest, type Decision } from "@/src/protocol";

/** The full approval-sheet state machine. */
export type RequestState =
  | "fresh"
  | "expiring"
  | "expired"
  | "approved"
  | "denied"
  | "superseded";

export interface PendingRequest {
  request: ApprovalRequest;
  state: RequestState;
  /** When the phone received it, unix ms. */
  receivedAt: number;
  /** How many identical requests coalesced behind this one. */
  coalesced: number;
}

export interface HistoryEntry {
  id: string;
  kind: ApprovalRequest["kind"];
  /** Display label: "Engineering/.env > graphql-api" or "github-deploy -> git@github.com". */
  label: string;
  /** The Mac this request came from (provenance.machine); searchable, provider-free. */
  origin: string;
  process: string;
  cwd: string;
  decision: Decision | "expired";
  /** Empty for approvals; the reason line for denials. */
  note?: string;
  at: number;
  /** How it was decided: "phone", "rule", "local". */
  via: string;
}

export interface Lease {
  id: string;
  /** e.g. "rowm launcher". */
  caller: string;
  /** e.g. "Engineering/.env". */
  scope: string;
  grantedAt: number;
  expiresAt: number;
}

export interface Settings {
  faceIdBeforeApprove: boolean;
  reduceMotion: boolean;
  defaultTimeoutSec: number;
  notificationsEnabled: boolean;
}

export type ConnectionRung = "lan" | "endpoint" | "relay" | "none";

export interface Connection {
  rung: ConnectionRung;
  machine: string;
  lastSeenAt: number;
}

export type ArmState = "armed" | "lockedDown" | "idle";

export interface AppState {
  paired: boolean;
  arm: ArmState;
  connection: Connection;
  pending: PendingRequest[];
  history: HistoryEntry[];
  leases: Lease[];
  settings: Settings;
  /** The six pairing words, held only during the ceremony. */
  pairingWords: string[] | null;
  /** Fingerprint of this phone's own public identity, for the pairing explainer. */
  ownFingerprint: string | null;
}
