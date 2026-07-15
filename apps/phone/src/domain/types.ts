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
  /**
   * The recorded outcome. `"superseded"` is the zero-knowledge #36 case: another
   * paired device resolved a ring-all request (or the daemon withdrew it), so this
   * phone dismissed its copy without learning whether it was an approve or a deny.
   */
  decision: Decision | "expired" | "superseded";
  /** Empty for approvals; the reason line for denials or a dismissal note. */
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

/**
 * The transport link, a quiet status dot only. Deliberately carries no machine
 * name: the pairing pins keys, not hostnames, and a transport address (the
 * relay's, say) must never stand in for the paired Mac. The Mac's display name
 * comes from daemon-signed provenance (see `pairedMacName`).
 */
export interface Connection {
  rung: ConnectionRung;
  lastSeenAt: number;
}

export type ArmState = "armed" | "idle";

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
