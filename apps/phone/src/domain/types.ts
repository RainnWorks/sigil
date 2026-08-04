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

/**
 * The relay's own note of the network address it saw a delivery deposited from,
 * mirroring `crates/sigil-relay/src/protocol.rs::Origin`.
 *
 * RELAY-ASSERTED, DISPLAY ONLY. The relay is the adversary in this system's
 * threat model: it can forge this, strip it, or replay an old one, and no client
 * can tell. The daemon does not sign it and it is not part of the sealed
 * envelope. So it must never gate anything, never be compared as a check, never
 * be rendered as verified, and never be persisted to history. Its entire value
 * is as a soft human tell: an approval claiming to come from Tom's own Mac,
 * arriving from an unfamiliar network, is the signal a stolen keystore file
 * would trip.
 *
 * Kept deliberately OFF {@link ApprovalRequest}: that type byte-matches the
 * daemon-signed proto, and an unsigned relay claim must never sit in the same
 * object as the fields the daemon actually vouched for.
 */
export interface RelayOrigin {
  /**
   * The address as the relay rendered it. Validated on arrival to an IP-literal
   * shape (see `relay-http.ts::parseOrigin`), because a hostile relay would
   * otherwise be handing free text straight to the approval sheet.
   */
  ip: string;
  /** When the relay says it observed the deposit, unix ms. Not displayed in v1. */
  atMs: number;
}

export interface PendingRequest {
  request: ApprovalRequest;
  state: RequestState;
  /** When the phone received it, unix ms. */
  receivedAt: number;
  /** How many identical requests coalesced behind this one. */
  coalesced: number;
  /**
   * The relay's claim about where this delivery came from, when there is one and
   * it survived validation. Absent on the LAN/direct rung (no relay in the path),
   * on an older relay, and whenever the claim looked wrong. Absent renders
   * nothing: the sheet never says "unknown network", which would read as a
   * finding rather than a silence.
   *
   * Named `relayOrigin`, never plain `origin`: this codebase already uses that
   * word for the asking machine ({@link HistoryEntry.origin}, and the sheet's
   * header), and a field that means "an unverified network address" must not
   * share a name with one that means "which Mac asked".
   */
  relayOrigin?: RelayOrigin;
}

export interface HistoryEntry {
  id: string;
  kind: ApprovalRequest["kind"];
  /** Display label: "Engineering/.env > graphql-api" or "github-deploy -> github.com". */
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
  /**
   * The matched RULE's name, mirroring the daemon's `LeaseJson.scope`, e.g.
   * "op-eu". NOT the command line that opened the lease: one lease covers any
   * command that rule matches, run by the caller chain that opened it, until it
   * expires. Anything rendering this must not imply it covers a single command.
   */
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
 * The transport link, a quiet status dot only, fed live by the transport's
 * drain results (see `store.noteTransport`). Deliberately carries no machine
 * name: the pairing pins keys, not hostnames, and a transport address (the
 * relay's, say) must never stand in for the paired Mac. The Mac's display name
 * comes from daemon-signed provenance (see `pairedMacName`).
 */
export interface Connection {
  rung: ConnectionRung;
  /** When the transport last drained successfully, unix ms; 0 = never. */
  lastSeenAt: number;
}

export type ArmState = "armed" | "idle";

export interface AppState {
  paired: boolean;
  arm: ArmState;
  connection: Connection;
  /** When this pairing was pinned, unix ms; 0 = unpaired. Distinct from the
   * connection's lastSeenAt, which moves on every successful drain. */
  pairedAt: number;
  pending: PendingRequest[];
  history: HistoryEntry[];
  leases: Lease[];
  settings: Settings;
  /** The six pairing words, held only during the ceremony. */
  pairingWords: string[] | null;
  /** Fingerprint of this phone's own public identity, for the pairing explainer. */
  ownFingerprint: string | null;
}
