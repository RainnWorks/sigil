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

/**
 * One active daemon lease, as this phone last heard it and stamped it against
 * its own clock. Built from a wire {@link LeaseRow} by `toActiveLeases`
 * (src/domain/leases.ts); every display string has already been through the
 * daemon's label allowlist a second time there.
 *
 * A MIRROR, never a source of truth: the daemon is the only lease authority, and
 * every field here describes what it said at {@link LeaseView.answeredAt}. The
 * phone holds no lease state of its own, which is why removing a row locally can
 * never stand in for revoking one.
 */
export interface ActiveLease {
  /** Opaque grant key from the daemon. Stable across windows, so it is NOT the
   *  row's identity; it is one half of what a revoke names. Never phone-derived. */
  grantHex: string;
  /** This window's opaque instance id: the row's identity, and the half of a
   *  revoke that binds it to the window the human is actually looking at. */
  instance: string;
  /**
   * The matched RULE's name, mirroring the daemon's `LeaseInfo.scope`, e.g.
   * "op-eu". NOT the command line that opened the lease: one lease covers any
   * command that rule matches, run by the caller chain that opened it, until it
   * expires. Anything rendering this must not imply it covers a single command.
   * Null when the daemon sent nothing usable.
   */
  scope: string | null;
  /** The daemon's own description of the rule's breadth; null when it sent none,
   *  which never means the window is narrow. */
  covers: string | null;
  /** The account the window is scoped to; null for a plain gate that holds no values. */
  account: string | null;
  /** Absolute local expiry, unix ms: arrival time plus the daemon's `remainingMs`. */
  expiresAt: number;
  /** Absolute local grant time, unix ms: arrival time minus the daemon's `ageMs`. */
  grantedAt: number;
}

/** A revoke this phone has sent and not yet had confirmed. */
export interface PendingRevoke {
  /** The correlation id sent with it; this is what attributes the reply. */
  queryId: string;
  grantHex: string;
  /** The window it names. Rows and pending revokes are both keyed on this. */
  instance: string;
  /** When the revoke left this device, unix ms. */
  sentAt: number;
  /**
   * True once the reply window has passed with no answer. The row STAYS on
   * screen and says the window may still be open: a suppressed reply must never
   * leave the human believing a window closed.
   */
  unconfirmed: boolean;
}

/**
 * How the last completed revoke ended. Held until the next revoke starts, so the
 * one line of feedback does not blink out from under someone mid-read; it names
 * no rule, so it cannot be misread as describing a row that arrived after it.
 */
export interface RevokeNote {
  instance: string;
  /**
   * `closed`: the daemon ended a live window. `alreadyGone`: it had no such
   * lease (unknown, expired, or already revoked), which is equally a success.
   */
  outcome: "closed" | "alreadyGone";
  at: number;
}

/**
 * What this phone knows about the daemon's leases, and how recently it knew it.
 *
 * The freshness fields are load-bearing, not decoration. The phone may state
 * that nothing is open ONLY from a fresh successful answer; a phone that cannot
 * reach the daemon saying "no active leases" is a false statement of fact about
 * a containment surface. `answeredAt === 0` means never answered, and that is a
 * different sentence from "asked and got none".
 */
export interface LeaseView {
  /** The rows from the last successful answer. Empty is meaningful only when
   *  {@link answeredAt} is non-zero. */
  rows: ActiveLease[];
  /** When the last successful answer arrived, unix ms. 0 = never answered. */
  answeredAt: number;
  /** A list query is in flight right now. */
  asking: boolean;
  /** The last query did not come back. Cleared by the next successful answer. */
  unreachable: boolean;
  /** Revokes sent and not yet confirmed, keyed off {@link ActiveLease.instance}. */
  revokes: PendingRevoke[];
  /** The outcome of the last completed revoke, for one line of plain feedback.
   *  Both outcomes are successes; see {@link RevokeNote}. */
  note: RevokeNote | null;
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
  /** What the daemon last said is open, and how recently it said it. */
  leases: LeaseView;
  settings: Settings;
  /** The six pairing words, held only during the ceremony. */
  pairingWords: string[] | null;
  /** Fingerprint of this phone's own public identity, for the pairing explainer. */
  ownFingerprint: string | null;
}
