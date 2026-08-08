/**
 * The lease list's pure core: turning the daemon's snapshot into rows the
 * settings screen can render, and deciding which of several very different
 * sentences the screen is entitled to say.
 *
 * All of it is pure and lives here rather than in the screen, because the honesty
 * rules this file encodes are the whole point of the feature and belong somewhere
 * a unit test can pin them (`leases.selftest.ts`). Three rules, stated once:
 *
 *   1. **The phone may claim the list is complete only from a fresh successful
 *      answer.** "Asked and got none", "cannot ask right now", and "never asked"
 *      are three different facts about the world and get three different
 *      sentences. A phone that cannot reach the daemon saying "No active leases"
 *      would be a false statement of fact on the surface the brief cites as the
 *      containment for a rule-wide window.
 *   2. **What comes back is a snapshot, not a view.** It carries the daemon's own
 *      `asOfMs`, the screen shows it, and it goes visibly stale within seconds
 *      rather than sitting there implying it still describes the Mac.
 *   3. **Failing means failing toward "the window may still be open."** Never
 *      toward a clean-looking list. An unconfirmed revoke keeps warning until
 *      something actually settles it.
 */
import { relativeTime, remainingWindow, safeLabel } from "@/src/lib/format";
import { LEASE_LABEL_MAX_CHARS, type LeaseRow } from "@/src/protocol";

import {
  type ActiveLease,
  type HistoryEntry,
  type LeaseView,
  type PendingRevoke,
} from "./types";

/**
 * How long a snapshot still counts as describing now.
 *
 * Short on purpose. A window can lapse or be revoked from the Mac at any moment,
 * and this screen is read by someone deciding whether to act; a list that goes on
 * looking live is the failure mode, not a slow refresh. Ten seconds is roughly
 * how long it takes to read the screen, so the reader sees it age under them.
 */
export const LEASE_SNAPSHOT_FRESH_MS = 10_000;

/**
 * How long to wait for a reply before saying so. Generous, because the transport
 * ladder's bottom rung is a long-poll through the relay: a slow answer is common,
 * and calling it a failure early would cry wolf on a surface whose warnings have
 * to mean something.
 */
export const LEASE_REPLY_TIMEOUT_MS = 20_000;

// The bound for every daemon string this screen sets in its own prose is the
// daemon's own LEASE_LABEL_MAX_CHARS, imported rather than re-guessed: the two
// surfaces must not be able to render the same input at different lengths.

/** The never-asked resting state, and what a cleared snapshot returns to. */
export function emptyLeaseView(): LeaseView {
  return {
    rows: [],
    askedAt: 0,
    asOfMs: 0,
    asking: false,
    unreachable: false,
    noBiometric: false,
    revokes: [],
    note: null,
  };
}

/**
 * Stamp a daemon snapshot against this phone's clock.
 *
 * The daemon sends a duration, not a deadline, so `receivedAt` fixes it to a
 * local timeline the countdown can tick against. Transit delay makes the result
 * generous: the window really closes a round trip earlier than the row says. On
 * an honest link that is a few hundred milliseconds. Under a hostile one it is
 * as much as the reply timeout, because the relay chooses the delay, so state
 * the bound as up to {@link LEASE_REPLY_TIMEOUT_MS} rather than "a moment".
 *
 * Arrival is still the right stamp HERE, and the asymmetry with
 * {@link snapshotFresh} is deliberate: overstating how long a window is open
 * prompts a revoke, while understating it would invite the human to relax. Age
 * the snapshot from send, age the window from arrival, and both err toward
 * "assume more is open than you can see".
 *
 * Rows already past their expiry are dropped rather than rendered at zero, and
 * every display string goes through the daemon's own label allowlist a second
 * time. `scope` and `account` are raw config text the user wrote, so that second
 * pass is not ceremony (defence in depth, exactly as the approval caption does).
 */
export function toActiveLeases(rows: LeaseRow[], receivedAt: number): ActiveLease[] {
  const out: ActiveLease[] = [];
  for (const r of rows) {
    if (r.remainingMs <= 0) continue;
    out.push({
      leaseId: r.leaseId,
      scope: safeLabel(r.scope, LEASE_LABEL_MAX_CHARS),
      covers: safeLabel(r.covers, LEASE_LABEL_MAX_CHARS),
      account: safeLabel(r.account, LEASE_LABEL_MAX_CHARS),
      expiresAt: receivedAt + r.remainingMs,
      windowMs: r.remainingMs,
    });
  }
  // Least time left first: the window about to lapse on its own is the one the
  // reader can stop worrying about, and the long one is the one worth ending.
  out.sort((a, b) => a.expiresAt - b.expiresAt);
  return out;
}

/** The rows that have not run out since the snapshot arrived. */
export function liveLeases(view: LeaseView, nowMs: number): ActiveLease[] {
  return view.rows.filter((l) => l.expiresAt > nowMs);
}

/**
 * Whether the snapshot on screen still counts as describing now.
 *
 * Aged from when the QUERY WAS SENT ({@link LeaseView.askedAt}), not from when
 * the reply arrived, and this is a security property rather than a detail. A
 * relay decides how long to sit on a reply, so arrival time is a number the
 * adversary picks: stalling an answer for nineteen seconds, just inside the
 * reply timeout, would hand this phone a nineteen second old answer reading as
 * current, and the unqualified "No active leases." would then rest on
 * information nearly a minute stale. Send time cannot be pushed later by anyone
 * but this phone, so it is the correct upper bound on the answer's age.
 */
export function snapshotFresh(view: LeaseView, nowMs: number): boolean {
  if (view.askedAt === 0) return false;
  return nowMs - view.askedAt < LEASE_SNAPSHOT_FRESH_MS && !view.unreachable;
}

/**
 * The daemon's own snapshot time as a wall clock, e.g. "14:23:07".
 *
 * DISPLAY ONLY. It is the daemon's claim about its own clock, and nothing
 * authenticates it as a time source: a daemon running fast could otherwise make
 * an old snapshot look current. The staleness DECISION is {@link snapshotFresh},
 * which ages from the moment this phone sent the query and never touches this
 * value. Display their claim, decide on your own clock.
 */
export function asOfClock(asOfMs: number): string {
  const d = new Date(asOfMs);
  const two = (n: number) => n.toString().padStart(2, "0");
  return `${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}`;
}

/**
 * Where a revoke for one window stands. `"unconfirmed"` is the one that matters:
 * the revoke left this phone and nothing came back, so the window's state is
 * unknown and the screen must keep saying so.
 */
export function revokeState(view: LeaseView, leaseId: string): "idle" | "sending" | "unconfirmed" {
  const p = view.revokes.find((r) => r.leaseId === leaseId);
  if (!p) return "idle";
  return p.unconfirmed ? "unconfirmed" : "sending";
}

/** The revokes that went out and were never answered. */
export function unconfirmedRevokes(view: LeaseView): PendingRevoke[] {
  return view.revokes.filter((r) => r.unconfirmed);
}

/**
 * Whether an unanswered revoke is still an open question, or has been settled by
 * the window simply running out.
 *
 * A warning with no dismiss is the right shape here, because a dismissible
 * warning about an open window is one people clear reflexively. But "forever" has
 * its own failure mode: a warning that never resolves stops being read. A lease
 * is TTL-bounded, so there is an honest end to this one. Once the window's own
 * expiry has passed it is closed regardless of whether the revoke arrived, which
 * also catches the case where a genuinely successful revoke was answered a second
 * after the reply timeout and the answer had to be dropped.
 *
 * The exception is a REFRESH: a later approval extends an existing window rather
 * than starting a new one, so a window this phone watched expire may have been
 * renewed since. That cannot be observed directly, because the phone holds no
 * lease state, so it is inferred conservatively from the only evidence there is.
 * Any approval recorded after the revoke went out could have been the one that
 * renewed it, and a request another device resolved could have been too, since
 * this phone is never told whether that was an approve. Either keeps the warning
 * standing. Over-warning is the safe direction.
 */
export function revokeResolution(
  revoke: PendingRevoke,
  history: HistoryEntry[],
  nowMs: number,
): "standing" | "lapsed" {
  if (nowMs <= revoke.windowExpiresAt) return "standing";
  const renewable = history.some(
    (h) => h.at >= revoke.sentAt && (h.decision === "approved" || h.decision === "superseded"),
  );
  return renewable ? "standing" : "lapsed";
}

/** The line for an unanswered revoke whose window has since run out on its own. */
export function lapsedRevokeLine(revoke: PendingRevoke): string {
  const what = revoke.scope ? `The revoke of ${revoke.scope}` : "A revoke this phone sent";
  return `${what} was never confirmed, but that window has since run out on its own.`;
}

/**
 * The Mac-side steps that end a window for certain, offered whenever this phone
 * could not confirm a revoke. Deliberately a LITERAL placeholder rather than an
 * id this phone prints: `sigil lease revoke` is prefix matched, so an id that
 * arrived truncated or empty would revoke everything while reporting success.
 * The human reads the real id off `sigil lease list` on the Mac, where it cannot
 * have been mangled in transit.
 */
export const REVOKE_FALLBACK_LIST = "sigil lease list";
export const REVOKE_FALLBACK_REVOKE = "sigil lease revoke <prefix>";

/**
 * The caveat that has to travel with the fallback. The Mac's revoke matches on a
 * prefix of the GRANT KEY, and one grant key can have more than one live window
 * under it (different accounts or sources), so the command may close siblings
 * this phone never showed. Closing too much is the safe direction and the command
 * stays as it is; being surprised by it is not, so the screen says so first.
 */
export const REVOKE_FALLBACK_CAVEAT =
  "That command matches on a prefix, so it may close other windows opened by the same caller under that rule.";

/** The standing warning for a revoke that was never confirmed. */
export function unconfirmedRevokeLine(revoke: PendingRevoke): string {
  const what = revoke.scope ? `The revoke of ${revoke.scope}` : "A revoke this phone sent";
  return `${what} was never confirmed, so that window may still be open.`;
}

/** When it was sent, so the reader can tell a fresh silence from an old one. */
export function unconfirmedRevokeDetail(revoke: PendingRevoke, nowMs: number): string {
  return `Sent ${relativeTime(revoke.sentAt, nowMs)} with no reply. To be certain it is closed, on the Mac run:`;
}

/** One row's second line: what the window covers, in the daemon's words. */
export function coverageSentence(lease: ActiveLease): string {
  return lease.covers
    ? `Covers ${lease.covers}, and every command that rule matches.`
    : "Covers every command that rule matches.";
}

/**
 * One row's third line: how long is left, and what the window is scoped to.
 * Takes the remaining span rather than a clock, because the row's countdown ticks
 * on its own timer, faster than the section's.
 */
export function remainingSentence(lease: ActiveLease, remainingMs: number): string {
  const left = remainingWindow(remainingMs);
  return lease.account ? `${left}, ${lease.account}` : left;
}

export interface LeaseListStatus {
  kind: "never" | "asking" | "unreachable" | "empty" | "rows";
  /** The headline sentence, always present. */
  line: string;
  /** A quieter second sentence, when there is more to say. */
  detail?: string;
  /**
   * True only when this phone has a fresh successful snapshot and may therefore
   * present the list as complete. Every "no leases" claim is gated on it.
   */
  authoritative: boolean;
}

/** The one sentence a stale snapshot has to carry, whatever it contains. */
const AGED = "Check again for what is open now.";

/**
 * Which sentence the section is entitled to say, given what it knows and when it
 * last knew it. See the file header for why this is a function rather than a
 * ternary in the screen.
 */
export function leaseListStatus(view: LeaseView, nowMs: number): LeaseListStatus {
  const answered = view.askedAt > 0;
  const fresh = snapshotFresh(view, nowMs);

  if (!answered) {
    // Nothing has ever come back, so there is no list to qualify: say which of
    // the three no-list situations this is, and never imply emptiness.
    if (view.asking) {
      return { kind: "asking", line: "Checking with your Mac.", authoritative: false };
    }
    if (view.noBiometric) {
      return {
        kind: "unreachable",
        line: "Cannot check from this device.",
        detail:
          "Showing the list needs Face ID, and none is enrolled here. Run sigil lease list on the Mac instead.",
        authoritative: false,
      };
    }
    if (view.unreachable) {
      return {
        kind: "unreachable",
        line: "Cannot check right now.",
        detail: "This phone did not hear back from your Mac, so it cannot say what is open.",
        authoritative: false,
      };
    }
    return {
      kind: "never",
      line: "Not checked yet.",
      detail: "Checking asks your Mac for a snapshot of its open windows, and needs Face ID.",
      authoritative: false,
    };
  }

  const at = asOfClock(view.asOfMs);
  const doubt = view.unreachable
    ? `This phone cannot reach your Mac right now. ${AGED}`
    : `That snapshot has aged. ${AGED}`;
  const rows = liveLeases(view, nowMs);

  if (rows.length === 0) {
    // The one claim that has to be earned. A fresh snapshot says it plainly; a
    // stale one says only what it can stand behind: that this is what the Mac
    // said at a stated moment which has now passed.
    return fresh
      ? {
          kind: "empty",
          line: "No active leases.",
          detail: `Snapshot as of ${at}.`,
          authoritative: true,
        }
      : {
          kind: "empty",
          line: `No active leases as of ${at}.`,
          detail: doubt,
          authoritative: false,
        };
  }
  return fresh
    ? { kind: "rows", line: `Snapshot as of ${at}.`, authoritative: true }
    : { kind: "rows", line: `Snapshot as of ${at}.`, detail: doubt, authoritative: false };
}

/** The plain sentence for a confirmed revoke. Both outcomes are successes. */
export function revokeNoteLine(outcome: "closed" | "alreadyGone"): string {
  return outcome === "closed"
    ? "Window closed. The next matching command asks again."
    : "That window was already closed. Nothing to revoke.";
}
