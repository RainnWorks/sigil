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
    arrivedAt: 0,
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

/** The four states a revoke can be in; {@link revokeState} explains each. */
export type RevokeState = "idle" | "sending" | "retrying" | "unconfirmed";

/**
 * Where a revoke for one window stands.
 *
 * `"unconfirmed"` is the one that matters, and it is a state the control must be
 * TAPPABLE in. Leaving the button dead there made refusing heavier than
 * approving: twenty seconds after a silent revoke the only way left to close the
 * window was the Mac, on a surface whose whole argument for having no
 * confirmation step is that a revoke only ever narrows authority. That argument
 * licenses the retry just as much: the transport may simply have recovered, and a
 * second revoke can do no harm a first could not.
 *
 * `"retrying"` is in flight AND still unconfirmed, which is why the two facts are
 * tracked separately: the row shows work happening while the warning goes on
 * standing, rather than the warning blinking out for the twenty seconds an
 * attempt is in the air.
 */
export function revokeState(view: LeaseView, leaseId: string): RevokeState {
  const p = view.revokes.find((r) => r.leaseId === leaseId);
  if (!p) return "idle";
  if (p.inFlight) return p.unconfirmed ? "retrying" : "sending";
  return p.unconfirmed ? "unconfirmed" : "idle";
}

/**
 * The pending revokes a snapshot has just proved closed, by not containing them.
 *
 * **ORDERING IS IRRELEVANT HERE, and that is worth stating because the obvious
 * guard looks necessary and is not.** This deliberately does NOT check that the
 * snapshot was taken after the revoke was sent. It does not need to, and a check
 * implying otherwise would invite a later reader to "fix" it into something
 * `asOfMs`-based, which would be actively wrong: `asOfMs` is the daemon's
 * unauthenticated clock, and nothing here may decide anything on it.
 *
 * The whole inference rests on lease-id PERMANENCE instead. An id goes live to
 * dead and never back: a refresh keeps the id (it extends one window rather than
 * starting another), and no id is ever handed to a second window. So a genuine
 * snapshot omitting an id proves that id was dead when the snapshot was computed,
 * and dead is permanent, so it is still dead now. That holds whether the snapshot
 * was computed before or after the revoke went out, and whatever a relay does to
 * ordering.
 *
 * The converse is the safe direction too: a snapshot computed before the revoke
 * that still SHOWS the window leaves it pending, which is conservative rather
 * than wrong. The property is pinned daemon-side in
 * `a_live_window_keeps_its_id_and_a_dead_one_never_lends_it_out`
 * (crates/sigil/src/lease.rs), from this consumer's side.
 *
 * The one thing it does depend on is exactly one list question being in flight,
 * which the session controller enforces: two could interleave and let an older
 * snapshot arrive last.
 */
export function settledByAbsence(
  revokes: PendingRevoke[],
  rows: ActiveLease[],
): PendingRevoke[] {
  const present = new Set(rows.map((l) => l.leaseId));
  return revokes.filter((r) => !present.has(r.leaseId));
}

/** The revokes that went out and were never answered. */
export function unconfirmedRevokes(view: LeaseView): PendingRevoke[] {
  return view.revokes.filter((r) => r.unconfirmed);
}

/**
 * Fold a fresh revoke attempt into whatever was already pending for that window.
 *
 * **A RETRY MUST NOT ERASE THE WARNING IT IS RETRYING.** Replacing the entry
 * wholesale would clear `unconfirmed` for the twenty seconds the new attempt is
 * in flight, so a window whose state is genuinely unknown would present as merely
 * busy, which is the same false reassurance the whole feature exists to prevent.
 * So `unconfirmed` is sticky: only a confirmed reply or the window's own expiry
 * clears it.
 *
 * `sentAt` is likewise kept from the FIRST attempt. It dates how long this window
 * has been unresolved, which is what the reader needs, and it keeps
 * {@link revokeResolution}'s renewal check looking back across the whole
 * unresolved span rather than only since the latest tap, which is the
 * conservative direction.
 */
export function mergeRevoke(prior: PendingRevoke | undefined, next: PendingRevoke): PendingRevoke {
  if (!prior) return next;
  return { ...next, unconfirmed: prior.unconfirmed, sentAt: prior.sentAt };
}

/**
 * Unanswered revokes still worth acting on, and those the window outlived,
 * separated because they belong in different places on the screen.
 *
 * A standing warning is the most important thing the section can say and sits
 * above everything. A lapsed one has no action left in it, so it sinks below the
 * rows: left at the top it would push live windows down the screen and, worse,
 * suppress the confirmed-revoke note behind something that is no longer news.
 */
export function partitionRevokes(
  view: LeaseView,
  history: HistoryEntry[],
  nowMs: number,
): { standing: PendingRevoke[]; lapsed: PendingRevoke[] } {
  const standing: PendingRevoke[] = [];
  const lapsed: PendingRevoke[] = [];
  for (const r of unconfirmedRevokes(view)) {
    if (revokeResolution(r, history, nowMs) === "standing") standing.push(r);
    else lapsed.push(r);
  }
  return { standing, lapsed };
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

/**
 * The subject both warning lines are about: the WINDOW, never the revoke and
 * never the rule. "The revoke of op-eu" read as though the rule itself were being
 * revoked, which is a much larger thing than a lease and not what happened.
 */
function windowPhrase(revoke: PendingRevoke): string {
  return revoke.scope ? `the ${revoke.scope} window` : "that window";
}

/**
 * The line for an unanswered revoke whose window has since run out on its own.
 *
 * Leads with the resolution, because that is the news, then keeps the residual
 * the reader actually needs: the revoke was never confirmed, so the window has to
 * be assumed to have been open for its whole remaining life. Saying only that it
 * expired would quietly imply the revoke worked.
 */
export function lapsedRevokeLine(revoke: PendingRevoke): string {
  const subject = windowPhrase(revoke);
  const head = subject.charAt(0).toUpperCase() + subject.slice(1);
  return `${head} has since run out on its own. The revoke was never confirmed, so assume it was open until then.`;
}

/**
 * The Mac-side steps that end a window for certain, offered whenever this phone
 * could not confirm a revoke. Deliberately a LITERAL placeholder rather than an
 * id this phone prints: `sigil lease revoke` is prefix matched, so an id that
 * arrived truncated or empty would revoke everything while reporting success.
 * The human reads the real id off `sigil lease list` on the Mac, where it cannot
 * have been mangled in transit.
 */
export const REVOKE_FALLBACK_LEAD = "To end a window for certain, on the Mac run:";
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
  "That command matches on a prefix, so it may close other windows opened by the same caller under that rule. Closing more than you meant to only costs another approval.";

/**
 * The standing warning for a revoke that was never confirmed.
 *
 * Says "no reply" rather than "was never confirmed": twenty seconds of silence is
 * not a settled outcome, and "never" reads final for something this recent and
 * still retryable.
 */
export function unconfirmedRevokeLine(revoke: PendingRevoke): string {
  return `No reply about ${windowPhrase(revoke)}, so it may still be open.`;
}

/**
 * When it was first sent, so the reader can tell a fresh silence from an old one,
 * and what to do about it.
 *
 * The second half VARIES WITH THE CONTROL, because the earlier version did not
 * and contradicted it: while a retry was in flight the card said "Tap Revoke
 * again to retry" beside a disabled button already reading "Revoking". Keeping
 * `sentAt` at the first attempt is right and makes that worse, since "Sent 4m ago
 * with no reply" reads as nothing happening at the moment something is.
 *
 * Neither form ends in a colon: the Mac steps moved out to their own block with
 * its own lead-in, so a trailing colon here would point at the next warning.
 */
export function unconfirmedRevokeDetail(
  revoke: PendingRevoke,
  nowMs: number,
  retrying: boolean,
): string {
  const sent = `Sent ${relativeTime(revoke.sentAt, nowMs)} with no reply.`;
  return retrying ? `${sent} Trying again now.` : `${sent} Tap Revoke again to retry.`;
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
  // Three reasons a snapshot may not describe now, and they are different facts.
  // Unreachable wins, because not being able to ask is the bigger one. Born stale
  // comes next: if the round trip alone outran the freshness budget, this list was
  // never current on the screen, and saying "has aged" would tell someone they saw
  // a current list a moment ago when they never did. The 10 to 20 second band is
  // the ordinary slow path down a relay rung, so this is not a rare case.
  const bornStale = view.arrivedAt > 0 && view.arrivedAt - view.askedAt >= LEASE_SNAPSHOT_FRESH_MS;
  const doubt = view.unreachable
    ? `This phone cannot reach your Mac right now. ${AGED}`
    : bornStale
      ? `That answer arrived too late to count as current. ${AGED}`
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
    : "That window was already closed. The next matching command asks again.";
}
