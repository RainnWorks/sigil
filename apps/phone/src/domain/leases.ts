/**
 * The lease list's pure core: turning the daemon's answer into rows the settings
 * screen can render, and deciding which of several very different sentences the
 * screen is entitled to say.
 *
 * All of it is pure and lives here rather than in the screen, because the honesty
 * rules this file encodes are the whole point of the feature and belong somewhere
 * a unit test can pin them (`leases.selftest.ts`). The rule, stated once:
 *
 *   **The phone may claim the list is complete only from a fresh successful
 *   answer.** "Asked and got none", "cannot ask right now", and "never asked" are
 *   three different facts about the world and get three different sentences. A
 *   phone that cannot reach the daemon saying "No active leases" would be a false
 *   statement of fact on the surface the brief cites as the containment for a
 *   rule-wide window, which is exactly the consent theatre this replaces.
 */
import { relativeTime, remainingWindow, safeLabel } from "@/src/lib/format";
import { COVERS_MAX_CHARS, type LeaseRow } from "@/src/protocol";

import { type ActiveLease, type LeaseView } from "./types";

/**
 * How long a successful answer still counts as describing now. Leases expire on
 * their own and can be revoked from the Mac, so an older answer is a snapshot,
 * not a state. Comfortably longer than {@link LEASE_POLL_MS} so a screen that is
 * polling normally never flickers into the stale wording.
 */
export const LEASE_ANSWER_FRESH_MS = 40_000;

/** How often the open settings screen re-asks, so the list stays a live thing. */
export const LEASE_POLL_MS = 15_000;

/**
 * How long to wait for a reply before saying so. Generous, because the transport
 * ladder's bottom rung is a long-poll through the relay: a slow answer is common,
 * and calling it a failure early would cry wolf on a surface whose warnings have
 * to mean something.
 */
export const LEASE_REPLY_TIMEOUT_MS = 20_000;

/** Layout bounds for the two daemon strings this screen sets in its own prose. */
export const SCOPE_MAX_CHARS = 48;
export const ACCOUNT_MAX_CHARS = 48;

/** The never-asked starting point, and what a reset returns to. */
export function emptyLeaseView(): LeaseView {
  return { rows: [], answeredAt: 0, asking: false, unreachable: false, revokes: [], note: null };
}

/**
 * Stamp a daemon answer against this phone's clock.
 *
 * The daemon sends durations, not deadlines, so `receivedAt` fixes them to a
 * local timeline the countdown can tick against. Transit delay makes the result
 * very slightly generous (the window really closed a round trip earlier than the
 * row says), which is the direction to err: overstating how long a window is open
 * prompts a revoke, understating it would invite the human to relax.
 *
 * Rows already past their expiry are dropped rather than rendered at zero, and
 * every display string goes through the daemon's own label allowlist a second
 * time (defence in depth, exactly as the approval caption does).
 */
export function toActiveLeases(rows: LeaseRow[], receivedAt: number): ActiveLease[] {
  const out: ActiveLease[] = [];
  for (const r of rows) {
    if (r.remainingMs <= 0) continue;
    out.push({
      grantHex: r.grantHex,
      instance: r.instance,
      scope: safeLabel(r.scope, SCOPE_MAX_CHARS),
      covers: safeLabel(r.covers, COVERS_MAX_CHARS),
      account: safeLabel(r.account, ACCOUNT_MAX_CHARS),
      expiresAt: receivedAt + r.remainingMs,
      grantedAt: receivedAt - r.ageMs,
    });
  }
  // Oldest window first, matching the daemon's own `sigil lease list` order: the
  // one that has been open longest is the one worth looking at first.
  out.sort((a, b) => a.grantedAt - b.grantedAt);
  return out;
}

/** The rows that have not run out since the answer arrived. */
export function liveLeases(view: LeaseView, nowMs: number): ActiveLease[] {
  return view.rows.filter((l) => l.expiresAt > nowMs);
}

/**
 * Where a revoke for one WINDOW stands, keyed on the instance id rather than the
 * grant key: a grant key is stable across windows, so keying on it could show a
 * newly granted window wearing the previous one's in-flight state.
 *
 * `"unconfirmed"` is the one that matters: the revoke left this phone and nothing
 * came back, so the window's state is unknown and the row must keep saying so.
 */
export function revokeState(view: LeaseView, instance: string): "idle" | "sending" | "unconfirmed" {
  const p = view.revokes.find((r) => r.instance === instance);
  if (!p) return "idle";
  return p.unconfirmed ? "unconfirmed" : "sending";
}

/**
 * The Mac-side command that ends this window for certain, named with the row's
 * real grant prefix so it can be typed as shown. Offered whenever this phone
 * cannot confirm a revoke: the fallback has to be actionable at the moment the
 * phone's own control has stopped being trustworthy.
 */
export function revokeFallback(grantHex: string): string {
  return `sigil lease revoke ${grantHex.slice(0, 12)}`;
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
   * True only when this phone has a fresh successful answer and may therefore
   * present the list as complete. Every "no leases" claim is gated on it.
   */
  authoritative: boolean;
}

/**
 * Which sentence the section is entitled to say, given what it knows and when it
 * last knew it. See the file header for why this is a function rather than a
 * ternary in the screen.
 */
export function leaseListStatus(view: LeaseView, nowMs: number): LeaseListStatus {
  const answered = view.answeredAt > 0;
  const fresh = answered && nowMs - view.answeredAt < LEASE_ANSWER_FRESH_MS && !view.unreachable;

  if (!answered) {
    // Nothing has ever come back, so there is no list to qualify: say which of
    // the three no-list situations this is, and never imply emptiness.
    if (view.asking) {
      return { kind: "asking", line: "Checking with your Mac.", authoritative: false };
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
      detail: "This phone has not yet asked your Mac what windows are open.",
      authoritative: false,
    };
  }

  const checked = `Checked ${relativeTime(view.answeredAt, nowMs)}.`;
  const doubt = view.unreachable
    ? "This phone cannot reach your Mac right now, so this may be out of date."
    : "This may be out of date.";
  const rows = liveLeases(view, nowMs);

  if (rows.length === 0) {
    // The one claim that has to be earned. A fresh answer says it plainly; a
    // stale one says only what it can stand behind: that this is what the Mac
    // said when it was last heard from.
    return fresh
      ? { kind: "empty", line: "No active leases.", detail: checked, authoritative: true }
      : {
          kind: "empty",
          line: "No active leases when this phone last checked.",
          detail: `${checked} ${doubt}`,
          authoritative: false,
        };
  }
  return fresh
    ? { kind: "rows", line: checked, authoritative: true }
    : { kind: "rows", line: checked, detail: doubt, authoritative: false };
}

/** The plain sentence for a completed revoke. Both outcomes are successes. */
export function revokeNoteLine(outcome: "closed" | "alreadyGone"): string {
  return outcome === "closed"
    ? "Window closed. The next matching command asks again."
    : "That window was already closed. Nothing to revoke.";
}
