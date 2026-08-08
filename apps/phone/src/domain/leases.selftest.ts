/**
 * Unit checks for the lease list's honesty rules: which sentence the settings
 * screen is entitled to say, what a wire answer turns into, and what the phone
 * refuses to believe.
 *
 * These are pinned here rather than left to a device pass because the failure
 * they guard against is silent. A list that renders beautifully while saying "No
 * active leases" to a phone that cannot reach the daemon looks exactly like a
 * working list, and the brief cites this surface as the containment for a
 * rule-wide window.
 *
 * House style matches src/lib/format.selftest.ts: a plain `bun run` script with
 * an `ok()` harness (no `bun:test`, so tsc stays clean and no new dep).
 * Run: `bun run src/domain/leases.selftest.ts`.
 */
import { classifyToPhone, type LeaseRow, parseLeaseListReply } from "../protocol/requests";
import { LABEL_REJECTED } from "../lib/format";
import {
  emptyLeaseView,
  LEASE_ANSWER_FRESH_MS,
  leaseListStatus,
  liveLeases,
  revokeFallback,
  revokeNoteLine,
  revokeState,
  toActiveLeases,
} from "./leases";
import { type LeaseView } from "./types";

let failures = 0;
function eq<T>(a: T, b: T, label: string): void {
  if (a === b) {
    console.log(`  ok    ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label} (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`);
  }
}
function ok(cond: boolean, label: string): void {
  eq(cond, true, label);
}

const NOW = 1_700_000_000_000;
// Exactly-width identifiers: the daemon promises 64 hex for a grant key and 32
// for a window instance, and the phone treats any other width as malformed.
const GRANT = "a1b2c3d4e5f60718".repeat(4);
const INST = "0f1e2d3c4b5a6978".repeat(2);
const INST2 = "1122334455667788".repeat(2);
const QUERY = "q-0001";

function row(over: Partial<LeaseRow> = {}): LeaseRow {
  return {
    grantHex: GRANT,
    instance: INST,
    scope: "op-eu",
    covers: "",
    account: "",
    remainingMs: 600_000,
    ageMs: 60_000,
    ...over,
  };
}

function view(over: Partial<LeaseView> = {}): LeaseView {
  return { ...emptyLeaseView(), ...over };
}

function main(): void {
  console.log("leaseListStatus (the three no-list situations are three sentences)");
  {
    const never = leaseListStatus(view(), NOW);
    eq(never.kind, "never", "never asked");
    eq(never.line, "Not checked yet.", "never asked line");
    ok(!never.authoritative, "never asked is not authoritative");

    const asking = leaseListStatus(view({ asking: true }), NOW);
    eq(asking.kind, "asking", "asking, nothing known yet");
    eq(asking.line, "Checking with your Mac.", "asking line");

    const cannot = leaseListStatus(view({ unreachable: true }), NOW);
    eq(cannot.kind, "unreachable", "asked and could not");
    eq(cannot.line, "Cannot check right now.", "unreachable line");
    ok(!cannot.authoritative, "unreachable is not authoritative");
    // The whole point: this state must never produce the empty-list sentence.
    ok(!cannot.line.startsWith("No active leases"), "unreachable never claims emptiness");
  }

  console.log("leaseListStatus (an empty list is a claim that has to be earned)");
  {
    const fresh = leaseListStatus(view({ answeredAt: NOW - 1_000 }), NOW);
    eq(fresh.kind, "empty", "fresh answer, no rows");
    eq(fresh.line, "No active leases.", "fresh empty line");
    ok(fresh.authoritative, "a fresh answer is authoritative");

    // Same answer, one tick past the freshness window: the sentence weakens.
    const old = leaseListStatus(view({ answeredAt: NOW - LEASE_ANSWER_FRESH_MS - 1 }), NOW);
    eq(old.line, "No active leases when this phone last checked.", "stale empty line");
    ok(!old.authoritative, "a stale answer is not authoritative");

    // A recent answer plus a failed query since: also not authoritative, because
    // the world may have moved and this phone would not have heard.
    const broken = leaseListStatus(view({ answeredAt: NOW - 1_000, unreachable: true }), NOW);
    eq(broken.line, "No active leases when this phone last checked.", "unreachable weakens a fresh answer");
    ok(!broken.authoritative, "unreachable is never authoritative");
    ok(
      broken.detail?.includes("cannot reach your Mac right now") ?? false,
      "stale-by-unreachable says why",
    );
  }

  console.log("leaseListStatus (rows)");
  {
    const rows = toActiveLeases([row()], NOW);
    const fresh = leaseListStatus(view({ rows, answeredAt: NOW }), NOW);
    eq(fresh.kind, "rows", "fresh rows");
    eq(fresh.line, "Checked just now.", "fresh rows say when");
    ok(fresh.detail === undefined, "fresh rows need no caveat");

    const stale = leaseListStatus(
      view({ rows, answeredAt: NOW - LEASE_ANSWER_FRESH_MS - 60_000 }),
      NOW,
    );
    eq(stale.detail, "This may be out of date.", "stale rows carry a caveat");

    // Rows that have all run out read as an empty list, not as rows.
    const lapsed = leaseListStatus(view({ rows, answeredAt: NOW }), NOW + 600_001);
    eq(lapsed.kind, "empty", "every row lapsed");
  }

  console.log("toActiveLeases (stamping the daemon's durations onto this clock)");
  {
    const [l] = toActiveLeases([row()], NOW);
    ok(l !== undefined, "one row in, one row out");
    eq(l!.expiresAt, NOW + 600_000, "expiry is arrival plus remaining");
    eq(l!.grantedAt, NOW - 60_000, "granted is arrival minus age");
    eq(l!.instance, INST, "the window id is carried through as the row identity");
    eq(l!.scope, "op-eu", "scope survives the allowlist");
    eq(l!.covers, null, "an empty covers is null, never an empty gap");
    eq(l!.account, null, "an empty account is null");

    // Already lapsed on arrival: dropped rather than rendered at zero.
    eq(toActiveLeases([row({ remainingMs: 0 })], NOW).length, 0, "expired row dropped");

    // The daemon sanitizes first; this pass is defence in depth, exactly as the
    // approval sheet's coverage caption does it.
    const nasty = toActiveLeases([row({ scope: "op‮eu" })], NOW);
    eq(nasty[0]!.scope, `op${LABEL_REJECTED}eu`, "bidi override in a rule name is marked");

    // Oldest window first: the one open longest is the one worth seeing first.
    const two = toActiveLeases(
      [row({ ageMs: 10_000 }), row({ instance: INST2, ageMs: 900_000 })],
      NOW,
    );
    eq(two[0]!.instance, INST2, "oldest first");
  }

  console.log("parseLeaseListReply (one bad row voids the answer)");
  {
    const good = parseLeaseListReply({ type: "leaseListReply", queryId: QUERY, leases: [row()] });
    eq(good?.leases.length, 1, "a well formed answer parses");
    eq(good?.queryId, QUERY, "the correlation id is carried through");

    const empty = parseLeaseListReply({ type: "leaseListReply", queryId: QUERY, leases: [] });
    eq(empty?.leases.length, 0, "an empty answer is a valid answer");

    eq(
      parseLeaseListReply({ type: "leaseListReply", leases: [] }),
      null,
      "an answer with no correlation id is dropped",
    );

    // Under-reporting is the one direction this surface must not fail in: a
    // shorter list reads as "that is everything", so a bad row voids the lot and
    // the screen falls back to saying it does not know.
    const list = (leases: unknown[]) =>
      parseLeaseListReply({ type: "leaseListReply", queryId: QUERY, leases });
    eq(list([row(), { grantHex: "nope" }]), null, "a malformed row voids the whole answer");
    eq(list([row({ grantHex: "../../etc" })]), null, "a non-hex grant key is rejected");
    eq(list([row({ grantHex: GRANT.slice(1) })]), null, "a short grant key is rejected");
    eq(list([row({ instance: "" })]), null, "a missing window id is rejected");
    eq(list([{ ...row(), remainingMs: "10" }]), null, "a non-numeric remaining is rejected");
    eq(list([{ ...row(), scope: 42 }]), null, "a non-string rule name is rejected");
    eq(
      parseLeaseListReply({ type: "leaseListReply", queryId: QUERY }),
      null,
      "a missing list is not an empty list",
    );
    eq(parseLeaseListReply(null), null, "null is not an answer");
  }

  console.log("classifyToPhone (lease answers demux, and fail closed)");
  {
    const listed = classifyToPhone({ type: "leaseListReply", queryId: QUERY, leases: [] });
    eq(listed?.kind, "leaseList", "a list reply is recognized");
    const revoked = classifyToPhone({
      type: "leaseRevokeReply",
      queryId: QUERY,
      grantHex: GRANT,
      revoked: true,
    });
    eq(revoked?.kind, "leaseRevoke", "a revoke reply is recognized");
    eq(
      classifyToPhone({ type: "leaseRevokeReply", queryId: QUERY, grantHex: GRANT }),
      null,
      "a revoke reply with no verdict is dropped",
    );
    eq(
      classifyToPhone({ type: "leaseRevokeReply", queryId: QUERY, grantHex: GRANT, revoked: "yes" }),
      null,
      "a non-boolean verdict is dropped",
    );
    eq(
      classifyToPhone({ type: "leaseRevokeReply", grantHex: GRANT, revoked: true }),
      null,
      "a revoke reply with no correlation id is dropped",
    );
    // An untagged payload is still an approval request: the existing wire shape
    // must not shift under the new tags.
    eq(classifyToPhone({ requestId: "r1" })?.kind, "request", "untagged is still a request");
  }

  console.log("revoke state and copy");
  {
    const rows = toActiveLeases([row()], NOW);
    eq(revokeState(view({ rows }), INST), "idle", "no revoke sent");
    const sending = view({
      rows,
      revokes: [{ queryId: QUERY, grantHex: GRANT, instance: INST, sentAt: NOW, unconfirmed: false }],
    });
    eq(revokeState(sending, INST), "sending", "in flight");
    // The row is still there while in flight: nothing is cleared optimistically.
    eq(liveLeases(sending, NOW).length, 1, "an in-flight revoke does not clear its row");

    const silent = view({
      rows,
      revokes: [{ queryId: QUERY, grantHex: GRANT, instance: INST, sentAt: NOW, unconfirmed: true }],
    });
    eq(revokeState(silent, INST), "unconfirmed", "no reply came back");
    // Keyed on the window, not the key: a later window under the same grant key
    // must not inherit the previous one's in-flight state.
    eq(revokeState(silent, INST2), "idle", "a different window is unaffected");
    eq(liveLeases(silent, NOW).length, 1, "an unconfirmed revoke leaves the row on screen");

    eq(revokeFallback(GRANT), "sigil lease revoke a1b2c3d4e5f6", "fallback names the real prefix");

    // Both outcomes are successes, and the second must not read as a failure.
    eq(revokeNoteLine("closed"), "Window closed. The next matching command asks again.", "closed");
    eq(
      revokeNoteLine("alreadyGone"),
      "That window was already closed. Nothing to revoke.",
      "already gone reads as a success",
    );
  }

  console.log("voice (a consent-adjacent surface: no em-dashes, no emoji)");
  {
    const strings = [
      leaseListStatus(view(), NOW),
      leaseListStatus(view({ asking: true }), NOW),
      leaseListStatus(view({ unreachable: true }), NOW),
      leaseListStatus(view({ answeredAt: NOW }), NOW),
      leaseListStatus(view({ answeredAt: NOW - 10 * 60_000, unreachable: true }), NOW),
    ]
      .flatMap((s) => [s.line, s.detail ?? ""])
      .concat(revokeNoteLine("closed"), revokeNoteLine("alreadyGone"));
    for (const s of strings) {
      ok(!/[—–]/.test(s), `no dash rule: ${JSON.stringify(s)}`);
      ok(!/\p{Extended_Pictographic}/u.test(s), `no emoji: ${JSON.stringify(s)}`);
    }
  }

  console.log(failures === 0 ? "\nlease self-test: all green" : `\nlease self-test: ${failures} FAILED`);
  if (failures > 0) process.exit(1);
}

main();
