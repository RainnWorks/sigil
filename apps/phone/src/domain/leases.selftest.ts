/**
 * Unit checks for the lease list's honesty rules: which sentence the settings
 * screen is entitled to say, what a wire snapshot turns into, what the phone
 * refuses to believe, and the correlation that stops a captured reply from
 * confirming a revoke that never happened.
 *
 * These are pinned here rather than left to a device pass because the failures
 * they guard against are silent. A list that renders beautifully while saying "No
 * active leases" to a phone that cannot reach the daemon looks exactly like a
 * working list, and a revoke that reports success on a replayed reply looks
 * exactly like a revoke.
 *
 * House style matches src/lib/format.selftest.ts: a plain `bun run` script with
 * an `ok()` harness (no `bun:test`, so tsc stays clean and no new dep).
 * Run: `bun run src/domain/leases.selftest.ts`.
 */
import {
  classifyToPhone,
  LEASE_ID_CHARS,
  LEASE_PAD_BUCKET,
  type LeaseListMessage,
  type LeaseRevokeMessage,
  type LeaseRow,
  padLeaseControl,
  parseLeaseListReply,
  parseLeaseRevokeReply,
} from "../protocol/requests";
import { LABEL_REJECTED } from "../lib/format";
import { OutstandingRequests } from "../session/outstanding";
import {
  asOfClock,
  emptyLeaseView,
  LEASE_SNAPSHOT_FRESH_MS,
  leaseListStatus,
  liveLeases,
  mergeRevoke,
  partitionRevokes,
  REVOKE_FALLBACK_CAVEAT,
  REVOKE_FALLBACK_LEAD,
  REVOKE_FALLBACK_LIST,
  REVOKE_FALLBACK_REVOKE,
  lapsedRevokeLine,
  revokeNoteLine,
  revokeResolution,
  revokeState,
  settledByAbsence,
  snapshotFresh,
  toActiveLeases,
  unconfirmedRevokeDetail,
  unconfirmedRevokeLine,
  unconfirmedRevokes,
} from "./leases";
import { type LeaseView, type PendingRevoke } from "./types";

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
/** 128 opaque bits as 32 lowercase hex: the exact width the daemon promises. */
const LEASE = "0f1e2d3c4b5a6978".repeat(2);
const LEASE2 = "1122334455667788".repeat(2);
const REQ = "0192f0a1-b2c3-7d4e-8f90-1a2b3c4d5e6f";
const REQ2 = "0192f0a1-b2c3-7d4e-8f90-aabbccddeeff";
/** A grant key width, which must never appear on this surface at all. */
const GRANT = "a1b2c3d4e5f60718".repeat(4);

function row(over: Partial<LeaseRow> = {}): LeaseRow {
  return { leaseId: LEASE, scope: "op-eu", covers: "", account: "", remainingMs: 600_000, ...over };
}

function view(over: Partial<LeaseView> = {}): LeaseView {
  return { ...emptyLeaseView(), ...over };
}

function revoke(over: Partial<PendingRevoke> = {}): PendingRevoke {
  return {
    requestId: REQ,
    leaseId: LEASE,
    scope: "op-eu",
    sentAt: NOW,
    windowExpiresAt: NOW + 600_000,
    inFlight: false,
    unconfirmed: false,
    ...over,
  };
}

/** A minimal history row; only `decision` and `at` are ever read here. */
const historyEntry = {
  id: "h1",
  kind: "secret_read" as const,
  label: "",
  origin: "",
  process: "",
  cwd: "",
  decision: "approved" as const,
  at: NOW,
  via: "phone",
};

function main(): void {
  console.log("leaseListStatus (the three no-list situations are three sentences)");
  {
    const never = leaseListStatus(view(), NOW);
    eq(never.kind, "never", "never asked");
    eq(never.line, "Not checked yet.", "never asked line");
    ok(never.detail?.includes("Face ID") ?? false, "never asked says asking costs a biometric");
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

    // A device with no enrolled biometric cannot ask at all, which is a dead end
    // rather than a fault in the link, and reads as one.
    const noBio = leaseListStatus(view({ noBiometric: true }), NOW);
    eq(noBio.line, "Cannot check from this device.", "no biometric enrolled");
    ok(noBio.detail?.includes("sigil lease list") ?? false, "and names the Mac instead");
    ok(!noBio.authoritative, "no biometric is not authoritative");
  }

  console.log("leaseListStatus (an empty list is a claim that has to be earned)");
  {
    const answered = { askedAt: NOW - 1_000, asOfMs: NOW - 1_000 };
    const fresh = leaseListStatus(view(answered), NOW);
    eq(fresh.kind, "empty", "fresh snapshot, no rows");
    eq(fresh.line, "No active leases.", "fresh empty line");
    ok(fresh.detail?.startsWith("Snapshot as of ") ?? false, "fresh empty stamps the snapshot");
    ok(fresh.authoritative, "a fresh snapshot is authoritative");

    // One tick past the freshness window: the sentence weakens and dates itself.
    const agedAt = NOW - LEASE_SNAPSHOT_FRESH_MS - 1;
    const old = leaseListStatus(view({ askedAt: agedAt, asOfMs: agedAt }), NOW);
    eq(old.line, `No active leases as of ${asOfClock(agedAt)}.`, "stale empty line dates itself");
    ok(!old.authoritative, "a stale snapshot is not authoritative");
    ok(old.detail?.includes("Check again") ?? false, "a stale snapshot says what to do");

    // A recent snapshot plus a failed query since: also not authoritative,
    // because the world may have moved and this phone would not have heard.
    const broken = leaseListStatus(view({ ...answered, unreachable: true }), NOW);
    ok(!broken.authoritative, "unreachable is never authoritative");
    ok(
      broken.detail?.includes("cannot reach your Mac right now") ?? false,
      "stale-by-unreachable says why",
    );
  }

  console.log("snapshot freshness (10s, measured locally, not on the daemon's clock)");
  {
    ok(!snapshotFresh(view(), NOW), "never answered is never fresh");
    ok(snapshotFresh(view({ askedAt: NOW - 9_000, asOfMs: NOW }), NOW), "9s old is fresh");
    ok(!snapshotFresh(view({ askedAt: NOW - 11_000, asOfMs: NOW }), NOW), "11s old is stale");
    // A daemon clock running fast must not be able to refresh an old snapshot.
    ok(
      !snapshotFresh(view({ askedAt: NOW - 60_000, asOfMs: NOW + 3_600_000 }), NOW),
      "a future asOfMs cannot make an old snapshot look current",
    );
    eq(asOfClock(new Date(2026, 0, 2, 14, 3, 7).getTime()), "14:03:07", "asOfMs renders as a clock");
  }

  console.log("a stalled reply cannot buy currency (R7-F1)");
  {
    // The relay picks how long to sit on an answer. Stalling it 19s, just inside
    // the 20s reply timeout, must not produce a snapshot that reads as current:
    // age is measured from when the QUESTION went out, which no one but this
    // phone can push later.
    const sentAt = NOW - 19_000;
    const stalled = view({ askedAt: sentAt, asOfMs: NOW - 100 });
    ok(!snapshotFresh(stalled, NOW), "a 19s stalled reply is not fresh");
    const s = leaseListStatus(stalled, NOW);
    eq(s.line, `No active leases as of ${asOfClock(NOW - 100)}.`, "and cannot claim emptiness flatly");
    ok(!s.authoritative, "a stalled reply is never authoritative");

    // Had it been stamped at arrival, this same answer would have read as brand
    // new. That is the bug this pins, so state it as an assertion rather than
    // trusting the constant above to stay put.
    ok(
      snapshotFresh(view({ askedAt: NOW, asOfMs: NOW - 100 }), NOW),
      "the same answer stamped at arrival would have looked current",
    );

    // A prompt answer is still fresh: the fix must not make the definite claim
    // unreachable over an honest link.
    ok(snapshotFresh(view({ askedAt: NOW - 1_500, asOfMs: NOW }), NOW), "a 1.5s round trip stays fresh");
  }

  console.log("born stale: a snapshot that was never current on this screen");
  {
    // The 10 to 20 second band is the ordinary slow path down a relay rung, so
    // this is not rare. "That snapshot has aged" would tell someone they saw a
    // current list a moment ago when they never did.
    const born = view({ askedAt: NOW - 15_000, arrivedAt: NOW - 1_000, asOfMs: NOW - 2_000 });
    const s = leaseListStatus(born, NOW);
    ok(s.detail?.includes("arrived too late to count as current") ?? false, "says it was born stale");
    ok(!(s.detail?.includes("has aged") ?? false), "and not that it aged on screen");

    // A prompt round trip that later ages still reads as having aged.
    const aged = view({ askedAt: NOW - 15_000, arrivedAt: NOW - 14_000, asOfMs: NOW - 14_000 });
    ok(leaseListStatus(aged, NOW).detail?.includes("has aged") ?? false, "an aged snapshot says so");

    // Unreachable still wins: not being able to ask is the bigger fact.
    const broken = view({ askedAt: NOW - 15_000, arrivedAt: NOW - 1_000, unreachable: true });
    ok(
      leaseListStatus(broken, NOW).detail?.includes("cannot reach your Mac") ?? false,
      "unreachable outranks born stale",
    );

    // arrivedAt is display reasoning only and must never reach the freshness
    // decision, which ages from askedAt so a stalled reply cannot buy currency.
    ok(!snapshotFresh(born, NOW), "a born-stale snapshot is not fresh");
    ok(
      snapshotFresh(view({ askedAt: NOW - 1_000, arrivedAt: NOW - 30_000 }), NOW),
      "and a bogus arrival time cannot change the freshness verdict",
    );
  }

  console.log("leaseListStatus (rows)");
  {
    const rows = toActiveLeases([row()], NOW);
    const fresh = leaseListStatus(view({ rows, askedAt: NOW, asOfMs: NOW }), NOW);
    eq(fresh.kind, "rows", "fresh rows");
    eq(fresh.line, `Snapshot as of ${asOfClock(NOW)}.`, "fresh rows stamp the snapshot");
    ok(fresh.detail === undefined, "fresh rows need no caveat");

    const agedAt = NOW - LEASE_SNAPSHOT_FRESH_MS - 60_000;
    const stale = leaseListStatus(view({ rows, askedAt: agedAt, asOfMs: agedAt }), NOW);
    ok(stale.detail?.includes("Check again") ?? false, "stale rows carry a caveat");

    // Rows that have all run out read as an empty list, not as rows.
    const lapsed = leaseListStatus(view({ rows, askedAt: NOW, asOfMs: NOW }), NOW + 600_001);
    eq(lapsed.kind, "empty", "every row lapsed");
  }

  console.log("toActiveLeases (stamping the daemon's snapshot onto this clock)");
  {
    const [l] = toActiveLeases([row()], NOW);
    ok(l !== undefined, "one row in, one row out");
    eq(l!.leaseId, LEASE, "the opaque window id is the row identity");
    eq(l!.expiresAt, NOW + 600_000, "expiry is arrival plus remaining");
    eq(l!.windowMs, 600_000, "the countdown scale is remaining-on-arrival");
    eq(l!.scope, "op-eu", "scope survives the allowlist");
    eq(l!.covers, null, "an empty covers is null, never an empty gap");
    eq(l!.account, null, "an empty account is null");

    // THE ASYMMETRY, pinned so nobody "makes it consistent" later. Remaining
    // time is stamped at ARRIVAL, which over-reports how long a window is open
    // and so prompts a revoke. Snapshot age is measured from SEND, which
    // over-reports staleness and so withholds the "none" claim. Both err toward
    // "assume more is open than you can see".
    const arrived = NOW + 19_000; // a relay stalled the reply this long
    const stamped = toActiveLeases([row({ remainingMs: 600_000 })], arrived);
    ok(
      stamped[0]!.expiresAt > NOW + 600_000,
      "remaining time is stamped at arrival, so a stalled reply over-reports the window",
    );

    // Already lapsed on arrival: dropped rather than rendered at zero.
    eq(toActiveLeases([row({ remainingMs: 0 })], NOW).length, 0, "expired row dropped");

    // scope and account are raw config text the user wrote, so the daemon
    // sanitizes and this pass repeats it. Defence in depth, not ceremony.
    const nasty = toActiveLeases([row({ scope: "op‮eu", account: "prod​vault" })], NOW);
    eq(nasty[0]!.scope, `op${LABEL_REJECTED}eu`, "bidi override in a rule name is marked");
    eq(nasty[0]!.account, `prod${LABEL_REJECTED}vault`, "zero width in an account is marked");

    // Least time left first: the long window is the one worth ending.
    const two = toActiveLeases(
      [row({ remainingMs: 900_000 }), row({ leaseId: LEASE2, remainingMs: 60_000 })],
      NOW,
    );
    eq(two[0]!.leaseId, LEASE2, "soonest to lapse first");
  }

  console.log("parseLeaseListReply (correlated, stamped, and all-or-nothing)");
  {
    const good = parseLeaseListReply({
      type: "leaseListReply",
      inReplyTo: REQ,
      asOfMs: NOW,
      leases: [row()],
    });
    eq(good?.leases.length, 1, "a well formed snapshot parses");
    eq(good?.inReplyTo, REQ, "the correlation id is carried through");
    eq(good?.asOfMs, NOW, "the snapshot time is carried through");

    const list = (leases: unknown[], over: Record<string, unknown> = {}) =>
      parseLeaseListReply({ type: "leaseListReply", inReplyTo: REQ, asOfMs: NOW, ...over, leases });

    eq(list([])?.leases.length, 0, "an empty snapshot is a valid snapshot");
    eq(list([], { inReplyTo: undefined }), null, "a snapshot with no correlation id is dropped");
    eq(list([], { inReplyTo: "not-a-uuid" }), null, "a malformed correlation id is dropped");
    eq(list([], { asOfMs: undefined }), null, "an unstamped snapshot is dropped");

    // `pad` is inert filler. It must parse away to nothing: never surfaced,
    // never sanitized, and never able to change what the screen decides.
    const padded = list([row()], { pad: ".".repeat(4096) });
    eq(padded?.leases.length, 1, "a padded snapshot parses exactly as an unpadded one");
    eq((padded as unknown as Record<string, unknown>).pad, undefined, "and the filler is dropped");

    // Under-reporting is the one direction this surface must not fail in: a
    // shorter list reads as "that is everything", so a bad row voids the lot and
    // the screen falls back to saying it does not know.
    eq(list([row(), { leaseId: "nope" }]), null, "a malformed row voids the whole snapshot");
    eq(list([row({ leaseId: GRANT })]), null, "a grant-key-width id is not a lease id");
    eq(list([row({ leaseId: LEASE.slice(1) })]), null, "a short lease id is rejected");
    eq(list([{ ...row(), remainingMs: "10" }]), null, "a non-numeric remaining is rejected");
    eq(list([{ ...row(), scope: 42 }]), null, "a non-string rule name is rejected");
    eq(parseLeaseListReply({ type: "leaseListReply", inReplyTo: REQ, asOfMs: NOW }), null, "a missing list is not an empty list");
    eq(parseLeaseListReply(null), null, "null is not a snapshot");
  }

  console.log("parseLeaseRevokeReply (nothing confirms without a correlation id)");
  {
    const base = { type: "leaseRevokeReply", inReplyTo: REQ, leaseId: LEASE, revoked: true };
    eq(parseLeaseRevokeReply(base)?.revoked, true, "a well formed verdict parses");
    eq(parseLeaseRevokeReply({ ...base, inReplyTo: undefined }), null, "no correlation id, no confirmation");
    eq(parseLeaseRevokeReply({ ...base, revoked: "yes" }), null, "a non-boolean verdict is dropped");
    eq(parseLeaseRevokeReply({ ...base, leaseId: GRANT }), null, "a grant-key-width id is dropped");
  }

  console.log("classifyToPhone (lease answers demux, and fail closed)");
  {
    const listed = classifyToPhone({ type: "leaseListReply", inReplyTo: REQ, asOfMs: NOW, leases: [] });
    eq(listed?.kind, "leaseList", "a snapshot is recognized");
    const revoked = classifyToPhone({
      type: "leaseRevokeReply",
      inReplyTo: REQ,
      leaseId: LEASE,
      revoked: true,
    });
    eq(revoked?.kind, "leaseRevoke", "a verdict is recognized");
    eq(
      classifyToPhone({ type: "leaseRevokeReply", leaseId: LEASE, revoked: true }),
      null,
      "an uncorrelated verdict never reaches the app",
    );
    // An untagged payload is still an approval request: the existing wire shape
    // must not shift under the new tags.
    eq(classifyToPhone({ requestId: "r1" })?.kind, "request", "untagged is still a request");
  }

  console.log("padLeaseControl (F7: length must not carry the row count)");
  {
    const bytes = (v: unknown) => new TextEncoder().encode(JSON.stringify(v)).length;

    const list = padLeaseControl<LeaseListMessage>({ type: "leaseList", pad: "" });
    eq(bytes(list) % LEASE_PAD_BUCKET, 0, "a list request lands on a bucket");
    eq(bytes(list), LEASE_PAD_BUCKET, "and fits in the first one");

    const rev = padLeaseControl<LeaseRevokeMessage>({
      type: "leaseRevoke",
      leaseId: LEASE,
      pad: "",
    });
    eq(bytes(rev) % LEASE_PAD_BUCKET, 0, "a revoke lands on a bucket");
    // The whole point: the two must be indistinguishable by length, or the relay
    // reads "the human is revoking something" straight off the ciphertext.
    eq(bytes(rev), bytes(list), "a revoke is the same size as a list");

    // Padding is exact, not approximate: `pad` always serializes, so measuring
    // with it empty already accounts for the field's own overhead.
    eq(padLeaseControl({ pad: "" }).pad.length, LEASE_PAD_BUCKET - bytes({ pad: "" }), "exact fill");

    // A payload that overflows still lands on a bucket rather than spilling.
    const big = padLeaseControl({ pad: "", blob: "x".repeat(2000) });
    eq(bytes(big) % LEASE_PAD_BUCKET, 0, "an oversized payload rolls to the next bucket");
    ok(bytes(big) > LEASE_PAD_BUCKET, "and really did overflow the first");

    // Idempotent: padding an already-padded message must not grow it, or a
    // resend would change size and leak that it was a resend.
    eq(bytes(padLeaseControl(list)), bytes(list), "padding twice changes nothing");
  }

  console.log("OutstandingRequests (F3: the captured-reply replay)");
  {
    const o = new OutstandingRequests();
    o.issue(REQ, "revoke", NOW);
    ok(o.claim(REQ, "revoke") !== null, "a reply to a question we asked is claimed");
    ok(o.claim(REQ, "revoke") === null, "the same reply cannot be claimed twice");
    eq(o.size, 0, "claiming consumes the entry");

    o.issue(REQ, "revoke", NOW);
    ok(o.claim(REQ, "list") === null, "a reply of the wrong kind is not claimed");
    ok(o.claim(REQ2, "revoke") === null, "a reply naming a question we never asked is not claimed");

    o.issue(REQ2, "list", NOW);
    o.abandon(REQ2);
    ok(o.claim(REQ2, "list") === null, "a question given up on cannot be answered later");

    // The send time rides with the question, because the answer's age is
    // measured from it rather than from whenever the reply turns up.
    const timed = new OutstandingRequests();
    timed.issue(REQ, "list", NOW - 19_000);
    eq(timed.claim(REQ, "list")?.sentAt, NOW - 19_000, "the send time comes back with the claim");

    // Only one list question may be outstanding: two would let an older snapshot
    // land after a newer one and repaint the screen backwards.
    const many = new OutstandingRequests();
    many.issue(REQ, "list", NOW);
    many.issue(REQ2, "revoke", NOW);
    eq(many.idsOfKind("list").length, 1, "outstanding list questions are enumerable");
    eq(many.idsOfKind("list")[0], REQ, "and the caller can stand the old one down");

    // The attack, end to end. The relay captured a genuine revoked:true from an
    // earlier session; the app was killed, which is what empties both this set
    // and the envelope guard's; the human taps revoke and the relay suppresses
    // the request and delivers the captured reply. A fresh process has no entry
    // for it, so it confirms nothing and the row stays put.
    const afterRestart = new OutstandingRequests();
    const captured = REQ;
    afterRestart.issue(REQ2, "revoke", NOW); // the human's new, suppressed revoke
    ok(
      afterRestart.claim(captured, "revoke") === null,
      "a captured reply replayed into a fresh session confirms nothing",
    );
    ok(afterRestart.size === 1, "and the human's real question is still outstanding");
  }

  console.log("revoke state, standing warnings, and copy");
  {
    const rows = toActiveLeases([row()], NOW);
    eq(revokeState(view({ rows }), LEASE), "idle", "no revoke sent");

    const sending = view({ rows, revokes: [revoke({ inFlight: true })] });
    eq(revokeState(sending, LEASE), "sending", "in flight");
    // The row is still there while in flight: nothing is cleared optimistically.
    eq(liveLeases(sending, NOW).length, 1, "an in-flight revoke does not clear its row");
    eq(unconfirmedRevokes(sending).length, 0, "in flight is not yet a warning");

    const silent = view({ rows, revokes: [revoke({ unconfirmed: true })] });
    eq(revokeState(silent, LEASE), "unconfirmed", "no reply came back");
    eq(liveLeases(silent, NOW).length, 1, "an unconfirmed revoke leaves the row on screen");
    eq(unconfirmedRevokes(silent).length, 1, "and raises a standing warning");
    eq(revokeState(silent, LEASE2), "idle", "a different window is unaffected");

    // MUST FIX 1. An unconfirmed revoke has to stay actionable. Dead here, the
    // only way left to close the window was the Mac, which makes refusing heavier
    // than approving on the one control that must never be, and contradicts the
    // very argument used to justify having no confirmation step.
    ok(revokeState(silent, LEASE) !== "sending", "unconfirmed is not an in-flight state");

    // A retry is BOTH in flight and still unconfirmed, so the row can show work
    // happening while the warning goes on standing.
    const retrying = view({ rows, revokes: [revoke({ inFlight: true, unconfirmed: true })] });
    eq(revokeState(retrying, LEASE), "retrying", "a retry is its own state");
    eq(unconfirmedRevokes(retrying).length, 1, "and the warning survives it");

    // The merge is what makes that true: a retry must not erase the warning it is
    // retrying, and must not restart the clock the warning dates itself from.
    const prior = revoke({ unconfirmed: true, sentAt: NOW });
    const attempt = revoke({ requestId: REQ2, inFlight: true, unconfirmed: false, sentAt: NOW + 30_000 });
    const merged = mergeRevoke(prior, attempt);
    eq(merged.unconfirmed, true, "a retry keeps the unconfirmed flag");
    eq(merged.sentAt, NOW, "and the original send time");
    eq(merged.inFlight, true, "while being in flight again");
    eq(merged.requestId, REQ2, "under the new request id");
    eq(mergeRevoke(undefined, attempt), attempt, "a first attempt merges with nothing");

    // Settling by absence. The inference rests entirely on lease-id permanence,
    // NOT on the snapshot having been taken after the revoke went out, so a
    // snapshot computed before the revoke settles it just the same. This is
    // pinned because the ordering guard looks necessary and is not, and a reader
    // who reinstated one would likely reach for asOfMs, the daemon's
    // unauthenticated clock, which nothing here may decide on.
    const rowsNow = toActiveLeases([row()], NOW);
    const pending = revoke({ unconfirmed: true, sentAt: NOW });
    eq(settledByAbsence([pending], rowsNow).length, 0, "a window still listed is not settled");
    eq(settledByAbsence([pending], []).length, 1, "a window absent from a snapshot is settled");
    // Absence proves death at compute time and death is permanent, so a snapshot
    // the daemon computed BEFORE this revoke was even sent still settles it.
    const stale = revoke({ unconfirmed: true, sentAt: NOW + 60_000 });
    eq(settledByAbsence([stale], []).length, 1, "ordering does not enter into it");
    // The converse is conservative rather than wrong: still listed, still pending.
    eq(settledByAbsence([stale], rowsNow).length, 0, "and still-listed stays pending either way");
    // Only the absent one settles when several are pending.
    const other = revoke({ unconfirmed: true, leaseId: LEASE2 });
    const both = settledByAbsence([pending, other], rowsNow);
    eq(both.length, 1, "one of two pending revokes settles");
    eq(both[0]!.leaseId, LEASE2, "and it is the one the snapshot does not list");

    // TTL retirement. A warning with no dismiss is right, but one that never
    // resolves stops being read, and a lease is TTL-bounded so there is an honest
    // end to it: past the window's own expiry it is closed whether or not the
    // revoke landed. This also catches a genuine success answered a second after
    // the reply timeout, which had to be dropped.
    const r = revoke({ unconfirmed: true, sentAt: NOW, windowExpiresAt: NOW + 60_000 });
    eq(revokeResolution(r, [], NOW), "standing", "before the window expires, still an open question");
    eq(revokeResolution(r, [], NOW + 60_001), "lapsed", "past its expiry, it ran out on its own");
    // Leads with the resolution, then keeps the residual: saying only that it
    // expired would quietly imply the revoke worked.
    ok(lapsedRevokeLine(r).startsWith("The op-eu window has since run out"), "leads with the news");
    ok(lapsedRevokeLine(r).includes("assume it was open until then"), "and keeps the residual");
    ok(
      lapsedRevokeLine(revoke({ scope: null })).startsWith("That window has since run out"),
      "the no-scope variant still reads as a sentence",
    );
    // Both warning lines are about the WINDOW, never the rule: "the revoke of
    // op-eu" read as though the rule itself were being revoked.
    ok(!lapsedRevokeLine(r).includes("revoke of"), "lapsed line does not revoke a rule");
    ok(!unconfirmedRevokeLine(r).includes("revoke of"), "standing line does not revoke a rule");
    eq(
      unconfirmedRevokeLine(r),
      "No reply about the op-eu window, so it may still be open.",
      "standing line says no reply rather than never",
    );

    // A refresh extends an existing window, so an approval since the revoke went
    // out could have renewed it. That cannot be observed, so it is inferred
    // conservatively: any approval, and any request another device resolved,
    // keeps the warning standing. Over-warning is the safe direction.
    const approved = [{ ...historyEntry, decision: "approved" as const, at: NOW + 10 }];
    eq(revokeResolution(r, approved, NOW + 60_001), "standing", "an approval since could have renewed it");
    const elsewhere = [{ ...historyEntry, decision: "superseded" as const, at: NOW + 10 }];
    eq(revokeResolution(r, elsewhere, NOW + 60_001), "standing", "so could another device resolving one");
    const denied = [{ ...historyEntry, decision: "denied" as const, at: NOW + 10 }];
    eq(revokeResolution(r, denied, NOW + 60_001), "lapsed", "a denial cannot have renewed anything");
    const before = [{ ...historyEntry, decision: "approved" as const, at: NOW - 10 }];
    eq(revokeResolution(r, before, NOW + 60_001), "lapsed", "an approval from before the revoke is irrelevant");

    // Standing and lapsed warnings go to different places on screen, so they are
    // partitioned rather than filtered at the render site.
    const mixed = view({
      revokes: [
        revoke({ unconfirmed: true, leaseId: LEASE, windowExpiresAt: NOW + 60_000 }),
        revoke({ unconfirmed: true, leaseId: LEASE2, windowExpiresAt: NOW - 1 }),
      ],
    });
    const parts = partitionRevokes(mixed, [], NOW);
    eq(parts.standing.length, 1, "one still standing");
    eq(parts.standing[0]!.leaseId, LEASE, "the one whose window has time left");
    eq(parts.lapsed.length, 1, "one lapsed");
    eq(parts.lapsed[0]!.leaseId, LEASE2, "the one whose window ran out");

    // The warning has to stand on its own once the snapshot behind it is gone.
    const orphaned = view({ revokes: [revoke({ unconfirmed: true })] });
    eq(unconfirmedRevokes(orphaned).length, 1, "a warning outlives its snapshot");
    ok(
      unconfirmedRevokeLine(revoke({ unconfirmed: true })).includes("may still be open"),
      "the warning says the window may still be open",
    );
    ok(
      unconfirmedRevokeLine(revoke({ scope: null })).includes("that window"),
      "a warning with no rule name still reads as a sentence",
    );
    // MUST FIX A. The detail line has to agree with the control beside it. While
    // a retry is in flight the button is disabled and reads "Revoking", so
    // telling the human to tap it would point at a dead control that already says
    // it is working. And because sentAt stays at the first attempt, "Sent 4m ago
    // with no reply" alone reads as nothing happening while something is.
    const idleDetail = unconfirmedRevokeDetail(revoke({ unconfirmed: true }), NOW, false);
    ok(idleDetail.includes("Tap Revoke again"), "idle offers the retry");
    const retryDetail = unconfirmedRevokeDetail(revoke({ unconfirmed: true }), NOW, true);
    ok(retryDetail.includes("Trying again now"), "retrying says work is happening");
    ok(!retryDetail.includes("Tap Revoke again"), "and never points at the disabled control");
    // Neither form may end in a colon: the Mac steps moved to their own block, so
    // a trailing colon would point at whatever renders next, which with two
    // standing warnings is the other warning.
    ok(!idleDetail.trimEnd().endsWith(":"), "idle detail does not dangle a colon");
    ok(!retryDetail.trimEnd().endsWith(":"), "retrying detail does not dangle a colon");
    // MUST FIX B. The hoisted block carries the lead-in the per-warning line lost.
    ok(REVOKE_FALLBACK_LEAD.trimEnd().endsWith(":"), "the Mac block introduces its commands");
    ok(REVOKE_FALLBACK_LEAD.includes("on the Mac"), "and says where they are run");

    // The Mac fallback names a placeholder, never an id from here: the CLI's
    // revoke is prefix matched, so a truncated id would revoke everything.
    ok(REVOKE_FALLBACK_REVOKE.includes("<prefix>"), "the fallback is a placeholder");
    ok(REVOKE_FALLBACK_LIST === "sigil lease list", "and is preceded by the listing step");
    // The Mac's revoke is a prefix match over the grant key, so it can close
    // siblings this phone never showed. Closing too much is safe; being
    // surprised by it is not (R7-F4).
    ok(REVOKE_FALLBACK_CAVEAT.includes("may close other windows"), "the fallback warns it closes more");
    // ...and immediately says why that is not a reason to hesitate. Leaving a
    // window open is the failure this feature exists to prevent.
    ok(
      REVOKE_FALLBACK_CAVEAT.includes("only costs another approval"),
      "and tells the reader the over-shoot is cheap",
    );

    // Both verdicts are successes, and the second must not read as a failure.
    eq(revokeNoteLine("closed"), "Window closed. The next matching command asks again.", "closed");
    eq(
      revokeNoteLine("alreadyGone"),
      "That window was already closed. The next matching command asks again.",
      "already gone states the same consequence as the closed line",
    );
  }

  console.log("no grant key reaches this surface, in any string");
  {
    // A grant key is not unique per window, is a stable correlator that would
    // outlive the window and survive a re-pair, and is what the CLI's prefix
    // matcher over-matches on. The phone must never render or hold one, so every
    // string this module can produce is checked for anything of that shape.
    const rows = toActiveLeases([row()], NOW);
    const strings = [
      ...[view(), view({ asking: true }), view({ unreachable: true }), view({ askedAt: NOW, asOfMs: NOW }), view({ rows, askedAt: NOW, asOfMs: NOW })]
        .map((v) => leaseListStatus(v, NOW))
        .flatMap((s) => [s.line, s.detail ?? ""]),
      unconfirmedRevokeLine(revoke({ unconfirmed: true })),
      lapsedRevokeLine(revoke({ unconfirmed: true })),
      unconfirmedRevokeDetail(revoke({ unconfirmed: true }), NOW, false),
      unconfirmedRevokeDetail(revoke({ unconfirmed: true }), NOW, true),
      REVOKE_FALLBACK_LEAD,
      REVOKE_FALLBACK_CAVEAT,
      REVOKE_FALLBACK_LIST,
      REVOKE_FALLBACK_REVOKE,
      revokeNoteLine("closed"),
      revokeNoteLine("alreadyGone"),
      JSON.stringify(rows),
    ];
    for (const s of strings) {
      ok(!/[0-9a-f]{33,}/i.test(s), `no grant-key-shaped hex: ${JSON.stringify(s.slice(0, 60))}`);
    }
    // The row keeps its opaque id, which is exactly the permitted width.
    eq(rows[0]!.leaseId.length, LEASE_ID_CHARS, "the row's id is a lease id, not a grant key");
  }

  console.log("voice (a consent-adjacent surface: no em-dashes, no emoji)");
  {
    const rows = toActiveLeases([row()], NOW);
    const strings = [
      view(),
      view({ asking: true }),
      view({ unreachable: true }),
      view({ askedAt: NOW, asOfMs: NOW }),
      view({ askedAt: NOW - 10 * 60_000, asOfMs: NOW - 10 * 60_000, unreachable: true }),
      view({ rows, askedAt: NOW, asOfMs: NOW }),
    ]
      .map((v) => leaseListStatus(v, NOW))
      .flatMap((s) => [s.line, s.detail ?? ""])
      .concat(
        unconfirmedRevokeLine(revoke({ unconfirmed: true })),
        lapsedRevokeLine(revoke({ unconfirmed: true })),
        revokeNoteLine("closed"),
        revokeNoteLine("alreadyGone"),
      );
    for (const s of strings) {
      // Escaped rather than literal so this assertion does not itself trip
      // the house-rules lint, which scans this tree for em-dash codepoints.
      // Same two characters: U+2014 em-dash, U+2013 en-dash.
      ok(!/[\u2014\u2013]/.test(s), `no dash rule: ${JSON.stringify(s)}`);
      ok(!/\p{Extended_Pictographic}/u.test(s), `no emoji: ${JSON.stringify(s)}`);
    }
  }

  console.log(failures === 0 ? "\nlease self-test: all green" : `\nlease self-test: ${failures} FAILED`);
  if (failures > 0) process.exit(1);
}

main();
