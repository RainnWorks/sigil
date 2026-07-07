// Scratch adversarial tests for the v5.1 coexisting-waiter / newest-wins change.
// Run: bun test scratch-adversarial.test.ts   (from relay/)
import { test, expect } from "bun:test";
import * as P from "./shared/protocol";

// A "dead" waiter models a connection that is gone but whose server-side abort
// never fired (the confirmed DO behaviour): it stays registered but whatever it
// is handed goes into the void. We record what it received to prove loss.
function deadWaiter(sink: string[][]): P.Waiter {
  return (blobs) => sink.push(blobs);
}

test("RESIDUAL IS REAL: newest waiter dead + older waiter live => deposit lost to the void", () => {
  // Precondition for this loss: two coexisting waiters where the NEWER is dead
  // and the OLDER is live. wake() pops the newest (dead) and drains into it.
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  const voided: string[][] = [];
  let liveGot: string[] | null = null;

  // Older, LIVE waiter (real reconnect that can still receive).
  P.longPoll(list, waiters, Date.now(), 60_000).then((v) => (liveGot = v));
  // Newer, DEAD waiter registered after it (a second overlapping poll whose
  // connection died without its signal firing).
  waiters.push(deadWaiter(voided));
  expect(waiters.length).toBe(2);

  list.push({ blob: "approval-response", exp: Date.now() + 10_000 });
  P.wake(list, waiters, Date.now());

  // The deposit went to the dead newest and is gone; the live older got nothing.
  expect(voided).toEqual([["approval-response"]]);
  expect(liveGot).toBeNull();
  expect(list).toEqual([]); // drained, not requeued: genuinely lost
});

test("NOT reachable by a single-flight client: coexisting waiters always have the live one newest", async () => {
  // The shipped daemon (blocking, one GET at a time) and phone (activeWaits
  // aborts the prior poll before a new one) only ever overlap via
  // disconnect-then-reconnect, which makes the OLDER the orphan and the NEWER
  // live. Newest-wins then delivers correctly. This is the safe ordering.
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  const orphanVoid: string[][] = [];
  let reconnectGot: string[] | null = null;

  waiters.push(deadWaiter(orphanVoid)); // older = dead orphan
  P.longPoll(list, waiters, Date.now(), 60_000).then((v) => (reconnectGot = v)); // newer = live

  list.push({ blob: "approval-response", exp: Date.now() + 10_000 });
  P.wake(list, waiters, Date.now());
  await new Promise((r) => setTimeout(r, 0));

  expect(reconnectGot).toEqual(["approval-response"]); // live reconnect got it
  expect(orphanVoid).toEqual([]); // orphan never touched
});

const tick = () => new Promise((r) => setTimeout(r, 0));

test("STRUCTURAL: one party's slot-flood cannot evict the other party's delivery waiter", async () => {
  // toPhoneWaiters (phone reading) and toDaemonWaiters (daemon reading) are
  // disjoint. A flood on one slot never reaches the other, so neither paired
  // party can starve the other's inbound delivery via MAX_WAITERS.
  const m = P.newMailbox();
  // Daemon parks a legitimate waiter on to-daemon.
  let daemonGot: string[] | null = null;
  P.longPoll(m.toDaemon, m.toDaemonWaiters, Date.now(), 60_000).then((v) => (daemonGot = v));

  // Attacker floods to-phone far past the cap.
  for (let i = 0; i < P.MAX_WAITERS * 4; i++) {
    P.longPoll(m.toPhone, m.toPhoneWaiters, Date.now(), 60_000);
  }
  expect(m.toPhoneWaiters.length).toBe(P.MAX_WAITERS); // bounded
  expect(m.toDaemonWaiters.length).toBe(1); // untouched: daemon's waiter survives

  // A phone->daemon deposit still reaches the daemon's live waiter.
  P.enqueue(m.toDaemon, "still-delivered", Date.now());
  P.wake(m.toDaemon, m.toDaemonWaiters, Date.now());
  await tick();
  expect(daemonGot).toEqual(["still-delivered"]);
});

test("MAX_WAITERS drop-oldest never loses a queued deposit: slot is provably empty at eviction", () => {
  // Eviction only runs on the empty-slot branch of longPoll (drain returned
  // nothing), synchronously, no await between drain and the while-loop. So a
  // dropped waiter cannot be masking an undelivered item.
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  const drops: string[][] = [];
  for (let i = 0; i < P.MAX_WAITERS; i++) waiters.push(deadWaiter(drops));
  // A real item is queued, but the drop path is unreachable while list is
  // non-empty: longPoll would drain-and-return immediately instead of evicting.
  const immediate = P.longPoll(
    [{ blob: "queued", exp: Date.now() + 10_000 }],
    waiters,
    Date.now(),
    60_000,
  );
  return immediate.then((v) => {
    expect(v).toEqual(["queued"]); // returned to the caller, no eviction happened
    expect(drops).toEqual([]); // nobody dropped, nothing lost
  });
});
