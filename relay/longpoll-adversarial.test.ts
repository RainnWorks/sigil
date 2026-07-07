// Scratch adversarial tests for the v5.1 coexisting-waiter / newest-wins change.
// Run: bun test scratch-adversarial.test.ts   (from relay/)
import { test, expect } from "bun:test";
import * as P from "./shared/protocol";

// A SILENT-ORPHAN waiter models a connection that is gone but whose server-side
// abort never fired (the confirmed DO behaviour): it stays registered, is NOT
// settled, so it still reports it ACCEPTED (returns true), and whatever it is
// handed goes into the void. This is the case the relay cannot observe and so
// cannot save. We record what it received to prove loss.
function silentOrphan(sink: string[][]): P.Waiter {
  return (blobs) => {
    sink.push(blobs);
    return true; // not settled => accepts; the loss the relay cannot detect
  };
}

// A SETTLED-DEAD waiter models a connection whose abort/timeout DID fire: the
// real longPoll waiter would have spliced itself out of the array on settling,
// but if wake ever reaches one it must REJECT the offer (return false) so the
// item is preserved. Offer-then-drain relies on exactly this.
function settledDead(): P.Waiter {
  return () => false;
}

test("RESIDUAL IS REAL: newest waiter SILENTLY dead (accepts) + older live => deposit lost to the void", () => {
  // Precondition for this loss: two coexisting waiters where the NEWER is a
  // silent orphan (abort never fired, still accepts) and the OLDER is live.
  // wake() offers to the newest; it accepts (it is not settled) and drains.
  // This is the undetectable orphan-gap residual, NOT fixed by offer-then-drain.
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  const voided: string[][] = [];
  let liveGot: string[] | null = null;

  // Older, LIVE waiter (real reconnect that can still receive).
  P.longPoll(list, waiters, Date.now(), 60_000).then((v) => (liveGot = v));
  // Newer, SILENTLY DEAD waiter (a second overlapping poll whose connection
  // died without its signal firing, so it is not settled and still accepts).
  waiters.push(silentOrphan(voided));
  expect(waiters.length).toBe(2);

  list.push({ blob: "approval-response", exp: Date.now() + 10_000 });
  P.wake(list, waiters, Date.now());

  // The deposit went to the silent-dead newest and is gone; the live older got
  // nothing. This remains the documented residual: the sender's poll backstop
  // and the item TTL are what cover it, not the relay.
  expect(voided).toEqual([["approval-response"]]);
  expect(liveGot).toBeNull();
  expect(list).toEqual([]); // drained, not requeued: genuinely lost
});

test("HARDENED (offer-then-drain): newest waiter SETTLED-dead (rejects) + older live => item reaches the live one, not lost", () => {
  // The disconnect-mid-delivery case the relay CAN observe: the newest waiter's
  // abort/timeout fired, so it rejects the offer. Under the old drain-then-offer
  // wake this drained into the dead newest and was lost. Now wake offers first,
  // the settled newest rejects, and wake falls through to the live older waiter,
  // draining only after that positive accept. Nothing is lost.
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  let liveGot: string[] | null = null;

  waiters.push((blobs) => {          // older, LIVE
    liveGot = blobs;
    return true;
  });
  waiters.push(settledDead());       // newer, SETTLED-dead (rejects)
  expect(waiters.length).toBe(2);

  list.push({ blob: "approval-response", exp: Date.now() + 10_000 });
  P.wake(list, waiters, Date.now());

  expect(liveGot).toEqual(["approval-response"]); // fell through to the live one
  expect(list).toEqual([]);                       // drained only on the accept
  expect(waiters).toEqual([]);                    // both waiters consumed
});

test("HARDENED (offer-then-drain): a lone SETTLED-dead waiter never swallows the item; it stays queued for the next GET", async () => {
  // The single-orphan gap, but with a waiter whose disconnect the relay CAN see
  // (settled => rejects). Old wake drained-then-offered and lost it; new wake
  // offers, the rejection preserves the item, and a later real poll drains it.
  const list: P.Item[] = [{ blob: "to-daemon-response", exp: Date.now() + 10_000 }];
  const waiters: P.Waiter[] = [settledDead()];

  P.wake(list, waiters, Date.now());

  expect(list.map((i) => i.blob)).toEqual(["to-daemon-response"]); // preserved
  expect(waiters).toEqual([]); // the rejecting waiter was consumed off the list

  // A real reconnecting poll now drains the still-queued item: delivered, not lost.
  const out = await P.longPoll(list, waiters, Date.now(), 50);
  expect(out).toEqual(["to-daemon-response"]);
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

  waiters.push(silentOrphan(orphanVoid)); // older = dead orphan
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
  for (let i = 0; i < P.MAX_WAITERS; i++) waiters.push(silentOrphan(drops));
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
