// Pure unit tests for the long-poll/wake mechanics in ./protocol.ts. These
// don't need a server: longPoll/wake operate directly on an Item[] and a
// Waiter[], so the fast (immediate) and slow (timeout) paths are both
// testable without spinning up Bun or a Durable Object. Run with `bun test`
// (no Workers-specific imports here, so this needs no separate Worker suite).
import { test, expect } from "bun:test";
import * as P from "./protocol";

test("data already present resolves immediately, drained", async () => {
  const list: P.Item[] = [{ blob: "hello", exp: Date.now() + 10_000 }];
  const waiters: P.Waiter[] = [];
  const out = await P.longPoll(list, waiters, Date.now());
  expect(out).toEqual(["hello"]);
  expect(list).toEqual([]); // drained
  expect(waiters).toEqual([]); // never registered; nothing to clean up
});

test("an empty slot holds, then resolves when woken by a deposit", async () => {
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  const pending = P.longPoll(list, waiters, Date.now(), 5_000);
  expect(waiters.length).toBe(1); // registered while waiting

  // Simulate a deposit: push the item, then wake it, exactly as the server
  // handlers do after a successful enqueue.
  list.push({ blob: "woke-up", exp: Date.now() + 10_000 });
  P.wake(list, waiters, Date.now());

  expect(await pending).toEqual(["woke-up"]);
  expect(waiters).toEqual([]); // cleaned up, not left dangling
});

test("times out to an empty result when nothing arrives, and cleans up", async () => {
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  const out = await P.longPoll(list, waiters, Date.now(), 20);
  expect(out).toEqual([]);
  expect(waiters).toEqual([]); // the timeout removed its own waiter
});

test("wake() on a slot with no waiters is a no-op, item stays queued", () => {
  const list: P.Item[] = [{ blob: "unread", exp: Date.now() + 10_000 }];
  const waiters: P.Waiter[] = [];
  P.wake(list, waiters, Date.now());
  expect(list.map((i) => i.blob)).toEqual(["unread"]); // still there
});

test("a lone long-poll on an empty slot HOLDS: it does not resolve early", async () => {
  // The core anti-hammer property. An empty-slot poll must sit for its full
  // window, not return a fast empty a client would instantly re-fire on. We
  // give it a comfortably long timeout and confirm it is still pending a beat
  // later (nothing resolved it), then let a deposit wake it so nothing leaks.
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  let resolved = false;
  const pending = P.longPoll(list, waiters, Date.now(), 5_000).then((v) => {
    resolved = true;
    return v;
  });
  await new Promise((r) => setTimeout(r, 30));
  expect(resolved).toBe(false); // still holding, not a fast empty
  expect(waiters.length).toBe(1);

  list.push({ blob: "eventually", exp: Date.now() + 10_000 });
  P.wake(list, waiters, Date.now());
  expect(await pending).toEqual(["eventually"]);
});

test("a second concurrent GET does NOT resolve the first empty (no ping-pong)", async () => {
  // The regression guard for the reported hammer: superseding a live waiter the
  // instant a second GET arrived turned one quiet wait into an instant-empty
  // cascade. Now both waiters coexist and hold; neither is resolved early.
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  let firstResolved = false;
  const first = P.longPoll(list, waiters, Date.now(), 5_000).then((v) => {
    firstResolved = true;
    return v;
  });
  expect(waiters.length).toBe(1);

  const second = P.longPoll(list, waiters, Date.now(), 5_000); // concurrent, same slot
  await new Promise((r) => setTimeout(r, 10));
  expect(firstResolved).toBe(false); // the newcomer did NOT flush the first empty
  expect(waiters.length).toBe(2); // both coexist, both holding

  // A deposit goes to the NEWEST (second); the first keeps holding, unflushed.
  list.push({ blob: "for-the-newest", exp: Date.now() + 10_000 });
  P.wake(list, waiters, Date.now());
  expect(await second).toEqual(["for-the-newest"]);
  expect(firstResolved).toBe(false); // still holding after the newest was served
  expect(waiters.length).toBe(1); // only the first remains

  // A second deposit then reaches the first; nothing was lost or fast-emptied.
  list.push({ blob: "for-the-first", exp: Date.now() + 10_000 });
  P.wake(list, waiters, Date.now());
  expect(await first).toEqual(["for-the-first"]);
  expect(waiters).toEqual([]);
});

test("no deposit is lost across a disconnect/reconnect: it reaches the reconnect, not the orphan", async () => {
  // Models the real gap this exists for: a client's long-poll GET disconnects
  // without its AbortSignal ever firing (confirmed not to fire reliably when
  // forwarded through a Durable Object), leaving an orphaned waiter. The client
  // reconnects with a fresh long-poll *before* the next deposit. The deposit
  // must reach the live reconnect, not the orphan nobody can hear from — and
  // (unlike the old design) without the orphan being resolved empty early.
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  let orphanResolved = false;
  const orphaned = P.longPoll(list, waiters, Date.now(), 5_000).then((v) => {
    orphanResolved = true;
    return v;
  }); // signal never fires; simulates a real disconnect
  expect(waiters.length).toBe(1);

  const reconnected = P.longPoll(list, waiters, Date.now(), 5_000); // the client's fresh attach
  expect(waiters.length).toBe(2); // orphan not evicted; both registered

  // The deposit reaches the newest (the live reconnect), never the orphan.
  list.push({ blob: "the-actual-message", exp: Date.now() + 10_000 });
  P.wake(list, waiters, Date.now());
  expect(await reconnected).toEqual(["the-actual-message"]); // delivered to the live client
  expect(orphanResolved).toBe(false); // orphan never received (nor stole) the deposit
  expect(list).toEqual([]); // nothing lost, nothing left queued
});

test("the coexisting-waiter count is bounded: past MAX_WAITERS the oldest is dropped", async () => {
  // Overlapping GETs can't grow the waiter list without limit. At the cap a new
  // GET drops the OLDEST waiter (resolved empty, the slot is provably empty) to
  // admit the newcomer, keeping the bound while never touching the newer ones.
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  const polls: Promise<string[]>[] = [];
  for (let i = 0; i < P.MAX_WAITERS; i++) {
    polls.push(P.longPoll(list, waiters, Date.now(), 5_000));
  }
  expect(waiters.length).toBe(P.MAX_WAITERS); // full, none dropped yet

  const overflow = P.longPoll(list, waiters, Date.now(), 5_000); // one past the cap
  expect(waiters.length).toBe(P.MAX_WAITERS); // still bounded, not grown
  expect(await polls[0]).toEqual([]); // the oldest was the one dropped, resolved empty

  // The newcomer holds normally and a deposit still reaches the newest.
  list.push({ blob: "still-delivered", exp: Date.now() + 10_000 });
  P.wake(list, waiters, Date.now());
  expect(await overflow).toEqual(["still-delivered"]);
});

test("an aborted signal resolves empty and cleans up its waiter, before any timeout", async () => {
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  const ctrl = new AbortController();
  const pending = P.longPoll(list, waiters, Date.now(), 5_000, ctrl.signal);
  expect(waiters.length).toBe(1);

  ctrl.abort();
  expect(await pending).toEqual([]);
  expect(waiters).toEqual([]); // no leaked waiter after disconnect
});

test("disconnect mid-delivery: wake offers before draining, so a settled waiter never swallows the item", async () => {
  // The core #53 hardening. wake() must not remove an item from the buffer and
  // THEN discover the waiter it handed it to is dead. It offers the still-queued
  // item and drains only once a waiter reports it accepted (was live). Here the
  // newest waiter has settled (its abort fired mid-delivery) and rejects; wake
  // falls through to the live older waiter and drains only then. Nothing lost.
  const list: P.Item[] = [{ blob: "in-flight", exp: Date.now() + 10_000 }];
  const waiters: P.Waiter[] = [];
  const liveGot: string[][] = [];
  waiters.push((blobs) => {   // older, still live: accepts
    liveGot.push(blobs);
    return true;
  });
  waiters.push(() => false);  // newer, settled mid-delivery: rejects the offer

  P.wake(list, waiters, Date.now());

  expect(liveGot).toEqual([["in-flight"]]); // reached the live waiter, not the void
  expect(list).toEqual([]); // drained only after the positive accept
  expect(waiters).toEqual([]); // both offered-to and removed

  // And the fully abandoned case: a lone settled waiter must leave the item
  // queued for the next real GET rather than eating it.
  const list2: P.Item[] = [{ blob: "next-poll-gets-it", exp: Date.now() + 10_000 }];
  const waiters2: P.Waiter[] = [() => false];
  P.wake(list2, waiters2, Date.now());
  expect(list2.map((i) => i.blob)).toEqual(["next-poll-gets-it"]); // preserved
  const out = await P.longPoll(list2, waiters2, Date.now(), 20);
  expect(out).toEqual(["next-poll-gets-it"]); // a later poll drains it
});

test("a wake after abort is harmless: the waiter is already gone", async () => {
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  const ctrl = new AbortController();
  const pending = P.longPoll(list, waiters, Date.now(), 5_000, ctrl.signal);

  ctrl.abort();
  await pending;
  expect(waiters).toEqual([]);

  // A deposit arriving just after the disconnect must not throw or resurrect
  // the departed waiter; it simply has no one left to wake.
  list.push({ blob: "late", exp: Date.now() + 10_000 });
  expect(() => P.wake(list, waiters, Date.now())).not.toThrow();
  expect(list.map((i) => i.blob)).toEqual(["late"]); // still queued for the next reader
});
