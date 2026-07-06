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

test("a second long-poll on the same slot evicts the first, which resolves empty", async () => {
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  const first = P.longPoll(list, waiters, Date.now(), 5_000);
  expect(waiters.length).toBe(1);

  const second = P.longPoll(list, waiters, Date.now(), 5_000);
  expect(await first).toEqual([]); // evicted, not left dangling forever
  expect(waiters.length).toBe(1); // only the second remains registered

  list.push({ blob: "for-the-survivor", exp: Date.now() + 10_000 });
  P.wake(list, waiters, Date.now());
  expect(await second).toEqual(["for-the-survivor"]);
  expect(waiters).toEqual([]);
});

test("eviction on reconnect prevents a deposit from being lost to an orphaned waiter", async () => {
  // Models the real gap this exists for: a client's long-poll GET disconnects
  // without its AbortSignal ever firing (confirmed not to fire reliably when
  // forwarded through a Durable Object), leaving an orphaned waiter. The
  // client reconnects with a fresh long-poll *before* the next deposit — that
  // reconnect must evict the orphan so the deposit reaches the live waiter,
  // not the one nobody can hear from any more.
  const list: P.Item[] = [];
  const waiters: P.Waiter[] = [];
  const orphaned = P.longPoll(list, waiters, Date.now(), 5_000); // signal never fires; simulates a real disconnect
  expect(waiters.length).toBe(1);

  const reconnected = P.longPoll(list, waiters, Date.now(), 5_000); // the client's fresh attach
  expect(await orphaned).toEqual([]); // evicted, not stealing the next deposit
  expect(waiters.length).toBe(1);

  list.push({ blob: "the-actual-message", exp: Date.now() + 10_000 });
  P.wake(list, waiters, Date.now());
  expect(await reconnected).toEqual(["the-actual-message"]); // delivered to the live client
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
