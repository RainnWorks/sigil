// Bun-native integration tests. Run: `bun test bun/server.test.ts` (from relay/).
// Spawns the real server on an ephemeral port and drives it over plain HTTP,
// mirroring the Worker suite so both variants are checked against one
// contract. APNS_KEY_P8 is deliberately left unset here: the push path is
// covered on its own in ../shared/push.test.ts, so these tests only need to
// confirm a deposit with a pushToken still 200s when no key is configured.
//
// The server is spawned with a tiny LONG_POLL_MS so a GET on an empty slot
// times out to `{"envelopes":[]}` in well under a second instead of the real
// ~25s; the long-poll mechanics themselves (immediate/wake/timeout/abort) are
// unit-tested directly against ../shared/protocol in protocol.test.ts.
import { test, expect, beforeAll, afterAll } from "bun:test";
import type { Subprocess } from "bun";
import * as P from "../shared/protocol";

let proc: Subprocess;
let baseUrl = "";
const port = 8799;
const testLongPollMs = 150;

function mailboxId(): string {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
const mbox = (id: string, verb: string) => `${baseUrl}/mailbox/${id}/${verb}`;
const toPhone = (id: string, body: unknown) =>
  fetch(mbox(id, "to-phone"), { method: "POST", body: JSON.stringify(body) });
const toDaemon = (id: string, body: unknown) =>
  fetch(mbox(id, "to-daemon"), { method: "POST", body: JSON.stringify(body) });

beforeAll(async () => {
  proc = Bun.spawn(["bun", "run", `${import.meta.dir}/server.ts`], {
    env: {
      ...process.env,
      PORT: String(port),
      APNS_KEY_P8: "",
      APNS_KEY_P8_PATH: "",
      LONG_POLL_MS: String(testLongPollMs),
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  baseUrl = `http://127.0.0.1:${port}`;
  // Wait for the listener to come up.
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`${baseUrl}/health`);
      if (r.ok) return;
    } catch {
      // not up yet
    }
    await Bun.sleep(50);
  }
  throw new Error("bun relay did not start");
});

afterAll(() => proc?.kill());

test("health needs no mailbox", async () => {
  expect(await (await fetch(`${baseUrl}/health`)).json()).toEqual({
    ok: true,
    service: "sigil-relay",
  });
});

test("GET / serves the landing page as HTML, not the health JSON", async () => {
  const r = await fetch(baseUrl);
  expect(r.status).toBe(200);
  expect(r.headers.get("content-type")).toBe("text/html; charset=utf-8");
  const body = await r.text();
  expect(body).toContain("<title>Sigil relay</title>");
});

test("rejects a malformed mailbox id", async () => {
  expect((await fetch(`${baseUrl}/mailbox/nope/to-phone`)).status).toBe(400);
});

test("to-phone: deposit then drain, then a held GET times out empty", async () => {
  const id = mailboxId();
  const env = '{"pairing_id":[1,2,3],"ciphertext":[9,9,9]}';
  const r = await toPhone(id, { env });
  expect(r.status).toBe(200);
  expect(await r.json()).toEqual({ ok: true });
  const first = await (await fetch(mbox(id, "to-phone"))).json();
  expect(first).toEqual({ envelopes: [env] });
  // Nothing queued now: this GET long-polls and times out to empty rather
  // than returning instantly, hence the tiny test LONG_POLL_MS.
  const second = await (await fetch(mbox(id, "to-phone"))).json();
  expect(second).toEqual({ envelopes: [] });
});

test("to-daemon: deposit then drain, symmetric with to-phone", async () => {
  const id = mailboxId();
  const env = '{"to":"daemon"}';
  expect((await toDaemon(id, { env })).status).toBe(200);
  expect(await (await fetch(mbox(id, "to-daemon"))).json()).toEqual({ envelopes: [env] });
  expect(await (await fetch(mbox(id, "to-daemon"))).json()).toEqual({ envelopes: [] });
});

test("a long-poll GET resolves as soon as a deposit arrives, well before its timeout", async () => {
  const id = mailboxId();
  const started = Date.now();
  const held = fetch(mbox(id, "to-phone")); // nothing queued yet: this holds
  await Bun.sleep(testLongPollMs / 4); // well inside the hold, before it'd time out
  await toPhone(id, { env: "woke-it-up" });
  const body = await (await held).json();
  const elapsed = Date.now() - started;
  expect(body).toEqual({ envelopes: ["woke-it-up"] });
  expect(elapsed).toBeLessThan(testLongPollMs); // woken, not timed out
});

test("a disconnected long-poll GET does not leak: a later deposit still lands normally", async () => {
  const id = mailboxId();
  const ctrl = new AbortController();
  const held = fetch(mbox(id, "to-phone"), { signal: ctrl.signal });
  await Bun.sleep(10);
  ctrl.abort();
  await expect(held).rejects.toThrow(); // the client's own fetch is cancelled

  // The relay-side waiter must have been cleaned up by the abort, not left
  // registered forever; a fresh GET after this should behave like any other
  // empty-slot long-poll (times out empty here, since nothing is queued),
  // not immediately resolve to some stale leftover state.
  const after = await (await fetch(mbox(id, "to-phone"))).json();
  expect(after).toEqual({ envelopes: [] });

  // And a real deposit afterward still drains normally: the mailbox was
  // never corrupted by the earlier disconnect.
  await toPhone(id, { env: "still-works" });
  expect(await (await fetch(mbox(id, "to-phone"))).json()).toEqual({
    envelopes: ["still-works"],
  });
});

test("the two directions are independent queues", async () => {
  const id = mailboxId();
  await toPhone(id, { env: "for-phone" });
  await toDaemon(id, { env: "for-daemon" });
  expect(await (await fetch(mbox(id, "to-phone"))).json()).toEqual({ envelopes: ["for-phone"] });
  expect(await (await fetch(mbox(id, "to-daemon"))).json()).toEqual({ envelopes: ["for-daemon"] });
});

test("opacity: arbitrary non-JSON-ish bytes round-trip byte-identically inside env", async () => {
  const id = mailboxId();
  const opaque = '\\x00{"not":parsed}\n\t"quote"☁ \x7f raw';
  await toPhone(id, { env: opaque });
  expect(await (await fetch(mbox(id, "to-phone"))).json()).toEqual({ envelopes: [opaque] });
});

test("a deposit with a pushToken still 200s when no APNs key is configured", async () => {
  const id = mailboxId();
  const r = await toPhone(id, { env: "hello", pushToken: "deadbeef", platform: "apns" });
  expect(r.status).toBe(200);
  expect(await (await fetch(mbox(id, "to-phone"))).json()).toEqual({ envelopes: ["hello"] });
});

test("a body missing env is rejected with 400", async () => {
  const id = mailboxId();
  expect((await toPhone(id, { pushToken: "deadbeef" })).status).toBe(400);
  expect((await toDaemon(id, { nope: true })).status).toBe(400);
});

test("rejects an oversized envelope with 413", async () => {
  const id = mailboxId();
  expect((await toPhone(id, { env: "x".repeat(P.MAX_ENVELOPE_BYTES + 1) })).status).toBe(413);
});

test("rejects past the queue bound with 507", async () => {
  const id = mailboxId();
  for (let i = 0; i < P.MAX_QUEUE; i++) {
    expect((await toDaemon(id, { env: `e${i}` })).status).toBe(200);
  }
  expect((await toDaemon(id, { env: "overflow" })).status).toBe(507);
});

test("rate-limits a flood with 429", async () => {
  const id = mailboxId();
  let sawLimit = false;
  for (let i = 0; i < P.RATE_MAX + 5; i++) {
    // A malformed deposit (missing env) still counts against the mailbox's
    // rate limit, which is checked before the body is even parsed, without
    // enqueueing anything or long-polling - so this floods fast regardless
    // of MAX_QUEUE or LONG_POLL_MS.
    if ((await toPhone(id, {})).status === 429) {
      sawLimit = true;
      break;
    }
  }
  expect(sawLimit).toBe(true);
});
