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

// Read the live relayed-message count the way an uptime probe would. The Bun
// counter is bumped synchronously in the deposit handler, so it is already
// reflected on the next /health.
async function relayedCount(base = baseUrl): Promise<number> {
  const body = (await (await fetch(`${base}/health`)).json()) as { count: number };
  return body.count;
}

// Spawn a relay process and wait for its listener. Shared by the main suite and
// the restart test (which needs its own process on its own port). No counter
// path: the count is in-memory only, nothing is persisted.
async function spawnRelay(opts: { port: number }): Promise<Subprocess> {
  const p = Bun.spawn(["bun", "run", `${import.meta.dir}/server.ts`], {
    env: {
      ...process.env,
      PORT: String(opts.port),
      APNS_KEY_P8: "",
      APNS_KEY_P8_PATH: "",
      LONG_POLL_MS: String(testLongPollMs),
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const url = `http://127.0.0.1:${opts.port}`;
  for (let i = 0; i < 50; i++) {
    try {
      if ((await fetch(`${url}/health`)).ok) return p;
    } catch {
      // not up yet
    }
    await Bun.sleep(50);
  }
  throw new Error("bun relay did not start");
}

beforeAll(async () => {
  proc = await spawnRelay({ port });
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(() => proc?.kill());

test("health needs no mailbox, and carries the live count", async () => {
  const body = (await (await fetch(`${baseUrl}/health`)).json()) as {
    ok: boolean;
    service: string;
    count: number;
  };
  expect(body.ok).toBe(true);
  expect(body.service).toBe("sigil-relay");
  // A bare non-negative integer, nothing more.
  expect(Number.isInteger(body.count)).toBe(true);
  expect(body.count).toBeGreaterThanOrEqual(0);
});

test("GET / serves the landing page as HTML, with the copy and both figures rendered", async () => {
  const r = await fetch(baseUrl);
  expect(r.status).toBe(200);
  expect(r.headers.get("content-type")).toBe("text/html; charset=utf-8");
  const body = await r.text();
  expect(body).toContain("<title>Sigil relay</title>");
  // No unrendered placeholder is left behind; both figures are injected.
  expect(body).not.toContain("{{");
  expect(body).toContain(P.RELAY_SINCE); // "up since" date, from protocol's fallback
  expect(body).toContain("up since");
  expect(body).toMatch(/[\d,]+<\/span>\s*<span class="num-label">messages? passed/);
  // The ephemeral-counter gag and the rewritten ELI5 copy are present, and
  // both variants serve identical HTML (same renderLanding, same source file).
  expect(body).toContain("even this number isn't stored");
  expect(body).toContain("coat check");
  expect(body).toContain("two-factor authentication for your command line");
  expect(body).toContain("What it carries");
  expect(body).toContain("https://github.com/RainnWorks/sigil");
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

// The relayed-message counter: in-memory only, never persisted. Bumped
// synchronously in the deposit handler, so it is immediately observable on the
// next /health, and forgotten entirely when the process dies.

test("counter increments exactly once per successful deposit, either direction", async () => {
  const id = mailboxId();
  const before = await relayedCount();
  expect((await toPhone(id, { env: "a" })).status).toBe(200);
  expect((await toDaemon(id, { env: "b" })).status).toBe(200);
  expect((await toPhone(id, { env: "c" })).status).toBe(200);
  expect(await relayedCount()).toBe(before + 3);
});

test("counter does not move for a rejected deposit (400 bad body, 507 over-queue)", async () => {
  const id = mailboxId();
  // Fill the to-daemon queue so the next to-daemon deposit is a 507.
  for (let i = 0; i < P.MAX_QUEUE; i++) {
    expect((await toDaemon(id, { env: `e${i}` })).status).toBe(200);
  }
  const before = await relayedCount();
  expect((await toPhone(id, { pushToken: "deadbeef" })).status).toBe(400); // no env
  expect((await toDaemon(id, { env: "overflow" })).status).toBe(507); // queue full
  expect(await relayedCount()).toBe(before); // neither counted: nothing was relayed
});

test("counter does not move for a GET drain or long-poll, only a POST deposit", async () => {
  const id = mailboxId();
  await toPhone(id, { env: "one" }); // +1
  const before = await relayedCount();
  await fetch(mbox(id, "to-phone")); // drains "one"
  await fetch(mbox(id, "to-daemon")); // empty, times out
  expect(await relayedCount()).toBe(before); // reads are not relayed messages
});

test("the count is ephemeral: a process restart forgets it, back to zero", async () => {
  // The inverse of persistence, and the whole point: a fresh process on its own
  // port starts at zero, counts some deposits, and after a hard restart is back
  // to zero. Nothing was written anywhere, so nothing survives the process.
  const rport = 8801;
  const rurl = `http://127.0.0.1:${rport}`;
  let p: Subprocess | undefined;
  try {
    p = await spawnRelay({ port: rport });
    const id = mailboxId();
    const deposit = (i: number) =>
      fetch(`${rurl}/mailbox/${id}/to-daemon`, {
        method: "POST",
        body: JSON.stringify({ env: `m${i}` }),
      });
    expect(await relayedCount(rurl)).toBe(0); // fresh process: starts at zero
    for (let i = 0; i < 3; i++) expect((await deposit(i)).status).toBe(200);
    expect(await relayedCount(rurl)).toBe(3);

    // Hard restart: kill the process, spawn a new one. Nothing is persisted.
    p.kill();
    await p.exited;
    p = await spawnRelay({ port: rport });
    // The new process remembers nothing: the count is zero again, not 3.
    expect(await relayedCount(rurl)).toBe(0);
  } finally {
    p?.kill();
  }
});
