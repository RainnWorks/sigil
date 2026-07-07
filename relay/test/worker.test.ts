import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import * as P from "../shared/protocol";
import type { Mailbox } from "../src/index";

// A fresh, valid mailbox id per test isolates each Durable Object's state.
function mailboxId(): string {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
const base = "https://relay";
const mbox = (id: string, verb: string) => `${base}/mailbox/${id}/${verb}`;
const toPhone = (id: string, body: unknown) =>
  SELF.fetch(mbox(id, "to-phone"), { method: "POST", body: JSON.stringify(body) });
const toDaemon = (id: string, body: unknown) =>
  SELF.fetch(mbox(id, "to-daemon"), { method: "POST", body: JSON.stringify(body) });

describe("routing and health", () => {
  it("health needs no mailbox, and is a bare liveness body (no count)", async () => {
    const r = await SELF.fetch(`${base}/health`);
    // No counter of any kind: the relay keeps nothing to report.
    expect(await r.json()).toEqual({ ok: true, service: "sigil-relay" });
  });

  it("GET / serves the static landing page as HTML, with the ELI5 copy", async () => {
    const r = await SELF.fetch(base);
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toBe("text/html; charset=utf-8");
    const body = await r.text();
    expect(body).toContain("<title>Sigil relay</title>");
    // Served statically now: no templating, so no placeholder tokens survive.
    expect(body).not.toContain("{{");
    // The rewritten ELI5 copy is present; the removed counter/gag is not.
    expect(body).toContain("coat check");
    expect(body).toContain("two-factor authentication for your command line");
    expect(body).not.toContain("even this number isn't stored");
    expect(body).not.toContain("messages passed");
    // The message-type list and the "read the code" repo link.
    expect(body).toContain("What it carries");
    expect(body).toContain("https://github.com/RainnWorks/sigil");
  });

  it("rejects a malformed mailbox id", async () => {
    const r = await SELF.fetch(`${base}/mailbox/not-hex/to-phone`);
    expect(r.status).toBe(400);
  });
});

describe("deposit and drain", () => {
  it("to-phone: deposit then drain, then a held GET times out empty", async () => {
    const id = mailboxId();
    const env = '{"pairing_id":[1,2,3],"ciphertext":[9,9,9]}';
    const r = await toPhone(id, { env });
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ ok: true });
    expect(await (await SELF.fetch(mbox(id, "to-phone"))).json()).toEqual({ envelopes: [env] });
    // Nothing queued now: this GET long-polls and times out to empty rather
    // than returning instantly, hence the tiny LONG_POLL_MS test binding.
    expect(await (await SELF.fetch(mbox(id, "to-phone"))).json()).toEqual({ envelopes: [] });
  });

  it("a long-poll GET resolves as soon as a deposit arrives, well before its timeout", async () => {
    const id = mailboxId();
    const started = Date.now();
    const held = SELF.fetch(mbox(id, "to-phone")); // nothing queued yet: this holds
    await new Promise((r) => setTimeout(r, 30)); // well inside the hold
    await toPhone(id, { env: "woke-it-up" });
    const body = await (await held).json();
    const elapsed = Date.now() - started;
    expect(body).toEqual({ envelopes: ["woke-it-up"] });
    expect(elapsed).toBeLessThan(150); // woken, not timed out (matches the test LONG_POLL_MS)
  });

  it("a lone long-poll on an empty slot HOLDS for ~the full window, not an instant empty", async () => {
    // The anti-hammer property end to end: an empty-slot GET must sit for its
    // window (150ms test binding), not return a fast empty a client re-fires
    // on. It resolves empty, but only after holding, not instantly.
    const id = mailboxId();
    const started = Date.now();
    const body = await (await SELF.fetch(mbox(id, "to-phone"))).json();
    const elapsed = Date.now() - started;
    expect(body).toEqual({ envelopes: [] });
    expect(elapsed).toBeGreaterThanOrEqual(100); // held ~the full 150ms, not a fast return
  });

  it("a second concurrent GET does not ping-pong the first empty: it holds, deposit goes to the newest", async () => {
    // Two overlapping GETs on one slot. The newcomer must NOT flush the first
    // to an instant empty (the reported hammer). Both hold; a single deposit
    // reaches the newest; the other keeps holding and only then times out empty.
    const id = mailboxId();
    const started = Date.now();
    const first = SELF.fetch(mbox(id, "to-phone"));
    const second = SELF.fetch(mbox(id, "to-phone"));
    await new Promise((r) => setTimeout(r, 20)); // let both register and hold
    await toPhone(id, { env: "for-the-newest" });

    const [b1, b2] = await Promise.all([
      (async () => ({ body: await (await first).json(), t: Date.now() - started }))(),
      (async () => ({ body: await (await second).json(), t: Date.now() - started }))(),
    ]);
    const bodies = [b1.body, b2.body];
    // Exactly one got the deposit; the other is an empty that HELD (timed out
    // near the full window), never an instant empty from being superseded.
    expect(bodies).toContainEqual({ envelopes: ["for-the-newest"] });
    expect(bodies).toContainEqual({ envelopes: [] });
    const empty = b1.body && (b1.body as { envelopes: string[] }).envelopes.length === 0 ? b1 : b2;
    expect(empty.t).toBeGreaterThanOrEqual(100); // the empty one held, it was not fast-flushed
  });

  it("no deposit is lost across a disconnect/reconnect: the reconnect receives it", async () => {
    // A held GET disconnects without its signal firing server-side (an orphan
    // waiter may linger). A reconnecting GET then holds, and a subsequent
    // deposit must reach that live reconnect, not vanish into the orphan.
    const id = mailboxId();
    const ctrl = new AbortController();
    const disconnected = SELF.fetch(mbox(id, "to-phone"), { signal: ctrl.signal });
    await new Promise((r) => setTimeout(r, 15));
    ctrl.abort(); // client goes away mid-poll
    await expect(disconnected).rejects.toThrow();

    const reconnect = SELF.fetch(mbox(id, "to-phone")); // client comes back, holds
    await new Promise((r) => setTimeout(r, 15));
    await toPhone(id, { env: "survives-reconnect" });
    expect(await (await reconnect).json()).toEqual({ envelopes: ["survives-reconnect"] });
  });

  it("a disconnected long-poll GET does not leak: a later deposit still lands normally", async () => {
    const id = mailboxId();
    const ctrl = new AbortController();
    const held = SELF.fetch(mbox(id, "to-phone"), { signal: ctrl.signal });
    await new Promise((r) => setTimeout(r, 10));
    ctrl.abort();
    await expect(held).rejects.toThrow(); // the client's own fetch is cancelled

    // The DO-side waiter must have been cleaned up by the abort, not left
    // registered forever; a fresh GET after this behaves like any other
    // empty-slot long-poll (times out empty here, since nothing is queued).
    const after = await (await SELF.fetch(mbox(id, "to-phone"))).json();
    expect(after).toEqual({ envelopes: [] });

    // And a real deposit afterward still drains normally: the mailbox was
    // never corrupted by the earlier disconnect.
    await toPhone(id, { env: "still-works" });
    expect(await (await SELF.fetch(mbox(id, "to-phone"))).json()).toEqual({
      envelopes: ["still-works"],
    });
  });

  it("to-daemon: deposit then drain, symmetric with to-phone", async () => {
    const id = mailboxId();
    const env = '{"to":"daemon"}';
    expect((await toDaemon(id, { env })).status).toBe(200);
    expect(await (await SELF.fetch(mbox(id, "to-daemon"))).json()).toEqual({ envelopes: [env] });
    expect(await (await SELF.fetch(mbox(id, "to-daemon"))).json()).toEqual({ envelopes: [] });
  });

  it("the two directions are independent queues", async () => {
    const id = mailboxId();
    await toPhone(id, { env: "for-phone" });
    await toDaemon(id, { env: "for-daemon" });
    expect(await (await SELF.fetch(mbox(id, "to-phone"))).json()).toEqual({
      envelopes: ["for-phone"],
    });
    expect(await (await SELF.fetch(mbox(id, "to-daemon"))).json()).toEqual({
      envelopes: ["for-daemon"],
    });
  });

  it("a deposit with a pushToken still 200s when no APNs key is configured", async () => {
    // The test worker has no APNS_KEY_P8 secret bound, so this exercises the
    // fail-open path: push.ts logs and skips, the deposit still succeeds.
    const id = mailboxId();
    const r = await toPhone(id, { env: "hello", pushToken: "deadbeef", platform: "apns" });
    expect(r.status).toBe(200);
    expect(await (await SELF.fetch(mbox(id, "to-phone"))).json()).toEqual({
      envelopes: ["hello"],
    });
  });

  it("a body missing env is rejected with 400", async () => {
    const id = mailboxId();
    expect((await toPhone(id, { pushToken: "deadbeef" })).status).toBe(400);
    expect((await toDaemon(id, { nope: true })).status).toBe(400);
  });
});

describe("opacity: the relay cannot derive anything from a payload", () => {
  it("returns arbitrary non-JSON-ish bytes byte-identically", async () => {
    const id = mailboxId();
    // Deliberately not a valid envelope, not even valid JSON: quotes, braces,
    // newlines, unicode, a lone backslash. If the relay parsed or normalized
    // content, this would not survive intact.
    const opaque = '\\x00{"not":parsed}\n\t"quote"☁ \x7f raw';
    await toPhone(id, { env: opaque });
    const r = await (await SELF.fetch(mbox(id, "to-phone"))).json();
    expect(r).toEqual({ envelopes: [opaque] });
  });
});

describe("bounds and limits", () => {
  it("rejects an oversized envelope with 413", async () => {
    const id = mailboxId();
    const big = "x".repeat(P.MAX_ENVELOPE_BYTES + 1);
    const r = await toPhone(id, { env: big });
    expect(r.status).toBe(413);
  });

  it("rejects past the queue bound with 507", async () => {
    const id = mailboxId();
    for (let i = 0; i < P.MAX_QUEUE; i++) {
      expect((await toDaemon(id, { env: `e${i}` })).status).toBe(200);
    }
    const over = await toDaemon(id, { env: "overflow" });
    expect(over.status).toBe(507);
  });

  it("rate-limits a flood with 429", async () => {
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
});

describe("zero storage at rest (hard invariant)", () => {
  it("no Durable Object ever writes to ctx.storage", async () => {
    // The relay persists nothing. A deposit flows through a Mailbox DO; that DO
    // (the only DO there is) must never touch ctx.storage, so an evicted isolate
    // simply loses the mailbox. Reach into the DO after a full deposit+drain and
    // assert its storage is completely empty: no queue, no counter, nothing.
    const id = mailboxId();
    await toPhone(id, { env: "ephemeral" });
    await SELF.fetch(mbox(id, "to-phone")); // drain it back out
    const stub = env.MAILBOX.get(env.MAILBOX.idFromName(id));
    await runInDurableObject(stub, async (_inst: Mailbox, state) => {
      const all = await state.storage.list();
      expect(all.size).toBe(0); // nothing persisted at all
    });
  });
});
