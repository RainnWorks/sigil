import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import * as P from "../shared/protocol";
import type { Mailbox } from "../src/index";

// Read the live relayed-message count the way an uptime probe would. The count
// is bumped synchronously in the Worker's top-level fetch, before the deposit's
// response is returned, so it is already reflected on the next /health; no
// settle/poll dance is needed.
async function relayedCount(): Promise<number> {
  const body = (await (await SELF.fetch(`${base}/health`)).json()) as { count: number };
  return body.count;
}

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
  it("health needs no mailbox, and carries the live count", async () => {
    const r = await SELF.fetch(`${base}/health`);
    const body = (await r.json()) as { ok: boolean; service: string; count: number };
    expect(body.ok).toBe(true);
    expect(body.service).toBe("sigil-relay");
    // A bare non-negative integer, nothing more.
    expect(typeof body.count).toBe("number");
    expect(Number.isInteger(body.count)).toBe(true);
    expect(body.count).toBeGreaterThanOrEqual(0);
  });

  it("GET / serves the landing page as HTML, with the copy and both figures rendered", async () => {
    const r = await SELF.fetch(base);
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toBe("text/html; charset=utf-8");
    const body = await r.text();
    expect(body).toContain("<title>Sigil relay</title>");
    // No unrendered placeholder is left behind; both figures are injected.
    expect(body).not.toContain("{{");
    expect(body).toContain(P.RELAY_SINCE); // "up since" date, from the test env's fallback
    expect(body).toContain("up since");
    expect(body).toMatch(/[\d,]+<\/span>\s*<span class="num-label">messages? passed/);
    // The ephemeral-counter gag and the rewritten ELI5 copy are present.
    expect(body).toContain("even this number isn't stored");
    expect(body).toContain("coat check");
    expect(body).toContain("two-factor authentication for your command line");
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

describe("relayed-message counter (ephemeral, in-memory only, never stored)", () => {
  it("increments exactly once per successful deposit, either direction", async () => {
    const id = mailboxId();
    // The bump is synchronous with the deposit's response, so no settle is
    // needed: read, deposit 3 (mix of directions), read again => exactly +3.
    const before = await relayedCount();
    expect((await toPhone(id, { env: "a" })).status).toBe(200);
    expect((await toDaemon(id, { env: "b" })).status).toBe(200);
    expect((await toPhone(id, { env: "c" })).status).toBe(200);
    expect(await relayedCount()).toBe(before + 3); // exactly +3, no over- or under-count
  });

  it("does not count a rejected deposit (400 bad body, or 507 over-queue)", async () => {
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

  it("does not count a GET drain or a long-poll, only a POST deposit", async () => {
    const id = mailboxId();
    await toPhone(id, { env: "one" }); // +1
    const before = await relayedCount();
    // A GET drain and an empty-slot long-poll are not relayed messages.
    await SELF.fetch(mbox(id, "to-phone")); // drains "one"
    await SELF.fetch(mbox(id, "to-daemon")); // empty, times out
    expect(await relayedCount()).toBe(before); // unchanged by reads
  });

  it("keeps the count in memory only: no Durable Object ever writes to ctx.storage", async () => {
    // The ephemerality proof available in-runtime: the relay persists nothing.
    // A deposit flows through a Mailbox DO; that DO (the only DO there is) must
    // never touch ctx.storage, so an evicted isolate loses the mailbox AND the
    // count alike. Reach into the DO after a full deposit+drain and assert its
    // storage is completely empty.
    const id = mailboxId();
    await toPhone(id, { env: "ephemeral" });
    await SELF.fetch(mbox(id, "to-phone")); // drain it back out
    const stub = env.MAILBOX.get(env.MAILBOX.idFromName(id));
    await runInDurableObject(stub, async (_inst: Mailbox, state) => {
      const all = await state.storage.list();
      expect(all.size).toBe(0); // nothing persisted: not the queue, not a counter
    });
  });
});
