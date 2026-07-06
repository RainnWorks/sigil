// Bun-native integration tests. Run: `bun test bun/server.test.ts` (from relay/).
// Spawns the real server on an ephemeral port and drives it over plain HTTP,
// mirroring the Worker suite so both variants are checked against one
// contract. APNS_KEY_P8 is deliberately left unset here: the push path is
// covered on its own in ../shared/push.test.ts, so these tests only need to
// confirm a deposit with a pushToken still 200s when no key is configured.
import { test, expect, beforeAll, afterAll } from "bun:test";
import type { Subprocess } from "bun";
import * as P from "../shared/protocol";

let proc: Subprocess;
let baseUrl = "";
const port = 8799;

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
    env: { ...process.env, PORT: String(port), APNS_KEY_P8: "", APNS_KEY_P8_PATH: "" },
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
    service: "latch-relay",
  });
});

test("rejects a malformed mailbox id", async () => {
  expect((await fetch(`${baseUrl}/mailbox/nope/to-phone`)).status).toBe(400);
});

test("to-phone: deposit then drain, then empty on a second read", async () => {
  const id = mailboxId();
  const env = '{"pairing_id":[1,2,3],"ciphertext":[9,9,9]}';
  const r = await toPhone(id, { env });
  expect(r.status).toBe(200);
  expect(await r.json()).toEqual({ ok: true });
  const first = await (await fetch(mbox(id, "to-phone"))).json();
  expect(first).toEqual({ envelopes: [env] });
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
    if ((await fetch(mbox(id, "to-phone"))).status === 429) {
      sawLimit = true;
      break;
    }
  }
  expect(sawLimit).toBe(true);
});
