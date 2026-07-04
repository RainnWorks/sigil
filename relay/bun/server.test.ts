// Bun-native integration tests. Run: `bun test bun/server.test.ts` (from relay/).
// Spawns the real server on an ephemeral port and drives it over http + ws,
// mirroring the Worker suite so both variants are checked against one contract.
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
const mbox = (id: string, verb = "") => `${baseUrl}/mailbox/${id}/${verb}`;
const submit = (id: string, body: string) =>
  fetch(mbox(id, "submit"), { method: "POST", body });

// Open a daemon WebSocket and expose an async queue of received frames.
function attach(id: string): Promise<{ ws: WebSocket; next: () => Promise<string> }> {
  const url = mbox(id, "attach").replace("http", "ws");
  const ws = new WebSocket(url);
  const inbox: string[] = [];
  const waiters: ((s: string) => void)[] = [];
  ws.addEventListener("message", (e) => {
    const data = e.data as string;
    const w = waiters.shift();
    if (w) w(data);
    else inbox.push(data);
  });
  const next = () =>
    new Promise<string>((resolve) => {
      const q = inbox.shift();
      if (q !== undefined) resolve(q);
      else waiters.push(resolve);
    });
  return new Promise((resolve) =>
    ws.addEventListener("open", () => resolve({ ws, next }), { once: true }),
  );
}

beforeAll(async () => {
  proc = Bun.spawn(["bun", "run", `${import.meta.dir}/server.ts`], {
    env: { ...process.env, PORT: String(port) },
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
  expect((await fetch(`${baseUrl}/mailbox/nope/pending`)).status).toBe(400);
});

test("phone submit then daemon attach is delivered", async () => {
  const id = mailboxId();
  const env = '{"pairing_id":[1,2,3],"ciphertext":[9,9,9]}';
  expect((await submit(id, env)).status).toBe(200);
  const { next } = await attach(id);
  expect(JSON.parse(await next())).toEqual({ t: "deliver", env });
});

test("daemon send then phone pending, with ack", async () => {
  const id = mailboxId();
  const { ws, next } = await attach(id);
  const env = '{"to":"phone"}';
  ws.send(JSON.stringify({ t: "send", env }));
  expect(JSON.parse(await next())).toEqual({ t: "ack", depth: 1 });
  expect(await (await fetch(mbox(id, "pending"))).json()).toEqual({
    envelopes: [env],
    depth: 0,
  });
});

test("opacity: arbitrary non-JSON bytes round-trip byte-identically", async () => {
  const id = mailboxId();
  const opaque = '\\x00{"not":parsed}\n\t"quote"☁ \x7f raw';
  const { ws, next } = await attach(id);
  ws.send(JSON.stringify({ t: "send", env: opaque }));
  await next(); // ack
  expect(await (await fetch(mbox(id, "pending"))).json()).toEqual({
    envelopes: [opaque],
    depth: 0,
  });
});

test("depth reports both directions without draining", async () => {
  const id = mailboxId();
  await submit(id, "a");
  await submit(id, "b");
  expect(await (await fetch(mbox(id, "depth"))).json()).toEqual({ pending: 0, inbound: 2 });
  expect(await (await fetch(mbox(id, "depth"))).json()).toEqual({ pending: 0, inbound: 2 });
});

test("rejects an oversized submit with 413", async () => {
  const id = mailboxId();
  expect((await submit(id, "x".repeat(P.MAX_ENVELOPE_BYTES + 1))).status).toBe(413);
});

test("rejects past the queue bound with 507", async () => {
  const id = mailboxId();
  for (let i = 0; i < P.MAX_QUEUE; i++) expect((await submit(id, `e${i}`)).status).toBe(200);
  expect((await submit(id, "overflow")).status).toBe(507);
});

test("reconnect: items queued while away flush on the next attach", async () => {
  const id = mailboxId();
  await submit(id, "held-1");
  await submit(id, "held-2");
  const { next } = await attach(id);
  expect([JSON.parse(await next()).env, JSON.parse(await next()).env]).toEqual([
    "held-1",
    "held-2",
  ]);
});
