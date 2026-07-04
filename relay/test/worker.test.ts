import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import * as P from "../shared/protocol";

// A fresh, valid mailbox id per test isolates each Durable Object's state.
function mailboxId(): string {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
const base = "https://relay";
const mbox = (id: string, verb = "") => `${base}/mailbox/${id}/${verb}`;

async function attach(id: string): Promise<WebSocket> {
  const resp = await SELF.fetch(mbox(id, "attach"), { headers: { Upgrade: "websocket" } });
  expect(resp.status).toBe(101);
  const ws = resp.webSocket!;
  ws.accept();
  return ws;
}

// Resolve with the next frame the socket receives.
function nextFrame(ws: WebSocket): Promise<string> {
  return new Promise((resolve) =>
    ws.addEventListener("message", (e) => resolve(e.data as string), { once: true }),
  );
}

async function submit(id: string, body: string): Promise<Response> {
  return SELF.fetch(mbox(id, "submit"), { method: "POST", body });
}

describe("routing and health", () => {
  it("health needs no mailbox", async () => {
    const r = await SELF.fetch(`${base}/health`);
    expect(await r.json()).toEqual({ ok: true, service: "latch-relay" });
  });

  it("rejects a malformed mailbox id", async () => {
    const r = await SELF.fetch(`${base}/mailbox/not-hex/pending`);
    expect(r.status).toBe(400);
  });

  it("accepts a 64-hex mailbox id", async () => {
    const r = await SELF.fetch(mbox(mailboxId(), "pending"));
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ envelopes: [], depth: 0 });
  });
});

describe("store and forward", () => {
  it("phone submit then daemon attach is delivered", async () => {
    const id = mailboxId();
    const env = '{"pairing_id":[1,2,3],"ciphertext":[9,9,9]}';
    expect((await submit(id, env)).status).toBe(200);
    const ws = await attach(id);
    const frame = await nextFrame(ws);
    expect(JSON.parse(frame)).toEqual({ t: "deliver", env });
  });

  it("daemon send then phone pending is delivered, with an ack", async () => {
    const id = mailboxId();
    const ws = await attach(id);
    const env = '{"to":"phone","ciphertext":[7]}';
    const ack = nextFrame(ws);
    ws.send(JSON.stringify({ t: "send", env }));
    expect(JSON.parse(await ack)).toEqual({ t: "ack", depth: 1 });
    const r = await SELF.fetch(mbox(id, "pending"));
    expect(await r.json()).toEqual({ envelopes: [env], depth: 0 });
  });

  it("pending drains: a second pull is empty", async () => {
    const id = mailboxId();
    // Fill the phone queue via the daemon's send path.
    const ws = await attach(id);
    const ack = nextFrame(ws);
    ws.send(JSON.stringify({ t: "send", env: "one" }));
    await ack;
    const first = await (await SELF.fetch(mbox(id, "pending"))).json();
    expect(first).toEqual({ envelopes: ["one"], depth: 0 });
    const second = await (await SELF.fetch(mbox(id, "pending"))).json();
    expect(second).toEqual({ envelopes: [], depth: 0 });
  });

  it("depth reports both directions without draining", async () => {
    const id = mailboxId();
    await submit(id, "a"); // queues phone->daemon (no daemon attached)
    await submit(id, "b");
    const d = await (await SELF.fetch(mbox(id, "depth"))).json();
    expect(d).toEqual({ pending: 0, inbound: 2 });
    // still there after the peek
    const d2 = await (await SELF.fetch(mbox(id, "depth"))).json();
    expect(d2).toEqual({ pending: 0, inbound: 2 });
  });
});

describe("reconnect", () => {
  it("items queued while the daemon is away flush on the next attach", async () => {
    const id = mailboxId();
    await submit(id, "held-1");
    await submit(id, "held-2");
    const ws = await attach(id);
    const first = await nextFrame(ws);
    const second = await nextFrame(ws);
    expect([first, second].map((f) => JSON.parse(f).env)).toEqual(["held-1", "held-2"]);
  });
});

describe("opacity: the relay cannot derive anything from a payload", () => {
  it("returns arbitrary non-JSON bytes byte-identically", async () => {
    const id = mailboxId();
    // Deliberately not a valid envelope, not even valid JSON: quotes, braces,
    // newlines, unicode, a lone backslash. If the relay parsed or normalized
    // content, this would not survive intact.
    const opaque = '\\x00{"not":parsed}\n\t"quote"☁ \x7f raw';
    const ws = await attach(id);
    const ack = nextFrame(ws);
    ws.send(JSON.stringify({ t: "send", env: opaque }));
    await ack;
    const r = await (await SELF.fetch(mbox(id, "pending"))).json();
    expect(r).toEqual({ envelopes: [opaque], depth: 0 });
  });

  it("the only observable outputs are the payload back and coarse counts", async () => {
    // There is no route that returns anything derived from ciphertext: pending
    // echoes the opaque blob; depth returns integer queue sizes; health is
    // static. Enumerating the routes IS the proof surface.
    const id = mailboxId();
    const d = (await (await SELF.fetch(mbox(id, "depth"))).json()) as Record<string, number>;
    expect(Object.keys(d).sort()).toEqual(["inbound", "pending"]);
    expect(typeof d.pending).toBe("number");
  });
});

describe("bounds and limits", () => {
  it("rejects an oversized submit with 413", async () => {
    const id = mailboxId();
    const big = "x".repeat(P.MAX_ENVELOPE_BYTES + 1);
    const r = await submit(id, big);
    expect(r.status).toBe(413);
  });

  it("rejects past the queue bound with 507", async () => {
    const id = mailboxId();
    for (let i = 0; i < P.MAX_QUEUE; i++) {
      expect((await submit(id, `e${i}`)).status).toBe(200);
    }
    const over = await submit(id, "overflow");
    expect(over.status).toBe(507);
  });

  it("rate-limits a flood with 429", async () => {
    const id = mailboxId();
    let sawLimit = false;
    for (let i = 0; i < P.RATE_MAX + 5; i++) {
      const r = await SELF.fetch(mbox(id, "depth"));
      if (r.status === 429) {
        sawLimit = true;
        break;
      }
    }
    expect(sawLimit).toBe(true);
  });

  it("a WebSocket send past the queue bound gets an err frame, not a drop", async () => {
    const id = mailboxId();
    const ws = await attach(id);
    let lastFrame = "";
    for (let i = 0; i < P.MAX_QUEUE + 1; i++) {
      const f = nextFrame(ws);
      ws.send(JSON.stringify({ t: "send", env: `q${i}` }));
      lastFrame = await f;
    }
    expect(JSON.parse(lastFrame)).toEqual({ t: "err", code: 507 });
  });
});
