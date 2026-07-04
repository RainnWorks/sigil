// Latch blind relay: Bun variant, for self-hosting without Cloudflare.
//
// Same routes, same status codes, same JSON bodies, same WebSocket frames as the
// Worker: every wire decision comes from ../shared/protocol, so the two are
// byte-identical on the wire. The only difference is the backing store: the
// Worker uses one Durable Object per mailbox, this keeps mailboxes in a Map in
// one process. Run: `bun run relay/bun/server.ts` (PORT defaults to 8787).

import * as P from "../shared/protocol";
import type { ServerWebSocket } from "bun";

const now = () => Date.now();
const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

const boxes = new Map<string, P.Mailbox>();
const sockets = new Map<string, Set<ServerWebSocket<{ id: string }>>>();

function box(id: string): P.Mailbox {
  let m = boxes.get(id);
  if (!m) boxes.set(id, (m = P.newMailbox()));
  return m;
}
function socketsFor(id: string): Set<ServerWebSocket<{ id: string }>> {
  let s = sockets.get(id);
  if (!s) sockets.set(id, (s = new Set()));
  return s;
}
function flushToDaemon(m: P.Mailbox, ws: ServerWebSocket<{ id: string }>): void {
  for (const blob of P.drain(m.toDaemon, now())) ws.send(P.FRAME.deliver(blob));
}

const port = Number(process.env.PORT ?? 8787);

const server = Bun.serve<{ id: string }>({
  port,
  async fetch(req, server) {
    const parts = new URL(req.url).pathname.split("/").filter(Boolean);
    if (parts.length === 0 || parts[0] === "health") return json(P.RESP.health());
    if (parts[0] !== "mailbox" || !P.validId(parts[1])) {
      return json(P.RESP.err("bad_mailbox"), 400);
    }
    const id = parts[1];
    const verb = parts[2];
    const m = box(id);
    if (!P.rateOk(m, now())) return json(P.RESP.err("rate_limited"), 429);

    if (verb === "attach") {
      if (server.upgrade(req, { data: { id } })) return undefined; // Bun sends 101
      return json(P.RESP.err("expected_websocket"), 426);
    }

    if (verb === "pending" && req.method === "GET") {
      const envelopes = P.drain(m.toPhone, now());
      m.relayed += envelopes.length;
      return json(P.RESP.pending(envelopes));
    }

    if (verb === "submit" && req.method === "POST") {
      if (Number(req.headers.get("content-length") ?? "0") > P.MAX_ENVELOPE_BYTES) {
        return json(P.RESP.err("too_large"), 413);
      }
      const blob = await req.text();
      const r = P.enqueue(m.toDaemon, blob, now());
      if (!r.ok) return json(P.RESP.err(r.code === 413 ? "too_large" : "queue_full"), r.code);
      const s = socketsFor(id);
      for (const ws of s) flushToDaemon(m, ws);
      m.relayed += 1;
      return json(P.RESP.submit(s.size > 0));
    }

    if (verb === "depth" && req.method === "GET") {
      P.evictExpired(m, now());
      return json(P.RESP.depth(m.toPhone.length, m.toDaemon.length));
    }

    return json(P.RESP.err("not_found"), 404);
  },
  websocket: {
    open(ws) {
      socketsFor(ws.data.id).add(ws);
      flushToDaemon(box(ws.data.id), ws);
    },
    message(ws, message) {
      const m = box(ws.data.id);
      if (!P.rateOk(m, now())) return void ws.send(P.FRAME.err(429));
      const env = P.parseSend(typeof message === "string" ? message : "");
      if (env === null) return;
      const r = P.enqueue(m.toPhone, env, now());
      if (!r.ok) return void ws.send(P.FRAME.err(r.code));
      m.relayed += 1;
      ws.send(P.FRAME.ack(r.depth));
    },
    close(ws) {
      socketsFor(ws.data.id).delete(ws);
    },
  },
});

// Proactive TTL sweep, and drop mailboxes that are empty and unattached so the
// Map stays bounded. Correctness never depends on this: expired items are also
// filtered lazily on every access.
setInterval(() => {
  const t = now();
  for (const [id, m] of boxes) {
    P.evictExpired(m, t);
    if (!m.toPhone.length && !m.toDaemon.length && !socketsFor(id).size) {
      boxes.delete(id);
      sockets.delete(id);
    }
  }
}, P.RATE_WINDOW_MS).unref();

console.log(`latch-relay (bun) listening on :${server.port}`);
