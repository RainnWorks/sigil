// Latch blind relay: Cloudflare Worker + one Durable Object per mailbox.
//
// The Worker validates the mailbox id and routes to the mailbox's Durable
// Object; the DO stores and forwards opaque envelopes. All wire behaviour lives
// in ../shared/protocol so this variant and the Bun variant are byte-identical.
// The DO never parses an envelope: it only moves opaque strings between the
// daemon's outbound WebSocket and the phone's HTTPS pulls.

import { DurableObject } from "cloudflare:workers";
import * as P from "../shared/protocol";

export interface Env {
  MAILBOX: DurableObjectNamespace<Mailbox>;
}

const now = () => Date.now();

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export class Mailbox extends DurableObject<Env> {
  // State is persisted so it survives WebSocket hibernation, when the DO leaves
  // memory while the daemon stays connected. Load-modify-save is safe: the DO is
  // single-threaded and input gates serialize storage access.
  private async load(): Promise<P.Mailbox> {
    return (await this.ctx.storage.get<P.Mailbox>("m")) ?? P.newMailbox();
  }

  private async save(m: P.Mailbox): Promise<void> {
    await this.ctx.storage.put("m", m);
    if (m.toPhone.length || m.toDaemon.length) {
      await this.ctx.storage.setAlarm(now() + P.TTL_MS);
    }
  }

  // Deliver everything queued for the daemon over its socket, draining as we go.
  private flushToDaemon(m: P.Mailbox, ws: WebSocket): void {
    for (const blob of P.drain(m.toDaemon, now())) ws.send(P.FRAME.deliver(blob));
  }

  async fetch(req: Request): Promise<Response> {
    const verb = new URL(req.url).pathname.split("/").filter(Boolean)[2];
    const m = await this.load();
    if (!P.rateOk(m, now())) {
      await this.save(m);
      return json(P.RESP.err("rate_limited"), 429);
    }

    if (verb === "attach") {
      if (req.headers.get("Upgrade") !== "websocket") {
        return json(P.RESP.err("expected_websocket"), 426);
      }
      const [client, server] = Object.values(new WebSocketPair());
      this.ctx.acceptWebSocket(server); // hibernatable
      this.flushToDaemon(m, server);
      await this.save(m);
      return new Response(null, { status: 101, webSocket: client });
    }

    if (verb === "pending" && req.method === "GET") {
      const envelopes = P.drain(m.toPhone, now());
      m.relayed += envelopes.length;
      await this.save(m);
      return json(P.RESP.pending(envelopes));
    }

    if (verb === "submit" && req.method === "POST") {
      // Reject on Content-Length before reading, so we never buffer a large body.
      if (Number(req.headers.get("content-length") ?? "0") > P.MAX_ENVELOPE_BYTES) {
        return json(P.RESP.err("too_large"), 413);
      }
      const blob = await req.text();
      const r = P.enqueue(m.toDaemon, blob, now());
      if (!r.ok) {
        await this.save(m);
        return json(P.RESP.err(r.code === 413 ? "too_large" : "queue_full"), r.code);
      }
      const sockets = this.ctx.getWebSockets();
      for (const ws of sockets) this.flushToDaemon(m, ws);
      m.relayed += 1;
      await this.save(m);
      return json(P.RESP.submit(sockets.length > 0));
    }

    if (verb === "depth" && req.method === "GET") {
      P.evictExpired(m, now());
      await this.save(m);
      return json(P.RESP.depth(m.toPhone.length, m.toDaemon.length));
    }

    return json(P.RESP.err("not_found"), 404);
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const m = await this.load();
    if (!P.rateOk(m, now())) {
      await this.save(m);
      ws.send(P.FRAME.err(429));
      return;
    }
    const env = P.parseSend(typeof message === "string" ? message : "");
    if (env === null) {
      await this.save(m);
      return; // keepalive or unknown control frame
    }
    const r = P.enqueue(m.toPhone, env, now());
    if (!r.ok) {
      await this.save(m);
      ws.send(P.FRAME.err(r.code));
      return;
    }
    m.relayed += 1;
    await this.save(m);
    ws.send(P.FRAME.ack(r.depth));
  }

  async webSocketClose(): Promise<void> {
    // Nothing to clean up. Items queued for the daemon wait for the next attach.
  }

  async alarm(): Promise<void> {
    const m = await this.load();
    P.evictExpired(m, now());
    await this.ctx.storage.put("m", m);
    if (m.toPhone.length || m.toDaemon.length) {
      await this.ctx.storage.setAlarm(now() + P.TTL_MS);
    }
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const parts = new URL(req.url).pathname.split("/").filter(Boolean);
    if (parts.length === 0 || parts[0] === "health") return json(P.RESP.health());
    if (parts[0] !== "mailbox" || !P.validId(parts[1])) {
      return json(P.RESP.err("bad_mailbox"), 400);
    }
    return env.MAILBOX.getByName(parts[1]).fetch(req);
  },
} satisfies ExportedHandler<Env>;
