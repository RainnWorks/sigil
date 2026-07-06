// Latch/Sigil blind relay: Cloudflare Worker + one Durable Object per mailbox.
//
// The Worker validates the mailbox id and routes to the mailbox's Durable
// Object; the DO holds that one mailbox's envelopes ONLY in its own instance
// memory (`this.mailbox`), never in `ctx.storage`. Zero storage/KV writes: if
// the DO's isolate is evicted or recycled, the mailbox's contents are gone,
// exactly as if the relay had restarted; nothing here was ever meant to
// outlive a short TTL anyway. All wire behaviour lives in ../shared/protocol,
// and the push doorbell in ../shared/push, so this variant and the Bun
// variant are byte-identical.
//
// GETs are long-poll (see ../shared/protocol's longPoll/wake): held open on
// an empty slot until a matching POST wakes them, or ~LONG_POLL_MS elapses.
// A DO instance stays alive for the length of an in-flight fetch() the same
// way any Worker does; an outstanding long-poll `await` is exactly that, not
// idle time, so this never fights the runtime's own isolate lifecycle.

import { DurableObject } from "cloudflare:workers";
import * as P from "../shared/protocol";
import { sendPush } from "../shared/push";

export interface Env {
  MAILBOX: DurableObjectNamespace<Mailbox>;
  /** Publisher secret: `wrangler secret put APNS_KEY_P8` (the `.p8` PEM text).
   * Absent disables the doorbell; every deposit still succeeds and relies on
   * the phone's poll backstop. */
  APNS_KEY_P8?: string;
  /** Overridable only so tests can shrink the long-poll window; production
   * should leave this unset and get shared/protocol's LONG_POLL_MS. */
  LONG_POLL_MS?: string;
}

const now = () => Date.now();

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export class Mailbox extends DurableObject<Env> {
  // The entire state of this mailbox. In-memory only: no `ctx.storage` call
  // anywhere in this class.
  private mailbox: P.Mailbox = P.newMailbox();

  private get longPollMs(): number {
    return Number(this.env.LONG_POLL_MS) || P.LONG_POLL_MS;
  }

  async fetch(req: Request): Promise<Response> {
    const verb = new URL(req.url).pathname.split("/").filter(Boolean)[2];
    const m = this.mailbox;
    if (!P.rateOk(m, now())) return json(P.RESP.err("rate_limited"), 429);

    if (verb === "to-phone" && req.method === "GET") {
      const envelopes = await P.longPoll(m.toPhone, m.toPhoneWaiters, now(), this.longPollMs, req.signal);
      return json(P.RESP.envelopes(envelopes));
    }

    if (verb === "to-phone" && req.method === "POST") {
      if (Number(req.headers.get("content-length") ?? "0") > P.MAX_BODY_BYTES) {
        return json(P.RESP.err("too_large"), 413);
      }
      const body = P.parseToPhoneBody(await req.json().catch(() => null));
      if (!body) return json(P.RESP.err("bad_body"), 400);
      const r = P.enqueue(m.toPhone, body.env, now());
      if (!r.ok) return json(P.RESP.err(r.code === 413 ? "too_large" : "queue_full"), r.code);
      P.wake(m.toPhone, m.toPhoneWaiters, now());
      if (body.pushToken && P.pushOk(m, now())) {
        this.ctx.waitUntil(
          sendPush(
            { token: body.pushToken, platform: body.platform, keyPem: this.env.APNS_KEY_P8 },
            now(),
          ),
        );
      }
      return json(P.RESP.deposited());
    }

    if (verb === "to-daemon" && req.method === "GET") {
      const envelopes = await P.longPoll(m.toDaemon, m.toDaemonWaiters, now(), this.longPollMs, req.signal);
      return json(P.RESP.envelopes(envelopes));
    }

    if (verb === "to-daemon" && req.method === "POST") {
      if (Number(req.headers.get("content-length") ?? "0") > P.MAX_BODY_BYTES) {
        return json(P.RESP.err("too_large"), 413);
      }
      const env = P.parseEnvBody(await req.json().catch(() => null));
      if (env === null) return json(P.RESP.err("bad_body"), 400);
      const r = P.enqueue(m.toDaemon, env, now());
      if (!r.ok) return json(P.RESP.err(r.code === 413 ? "too_large" : "queue_full"), r.code);
      P.wake(m.toDaemon, m.toDaemonWaiters, now());
      return json(P.RESP.deposited());
    }

    return json(P.RESP.err("not_found"), 404);
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
