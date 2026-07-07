// Sigil blind relay: Cloudflare Worker + one Durable Object per mailbox.
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
//
// GET / serves the landing page (../landing.html, bundled in as a text module -
// see wrangler.jsonc's "rules" and src/html.d.ts) with two status figures
// templated in at serve time (deploy date + a live relayed-message count); GET
// /health is still the JSON liveness check any uptime probe relies on, now also
// carrying that count.
//
// That count is EPHEMERAL by design and stored nowhere: it is the module-scope
// `relayed` counter below, held only in this Worker isolate's own memory,
// bumped once per successful deposit and reset to zero whenever the isolate is
// evicted or recycled. There is no Durable Object storage, no KV, no `ctx.storage`
// write anywhere in this file - the relay keeps literally nothing at rest, and
// the landing page makes a joke of exactly that (an arrow at the number reading
// "even this number isn't stored"). Because each isolate counts only what it
// personally passed while awake, this is a live liveliness figure, not a total.

import { DurableObject } from "cloudflare:workers";
import * as P from "../shared/protocol";
import { sendPush } from "../shared/push";
import landingHtml from "../landing.html";

export interface Env {
  MAILBOX: DurableObjectNamespace<Mailbox>;
  /** Publisher secret: `wrangler secret put APNS_KEY_P8` (the `.p8` PEM text).
   * Absent disables the doorbell; every deposit still succeeds and relies on
   * the phone's poll backstop. */
  APNS_KEY_P8?: string;
  /** The deploy date the landing page reports as "up since". Optional; a
   * `var` in wrangler.jsonc, falling back to shared/protocol's RELAY_SINCE. */
  RELAY_SINCE?: string;
  /** Overridable only so tests can shrink the long-poll window; production
   * should leave this unset and get shared/protocol's LONG_POLL_MS. */
  LONG_POLL_MS?: string;
}

// The live relayed-message count: in-memory ONLY, per isolate. Not persisted,
// not a Durable Object, not `ctx.storage` - just a module-scope number that
// resets to zero when this isolate is recycled. That impermanence is the point
// (see the file header and the landing-page gag). It records nothing but its
// own value: no mailbox id, no timestamp, nothing linkable to anyone. Bumped in
// the top-level fetch below, once per successful deposit.
let relayed = 0;

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

/** A successful deposit is a POST to a mailbox's to-phone/to-daemon slot that
 * the Durable Object accepted (200). GETs (long-polls, drains) and rejects
 * (400/413/429/507) are not relayed messages and are not counted. */
function isRelayedDeposit(method: string, verb: string | undefined, status: number): boolean {
  return (
    method === "POST" && (verb === "to-phone" || verb === "to-daemon") && status === 200
  );
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const parts = new URL(req.url).pathname.split("/").filter(Boolean);
    if (parts.length === 0) {
      const since = env.RELAY_SINCE || P.RELAY_SINCE;
      return new Response(P.renderLanding(landingHtml, since, relayed), {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    if (parts[0] === "health") return json(P.RESP.health(relayed));
    if (parts[0] !== "mailbox" || !P.validId(parts[1])) {
      return json(P.RESP.err("bad_mailbox"), 400);
    }
    const resp = await env.MAILBOX.getByName(parts[1]).fetch(req);
    // Count one relayed message, in memory only (see `relayed`). Reading the
    // status is all this needs; it records nothing about which mailbox or when.
    if (isRelayedDeposit(req.method, parts[2], resp.status)) relayed += 1;
    return resp;
  },
} satisfies ExportedHandler<Env>;
