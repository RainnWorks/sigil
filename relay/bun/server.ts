// Latch/Sigil blind relay: Bun variant, for self-hosting without Cloudflare.
//
// Same routes, same status codes, same JSON bodies as the Worker: every wire
// decision comes from ../shared/protocol (and the push doorbell from
// ../shared/push), so the two are byte-identical. Mailboxes live in a Map in
// this one process; nothing is ever written to disk, so a restart just drops
// every mailbox. That's fine: envelopes are meant to be short-lived, and the
// side that deposited one still has its own copy if a retry is needed.
// GETs are long-poll (see ../shared/protocol's longPoll/wake): held open on an
// empty slot until a matching POST wakes them, or ~LONG_POLL_MS elapses. GET /
// serves the static landing page (../landing.html); GET /health is still the
// JSON liveness check the Docker HEALTHCHECK and any uptime probe rely on.
// Run: `bun run relay/bun/server.ts` (PORT defaults to 8787).

import { readFileSync } from "node:fs";
import * as P from "../shared/protocol";
import { sendPush } from "../shared/push";

const now = () => Date.now();
const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

// Read once at startup, same as the Worker bundles it in at build time, so
// both variants serve the identical bytes of the one source file.
const LANDING_HTML = readFileSync(`${import.meta.dir}/../landing.html`, "utf8");

const boxes = new Map<string, P.Mailbox>();

function box(id: string): P.Mailbox {
  let m = boxes.get(id);
  if (!m) boxes.set(id, (m = P.newMailbox()));
  return m;
}

// Resolved once at startup: either the raw PEM (APNS_KEY_P8) or a path to it
// (APNS_KEY_P8_PATH, meant to be a 0600 file). Absent disables the doorbell;
// every deposit still succeeds and relies on the phone's poll backstop.
function resolveApnsKey(): string | undefined {
  if (process.env.APNS_KEY_P8) return process.env.APNS_KEY_P8;
  const path = process.env.APNS_KEY_P8_PATH;
  if (!path) return undefined;
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    console.error(`push: reading APNS_KEY_P8_PATH: ${e}`);
    return undefined;
  }
}
const APNS_KEY_P8 = resolveApnsKey();

// Overridable only so the integration suite can shrink the long-poll window;
// production should leave this unset and get shared/protocol's LONG_POLL_MS.
const LONG_POLL_MS = Number(process.env.LONG_POLL_MS) || P.LONG_POLL_MS;

const port = Number(process.env.PORT ?? 8787);

const server = Bun.serve({
  port,
  async fetch(req) {
    const parts = new URL(req.url).pathname.split("/").filter(Boolean);
    if (parts.length === 0) {
      return new Response(LANDING_HTML, {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    if (parts[0] === "health") return json(P.RESP.health());
    if (parts[0] !== "mailbox" || !P.validId(parts[1])) {
      return json(P.RESP.err("bad_mailbox"), 400);
    }
    const id = parts[1];
    const verb = parts[2];
    const m = box(id);
    if (!P.rateOk(m, now())) return json(P.RESP.err("rate_limited"), 429);

    if (verb === "to-phone" && req.method === "GET") {
      const envelopes = await P.longPoll(m.toPhone, m.toPhoneWaiters, now(), LONG_POLL_MS, req.signal);
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
        void sendPush(
          { token: body.pushToken, platform: body.platform, keyPem: APNS_KEY_P8 },
          now(),
        );
      }
      return json(P.RESP.deposited());
    }

    if (verb === "to-daemon" && req.method === "GET") {
      const envelopes = await P.longPoll(m.toDaemon, m.toDaemonWaiters, now(), LONG_POLL_MS, req.signal);
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
  },
});

// Proactive TTL sweep, and drop mailboxes that are both empty and unwatched
// so the Map stays bounded. Never drop one with a live long-poll waiter: its
// queue is legitimately empty (that's the whole point of the wait), and
// deleting the entry here would orphan that waiter from the Mailbox object a
// concurrent deposit's `box(id)` would recreate, silently losing the wake.
// Correctness never depends on this sweep otherwise: expired items are also
// filtered lazily on every access.
setInterval(() => {
  const t = now();
  for (const [id, m] of boxes) {
    P.evictExpired(m, t);
    const idle =
      !m.toPhone.length &&
      !m.toDaemon.length &&
      !m.toPhoneWaiters.length &&
      !m.toDaemonWaiters.length;
    if (idle) boxes.delete(id);
  }
}, P.TTL_MS).unref();

console.log(`latch-relay (bun) listening on :${server.port}`);
