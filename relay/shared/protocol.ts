// Pure, runtime-agnostic relay logic. No I/O, no platform APIs, no dependencies.
//
// Both the Cloudflare Worker (../src) and the Bun server (../bun) drive their
// entire wire behaviour through this module, so the two speak a byte-identical
// protocol: identical routes, identical status codes, identical JSON bodies,
// identical WebSocket frames. If a wire decision is not made here, it is a bug.
//
// The relay never inspects an envelope. Every payload is an opaque string that
// flows in one side and out the other unchanged; nothing below parses it, hashes
// it, or reads a single field of it. Routing is by the mailbox id in the URL,
// which the daemon and phone both derive from their pinned keys (proto
// `mailbox_id`); the relay only pattern-checks its shape.

/** Envelope time-to-live, ms. Matches the client request-expiry window. */
export const TTL_MS = 600_000;
/** Bounded FIFO depth per direction. Overflow is rejected, never silently dropped. */
export const MAX_QUEUE = 32;
/** Envelopes are tiny (a sealed DEK or a small request). Anything larger is abuse. */
export const MAX_ENVELOPE_BYTES = 16_384;
/** Per-mailbox operations allowed per {@link RATE_WINDOW_MS}. */
export const RATE_MAX = 120;
export const RATE_WINDOW_MS = 60_000;
/** A mailbox id is the lowercase hex of the 32-byte proto `mailbox_id`. */
export const MAILBOX_ID = /^[0-9a-f]{64}$/;

export type Item = { blob: string; exp: number };

export type Mailbox = {
  /** daemon -> phone; drained by GET /pending. */
  toPhone: Item[];
  /** phone -> daemon; pushed over the attached daemon WebSocket. */
  toDaemon: Item[];
  rateCount: number;
  rateStart: number;
  /** Coarse lifetime relay count. Operational only; not per-message metadata. */
  relayed: number;
};

export function newMailbox(): Mailbox {
  return { toPhone: [], toDaemon: [], rateCount: 0, rateStart: 0, relayed: 0 };
}

export function validId(id: string | undefined): boolean {
  return typeof id === "string" && MAILBOX_ID.test(id);
}

/** Envelopes are ASCII JSON, so raw string length is a sound byte ceiling. */
export function tooBig(blob: string): boolean {
  return blob.length > MAX_ENVELOPE_BYTES;
}

function live(list: Item[], now: number): Item[] {
  return list.filter((i) => i.exp > now);
}

/** Replace a list's contents in place with only its unexpired items. */
function retainLive(list: Item[], now: number): void {
  const kept = live(list, now);
  list.length = 0;
  for (const i of kept) list.push(i);
}

export function evictExpired(m: Mailbox, now: number): void {
  retainLive(m.toPhone, now);
  retainLive(m.toDaemon, now);
}

/** Fixed-window limiter. Non-load-bearing anti-abuse; clients verify everything. */
export function rateOk(m: Mailbox, now: number): boolean {
  if (now - m.rateStart >= RATE_WINDOW_MS) {
    m.rateStart = now;
    m.rateCount = 0;
  }
  m.rateCount += 1;
  return m.rateCount <= RATE_MAX;
}

/** Result codes mirror the HTTP status the adapters return to the client. */
export type EnqueueResult = { ok: true; depth: number } | { ok: false; code: 413 | 507 };

/** Evict expired, reject oversized (413) or a full queue (507), else append. */
export function enqueue(list: Item[], blob: string, now: number): EnqueueResult {
  if (tooBig(blob)) return { ok: false, code: 413 };
  retainLive(list, now);
  if (list.length >= MAX_QUEUE) return { ok: false, code: 507 };
  list.push({ blob, exp: now + TTL_MS });
  return { ok: true, depth: list.length };
}

/** Return every unexpired blob and empty the queue (drain-on-read). */
export function drain(list: Item[], now: number): string[] {
  const out = live(list, now).map((i) => i.blob);
  list.length = 0;
  return out;
}

/** JSON response bodies, shared so both variants emit identical bytes. */
export const RESP = {
  health: () => ({ ok: true, service: "latch-relay" }),
  pending: (envelopes: string[]) => ({ envelopes, depth: 0 }),
  submit: (attached: boolean) => ({ ok: true, queued: true, attached }),
  depth: (pending: number, inbound: number) => ({ pending, inbound }),
  err: (error: string) => ({ ok: false, error }),
};

/**
 * WebSocket control frames on the daemon's outbound connection. The connection
 * multiplexes both directions plus flow control, so every frame is a small JSON
 * envelope with a tag `t`. The opaque payload rides in `env` as a string the
 * relay never parses.
 */
export const FRAME = {
  deliver: (env: string) => JSON.stringify({ t: "deliver", env }),
  ack: (depth: number) => JSON.stringify({ t: "ack", depth }),
  err: (code: number) => JSON.stringify({ t: "err", code }),
};

/**
 * A daemon -> relay frame is `{"t":"send","env":"<opaque envelope>"}`. Returns
 * the opaque `env` string, or null for keepalives and anything unrecognised.
 * This parses the control wrapper only; `env` is passed through untouched.
 */
export function parseSend(msg: string): string | null {
  try {
    const o = JSON.parse(msg);
    if (o && o.t === "send" && typeof o.env === "string") return o.env;
  } catch {
    // not a control frame; ignore
  }
  return null;
}
