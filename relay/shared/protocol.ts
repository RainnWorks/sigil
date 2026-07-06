// Pure, runtime-agnostic relay logic. No I/O, no platform APIs, no dependencies.
//
// Both the Cloudflare Worker (../src) and the Bun server (../bun) drive their
// entire wire behaviour through this module, so the two speak a byte-identical
// protocol: identical routes, identical status codes, identical JSON bodies. If
// a wire decision is not made here, it is a bug.
//
// The relay never inspects an envelope. Every payload is an opaque string that
// flows in one side and out the other unchanged; nothing below parses it, hashes
// it, or reads a single field of it. Routing is by the mailbox id in the URL,
// which the daemon and phone both derive from their pinned keys (proto
// `mailbox_id`); the relay only pattern-checks its shape.
//
// v4: plain HTTP deposit and drain, no held sockets. A mailbox is a small
// ephemeral in-memory buffer per direction (Durable Object instance memory, or
// a Bun Map): bounded, short-TTL, never written to disk. A deposit bound for
// the phone may also carry a push token, which the relay reads once to ring a
// content-free APNs doorbell (see ../shared/push) and then forgets; it is
// never part of the buffered item and never stored.

/** Envelope time-to-live, ms. Short: this only has to outlive the gap between
 * a deposit and the other side's next poll, not a real offline window.
 * Must stay ordered relay TTL >= proto REPLAY_WINDOW_MS (150_000) > the
 * approval timeout (120_000), so the relay never expires a queued envelope
 * before the replay window would still accept it. 180_000 leaves 30s of
 * headroom over the replay window itself, not just equality with it. */
export const TTL_MS = 180_000;
/** Bounded FIFO depth per direction. Overflow is rejected, never silently dropped. */
export const MAX_QUEUE = 32;
/** Envelopes are tiny (a sealed DEK or a small request). Anything larger is abuse. */
export const MAX_ENVELOPE_BYTES = 16_384;
/** Generous slack over {@link MAX_ENVELOPE_BYTES} for the JSON wrapper around
 * the opaque envelope (a push token and platform tag, both tiny). This is only
 * a coarse pre-read guard against an oversized body; the authoritative
 * per-envelope cap is enforced on `env` itself by {@link enqueue}. */
export const MAX_BODY_BYTES = MAX_ENVELOPE_BYTES + 4_096;
/** Per-mailbox operations allowed per {@link RATE_WINDOW_MS}. Held only in the
 * mailbox's in-memory record; never persisted. Non-load-bearing anti-abuse. */
export const RATE_MAX = 120;
export const RATE_WINDOW_MS = 60_000;
/** A separate, tighter cap on pushes specifically, so a leaked push token
 * can't turn a mailbox into a doorbell-spam amplifier. Residual: this is
 * per-mailbox, not per-token, so the same leaked token deposited against
 * different mailbox ids is rate-limited independently for each. */
export const PUSH_MAX = 5;
export const PUSH_WINDOW_MS = 60_000;
/** A mailbox id is the lowercase hex of the 32-byte proto `mailbox_id`. */
export const MAILBOX_ID = /^[0-9a-f]{64}$/;

export type Item = { blob: string; exp: number };

export type Mailbox = {
  /** daemon -> phone; drained by GET .../to-phone. */
  toPhone: Item[];
  /** phone -> daemon; drained by GET .../to-daemon. */
  toDaemon: Item[];
  rateCount: number;
  rateStart: number;
  pushCount: number;
  pushStart: number;
};

export function newMailbox(): Mailbox {
  return { toPhone: [], toDaemon: [], rateCount: 0, rateStart: 0, pushCount: 0, pushStart: 0 };
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

/** Fixed-window limiter over ordinary deposits/drains. Non-load-bearing
 * anti-abuse; clients verify everything themselves. */
export function rateOk(m: Mailbox, now: number): boolean {
  if (now - m.rateStart >= RATE_WINDOW_MS) {
    m.rateStart = now;
    m.rateCount = 0;
  }
  m.rateCount += 1;
  return m.rateCount <= RATE_MAX;
}

/** A separate, tighter fixed-window limiter gating only the push proxy. */
export function pushOk(m: Mailbox, now: number): boolean {
  if (now - m.pushStart >= PUSH_WINDOW_MS) {
    m.pushStart = now;
    m.pushCount = 0;
  }
  m.pushCount += 1;
  return m.pushCount <= PUSH_MAX;
}

/** Result codes mirror the HTTP status the adapters return to the client. */
export type EnqueueResult = { ok: true } | { ok: false; code: 413 | 507 };

/** Evict expired, reject oversized (413) or a full queue (507), else append. */
export function enqueue(list: Item[], blob: string, now: number): EnqueueResult {
  if (tooBig(blob)) return { ok: false, code: 413 };
  retainLive(list, now);
  if (list.length >= MAX_QUEUE) return { ok: false, code: 507 };
  list.push({ blob, exp: now + TTL_MS });
  return { ok: true };
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
  deposited: () => ({ ok: true }),
  envelopes: (list: string[]) => ({ envelopes: list }),
  err: (error: string) => ({ ok: false, error }),
};

/**
 * The body of a phone-bound deposit: the opaque envelope, plus an optional
 * push token and platform tag the relay reads once to ring a doorbell, then
 * forgets. This parses only these three fields; `env` itself stays opaque.
 */
export type ToPhoneBody = { env: string; pushToken?: string; platform?: string };

export function parseToPhoneBody(body: unknown): ToPhoneBody | null {
  if (!body || typeof body !== "object") return null;
  const o = body as Record<string, unknown>;
  if (typeof o.env !== "string") return null;
  const pushToken = typeof o.pushToken === "string" ? o.pushToken : undefined;
  const platform = typeof o.platform === "string" ? o.platform : undefined;
  return { env: o.env, pushToken, platform };
}

/** The body of a daemon-bound deposit: just the opaque envelope. Carries both
 * an ApprovalResponse and a PushRegister; the relay can't tell which, and
 * doesn't need to. */
export function parseEnvBody(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const env = (body as Record<string, unknown>).env;
  return typeof env === "string" ? env : null;
}
