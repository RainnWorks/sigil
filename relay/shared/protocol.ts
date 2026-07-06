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
//
// v5: GET .../to-phone and .../to-daemon are long-poll, not instant-return.
// An empty slot holds the request open (see {@link longPoll}) until a
// matching deposit wakes it (see {@link wake}) or ~LONG_POLL_MS elapses. This
// is not the v3 held-socket mistake: nothing is held for an idle party. A
// long-poll is held only by whichever side is actively waiting on a live
// operation (a pending approval, a pairing in progress), for seconds, not for
// as long as the app is open. Idle daemon/phone hold nothing open at all.
//
// Known residual, confirmed against a real local Workers runtime (not just a
// simulated test double): an incoming Request's `signal` does not reliably
// fire when a long-poll GET is forwarded through a Durable Object, so a
// client that disconnects mid-poll can leave an orphaned waiter behind that
// nobody will ever hear from. `longPoll` evicts any such stale waiter the
// moment the same slot's next long-poll re-attaches, so wake() can never hand
// a deposit to a waiter that's already been superseded. The gap this does
// NOT close: a deposit landing in the narrow window after the disconnect but
// before the reconnect's long-poll re-attaches is still handed to the
// (already-abandoned) orphan and is genuinely lost, not merely delayed, for
// that one delivery. Bounded, rare (requires unlucky timing on top of an
// actual disconnect), and something client-side retry/resend should account
// for regardless of this relay's behavior; flagged here rather than silently
// assumed away. Confirm on a real Cloudflare deploy whether the edge network
// behaves differently from local wrangler dev before treating it as closed.

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
/** How long a long-poll GET holds an empty slot open before returning an
 * empty result. Clients read with a comfortably longer timeout than this. */
export const LONG_POLL_MS = 25_000;
/** Per-mailbox operations allowed per {@link RATE_WINDOW_MS}. Held only in the
 * mailbox's in-memory record; never persisted. Non-load-bearing anti-abuse.
 * Long-poll GETs are event-driven now, not a 2s/400ms hammer: each side holds
 * at most one outstanding GET per slot and re-issues it only after it
 * resolves, so a two-sided active exchange is on the order of a couple of
 * requests a minute per direction. 60 is a low floor with real headroom over
 * that, not a tuned ceiling against a poll cadence. */
export const RATE_MAX = 60;
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

/** A pending long-poll GET's resolver, called at most once with whatever was
 * just drained for it. Held on the {@link Mailbox} itself so both variants
 * share one shape; nothing here is I/O, it's a plain callback. */
export type Waiter = (blobs: string[]) => void;

export type Mailbox = {
  /** daemon -> phone; drained by GET .../to-phone. */
  toPhone: Item[];
  /** phone -> daemon; drained by GET .../to-daemon. */
  toDaemon: Item[];
  /** GETs on .../to-phone currently long-polling an empty toPhone. */
  toPhoneWaiters: Waiter[];
  /** GETs on .../to-daemon currently long-polling an empty toDaemon. */
  toDaemonWaiters: Waiter[];
  rateCount: number;
  rateStart: number;
  pushCount: number;
  pushStart: number;
};

export function newMailbox(): Mailbox {
  return {
    toPhone: [],
    toDaemon: [],
    toPhoneWaiters: [],
    toDaemonWaiters: [],
    rateCount: 0,
    rateStart: 0,
    pushCount: 0,
    pushStart: 0,
  };
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

/**
 * Long-poll one slot: if it already has data, resolve immediately (drained,
 * same as the old instant-return GET). Otherwise register a waiter and hold
 * the returned promise open until either {@link wake} resolves it with a
 * fresh deposit, `signal` aborts (the client disconnected; the waiter is
 * cleaned up the same as on a real resolve, nobody is left to read the
 * result), or `timeoutMs` elapses, whichever comes first — at which point it
 * resolves with one last drain (ordinarily `[]`, but never presumed to be:
 * see the comment on the timeout branch below).
 *
 * `timeoutMs` defaults to {@link LONG_POLL_MS} and exists as a parameter
 * purely so tests can shrink it; production callers should not pass it.
 */
export function longPoll(
  list: Item[],
  waiters: Waiter[],
  now: number,
  timeoutMs: number = LONG_POLL_MS,
  signal?: AbortSignal,
): Promise<string[]> {
  const immediate = drain(list, now);
  if (immediate.length > 0) return Promise.resolve(immediate);

  // At most one live long-poll per slot: a new GET supersedes whatever was
  // already registered here, resolving it empty. This is the fix for a real,
  // confirmed gap: an incoming Request's `signal` does not reliably fire when
  // this fetch is forwarded through a Durable Object (verified against a real
  // local Workers runtime, not just a simulated one) — a client that
  // disconnects mid-poll can leave its waiter registered with nobody left to
  // hear from it. Without eviction, `wake` could hand a deposit to that
  // orphaned waiter and the data would be gone, not merely delayed, by the
  // time the reconnect's long-poll registers behind it. This closes that gap
  // for the disconnect-then-reconnect ordering. It does not close the
  // narrower one where a deposit lands in the gap before the reconnect's
  // long-poll re-attaches at all: see the residual note in the module header.
  for (const evicted of waiters.splice(0)) evicted([]);

  return new Promise<string[]>((resolve) => {
    let settled = false;
    const cleanup = () => {
      const idx = waiters.indexOf(waiter);
      if (idx >= 0) waiters.splice(idx, 1);
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    };
    const waiter: Waiter = (blobs) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(blobs);
    };
    const onAbort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve([]); // a disconnected client will never read this; harmless
    };
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      // {@link wake} always drains before calling a waiter, so in the normal
      // case nothing is left here; this final drain only matters for the
      // vanishingly unlikely case of a deposit landing in the same tick the
      // timer fires, after this waiter already left the array.
      resolve(drain(list, Date.now()));
    }, timeoutMs);
    waiters.push(waiter);
    signal?.addEventListener("abort", onAbort);
  });
}

/**
 * Wake the oldest pending long-poll waiter for a slot, if any, handing it
 * everything now queued (drained). Call this right after a successful
 * {@link enqueue} on the same list. A no-op if nothing is waiting: the item
 * just sits in the queue for the next GET, long-poll or not, to pick up.
 */
export function wake(list: Item[], waiters: Waiter[], now: number): void {
  if (waiters.length === 0) return;
  const waiter = waiters.shift()!;
  waiter(drain(list, now));
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
