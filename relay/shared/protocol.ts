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
// v5.1: a long-poll on an empty slot HOLDS for the full ~LONG_POLL_MS unless a
// deposit wakes it. It no longer resolves an already-registered waiter early
// when a second GET arrives on the same slot. That early-empty was the source
// of an instant-return -> instant-refire hammer: superseding a live waiter the
// instant a second GET landed turned one quiet wait into a burst of fast
// empties that a client re-fired on at network speed (and two such GETs could
// ping-pong empties off each other). The relay exists precisely so a waiting
// side sits in ONE held request; manufacturing a fast empty defeats that.
// Multiple waiters on one slot now coexist, each held for its full duration; a
// deposit is handed to the NEWEST of them (see {@link wake}), and the
// coexisting count is bounded by {@link MAX_WAITERS}.
//
// Why "newest": the only reason two GETs legitimately overlap on one slot is a
// single client whose earlier poll's connection died without its `signal`
// firing (confirmed unreliable when a long-poll GET is forwarded through a
// Durable Object; verified against a real local Workers runtime, not just a
// simulated test double) and then reconnected. The reconnect is the newest
// waiter and the live one; handing the deposit to the newest delivers it to
// the client that can still hear it, and does so WITHOUT resolving the older
// (possibly still-live) waiter empty first, so no fast empty is manufactured.
// The stale/orphaned older waiter simply times out into the void after
// ~LONG_POLL_MS with nobody listening.
//
// Known residual (this partly closes #53). Now CLOSED: the manufactured
// early-empty (a normal single poll holds the full window; a second concurrent
// GET can no longer ping-pong it empty), and the disconnect-then-reconnect
// delivery (the reconnect, being newest, receives the deposit rather than the
// orphan). Still OPEN: a deposit that lands in the gap after a disconnect but
// before ANY reconnecting long-poll re-attaches is handed to the orphaned
// waiter (it is the only, hence newest, waiter) and is genuinely lost, not
// merely delayed, for that one delivery. A second, narrower residual is NOT
// reachable by any client shipped today: it would need a client holding two
// overlapping polls where the NEWER connection dies while the older stays live
// (the deposit then goes to the dead-newer waiter). Both shipped clients are
// strictly single-flight per slot (the daemon blocks one GET at a time; the
// phone aborts its prior poll before a new one), so only a hypothetical future
// concurrent-poll client could reach it. The disconnect-gap residual above is
// bounded, requires an actual disconnect on top of unlucky timing, and is what
// client-side retry/resend must cover regardless of this relay.
// Confirm on a real Cloudflare deploy whether the edge network delivers a
// GET's abort signal more reliably than local wrangler dev before treating the
// disconnect-gap residual as fully closed.

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
/** Upper bound on how many long-poll waiters may coexist on one slot. In normal
 * use this is 1 (a client keeps a single poll in flight and re-issues only after
 * it resolves); it climbs above 1 only when a client's polls genuinely overlap
 * (a reconnect after a disconnect whose signal never fired, or a client firing
 * a second GET before the first returns). This caps that: rather than resolving
 * an existing waiter early to make room (the fast-empty this design exists to
 * avoid), a new GET past the cap drops the OLDEST waiter (the stalest, hence
 * likeliest orphaned) and takes its place. Small: a single client should never
 * legitimately hold this many at once, and each waiter self-expires after
 * {@link LONG_POLL_MS} regardless. This is the explicit memory bound; the rate
 * limiter is only a coarse backstop, not the mechanism. A third party cannot
 * weaponize this to evict or steal from a victim's slot: the two directions are
 * disjoint waiter lists (neither paired party can evict the other's delivery
 * waiter, so a flood is self-DoS only), and reaching a slot at all presupposes
 * the mailbox id, a BLAKE2b hash of the two pinned public keys (256-bit, carried
 * only inside TLS, never published), so an outsider cannot address it. */
export const MAX_WAITERS = 8;
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
 * A newcomer never resolves an existing waiter early: multiple waiters coexist
 * on a slot, each held for its full duration, and {@link wake} hands a deposit
 * to the newest. This is what keeps a normal poll holding the full window and
 * stops two concurrent GETs from ping-ponging empties. Only crossing
 * {@link MAX_WAITERS} drops a waiter (the oldest) before its natural end.
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

  // The slot is empty (the drain above returned nothing). Register this GET as
  // a waiter and hold it open for its full duration. A second concurrent GET on
  // the same empty slot does NOT resolve an existing waiter early: doing so is
  // exactly what manufactured the instant-return -> instant-refire hammer this
  // relay exists to prevent. Waiters coexist; each holds until a deposit wakes
  // it (handed to the NEWEST waiter — the client's current live connection, see
  // {@link wake}), its own timeout fires, or its `signal` aborts. A stale or
  // orphaned older waiter is never resolved early by a newcomer; it just times
  // out into the void. See the module header for the disconnect residual this
  // does and does not close, and why newest-wins delivers a reconnect correctly.
  //
  // Bound the coexisting count so overlapping GETs can't grow it without limit.
  // At the cap, drop the OLDEST waiter (the stalest, hence likeliest orphaned)
  // to admit the newcomer. The slot is provably empty here, so the dropped
  // waiter is resolved with [] and no queued deposit can be lost to it. This is
  // the only place a waiter resolves without either a deposit or its own
  // timeout, and it is reachable only under genuinely overlapping polls past
  // {@link MAX_WAITERS}, never in the normal single-poller case.
  while (waiters.length >= MAX_WAITERS) {
    const oldest = waiters.shift();
    oldest?.([]);
  }

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
 * Wake the NEWEST pending long-poll waiter for a slot, if any, handing it
 * everything now queued (drained). Call this right after a successful
 * {@link enqueue} on the same list. A no-op if nothing is waiting: the item
 * just sits in the queue for the next GET, long-poll or not, to pick up.
 *
 * Newest, not oldest: the only reason a slot holds more than one waiter is a
 * single client whose earlier poll's connection died without its `signal`
 * firing (see the module header) and then reconnected. The reconnect is the
 * newest waiter and the live one; the stale older waiter can no longer be
 * heard from. Delivering to the newest hands the deposit to the connection
 * that can still receive it, and — because {@link longPoll} never resolves the
 * older waiter early — does so without manufacturing a fast empty. The stale
 * older waiter is left to time out on its own into the void.
 */
export function wake(list: Item[], waiters: Waiter[], now: number): void {
  if (waiters.length === 0) return;
  const waiter = waiters.pop()!;
  waiter(drain(list, now));
}

/** JSON response bodies, shared so both variants emit identical bytes. */
export const RESP = {
  health: () => ({ ok: true, service: "sigil-relay" }),
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
