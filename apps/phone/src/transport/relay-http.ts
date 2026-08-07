/**
 * The blind relay's v4 HTTP contract, as the phone speaks it. One mailbox, two
 * opaque endpoints, exactly matching relay/shared/protocol.ts and the Rust
 * clients (crates/sigil-relay-client):
 *
 *   GET  /mailbox/{id}/to-phone    -> { envelopes: string[] }  (long-poll, drain-on-read)
 *   POST /mailbox/{id}/to-daemon   body { "env": "<opaque>" }  (deposit)
 *
 * `to-phone` (and the daemon's mirror `to-daemon` GET) LONG-POLLS: an empty
 * mailbox holds the request open server-side until a deposit lands or the
 * relay's own ~25s timeout, then returns (with or without envelopes) either
 * way. The doorbell is the whole point of this transport.
 *
 * A subtlety the poll loop MUST respect: the relay's long-poll is a single
 * holder per slot. When a second GET hits an already-held slot the server
 * resolves BOTH early and empty (mutual eviction), and any other fast-empty
 * path (a 429, an abort, a relay blip) likewise returns in well under the
 * ~25s hold. If the client re-fired immediately on such a fast return it would
 * become a network-speed hammer, so {@link RelayMailbox.waitOne} times each
 * GET: a return that did NOT actually hold triggers exponential backoff, and
 * only one poll loop per mailbox slot is ever allowed to run (see the
 * `activeWaits` registry). Steady state is otherwise an APNs doorbell, not a
 * poll; see PhoneRelay.
 *
 * The relay never parses the payload; it is a UTF-8 string in one side and out
 * the other. The steady-state {@link PhoneRelay} and the pairing rendezvous
 * both layer on this: the only difference is what the opaque string is (a
 * sealed envelope's JSON, or a base64url PairingResponse).
 *
 * Push SENDING is the relay's job now (it holds the publisher's APNs cert);
 * this phone never talks push wire directly, only registers its token with
 * the daemon over `to-daemon` (`src/lib/push.ts`'s PushRegisterMessage) -
 * unaffected by this module.
 */
import { toHex } from "@/src/protocol/bytes";
import { type RelayOrigin } from "@/src/domain/types";

/**
 * Client-side ceiling on one `to-phone` GET, comfortably above the relay's
 * own ~25s server-side hold so a normal long-poll never gets aborted
 * mid-hold; only a relay that hangs past its own timeout trips this.
 */
const FETCH_TIMEOUT_MS = 30_000;

/**
 * The relay's server-side long-poll hold. A healthy empty GET returns at about
 * this age; anything materially shorter means the hold did NOT happen (fast
 * return) and must be backed off, not re-fired.
 */
const HELD_MIN_MS = 20_000;

/** Small floor after a genuine ~full hold returned empty: re-poll promptly. */
const HELD_FLOOR_MS = 250;

/** First backoff step after a fast return; doubles each consecutive fast return. */
const BACKOFF_BASE_MS = 1_000;

/** Backoff ceiling: a pathological fast-empty/429 storm settles to ~one GET / this. */
const BACKOFF_CAP_MS = 20_000;

/** Additive jitter ceiling, to desynchronize retries and never poll below a floor. */
const JITTER_MS = 1_000;

/**
 * How far back a relay's `at_ms` may sit before the hint is dropped rather than
 * shown. A delivery is drained within seconds of the deposit, so a stamp much
 * older than this belongs to some other moment (a stale or replayed note) and
 * would attach an address to a request it never described.
 */
const ORIGIN_MAX_AGE_MS = 5 * 60_000;

/** Tolerance for a relay clock running ahead of ours before the hint is dropped. */
const ORIGIN_MAX_SKEW_MS = 60_000;

/** Longest an IPv6 literal can render, the IPv4-mapped form `…:255.255.255.255`. */
const ORIGIN_IP_MAX_LEN = 45;

/**
 * IP-literal charset: hex digits, dots, and colons, and nothing else. This is a
 * HOSTILE-INPUT gate, not a formatter. An honest relay renders `ip` from a
 * parsed `IpAddr`, but a hostile one controls these bytes completely, and the
 * field lands in the approval sheet: without this, a relay could ship
 * "studio.local (verified)" and buy itself a verified look on the one screen
 * that authorizes a release. Anything outside the charset is dropped whole.
 *
 * No `%zone` suffix: Rust's `IpAddr` display never renders one, so accepting it
 * would widen the charset to arbitrary interface-name letters for a form the
 * relay cannot produce.
 */
const ORIGIN_IP_RE = /^[0-9a-fA-F.:]+$/;

/** The `/to-phone` GET response body. */
interface ToPhoneBody {
  envelopes: string[];
  /**
   * ADDITIVE, optional, index-aligned with `envelopes`: `origins[i]` describes
   * `envelopes[i]`, or is null where the relay has none. Absent entirely when no
   * delivered item carried one (always so before the relay stamped origins).
   */
  origins?: (RawOrigin | null)[] | null;
}

/** The wire shape of one origin (snake_case, as the relay serializes it). */
interface RawOrigin {
  ip?: unknown;
  at_ms?: unknown;
}

/** One drained item: the opaque envelope string plus the relay's claim about it. */
export interface Delivery {
  env: string;
  /** Present only when the relay sent a claim that passed {@link parseRelayOrigin}. */
  relayOrigin?: RelayOrigin;
}

/**
 * Validate one relay-asserted origin, returning `undefined` for anything not
 * plainly well-formed and current. FAIL QUIET, never fail closed: this is a
 * display hint, so a bad or stale claim costs the row and nothing else. It never
 * affects whether the envelope is delivered, opened, or approved.
 *
 * Rejects: a non-string or over-long `ip`, an `ip` outside the IP-literal
 * charset, a non-finite `at_ms`, a stamp older than {@link ORIGIN_MAX_AGE_MS},
 * and one further ahead than {@link ORIGIN_MAX_SKEW_MS}. None of this makes the
 * hint trustworthy: a hostile relay can still put a plausible address here. It
 * only stops the field from carrying free text or an unrelated moment into the
 * sheet.
 */
export function parseRelayOrigin(raw: unknown, now: number): RelayOrigin | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const { ip, at_ms: atMs } = raw as RawOrigin;
  if (typeof ip !== "string" || ip.length === 0 || ip.length > ORIGIN_IP_MAX_LEN) return undefined;
  if (!ORIGIN_IP_RE.test(ip)) return undefined;
  if (typeof atMs !== "number" || !Number.isFinite(atMs)) return undefined;
  if (atMs < now - ORIGIN_MAX_AGE_MS) return undefined;
  if (atMs > now + ORIGIN_MAX_SKEW_MS) return undefined;
  return { ip, atMs };
}

/** The structured outcome of one `to-phone` GET, so the loop can reason without throwing. */
interface PollResult {
  /** Drained payloads (empty when the hold expired with nothing waiting). */
  deliveries: Delivery[];
  /** HTTP status, or 0 for a network error / abort (no response). */
  status: number;
  /** `Retry-After` in ms if the server sent one (429/503), else null. */
  retryAfterMs: number | null;
  /** Wall-clock age of the GET, ms: how the loop tells a real hold from a fast return. */
  elapsedMs: number;
}

/** Injectable seams so {@link RelayMailbox.waitOne}'s timing/backoff is testable without real waits. */
export interface RelayMailboxDeps {
  fetch?: typeof fetch;
  now?: () => number;
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>;
  random?: () => number;
}

/**
 * At most ONE `waitOne` poll loop per mailbox slot, process-wide, keyed by the
 * `to-phone` URL. A second `waitOne` on the same slot (a React re-mount, a
 * duplicate subscription, even from a different {@link RelayMailbox} instance)
 * aborts the first before starting - two concurrent pollers on one slot are
 * exactly what triggers the relay's mutual-eviction ping-pong.
 */
const activeWaits = new Map<string, AbortController>();

/** Resolve after `ms`, or early if `signal` aborts. Never rejects. */
function realSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const timer = setTimeout(done, ms);
    const onAbort = () => done();
    function done(): void {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      resolve();
    }
    signal.addEventListener("abort", onAbort);
  });
}

/** Parse a `Retry-After` header (delta-seconds or HTTP-date) to ms, or null. */
function parseRetryAfter(headerValue: string | null, now: number): number | null {
  if (!headerValue) return null;
  const secs = Number(headerValue);
  if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
  const when = Date.parse(headerValue);
  if (!Number.isNaN(when)) return Math.max(0, when - now);
  return null;
}

/**
 * Normalize a relay base URL to an `http(s)` origin the fetch client can use.
 * The QR may carry a `ws(s)://` attach URL (a historical daemon-side rung);
 * map the scheme so the phone always speaks `http(s)`.
 */
export function normalizeRelayBase(url: string): string {
  const trimmed = url.trim().replace(/\/+$/, "");
  if (trimmed.startsWith("wss://")) return "https://" + trimmed.slice("wss://".length);
  if (trimmed.startsWith("ws://")) return "http://" + trimmed.slice("ws://".length);
  return trimmed;
}

/**
 * Pick the relay endpoint from a QR's endpoint list and normalize it. The daemon
 * carries its relay URL in `endpoints` (crates/sigil/src/pair.rs sets
 * `endpoints = [relay_url]`); a richer QR may also list `lan://` / `https://ddns`
 * rungs, so select the first http(s)/ws(s) entry. Throws if none is present.
 */
export function relayBaseFromEndpoints(endpoints: string[]): string {
  for (const e of endpoints) {
    if (/^(https?|wss?):\/\//.test(e.trim())) return normalizeRelayBase(e);
  }
  throw new Error("no relay endpoint in the pairing payload");
}

/** A client for one mailbox on the blind relay. */
export class RelayMailbox {
  private readonly base: string;
  private readonly mailboxHex: string;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly sleep: (ms: number, signal: AbortSignal) => Promise<void>;
  private readonly random: () => number;

  constructor(base: string, mailbox: Uint8Array, deps: RelayMailboxDeps = {}) {
    this.base = normalizeRelayBase(base);
    this.mailboxHex = toHex(mailbox);
    this.fetchImpl = deps.fetch ?? fetch;
    this.now = deps.now ?? Date.now;
    this.sleep = deps.sleep ?? realSleep;
    this.random = deps.random ?? Math.random;
  }

  private toDaemonUrl(): string {
    return `${this.base}/mailbox/${this.mailboxHex}/to-daemon`;
  }

  private toPhoneUrl(): string {
    return `${this.base}/mailbox/${this.mailboxHex}/to-phone`;
  }

  /** POST one opaque payload toward the daemon. Rejects on any non-2xx (fail closed). */
  async send(env: string): Promise<void> {
    const resp = await this.fetchImpl(this.toDaemonUrl(), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ env }),
    });
    if (!resp.ok) {
      throw new Error(`relay to-daemon: HTTP ${resp.status}`);
    }
  }

  /**
   * One `to-phone` GET, reported structurally instead of thrown, so the poll
   * loop can distinguish a genuine hold from a fast return / 429 / blip and
   * time it. Guards the GET with its own {@link FETCH_TIMEOUT_MS} abort and
   * with the caller's `signal` (so aborting the loop cancels an in-flight GET).
   */
  private async pollToPhone(signal: AbortSignal): Promise<PollResult> {
    const inner = new AbortController();
    const onOuterAbort = () => inner.abort();
    if (signal.aborted) inner.abort();
    else signal.addEventListener("abort", onOuterAbort);
    const timer = setTimeout(() => inner.abort(), FETCH_TIMEOUT_MS);
    const started = this.now();
    try {
      const resp = await this.fetchImpl(this.toPhoneUrl(), { method: "GET", signal: inner.signal });
      const elapsedMs = this.now() - started;
      if (!resp.ok) {
        const retryAfterMs = parseRetryAfter(resp.headers.get("retry-after"), this.now());
        return { deliveries: [], status: resp.status, retryAfterMs, elapsedMs };
      }
      const body = (await resp.json()) as ToPhoneBody;
      const envelopes = Array.isArray(body.envelopes) ? body.envelopes : [];
      // `origins` is index-aligned and entirely optional; a client that ignored
      // it would still be correct, so nothing here may throw or drop an
      // envelope. A missing, short, or malformed array simply yields no hint.
      const origins = Array.isArray(body.origins) ? body.origins : [];
      const now = this.now();
      const deliveries = envelopes.map((env) => ({ env }) as Delivery);
      deliveries.forEach((d, i) => {
        const o = parseRelayOrigin(origins[i], now);
        if (o) d.relayOrigin = o;
      });
      return { deliveries, status: resp.status, retryAfterMs: null, elapsedMs };
    } catch {
      // Network error, or an abort (loop cancel / fetch timeout): a fast,
      // payload-less return. The loop decides whether to back off or bail.
      return { deliveries: [], status: 0, retryAfterMs: null, elapsedMs: this.now() - started };
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", onOuterAbort);
    }
  }

  /**
   * GET and drain every queued payload for the mailbox (drain-on-read). This
   * is the single-shot long-poll call: the relay itself holds it open
   * server-side (up to ~25s) when the mailbox is empty. Throws on any non-2xx
   * or transport failure (fail closed), keeping the `relay to-phone:` prefix
   * its callers key error copy on. For a bounded, backing-off *wait*, use
   * {@link waitOne}; `drain` never loops or backs off on its own.
   *
   * Returns {@link Delivery} items rather than bare strings so the relay's
   * display-only origin hint can ride alongside its envelope without ever being
   * mixed into it.
   */
  async drain(): Promise<Delivery[]> {
    const controller = new AbortController();
    const r = await this.pollToPhone(controller.signal);
    if (r.status === 0) throw new Error("relay to-phone: request failed");
    if (r.status < 200 || r.status >= 300) throw new Error(`relay to-phone: HTTP ${r.status}`);
    return r.deliveries;
  }

  /**
   * Long-poll `to-phone` until one payload arrives or `timeoutMs` elapses, with
   * a MANDATORY floor between GETs so a fast return can never cause an instant
   * re-poll:
   *
   *   - A GET that actually held (empty, but >= {@link HELD_MIN_MS} old) is the
   *     healthy idle case: re-poll after only {@link HELD_FLOOR_MS} + jitter,
   *     and reset the backoff. Steady idle cost is ~one GET per hold (~25s).
   *   - A fast return - empty-but-quick (server eviction), a 429/5xx, or a
   *     network blip - did NOT hold: back off exponentially (base
   *     {@link BACKOFF_BASE_MS}, x2 per consecutive fast return, cap
   *     {@link BACKOFF_CAP_MS}) with additive jitter, honoring a `Retry-After`
   *     when the server sent one. A pathological storm settles to ~one GET per
   *     {@link BACKOFF_CAP_MS}; it is NEVER a >1/sec hammer.
   *
   * A 429/5xx is treated as such a fast return, not thrown - throwing would let
   * a retrying caller re-hammer. A hard relay outage therefore just backs off
   * quietly until `timeoutMs`, then returns `null` (fail closed, bounded).
   *
   * At most one loop per mailbox slot runs at a time (`activeWaits`): a second
   * `waitOne` on the same slot aborts the first, which then resolves `null`.
   *
   * Returns the first payload, or `null` once `timeoutMs` elapsed / the loop was
   * superseded. Extra payloads in a single drain are dropped here; the ceremony
   * this backs is strictly one-message-per-direction. The origin hint is dropped
   * too: this path is the pairing rendezvous, which has no approval sheet to
   * show it on.
   */
  async waitOne(timeoutMs: number): Promise<string | null> {
    const key = this.toPhoneUrl();
    // Dedupe: supersede any prior loop on this exact slot before starting.
    activeWaits.get(key)?.abort();
    const controller = new AbortController();
    activeWaits.set(key, controller);

    const deadline = this.now() + timeoutMs;
    let consecutiveFast = 0;
    try {
      for (;;) {
        if (controller.signal.aborted) return null;
        const r = await this.pollToPhone(controller.signal);
        if (controller.signal.aborted) return null;
        if (r.deliveries.length > 0) return r.deliveries[0]?.env ?? null;
        if (this.now() >= deadline) return null;

        const held = r.status >= 200 && r.status < 300 && r.elapsedMs >= HELD_MIN_MS;
        let delay: number;
        if (held) {
          // The hold worked; nothing waiting. Re-poll promptly, backoff reset.
          consecutiveFast = 0;
          delay = HELD_FLOOR_MS + this.random() * HELD_FLOOR_MS;
        } else {
          // A fast return: escalate so consecutive ones can never hammer.
          consecutiveFast += 1;
          const exp = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** (consecutiveFast - 1));
          const floor = r.retryAfterMs ?? exp;
          delay = floor + this.random() * JITTER_MS;
        }

        // Never sleep past the ceremony deadline.
        const remaining = deadline - this.now();
        if (remaining <= 0) return null;
        await this.sleep(Math.min(delay, remaining), controller.signal);
      }
    } finally {
      if (activeWaits.get(key) === controller) activeWaits.delete(key);
    }
  }
}
