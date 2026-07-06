/**
 * The blind relay's v4 HTTP contract, as the phone speaks it. One mailbox, two
 * opaque endpoints, exactly matching relay/shared/protocol.ts and the Rust
 * clients (crates/relay-client):
 *
 *   GET  /mailbox/{id}/to-phone    -> { envelopes: string[] }  (long-poll, drain-on-read)
 *   POST /mailbox/{id}/to-daemon   body { "env": "<opaque>" }  (deposit)
 *
 * `to-phone` (and the daemon's mirror `to-daemon` GET) LONG-POLLS: an empty
 * mailbox holds the request open server-side until a deposit lands or the
 * relay's own ~25s timeout, then returns (with or without envelopes) either
 * way. The doorbell is the whole point of this transport, so the phone never
 * sleep-polls; it just issues sequential GETs and lets the relay do the
 * waiting (see `FETCH_TIMEOUT_MS` below and {@link RelayMailbox.waitOne}).
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
import { toHex } from "@/src/protocol";

/**
 * Client-side ceiling on one `to-phone` GET, comfortably above the relay's
 * own ~25s server-side hold so a normal long-poll never gets aborted
 * mid-hold; only a relay that hangs past its own timeout trips this.
 */
const FETCH_TIMEOUT_MS = 30_000;

/** The `/to-phone` GET response body. */
interface ToPhoneBody {
  envelopes: string[];
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

  constructor(base: string, mailbox: Uint8Array) {
    this.base = normalizeRelayBase(base);
    this.mailboxHex = toHex(mailbox);
  }

  private toDaemonUrl(): string {
    return `${this.base}/mailbox/${this.mailboxHex}/to-daemon`;
  }

  private toPhoneUrl(): string {
    return `${this.base}/mailbox/${this.mailboxHex}/to-phone`;
  }

  /** POST one opaque payload toward the daemon. Rejects on any non-2xx (fail closed). */
  async send(env: string): Promise<void> {
    const resp = await fetch(this.toDaemonUrl(), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ env }),
    });
    if (!resp.ok) {
      throw new Error(`relay to-daemon: HTTP ${resp.status}`);
    }
  }

  /**
   * GET and drain every queued payload for the mailbox (drain-on-read). This
   * is the long-poll call: the relay itself holds it open server-side (up to
   * ~25s) when the mailbox is empty, so one call already waits - callers
   * never need their own sleep on top of it. `FETCH_TIMEOUT_MS` only guards
   * against the relay hanging past its own timeout.
   */
  async drain(): Promise<string[]> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const resp = await fetch(this.toPhoneUrl(), { method: "GET", signal: controller.signal });
      if (!resp.ok) {
        throw new Error(`relay to-phone: HTTP ${resp.status}`);
      }
      const body = (await resp.json()) as ToPhoneBody;
      return Array.isArray(body.envelopes) ? body.envelopes : [];
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Long-poll `to-phone` until one payload arrives or `timeoutMs` elapses.
   * Each `drain()` call already blocks server-side while the mailbox is
   * empty, so this just re-issues sequential GETs with no client sleep
   * between them - the relay does the waiting. Returns the first payload, or
   * `null` once `timeoutMs` has elapsed with nothing delivered. Extra
   * payloads in a single drain are returned on later calls only, for the
   * ceremony's strictly-one-per-direction use; the caller decides.
   */
  async waitOne(timeoutMs: number): Promise<string | null> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const batch = await this.drain();
      if (batch.length > 0) return batch[0] ?? null;
      if (Date.now() >= deadline) return null;
    }
  }
}
