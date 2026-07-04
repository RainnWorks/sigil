/**
 * The blind relay's HTTPS contract, as the phone speaks it. One mailbox, two
 * opaque endpoints, exactly matching relay/shared/protocol.ts and the Rust
 * clients (crates/relay-client phone_http.rs / rendezvous.rs):
 *
 *   POST /mailbox/{id}/submit   body = one opaque string   (enqueue toDaemon)
 *   GET  /mailbox/{id}/pending  -> { envelopes: string[] } (drain toPhone)
 *
 * The relay never parses the payload; it is a UTF-8 string in one side and out
 * the other. The steady-state {@link PhoneRelay} and the pairing rendezvous both
 * layer on this: the only difference is what the opaque string is (a sealed
 * envelope's JSON, or a base64url PairingResponse).
 */
import { toHex } from "@/src/protocol";

/** The `/pending` response body (`RESP.pending`). `depth` is advisory. */
interface PendingBody {
  envelopes: string[];
  depth: number;
}

/**
 * Normalize a relay base URL to an http(s) origin the fetch client can use. The
 * QR may carry a `ws(s)://` attach URL (the daemon dials the relay over a
 * WebSocket); the phone always polls over http(s), so map the schemes. Mirrors
 * the inverse of the Rust `attach_url`.
 */
export function normalizeRelayBase(url: string): string {
  const trimmed = url.trim().replace(/\/+$/, "");
  if (trimmed.startsWith("wss://")) return "https://" + trimmed.slice("wss://".length);
  if (trimmed.startsWith("ws://")) return "http://" + trimmed.slice("ws://".length);
  return trimmed;
}

/**
 * Pick the relay endpoint from a QR's endpoint list and normalize it. The daemon
 * carries its relay URL in `endpoints` (crates/latch/src/pair.rs sets
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

  private submitUrl(): string {
    return `${this.base}/mailbox/${this.mailboxHex}/submit`;
  }

  private pendingUrl(): string {
    return `${this.base}/mailbox/${this.mailboxHex}/pending`;
  }

  /** POST one opaque payload. Rejects on any non-2xx (fail closed). */
  async submit(payload: string): Promise<void> {
    const resp = await fetch(this.submitUrl(), {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: payload,
    });
    if (!resp.ok) {
      throw new Error(`relay submit: HTTP ${resp.status}`);
    }
  }

  /** GET and drain every queued payload for the mailbox (drain-on-read). */
  async pending(): Promise<string[]> {
    const resp = await fetch(this.pendingUrl(), { method: "GET" });
    if (!resp.ok) {
      throw new Error(`relay pending: HTTP ${resp.status}`);
    }
    const body = (await resp.json()) as PendingBody;
    return Array.isArray(body.envelopes) ? body.envelopes : [];
  }

  /**
   * Poll `/pending` until one payload arrives or `timeoutMs` elapses, sleeping
   * `intervalMs` between empty polls. Returns the first payload, or `null` on
   * timeout. Extra payloads in a single drain are returned on later calls only
   * for the ceremony's strictly-one-per-direction use; the caller decides.
   */
  async waitOne(timeoutMs: number, intervalMs = 400): Promise<string | null> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const batch = await this.pending();
      if (batch.length > 0) return batch[0] ?? null;
      if (Date.now() >= deadline) return null;
      await sleep(Math.min(intervalMs, Math.max(0, deadline - Date.now())));
    }
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
