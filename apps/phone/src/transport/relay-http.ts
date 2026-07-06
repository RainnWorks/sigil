/**
 * Relay base URL handling, shared by both consumers of the blind relay: the
 * steady-state {@link AttachSocket} (`relay-attach.ts`) and the pairing
 * ceremony's rendezvous attach (`src/session/pairing-flow.ts`). v3 dropped the
 * relay's HTTP mailbox surface entirely (no more `/submit`/`/pending`); both
 * sides now speak `ws(s)://.../attach/{mailbox_id_hex}` (see
 * `relay-attach.ts`), so this module's only remaining job is turning the QR's
 * endpoint list into one normalized `http(s)` base for storage and display,
 * from which `attachUrl` derives the `ws(s)` form.
 */

/**
 * Normalize a relay base URL to an `http(s)` origin. The QR may carry a
 * `ws(s)://` attach URL (the daemon dials the relay over a WebSocket); this
 * phone stores and displays the base as `http(s)`, mapping the scheme. Mirrors
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
