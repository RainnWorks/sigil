/**
 * JSON wire encoding for the envelope, shaped to match `serde_json` output of
 * the Rust `Envelope` so the two sides interoperate over the real transport:
 * fixed byte arrays serialize as arrays of numbers, `request_id` as a uuid
 * string, `sig` as a 64-number array. Tracks crates/sigil-proto; a shared vector
 * pins it (see vectors.contract.ts).
 *
 * The mock transport uses these too, so the dev loop exercises the exact codec
 * the daemon will speak.
 */
import { type Envelope } from "./envelope";

export interface EnvelopeWire {
  pairing_id: number[];
  request_id: string;
  counter: number;
  ts: number;
  ephemeral_pub: number[];
  nonce: number[];
  ciphertext: number[];
  sig: number[];
}

const arr = (b: Uint8Array): number[] => Array.from(b);

export function envelopeToWire(e: Envelope): EnvelopeWire {
  return {
    pairing_id: arr(e.pairingId),
    request_id: e.requestId,
    counter: e.counter,
    ts: e.ts,
    ephemeral_pub: arr(e.ephemeralPub),
    nonce: arr(e.nonce),
    ciphertext: arr(e.ciphertext),
    sig: arr(e.sig),
  };
}

export function envelopeFromWire(w: EnvelopeWire): Envelope {
  return {
    pairingId: Uint8Array.from(w.pairing_id),
    requestId: w.request_id,
    counter: w.counter,
    ts: w.ts,
    ephemeralPub: Uint8Array.from(w.ephemeral_pub),
    nonce: Uint8Array.from(w.nonce),
    ciphertext: Uint8Array.from(w.ciphertext),
    sig: Uint8Array.from(w.sig),
  };
}
