/**
 * The sealed, signed envelope, mirroring crates/proto/src/envelope.rs. It is
 * the only thing Latch ever puts on a wire; a relay or any hop sees only this.
 *
 * Sealed with crypto_box (X25519 + XSalsa20-Poly1305) to the pinned recipient
 * agreement key using a fresh per-envelope ephemeral (forward secrecy), signed
 * with Ed25519 by the pinned sender over the canonical bytes below, and
 * replay-protected by a single-use uuidv7 id + monotonic counter + timestamp.
 *
 * `canonicalBytes` MUST be byte-identical to the Rust `canonical_bytes`: the
 * signature covers exactly these length-prefixed fields in this order.
 */
import { parse as uuidParse, v7 as uuidv7 } from "uuid";

import { concatBytes, u64be } from "./bytes";
import { type PeerIdentity } from "./identity";
import { REPLAY_WINDOW_MS, type ReplayGuard } from "./replay";
import { type Sodium } from "./sodium";

export interface Envelope {
  /** Mailbox / pairing id. Routing only; carries no identity. 32 bytes. */
  pairingId: Uint8Array;
  /** Single-use uuidv7 string. Terminal once answered or expired. */
  requestId: string;
  /** Per-pairing, per-direction monotonic counter. */
  counter: number;
  /** Sender wall clock, unix ms. Bounded by the replay window. */
  ts: number;
  /** Fresh X25519 ephemeral public key for this envelope. 32 bytes. */
  ephemeralPub: Uint8Array;
  /** crypto_box nonce. 24 bytes. */
  nonce: Uint8Array;
  /** crypto_box ciphertext of the JSON payload. */
  ciphertext: Uint8Array;
  /** Ed25519 signature over the canonical bytes. 64 bytes. */
  sig: Uint8Array;
}

export type OpenError =
  | { kind: "badSignature" }
  | { kind: "replay"; message: string }
  | { kind: "decrypt" }
  | { kind: "deserialize" };

export class EnvelopeOpenError extends Error {
  constructor(readonly detail: OpenError) {
    super(detail.kind === "replay" ? detail.message : detail.kind);
    this.name = "EnvelopeOpenError";
  }
}

/**
 * Canonical byte string the signature covers. Length-prefixed fields so no two
 * distinct envelopes can share a canonical form. Order and widths match Rust.
 */
export function canonicalBytes(e: Omit<Envelope, "sig">): Uint8Array {
  const reqBytes = uuidParse(e.requestId) as Uint8Array;
  return concatBytes(
    e.pairingId,
    reqBytes,
    u64be(e.counter),
    u64be(e.ts),
    e.ephemeralPub,
    e.nonce,
    u64be(e.ciphertext.length),
    e.ciphertext,
  );
}

export interface SealParams {
  pairingId: Uint8Array;
  counter: number;
  /** Ed25519 secret key (64-byte libsodium form) of the pinned sender. */
  senderSigningSecret: Uint8Array;
  /** The pinned recipient's public identity. */
  recipient: PeerIdentity;
  /** Optional clock injection for deterministic vectors; defaults to now. */
  now?: number;
}

/** Seal a JSON-serializable payload into an envelope for the pinned recipient. */
export function seal<T>(sodium: Sodium, payload: T, params: SealParams): Envelope {
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));

  const ephemeral = sodium.crypto_box_keypair();
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  const ciphertext = sodium.crypto_box_easy(
    plaintext,
    nonce,
    params.recipient.agreement,
    ephemeral.privateKey,
  );

  const unsigned: Omit<Envelope, "sig"> = {
    pairingId: params.pairingId,
    requestId: uuidv7(),
    counter: params.counter,
    ts: params.now ?? Date.now(),
    ephemeralPub: ephemeral.publicKey,
    nonce,
    ciphertext,
  };
  const sig = sodium.crypto_sign_detached(
    canonicalBytes(unsigned),
    params.senderSigningSecret,
  );
  return { ...unsigned, sig };
}

export interface OpenParams {
  /** The pinned sender's public identity. */
  sender: PeerIdentity;
  /** This device's X25519 secret key. */
  recipientAgreementSecret: Uint8Array;
  guard: ReplayGuard;
  now?: number;
}

/**
 * Verify (signature first), replay-check, then decrypt. Order is load-bearing
 * and matches Rust: forgeries are rejected before the guard mutates state.
 */
export function open<T>(sodium: Sodium, e: Envelope, params: OpenParams): T {
  // 1. Authenticity.
  const ok = sodium.crypto_sign_verify_detached(
    e.sig,
    canonicalBytes(e),
    params.sender.verifying,
  );
  if (!ok) throw new EnvelopeOpenError({ kind: "badSignature" });

  // 2. Freshness and single use.
  try {
    params.guard.checkAndRecord(
      e.requestId,
      e.counter,
      e.ts,
      params.now ?? Date.now(),
      REPLAY_WINDOW_MS,
    );
  } catch (err) {
    throw new EnvelopeOpenError({
      kind: "replay",
      message: err instanceof Error ? err.message : String(err),
    });
  }

  // 3. Confidentiality.
  let plaintext: Uint8Array;
  try {
    plaintext = sodium.crypto_box_open_easy(
      e.ciphertext,
      e.nonce,
      e.ephemeralPub,
      params.recipientAgreementSecret,
    );
  } catch {
    throw new EnvelopeOpenError({ kind: "decrypt" });
  }

  try {
    return JSON.parse(new TextDecoder().decode(plaintext)) as T;
  } catch {
    throw new EnvelopeOpenError({ kind: "deserialize" });
  }
}
