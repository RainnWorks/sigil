/**
 * The pairing handshake's phone half, mirroring crates/sigil-proto/src/pairing.rs
 * byte-for-byte. The QR (message 0) is decoded by pairing.ts; this module builds
 * the phone's authenticated reply (message 1, `PairingResponse`) and derives the
 * rendezvous mailbox both parties route pairing traffic on before the phone key
 * is pinned.
 *
 * The security seam this fills: the phone proves it holds the one-time pairing
 * secret from the optically-scanned QR by MACing a transcript that binds the QR
 * contents *and* the phone's freshly minted identity. A network man-in-the-middle
 * that swaps the phone's key cannot recompute the MAC (it never saw the secret),
 * so key substitution on the return channel is rejected by the daemon.
 *
 * Crypto rules, matching proto exactly:
 *   - BLAKE2b for both the KDF and the MAC (no SHA-256 / HKDF / HMAC). The subkey
 *     is keyed BLAKE2b over `domain || label`; the tag is keyed BLAKE2b over the
 *     transcript. `crypto_generichash(32, msg, key)` is that keyed PRF.
 *   - The transcript is unkeyed BLAKE2b-512 truncated to 32 bytes, length-prefix
 *     framed identically to `pairing_transcript`.
 *   - No HKDF-Extract: the secret is a 256-bit CSPRNG value, already uniform.
 */
import { concatBytes, toBase64Url, u64be } from "./bytes";
import { type PeerIdentity } from "./identity";
import { type PairingPayload } from "./pairing";
import { type Sodium } from "./sodium";

const enc = new TextEncoder();

/** Domain separation for everything the pairing handshake hashes or MACs. */
const PAIRING_DOMAIN = enc.encode("sigil.pairing.v1");
/** Domain for the pairing rendezvous mailbox (message 1 and 3 transport). */
const RENDEZVOUS_DOMAIN = enc.encode("sigil.pairing.rendezvous.v1");
/** Label deriving the confirmation-MAC subkey from the pairing secret. */
const SUBKEY_CONFIRM_LABEL = enc.encode("confirm-tag");

/**
 * Length-prefix `field` (u64 big-endian length, then the bytes) so no two
 * distinct field sequences can share a hash input. Mirrors proto's `absorb`.
 */
function absorb(parts: Uint8Array[], field: Uint8Array): void {
  parts.push(u64be(field.length));
  parts.push(field);
}

/**
 * The bootstrap mailbox both parties route pairing messages on, before the
 * phone's key is pinned. Derived from the daemon's pinned identity and the
 * one-time secret, both carried in the QR, so only a party holding the scanned
 * QR can compute it. Distinct domain from the steady-state `mailboxId`, so
 * pairing traffic and approval traffic never share a queue.
 *
 * Mirrors `proto::rendezvous_mailbox`: `BLAKE2b-512(domain || absorb(verifying)
 * || absorb(agreement) || absorb(secret))[..32]`. The domain is fed raw (not
 * length-prefixed); the three fields are length-prefixed.
 */
export function rendezvousMailbox(
  sodium: Sodium,
  daemon: PeerIdentity,
  secret: Uint8Array,
): Uint8Array {
  const parts: Uint8Array[] = [RENDEZVOUS_DOMAIN];
  absorb(parts, daemon.verifying);
  absorb(parts, daemon.agreement);
  absorb(parts, secret);
  const digest = sodium.crypto_generichash(64, concatBytes(...parts));
  return digest.slice(0, 32);
}

/**
 * The transcript both sides bind the confirmation MAC to. Commits to every QR
 * field except the secret (the secret is the MAC key, not signed), plus the
 * phone identity and a fresh nonce. Unkeyed BLAKE2b-512 truncated to 32 bytes.
 *
 * Exported (only) for the shared-vector harness (verify-vectors.ts), which
 * checks this intermediate value byte-for-byte against crates/sigil-proto's
 * `pairing_transcript` before checking the final tag - the same cross-language
 * lock that would have caught the camelCase `seSharePub` bug in CI. Production
 * code never calls this directly; it goes through `buildPairingResponse(WithNonce)`.
 */
export function pairingTranscript(
  sodium: Sodium,
  daemon: PeerIdentity,
  endpoints: string[],
  createdAt: number,
  phone: PeerIdentity,
  nonce: Uint8Array,
  seSharePub?: string,
): Uint8Array {
  const parts: Uint8Array[] = [PAIRING_DOMAIN];
  absorb(parts, daemon.verifying);
  absorb(parts, daemon.agreement);
  parts.push(u64be(endpoints.length));
  for (const e of endpoints) absorb(parts, enc.encode(e));
  parts.push(u64be(createdAt));
  absorb(parts, phone.verifying);
  absorb(parts, phone.agreement);
  absorb(parts, nonce);
  // v2: bind the phone's Secure-Enclave threshold share `F` (se_share_pub) into
  // the same MAC that pins the phone's identity, so a relay cannot swap or strip
  // it without the pairing secret. Absorbed ONLY when present, so a v1 response
  // hashes byte-identically to before. The base64 STRING bytes are bound verbatim
  // (mirrors proto `pairing_transcript`); on-curve validation happens at pin.
  if (seSharePub !== undefined) absorb(parts, enc.encode(seSharePub));
  const digest = sodium.crypto_generichash(64, concatBytes(...parts));
  return digest.slice(0, 32);
}

/**
 * Derive a purpose-specific 32-byte subkey from the pairing secret:
 * `K_purpose = BLAKE2bMac(key = secret, msg = domain || label)`.
 */
function deriveSubkey(sodium: Sodium, secret: Uint8Array, label: Uint8Array): Uint8Array {
  return sodium.crypto_generichash(32, concatBytes(PAIRING_DOMAIN, label), secret);
}

/** `tag = BLAKE2bMac(key = K_confirm, msg = transcript)`. */
function confirmationTag(sodium: Sodium, kConfirm: Uint8Array, transcript: Uint8Array): Uint8Array {
  return sodium.crypto_generichash(32, transcript, kConfirm);
}

/**
 * The phone's authenticated reply to a scanned QR (message 1, phone -> Mac).
 * `phone` is pinned by the daemon; `tag` proves the sender held the secret and
 * is binding exactly this identity to this QR; `nonce` makes the reply one-shot.
 */
export interface PairingResponse {
  phone: PeerIdentity;
  nonce: Uint8Array;
  tag: Uint8Array;
  /**
   * The phone's v2 threshold share `F = f·G`, ANSI X9.63 uncompressed (65 bytes),
   * STANDARD base64. Present only for a v2 pairing; a v1 phone omits it. Bound
   * into {@link tag} via the transcript, so a relay cannot swap or strip it.
   */
  seSharePub?: string;
}

/** The serde form the daemon deserializes (byte arrays as number arrays). */
interface PairingResponseJson {
  phone: { verifying: number[]; agreement: number[] };
  nonce: number[];
  tag: number[];
  /**
   * Mirrors proto `se_share_pub`. proto's PairingResponse is
   * `#[serde(rename_all = "camelCase")]` with `#[serde(default,
   * skip_serializing_if = "Option::is_none")]`, so the WIRE key is `seSharePub`
   * and the field is omitted entirely when absent.
   */
  seSharePub?: string;
}

/**
 * Build the response with a caller-supplied nonce. Used by the shared-vector
 * parity harness (fixed nonce => reproducible tag); production code calls
 * {@link buildPairingResponse}, which supplies a fresh CSPRNG nonce. `seSharePub`
 * is the optional v2 threshold share `F` (standard base64 x963) to pin.
 */
export function buildPairingResponseWithNonce(
  sodium: Sodium,
  payload: PairingPayload,
  phone: PeerIdentity,
  nonce: Uint8Array,
  seSharePub?: string,
): PairingResponse {
  const kConfirm = deriveSubkey(sodium, payload.secret, SUBKEY_CONFIRM_LABEL);
  const transcript = pairingTranscript(
    sodium,
    payload.daemon,
    payload.endpoints,
    payload.createdAt,
    phone,
    nonce,
    seSharePub,
  );
  const tag = confirmationTag(sodium, kConfirm, transcript);
  return seSharePub !== undefined ? { phone, nonce, tag, seSharePub } : { phone, nonce, tag };
}

/**
 * Build the phone's authenticated response to a scanned `payload`. A fresh
 * 256-bit nonce is drawn per response, matching proto's `PairingResponse::build`
 * (the phone emits exactly one response per scan). `seSharePub` is the optional
 * v2 threshold share `F` (standard base64 x963) to bind and deliver.
 */
export function buildPairingResponse(
  sodium: Sodium,
  payload: PairingPayload,
  phone: PeerIdentity,
  seSharePub?: string,
): PairingResponse {
  const nonce = sodium.randombytes_buf(32);
  return buildPairingResponseWithNonce(sodium, payload, phone, nonce, seSharePub);
}

/** The serde JSON the daemon expects (matches `serde_json::to_vec(&resp)`). */
export function pairingResponseToJson(resp: PairingResponse): PairingResponseJson {
  const json: PairingResponseJson = {
    phone: {
      verifying: Array.from(resp.phone.verifying),
      agreement: Array.from(resp.phone.agreement),
    },
    nonce: Array.from(resp.nonce),
    tag: Array.from(resp.tag),
  };
  // Omit when absent, mirroring proto's skip_serializing_if = Option::is_none, so
  // a v1 response serializes byte-identically to before.
  if (resp.seSharePub !== undefined) json.seSharePub = resp.seSharePub;
  return json;
}

/**
 * The exact string the phone POSTs to the rendezvous mailbox's `/submit`:
 * base64url(JSON) with no padding, the form `sigil pair`'s daemon decodes first
 * (raw JSON is its fallback). See crates/sigil/src/pair.rs `decode_response`.
 */
export function pairingResponseToSubmitString(resp: PairingResponse): string {
  const json = JSON.stringify(pairingResponseToJson(resp));
  return toBase64Url(enc.encode(json));
}

/** Raised when a delivered DEK envelope does not decrypt to 32 raw key bytes. */
export class DekRecoverError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DekRecoverError";
  }
}

/**
 * Recover the 32-byte DEK from an opened DEK-delivery envelope. The daemon seals
 * a `Dek` (a `[u8; 32]` newtype) as the envelope payload, so `open` yields a
 * JSON array of 32 numbers. Fails closed on any other shape: a malformed DEK
 * yields an error, never a partial key.
 */
export function recoverDek(payload: unknown): Uint8Array {
  if (!Array.isArray(payload) || payload.length !== 32) {
    throw new DekRecoverError("DEK payload is not a 32-byte array");
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const b = payload[i];
    if (typeof b !== "number" || !Number.isInteger(b) || b < 0 || b > 255) {
      throw new DekRecoverError("DEK payload has a non-byte element");
    }
    out[i] = b;
  }
  return out;
}
