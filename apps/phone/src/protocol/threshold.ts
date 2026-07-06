/**
 * The v2 threshold combiner, mirroring crates/proto/src/threshold.rs
 * byte-for-byte. Decryption is a 2-of-2 AND of two independent P-256 ECDH
 * secrets combined by a KDF; this module is the KDF (`combine`) and the ECDH
 * output shaping (`shapeEcdh`), the two pieces the phone shares with the daemon.
 *
 *   Z_M = x(m·E)      the Mac's partial (daemon-side, software P-256)
 *   Z_F = x(f·E)      the phone's partial (Secure Enclave, under Face ID)
 *   K   = BLAKE2b-256( "latch.threshold.v2" ‖ len·Z_M ‖ len·Z_F ‖ len·E_x963 ‖ len·account_id )
 *
 * On device the phone only ever produces `Z_F` (see session/threshold-se.ts) and
 * hands it to the daemon, which runs `combine` and opens the token. `combine`
 * lives here too because it is the shared crypto core the interop vectors lock:
 * `verify-vectors.ts` replays the Rust `combiner` category through this TS.
 *
 * KDF encoding, pinned:
 *   - `THRESHOLD_DOMAIN` is a raw leading constant, NO length prefix;
 *   - every subsequent field is absorbed as big-endian u64 length ‖ bytes;
 *   - `E` is the canonical ANSI X9.63 uncompressed form (0x04‖X‖Y, 65 bytes);
 *   - digest width is 32 bytes; the libsodium mirror is
 *     `crypto_generichash(outlen = 32, msg)`.
 */
import { concatBytes, u32be, u64be } from "./bytes";
import { type EcdhAlgo } from "./requests";
import { type Sodium } from "./sodium";

/** Domain separator folded into every combiner hash. Matches Rust THRESHOLD_DOMAIN. */
export const THRESHOLD_DOMAIN: Uint8Array = new TextEncoder().encode("latch.threshold.v2");

/** Combiner identifier persisted in a record's `kdfAlgo`. */
export const KDF_ALGO_ID = "blake2b-v2";

/** The only at-rest record version the v2 path decrypts (R3: no downgrade). */
export const THRESHOLD_RECORD_VERSION = 2;

export const P256_X963_POINT_LEN = 65;
export const XCOORD_LEN = 32;
export const KEY_LEN = 32;

/** Length-prefix `field` (big-endian u64), the injective absorb the combiner uses. */
function absorb(field: Uint8Array): Uint8Array {
  return concatBytes(u64be(field.length), field);
}

/**
 * The combiner. Derive the 32-byte token key `K` from the two shaped ECDH
 * partials plus the account's public base `E` (x963) and id. `zm` and `zf` are
 * already in their final combiner-input shape (the caller/SE shapes them).
 */
export function combine(
  sodium: Sodium,
  zm: Uint8Array,
  zf: Uint8Array,
  eX963: Uint8Array,
  accountId: string,
): Uint8Array {
  const msg = concatBytes(
    THRESHOLD_DOMAIN,
    absorb(zm),
    absorb(zf),
    absorb(eX963),
    absorb(new TextEncoder().encode(accountId)),
  );
  return sodium.crypto_generichash(KEY_LEN, msg);
}

/**
 * Apply the record's ECDH-output shaping to a raw 32-byte X-coordinate, mirroring
 * Rust `shape()`. For "raw-x" this is the identity; for "x963-sha256" it is
 * Apple's ANSI-X9.63 SHA-256 KDF producing 32 bytes:
 * `SHA256(Z ‖ 0x00000001 ‖ sharedInfo=E_x963)` (32 bytes fit one block, so the
 * counter never advances).
 *
 * On device the authoritative shaping is CryptoKit's `x963DerivedSymmetricKey`
 * (see session/threshold-se.ts); this is the TS reference the combiner vectors
 * lock. NV-7: the exact x963 `sharedInfo` the SE applies to a *bare*
 * key-agreement must be confirmed on device and pinned to match this.
 */
export function shapeEcdh(
  sodium: Sodium,
  rawX: Uint8Array,
  algo: EcdhAlgo,
  eX963: Uint8Array,
): Uint8Array {
  if (algo === "raw-x") return rawX;
  return sodium.crypto_hash_sha256(concatBytes(rawX, u32be(1), eX963));
}

/**
 * A cheap structural precheck of an X9.63 P-256 point before it reaches the
 * on-curve validator. R2/NV-6: the LOAD-BEARING check is native
 * (CryptoKit `P256.KeyAgreement.PublicKey(x963Representation:)`, which rejects
 * off-curve/twist points); this only rules out obvious malformed input early and
 * never substitutes for it. Also rejects the all-zero identity encoding.
 */
export function looksLikeX963P256(bytes: Uint8Array): boolean {
  if (bytes.length !== P256_X963_POINT_LEN || bytes[0] !== 0x04) return false;
  for (let i = 1; i < bytes.length; i++) {
    if (bytes[i] !== 0) return true;
  }
  return false;
}

