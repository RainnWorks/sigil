/**
 * The single libsodium binding seam. Everything cryptographic in the protocol
 * layer goes through the `Sodium` interface below, so swapping the concrete
 * binding is a one-line change here and nowhere else.
 *
 * Two bindings, one API surface:
 *   - dev / CI / this file's default: `libsodium-wrappers` (pure JS/WASM, runs
 *     in Node, so the shared test vectors execute in CI with no simulator).
 *   - device build: `react-native-libsodium`, which exposes the same
 *     `crypto_*` functions and constants (a near drop-in). To ship on device,
 *     change the dynamic import in `loadSodium` to "react-native-libsodium".
 *
 * NEEDS VERIFICATION: react-native-libsodium is a native module and is NOT in
 * Expo Go. It requires a development build (`expo run:ios` / EAS dev client).
 * Confirm the installed version exposes crypto_box_easy, crypto_sign_detached,
 * crypto_sign_seed_keypair, crypto_generichash and crypto_box_seed_keypair with
 * the libsodium-wrappers signatures; the seam assumes they match. (Note:
 * react-native-libsodium does NOT export crypto_scalarmult_base, so the
 * agreement keypair is derived from a seed via crypto_box_seed_keypair, which
 * both bindings do export — see identity.ts.)
 *
 * The algorithms this maps onto crates/proto:
 *   crypto_box_easy        = crypto_box crate SalsaBox (X25519 + XSalsa20-Poly1305)
 *   crypto_sign_detached   = ed25519-dalek signature over canonical bytes
 *   crypto_generichash(64) = Blake2b512, unkeyed (fingerprint + mailbox id)
 */

export interface SodiumKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface Sodium {
  randombytes_buf(length: number): Uint8Array;

  crypto_box_easy(
    message: Uint8Array,
    nonce: Uint8Array,
    publicKey: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array;
  crypto_box_open_easy(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    publicKey: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array;
  crypto_box_keypair(): SodiumKeyPair;
  /**
   * Derive an X25519 agreement keypair deterministically from a 32-byte seed.
   * Present in both bindings (unlike crypto_scalarmult_base, which
   * react-native-libsodium omits), so this is how a stored device identity turns
   * its persisted seed into a stable public/secret agreement pair.
   */
  crypto_box_seed_keypair(seed: Uint8Array): SodiumKeyPair;

  crypto_sign_seed_keypair(seed: Uint8Array): SodiumKeyPair;
  crypto_sign_detached(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): boolean;

  /**
   * BLAKE2b. Unkeyed when `key` is omitted (fingerprint, mailbox id, pairing
   * transcript); keyed when `key` is given, which is a first-class PRF and is
   * how crates/proto's pairing handshake derives its subkey and confirmation
   * MAC (the Rust `Blake2bMac`). Both bindings accept the optional key with an
   * identical signature.
   */
  crypto_generichash(hashLength: number, message: Uint8Array, key?: Uint8Array | null): Uint8Array;

  readonly crypto_box_NONCEBYTES: number;
  readonly crypto_box_PUBLICKEYBYTES: number;
  readonly crypto_box_SECRETKEYBYTES: number;
  readonly crypto_box_SEEDBYTES: number;
  readonly crypto_sign_SEEDBYTES: number;
}

let cached: Sodium | null = null;

/**
 * Inject an already-resolved binding. The Node test loader uses this (the
 * libsodium-wrappers ESM entry does not resolve under Bun, so tests require the
 * CJS build); on device you may also call this once at startup with
 * react-native-libsodium if you prefer eager init over `loadSodium`.
 */
export function setSodium(s: Sodium): void {
  cached = s;
}

/**
 * Resolve the device binding once and reuse it. Await before any crypto call.
 * Uses react-native-libsodium, whose API mirrors libsodium-wrappers exactly
 * (same function names, same `.ready` promise). The Node test scripts do not
 * call this; they inject libsodium-wrappers via setSodium (see sodium-node.ts),
 * so the pure-JS test binding never enters the app bundle.
 */
export async function loadSodium(): Promise<Sodium> {
  if (cached) return cached;
  const mod = await import("react-native-libsodium");
  const s = (mod as { default?: unknown }).default ?? mod;
  await (s as { ready: Promise<void> }).ready;
  cached = s as unknown as Sodium;
  return cached;
}
