/**
 * Device identities, mirroring crates/sigil-proto/src/identity.rs.
 *
 * A device holds an Ed25519 signing key and an X25519 agreement key. On a real
 * phone the private halves live in the Secure Enclave and never surface here;
 * this module models the shapes and the in-memory operations used by the mock
 * transport, dev builds, and the shared test vectors.
 *
 * `PeerIdentity` is the public half exchanged at pairing and pinned forever.
 */
import { type Sodium } from "./sodium";

export interface PeerIdentity {
  /** Ed25519 verifying key, 32 bytes. */
  verifying: Uint8Array;
  /** X25519 public key, 32 bytes. */
  agreement: Uint8Array;
}

export interface DeviceIdentity {
  /** Ed25519 seed, 32 bytes (the dalek `SigningKey`). */
  signingSeed: Uint8Array;
  /**
   * X25519 agreement seed, 32 bytes. The agreement keypair is derived
   * deterministically from it via `crypto_box_seed_keypair`, so the identity is
   * stable across launches from just this stored material. We store the seed
   * (not the raw secret) because `crypto_box_seed_keypair` is present in both
   * bindings, whereas `crypto_scalarmult_base` — the obvious way to turn a raw
   * secret into its public half — is not exported by react-native-libsodium.
   */
  agreementSeed: Uint8Array;
}

export function generateDeviceIdentity(sodium: Sodium): DeviceIdentity {
  return {
    signingSeed: sodium.randombytes_buf(sodium.crypto_sign_SEEDBYTES),
    agreementSeed: sodium.randombytes_buf(sodium.crypto_box_SEEDBYTES),
  };
}

export function peerIdentity(sodium: Sodium, id: DeviceIdentity): PeerIdentity {
  const signing = sodium.crypto_sign_seed_keypair(id.signingSeed);
  const agreement = sodium.crypto_box_seed_keypair(id.agreementSeed);
  return {
    verifying: signing.publicKey,
    agreement: agreement.publicKey,
  };
}

/** The 64-byte Ed25519 secret libsodium wants for signing (seed + public). */
export function signingSecretKey(sodium: Sodium, id: DeviceIdentity): Uint8Array {
  return sodium.crypto_sign_seed_keypair(id.signingSeed).privateKey;
}

/**
 * The 32-byte X25519 secret for crypto_box, derived from the agreement seed.
 * This is the matched private half of `peerIdentity(...).agreement`, and is what
 * `crypto_box_open_easy` needs to open envelopes sealed to this device.
 */
export function agreementSecretKey(sodium: Sodium, id: DeviceIdentity): Uint8Array {
  return sodium.crypto_box_seed_keypair(id.agreementSeed).privateKey;
}
