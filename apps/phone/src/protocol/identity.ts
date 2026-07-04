/**
 * Device identities, mirroring crates/proto/src/identity.rs.
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
  /** X25519 secret key, 32 bytes. */
  agreementSecret: Uint8Array;
}

export function generateDeviceIdentity(sodium: Sodium): DeviceIdentity {
  return {
    signingSeed: sodium.randombytes_buf(sodium.crypto_sign_SEEDBYTES),
    agreementSecret: sodium.randombytes_buf(sodium.crypto_box_SECRETKEYBYTES),
  };
}

export function peerIdentity(sodium: Sodium, id: DeviceIdentity): PeerIdentity {
  const signing = sodium.crypto_sign_seed_keypair(id.signingSeed);
  return {
    verifying: signing.publicKey,
    agreement: sodium.crypto_scalarmult_base(id.agreementSecret),
  };
}

/** The 64-byte Ed25519 secret libsodium wants for signing (seed + public). */
export function signingSecretKey(sodium: Sodium, id: DeviceIdentity): Uint8Array {
  return sodium.crypto_sign_seed_keypair(id.signingSeed).privateKey;
}
