/**
 * Device identities, mirroring crates/sigil-proto/src/identity.rs.
 *
 * A device holds an Ed25519 signing key and an X25519 agreement key.
 *
 * **BOTH PRIVATE HALVES ARE HANDLED HERE, IN JS, ON EVERY USE, AND NEITHER IS IN
 * THE SECURE ENCLAVE.** This comment used to say the opposite, and the correction
 * matters more than a comment usually would, so be exact about what is where:
 *
 *   - The Ed25519 signing seed and the X25519 agreement seed are persisted
 *     base64 in `expo-secure-store` (`src/session/keystore.ts`), which is an iOS
 *     keychain item. `signingSecretKey` and `agreementSecretKey` below expand
 *     them into raw private keys in JS memory on every outbound seal and every
 *     inbound open (`src/session/session.ts`). No biometric gates either.
 *   - Only the P-256 threshold share `f` is enclave-resident and non-exportable
 *     (`modules/sigil-se`). That key is what a secret release depends on, and it
 *     is the one thing on this phone that genuinely never surfaces in JS.
 *
 * The consequence is the reason to state it plainly: FORGING AN APPROVAL AS THIS
 * PHONE DOES NOT REQUIRE ENCLAVE EXTRACTION. It requires reading one keychain
 * item. The old wording invited a reviewer to conclude the opposite and stop
 * looking, which is the expensive kind of wrong comment. What the enclave share
 * does buy is separate and real: holding these seeds is not enough to open a
 * threshold-sealed secret, because `Z_F` still has to come from the enclave under
 * biometry.
 *
 * NEEDS VERIFICATION (behaviour, not documentation): the keystore writes with no
 * `keychainAccessible` option, so it takes expo-secure-store's default, which
 * reads as `kSecAttrAccessibleWhenUnlocked` in the vendored source. That is not a
 * `ThisDeviceOnly` class, so the item can migrate to new hardware through an
 * encrypted backup restore. Whether that is the intended custody for the key that
 * authorizes approvals is a decision nobody has recorded making; it should be
 * pinned deliberately rather than inherited from a default.
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
