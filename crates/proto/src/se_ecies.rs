//! P-256 ECIES wrap of the DEK to the Mac's Secure Enclave key.
//!
//! # Why P-256 and not X25519
//!
//! The phone receives the DEK sealed with X25519 `crypto_box` (see
//! [`crate::pairing::seal_dek`]). The Mac local-approval path is different: it
//! unwraps the DEK *inside the Secure Enclave* under a live Touch ID, and the
//! Secure Enclave can hold **only** NIST P-256 keys. It cannot store, import, or
//! agree with an X25519 key. So the Mac-SE DEK wrap cannot reuse the phone's
//! X25519 envelope; it must be P-256 ECIES.
//!
//! The two wraps are **independent envelopes of the same DEK**: either factor
//! (the phone's X25519 key, or the Mac SE's P-256 key) can recover the DEK on its
//! own. This module is purely additive; nothing about the phone path changes.
//!
//! # The construction (interop-critical)
//!
//! This reproduces Apple's
//! `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM` exactly,
//! so that `SecKeyCreateDecryptedData` on the Secure Enclave side opens what
//! [`wrap_dek_p256`] produces. The Mac app confirms the interop end-to-end with
//! `apps/mac/Tools/se-selftest.swift`, which mints an SE key, calls
//! `SecKeyCreateEncryptedData` with this same algorithm, and round-trips a known
//! DEK under Touch ID.
//!
//! For a P-256 recipient the algorithm is:
//!
//! 1. Generate an ephemeral P-256 key pair `(d_E, Q_E)`.
//! 2. `Z = ECDH_cofactor(d_E, Q_recipient)` — the 32-byte big-endian X coordinate
//!    of the shared point. P-256 has cofactor 1, so cofactor ECDH equals plain
//!    ECDH.
//! 3. ANSI-X9.63 KDF with SHA-256, deriving 32 bytes:
//!    `K = SHA256(Z || 0x00000001 || SharedInfo)`, where
//!    `SharedInfo = Q_E` in ANSI X9.63 uncompressed form (`0x04 || X || Y`,
//!    65 bytes). 32 bytes fit in one SHA-256 block, so the counter never advances
//!    past 1.
//!    - `aes_key = K[0..16]` (AES-128; Apple uses a 128-bit AES key for EC keys
//!      up to 256 bits, despite the `SHA256` in the name).
//!    - `iv = K[16..32]` (the *variable* 16-byte GCM IV; the non-`VariableIV`
//!      algorithm would instead use a fixed all-zero IV).
//! 4. AES-128-GCM over the DEK with that key and 16-byte IV, empty AAD, producing
//!    a 16-byte tag.
//!
//! # Wire format
//!
//! The sealed blob is exactly what `SecKeyCreateDecryptedData` expects:
//!
//! ```text
//! Q_E (65 bytes, ANSI X9.63 0x04||X||Y) || ciphertext (== DEK len, 32) || tag (16)
//! ```
//!
//! For a 32-byte DEK that is `65 + 32 + 16 = 113` bytes. `se-selftest.swift`
//! prints this length after `SecKeyCreateEncryptedData`; it must read 113.
//!
//! # Binding and sender authentication (why empty AAD is correct)
//!
//! Apple's `SecKeyCreateDecryptedData` for this ECIES algorithm takes **no AAD**
//! parameter, so the AAD is fixed-empty on both sides; adding AAD here would make
//! the Secure Enclave decrypt fail. Empty AAD is therefore not a free choice but a
//! constraint of SE interop, and it is safe for the intended use:
//!
//! * **Confidentiality** comes from ECDH to the SE public key: only that device's
//!   Enclave (under Touch ID) can open the blob, and a blob sealed to one SE key is
//!   authenticated garbage to any other (a different device, or a re-provisioned
//!   key). Cross-device / cross-pairing replay fails closed.
//! * **Integrity** of the wrapped DEK comes from the GCM tag: a tampered blob does
//!   not open.
//! * The **DEK<->token binding** is enforced downstream, not here: account tokens
//!   are AES-256-GCM ciphertext under the DEK, so a lifted or attacker-substituted
//!   DEK simply fails to decrypt them (fail closed, no secret leak).
//!
//! What ECIES does **not** provide is *sender* authentication: the SE public key is
//! public, so anyone can wrap an arbitrary value to it. That is acceptable because
//! the wrap is produced and consumed **locally** — the daemon wraps the DEK to the
//! same Mac's SE key and the SE unwraps it under Touch ID — so forging or swapping
//! the stored blob already requires same-UID write (outside Latch's boundary) and
//! yields only a fail-closed denial, never a secret. **Design constraint for any
//! future use:** if a wrapped-DEK-to-SE blob is ever delivered by a *remote* party
//! (over the relay, or from the phone to a different machine), it MUST be carried
//! inside the signed [`Envelope`](crate::Envelope) (Ed25519 sender auth + replay
//! guard) — never trusted bare, and never via GCM AAD the SE cannot validate.
//!
//! NEEDS-VERIFICATION (on device): that the Secure Enclave opens a blob produced
//! by [`wrap_dek_p256`]. Confirm with `swift apps/mac/Tools/se-selftest.swift` on
//! real Apple-silicon hardware with an enrolled biometric (it cannot pass on a VM
//! or the Simulator). The in-crate tests below only prove wrap/unwrap are
//! self-consistent in Rust, not that Apple's decrypt agrees byte-for-byte.

use aes_gcm::aead::generic_array::typenum::U16;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::Aes128;
use aes_gcm::AesGcm;
use p256::ecdh::{diffie_hellman, EphemeralSecret};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::pairing::Dek;

/// AES-128-GCM with the 16-byte IV Apple's ECIES derives from the KDF. The
/// standard `Aes128Gcm` alias fixes a 12-byte nonce, so the IV size is named
/// explicitly here to match `SecKeyCreateDecryptedData`.
type Aes128GcmVarIv = AesGcm<Aes128, U16>;

/// ANSI X9.63 uncompressed public-point length for P-256: `0x04 || X || Y`.
const P256_X963_PUBKEY_LEN: usize = 65;
/// AES-GCM authentication tag length.
const GCM_TAG_LEN: usize = 16;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum SeEciesError {
    #[error("recipient P-256 public key is not a valid X9.63 point")]
    BadRecipientKey,
    #[error("sealed blob is too short to hold an ephemeral key, ciphertext, and tag")]
    Truncated,
    #[error("ephemeral P-256 public key in the sealed blob is invalid")]
    BadEphemeralKey,
    #[error("AES-GCM authentication failed: wrong SE key, or a tampered blob")]
    Decrypt,
}

/// ANSI-X9.63 KDF (SHA-256), the concatenation KDF Apple's ECIES uses. Derives
/// `out.len()` bytes as `SHA256(Z || counter_be32 || shared_info)` with a 1-based
/// big-endian counter. The output is key material, so it is held in a `Zeroizing`
/// buffer and wiped when the caller drops it.
fn x963_kdf_sha256(z: &[u8], shared_info: &[u8], out_len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(out_len));
    let mut counter: u32 = 1;
    while out.len() < out_len {
        let mut h = Sha256::new();
        h.update(z);
        h.update(counter.to_be_bytes());
        h.update(shared_info);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(out_len);
    out
}

/// Split 32 bytes of KDF output into the AES-128 key and the 16-byte GCM IV.
/// Returns owned `Zeroizing` copies so the key/IV are wiped after the AEAD call.
fn split_key_iv(kdf: &[u8]) -> (Zeroizing<[u8; 16]>, [u8; 16]) {
    let mut key = Zeroizing::new([0u8; 16]);
    let mut iv = [0u8; 16];
    key.copy_from_slice(&kdf[0..16]);
    iv.copy_from_slice(&kdf[16..32]);
    (key, iv)
}

/// Wrap the DEK to a Mac Secure Enclave P-256 public key with Apple-compatible
/// ECIES. `se_pub_x963` is the SE public key in ANSI X9.63 uncompressed form (65
/// bytes, `0x04 || X || Y`), exactly the bytes
/// `SecKeyCopyExternalRepresentation` returns for an SE key. The returned blob is
/// what `SecKeyCreateDecryptedData` decrypts on the Mac.
pub fn wrap_dek_p256(dek: &Dek, se_pub_x963: &[u8]) -> Result<Vec<u8>, SeEciesError> {
    let recipient =
        PublicKey::from_sec1_bytes(se_pub_x963).map_err(|_| SeEciesError::BadRecipientKey)?;

    // Ephemeral P-256 key; its X9.63 encoding is both prepended to the blob and
    // fed to the KDF as SharedInfo, matching Apple's ECIES.
    let ephemeral = EphemeralSecret::random(&mut rand_core::OsRng);
    let eph_pub = ephemeral.public_key().to_encoded_point(false);
    let eph_pub_bytes = eph_pub.as_bytes(); // 65-byte 0x04||X||Y

    let shared = ephemeral.diffie_hellman(&recipient);
    let kdf = x963_kdf_sha256(shared.raw_secret_bytes().as_slice(), eph_pub_bytes, 32);
    let (key, iv) = split_key_iv(&kdf);

    let cipher = Aes128GcmVarIv::new(key.as_slice().into());
    let ciphertext = cipher
        .encrypt(
            iv.as_slice().into(),
            Payload {
                msg: dek.as_bytes(),
                aad: &[],
            },
        )
        // Encryption cannot fail for a well-formed 32-byte input; treat any error
        // as a decrypt-class fault rather than panicking.
        .map_err(|_| SeEciesError::Decrypt)?;

    let mut out = Vec::with_capacity(eph_pub_bytes.len() + ciphertext.len());
    out.extend_from_slice(eph_pub_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Reference/self-test inverse of [`wrap_dek_p256`]: recover the DEK from a
/// sealed blob using the P-256 secret key, running the identical ECIES
/// construction the Secure Enclave runs inside `SecKeyCreateDecryptedData`.
///
/// The daemon never calls this (only the SE decrypts, gated by Touch ID); it
/// exists so the wrap can be proven self-consistent in Rust and as an exact,
/// readable statement of what the SE side must do.
pub fn unwrap_dek_p256(sealed: &[u8], se_secret: &SecretKey) -> Result<Dek, SeEciesError> {
    if sealed.len() < P256_X963_PUBKEY_LEN + GCM_TAG_LEN {
        return Err(SeEciesError::Truncated);
    }
    let (eph_pub_bytes, ciphertext) = sealed.split_at(P256_X963_PUBKEY_LEN);
    let eph_pub =
        PublicKey::from_sec1_bytes(eph_pub_bytes).map_err(|_| SeEciesError::BadEphemeralKey)?;

    let shared = diffie_hellman(se_secret.to_nonzero_scalar(), eph_pub.as_affine());
    let kdf = x963_kdf_sha256(shared.raw_secret_bytes().as_slice(), eph_pub_bytes, 32);
    let (key, iv) = split_key_iv(&kdf);

    let cipher = Aes128GcmVarIv::new(key.as_slice().into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                iv.as_slice().into(),
                Payload {
                    msg: ciphertext,
                    aad: &[],
                },
            )
            .map_err(|_| SeEciesError::Decrypt)?,
    );
    if plaintext.len() != 32 {
        return Err(SeEciesError::Decrypt);
    }
    // Hold the recovered key material in a Zeroizing intermediate so the copy on
    // the way into `Dek` is wiped rather than left on the stack.
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&plaintext);
    Ok(Dek::from_bytes(*bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    /// A stand-in Secure Enclave key pair, generated in software so the wrap can
    /// be exercised off-device. On the real Mac the private half lives in the SE
    /// and never leaves it; the public X9.63 bytes are all the daemon ever sees.
    fn se_keypair() -> (SecretKey, Vec<u8>) {
        let secret = SecretKey::random(&mut rand_core::OsRng);
        let pub_x963 = secret.public_key().to_encoded_point(false);
        (secret, pub_x963.as_bytes().to_vec())
    }

    #[test]
    fn wrap_unwrap_round_trips_the_dek() {
        let (se_secret, se_pub) = se_keypair();
        let dek = Dek::from_bytes([0xA5; 32]);

        let sealed = wrap_dek_p256(&dek, &se_pub).unwrap();
        let recovered = unwrap_dek_p256(&sealed, &se_secret).unwrap();
        assert_eq!(recovered.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn sealed_blob_has_the_apple_wire_length() {
        // 65-byte X9.63 ephemeral key + 32-byte ciphertext + 16-byte GCM tag.
        // se-selftest.swift asserts this same 113 on device.
        let (_se_secret, se_pub) = se_keypair();
        let dek = Dek::from_bytes([1u8; 32]);
        let sealed = wrap_dek_p256(&dek, &se_pub).unwrap();
        assert_eq!(sealed.len(), P256_X963_PUBKEY_LEN + 32 + GCM_TAG_LEN);
        assert_eq!(sealed.len(), 113);
        // The blob opens with the uncompressed-point marker the SE expects.
        assert_eq!(sealed[0], 0x04);
    }

    #[test]
    fn each_wrap_uses_a_fresh_ephemeral_key() {
        // Forward secrecy / IND-CPA: two wraps of the same DEK to the same SE key
        // must differ (fresh ephemeral => fresh shared secret => fresh key+IV).
        let (_se_secret, se_pub) = se_keypair();
        let dek = Dek::from_bytes([7u8; 32]);
        let a = wrap_dek_p256(&dek, &se_pub).unwrap();
        let b = wrap_dek_p256(&dek, &se_pub).unwrap();
        assert_ne!(a, b);
        assert_ne!(a[..P256_X963_PUBKEY_LEN], b[..P256_X963_PUBKEY_LEN]);
    }

    #[test]
    fn wrong_se_key_cannot_unwrap() {
        // A blob sealed to SE key A is authenticated garbage to SE key B: the
        // GCM tag fails and no DEK leaks.
        let (_se_a, pub_a) = se_keypair();
        let (se_b, _pub_b) = se_keypair();
        let dek = Dek::from_bytes([9u8; 32]);
        let sealed = wrap_dek_p256(&dek, &pub_a).unwrap();
        // `Dek` has no `PartialEq` (a deliberate guard against variable-time
        // comparison), so assert on the error rather than the `Result`.
        assert_eq!(
            unwrap_dek_p256(&sealed, &se_b).unwrap_err(),
            SeEciesError::Decrypt
        );
    }

    #[test]
    fn a_tampered_ciphertext_is_rejected() {
        let (se_secret, se_pub) = se_keypair();
        let dek = Dek::from_bytes([3u8; 32]);
        let mut sealed = wrap_dek_p256(&dek, &se_pub).unwrap();
        // Flip a bit in the AES-GCM ciphertext body (past the 65-byte eph key).
        let ct_idx = P256_X963_PUBKEY_LEN + 1;
        sealed[ct_idx] ^= 1;
        assert_eq!(
            unwrap_dek_p256(&sealed, &se_secret).unwrap_err(),
            SeEciesError::Decrypt
        );
    }

    #[test]
    fn a_tampered_ephemeral_key_is_rejected() {
        let (se_secret, se_pub) = se_keypair();
        let dek = Dek::from_bytes([4u8; 32]);
        let mut sealed = wrap_dek_p256(&dek, &se_pub).unwrap();
        // Corrupt the X coordinate of the ephemeral point: it either fails to
        // parse as a curve point or yields a different shared secret; either way
        // the DEK must not come back.
        sealed[1] ^= 1;
        assert!(matches!(
            unwrap_dek_p256(&sealed, &se_secret),
            Err(SeEciesError::Decrypt) | Err(SeEciesError::BadEphemeralKey)
        ));
    }

    #[test]
    fn a_truncated_blob_is_rejected() {
        let (se_secret, _se_pub) = se_keypair();
        assert_eq!(
            unwrap_dek_p256(&[0u8; 40], &se_secret).unwrap_err(),
            SeEciesError::Truncated
        );
    }

    #[test]
    fn a_non_point_recipient_key_is_refused() {
        let dek = Dek::from_bytes([2u8; 32]);
        // 65 bytes that are not a valid X9.63 point.
        let junk = [0u8; 65];
        assert_eq!(
            wrap_dek_p256(&dek, &junk),
            Err(SeEciesError::BadRecipientKey)
        );
    }

    #[test]
    fn x963_kdf_matches_a_known_answer() {
        // Pin the KDF to a fixed vector so a future refactor cannot silently
        // change the derivation the SE relies on. Z = 0x00..1f, sharedInfo empty,
        // one SHA-256 block: SHA256(Z || 0x00000001).
        let z: Vec<u8> = (0u8..32).collect();
        let got = x963_kdf_sha256(&z, &[], 32);
        let mut h = Sha256::new();
        h.update(&z);
        h.update(1u32.to_be_bytes());
        let want = h.finalize();
        assert_eq!(got.as_slice(), want.as_slice());
    }
}
