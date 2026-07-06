//! The v2 threshold combiner: per-request two-party decryption, retiring the
//! static DEK.
//!
//! Full design and the independent review verdict are in
//! `docs/design/threshold-v2.md`. This module is the **shared crypto core** that
//! both the daemon (Mac) and the phone build on; the combiner it defines is
//! mirrored byte-for-byte by the phone's TypeScript
//! (`apps/phone/src/protocol/__vectors__/sigil-vectors.json` locks the two
//! together — see `bin/export-vectors.rs`, the `combiner` category).
//!
//! # The construction (§3 of the design)
//!
//! Decryption is a genuine 2-of-2 AND of two independent P-256 ECDH secrets,
//! combined by a KDF — never a reconstructed private key, never point addition:
//!
//! ```text
//! Z_M = x(m · E)     // the Mac's partial, full software (RustCrypto p256)
//! Z_F = x(f · E)     // the phone's partial, exactly what the Secure Enclave emits
//! K   = BLAKE2b( "sigil.threshold.v2" ‖ len·Z_M ‖ len·Z_F ‖ len·E_x963 ‖ len·account_id )
//! token_ct = AES-256-GCM(token; K)
//! ```
//!
//! `m` is the long-term Mac share (a software scalar sealed in the keystore);
//! `f` is the phone's non-exportable Secure-Enclave key; `E = e·G` is a per-account
//! ephemeral base minted fresh at account-add, after which `e` is destroyed so
//! `Z_F` becomes computable only by the holder of `f` (CDH). Neither share alone
//! yields `K`.
//!
//! # KDF encoding, pinned for the phone mirror
//!
//! `combine` computes an **unkeyed BLAKE2b with a 32-byte digest** over, in order:
//!
//! 1. the raw domain constant [`THRESHOLD_DOMAIN`] (`b"sigil.threshold.v2"`, 18
//!    bytes, no length prefix — a fixed leading constant, exactly as
//!    [`crate::pairing::rendezvous_mailbox`] absorbs its domain);
//! 2. `Z_M`, length-prefixed;
//! 3. `Z_F`, length-prefixed;
//! 4. `E` in ANSI X9.63 uncompressed form (`0x04‖X‖Y`, 65 bytes), length-prefixed;
//! 5. `account_id` UTF-8 bytes, length-prefixed.
//!
//! Every length prefix is a big-endian `u64` (the same injective framing the
//! envelope's `canonical_bytes` and the pairing transcript use). The libsodium
//! mirror is `crypto_generichash(outlen = 32, msg = domain‖…)`.
//!
//! # ECDH output shape (`ecdh_algo`, NV-2 / NV-7)
//!
//! The Secure Enclave may return either the raw 32-byte X-coordinate
//! ([`EcdhAlgo::RawX`]) or, on hardware that refuses raw key-agreement, the output
//! of Apple's ANSI-X9.63 SHA-256 KDF over that X-coordinate
//! ([`EcdhAlgo::X963Sha256`]). The record pins which; both sides apply the
//! identical shaping so `Z_M` and `Z_F` agree byte-for-byte. For the X9.63 variant
//! this module fixes `sharedInfo = E`'s X9.63 bytes; **NV-7**: the exact parameter
//! dict the SE applies to a *bare* key-agreement (distinct from the ECIES use in
//! [`crate::se_ecies`]) must be confirmed on device and pinned to match this.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Domain separator folded into every combiner hash. Distinct from the pairing
/// domains, so threshold key material can never collide with a pairing subkey.
pub const THRESHOLD_DOMAIN: &[u8] = b"sigil.threshold.v2";

/// Combiner identifier persisted in the record's `kdf_algo`, for future-proofing.
pub const KDF_ALGO_ID: &str = "blake2b-v2";

/// The only at-rest record version this module decrypts (R3: no downgrade).
pub const THRESHOLD_RECORD_VERSION: u8 = 2;

/// ANSI X9.63 uncompressed P-256 point length: `0x04 ‖ X ‖ Y`.
pub const P256_X963_POINT_LEN: usize = 65;
/// Raw ECDH X-coordinate / combiner-share length.
pub const XCOORD_LEN: usize = 32;
/// AES-256-GCM nonce length (96-bit, unchanged from v1's at-rest format).
pub const TOKEN_NONCE_LEN: usize = 12;
/// Derived token-key (AES-256) length.
pub const KEY_LEN: usize = 32;

/// A 32-byte BLAKE2b, matching the combiner digest width. libsodium's
/// `crypto_generichash` with `outlen = 32` is the byte-exact mirror.
type Blake2b256 = Blake2b<U32>;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ThresholdError {
    #[error("P-256 point is not a valid on-curve X9.63 encoding (off-curve/twist rejected)")]
    BadPoint,
    #[error("P-256 scalar is not a valid non-zero field element")]
    BadScalar,
    #[error("account record version {found} is not a v2 threshold record")]
    BadRecordVersion { found: u8 },
    #[error("phone partial Z_F is not exactly 32 bytes")]
    ShortPartial,
    #[error("token ciphertext is malformed or truncated")]
    TokenTruncated,
    #[error("AEAD failed: wrong combined key (missing/incorrect share) or tampered ciphertext")]
    Aead,
    #[error("base64 decode failed")]
    Base64,
}

/// Which shape the Secure Enclave's ECDH output takes, pinned per record so the
/// Mac reproduces the phone's `Z_F` byte-for-byte. Serializes to the exact tags
/// the design and the phone use.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum EcdhAlgo {
    /// Raw 32-byte big-endian X-coordinate (`.ecdhKeyExchangeStandard`).
    #[serde(rename = "raw-x")]
    RawX,
    /// Apple ANSI-X9.63 SHA-256 KDF over the X-coordinate, `sharedInfo = E`.
    #[serde(rename = "x963-sha256")]
    X963Sha256,
}

/// A validated, on-curve P-256 public point in ANSI X9.63 uncompressed form.
///
/// **R2, load-bearing.** The only constructor, [`P256Point::from_x963`], parses
/// through `p256::PublicKey::from_sec1_bytes`, which rejects off-curve and twist
/// points *before* any scalar multiplication. Both the account base `E` and the
/// pinned phone key `F` are validated this way; the phone MUST use the equivalent
/// validating CryptoKit / Security-framework decoder (never a raw-coordinate
/// path) for the same protection of its Secure-Enclave key `f`.
#[derive(Clone, Debug)]
pub struct P256Point {
    key: PublicKey,
    x963: [u8; P256_X963_POINT_LEN],
}

impl P256Point {
    /// Validate `bytes` as an on-curve P-256 point. Rejects the identity, wrong
    /// lengths, non-canonical encodings, and — critically — off-curve/twist
    /// points, all as [`ThresholdError::BadPoint`].
    pub fn from_x963(bytes: &[u8]) -> Result<Self, ThresholdError> {
        let key = PublicKey::from_sec1_bytes(bytes).map_err(|_| ThresholdError::BadPoint)?;
        // Re-encode canonically so the bytes folded into the KDF are exactly the
        // curve library's uncompressed form, independent of the caller's framing.
        let enc = key.to_encoded_point(false);
        let mut x963 = [0u8; P256_X963_POINT_LEN];
        // `from_sec1_bytes` only accepts a point that encodes to 65 uncompressed
        // bytes, so this length always holds.
        x963.copy_from_slice(enc.as_bytes());
        Ok(Self { key, x963 })
    }

    /// The canonical 65-byte X9.63 encoding folded into the combiner and stored.
    pub fn as_x963(&self) -> &[u8; P256_X963_POINT_LEN] {
        &self.x963
    }

    fn public(&self) -> &PublicKey {
        &self.key
    }
}

/// The long-term Mac share `m`: a P-256 scalar held sealed in the platform
/// keystore, never in the Secure Enclave (a remote phone approval has no Touch
/// ID, so `m` must be usable in software; §5). Zeroized on drop by `SecretKey`.
pub struct MacShare {
    secret: SecretKey,
}

impl MacShare {
    /// Mint a fresh share, `m ← random`, at v2 setup.
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::random(&mut rand_core::OsRng),
        }
    }

    /// Reconstruct from the 32-byte scalar bytes read out of the sealed keystore
    /// blob. Rejects a zero/out-of-range scalar as [`ThresholdError::BadScalar`].
    pub fn from_scalar_bytes(bytes: &[u8]) -> Result<Self, ThresholdError> {
        let secret = SecretKey::from_slice(bytes).map_err(|_| ThresholdError::BadScalar)?;
        Ok(Self { secret })
    }

    /// The 32-byte scalar to seal into the keystore. Held in `Zeroizing` so the
    /// copy is wiped after the keystore write.
    pub fn scalar_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&self.secret.to_bytes());
        out
    }

    /// The public share `M = m·G`. Never needs to leave the Mac (only the Mac
    /// encrypts to the pair), but exposed for completeness and testing.
    pub fn public_point(&self) -> P256Point {
        let enc = self.secret.public_key().to_encoded_point(false);
        // A freshly derived public key always re-encodes as a valid 65-byte point.
        P256Point::from_x963(enc.as_bytes()).expect("own public key is on-curve")
    }

    /// Compute this scalar's shaped ECDH partial against `point`:
    /// `shape( x(scalar · point), algo, e_x963 )`. The single ECDH primitive the
    /// whole scheme rests on — used for `Z_M = x(m·E)` at decrypt, `Z_F = x(e·F)`
    /// at account-add, and (in the shared vectors) `Z_F = x(f·E)` standing in for
    /// the Secure Enclave. Result is `Zeroizing`.
    pub fn partial(
        &self,
        point: &P256Point,
        algo: EcdhAlgo,
        e_x963: &[u8],
    ) -> Zeroizing<[u8; XCOORD_LEN]> {
        let shared = diffie_hellman(self.secret.to_nonzero_scalar(), point.public().as_affine());
        let mut raw = Zeroizing::new([0u8; XCOORD_LEN]);
        raw.copy_from_slice(shared.raw_secret_bytes().as_slice());
        shape(&raw, algo, e_x963)
    }
}

/// Apply the record's ECDH-output shaping to a raw X-coordinate. For
/// [`EcdhAlgo::RawX`] this is the identity; for [`EcdhAlgo::X963Sha256`] it is
/// Apple's ANSI-X9.63 SHA-256 KDF with `sharedInfo = E` (NV-7: pin to the SE's
/// actual bare-key-agreement parameters on device).
fn shape(raw_x: &[u8; XCOORD_LEN], algo: EcdhAlgo, e_x963: &[u8]) -> Zeroizing<[u8; XCOORD_LEN]> {
    match algo {
        EcdhAlgo::RawX => Zeroizing::new(*raw_x),
        EcdhAlgo::X963Sha256 => x963_kdf_sha256_32(raw_x, e_x963),
    }
}

/// ANSI-X9.63 KDF (SHA-256) producing exactly 32 bytes: `SHA256(Z ‖ 0x00000001 ‖
/// sharedInfo)`. 32 bytes fit one SHA-256 block, so the counter never advances.
///
/// Deliberately local to this module and NOT shared with
/// [`crate::se_ecies::x963_kdf_sha256`]: that instance is Apple's *ECIES* KDF
/// (`sharedInfo` = the ephemeral point, 32-byte AES-key+IV output); this one is
/// the *bare key-agreement* KDF (`sharedInfo` = `E`). NV-7 warns the two uses must
/// not be conflated.
fn x963_kdf_sha256_32(z: &[u8], shared_info: &[u8]) -> Zeroizing<[u8; XCOORD_LEN]> {
    let mut h = Sha256::new();
    h.update(z);
    h.update(1u32.to_be_bytes());
    h.update(shared_info);
    let digest = h.finalize();
    let mut out = Zeroizing::new([0u8; XCOORD_LEN]);
    out.copy_from_slice(&digest);
    out
}

/// Length-prefix `field` into `h` (big-endian u64), the injective absorb the
/// envelope and pairing transcript use.
fn absorb(h: &mut Blake2b256, field: &[u8]) {
    h.update((field.len() as u64).to_be_bytes());
    h.update(field);
}

/// The combiner (§3/§6). Derive the 32-byte token key `K` from the two ECDH
/// partials plus the account's public base `E` and id. Both `zm` and `zf` are
/// already in their final combiner-input shape (the caller shapes `Z_M`; the
/// phone's `Z_F` arrives shaped by the SE). Returns `Zeroizing` so `K` is wiped
/// the instant the token is opened (§10).
pub fn combine(
    zm: &[u8; XCOORD_LEN],
    zf: &[u8; XCOORD_LEN],
    e_x963: &[u8],
    account_id: &str,
) -> Zeroizing<[u8; KEY_LEN]> {
    let mut h = Blake2b256::new();
    h.update(THRESHOLD_DOMAIN);
    absorb(&mut h, zm);
    absorb(&mut h, zf);
    absorb(&mut h, e_x963);
    absorb(&mut h, account_id.as_bytes());
    let digest = h.finalize();
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&digest);
    out
}

/// AES-256-GCM seal `pt` under `key` with the given 96-bit `nonce`. Returns
/// `ciphertext ‖ tag`; the AEAD primitive is byte-identical to v1's at-rest
/// `secrets.rs::encrypt_token`, so migration touches only where `key` comes from.
pub fn aead_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; TOKEN_NONCE_LEN],
    pt: &[u8],
) -> Result<Vec<u8>, ThresholdError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad: &[] })
        .map_err(|_| ThresholdError::Aead)
}

/// AES-256-GCM open `ct ‖ tag` under `key` and `nonce`. Fails closed
/// ([`ThresholdError::Aead`]) on a wrong `K` — i.e. a missing or wrong share — or
/// any tamper; the plaintext lands in a `Zeroizing` buffer.
pub fn aead_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; TOKEN_NONCE_LEN],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ThresholdError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &[] })
        .map_err(|_| ThresholdError::Aead)?;
    Ok(Zeroizing::new(pt))
}

/// Decode a base64 phone partial `Z_F` to exactly 32 bytes, held in `Zeroizing`.
/// Fails closed to [`ThresholdError::ShortPartial`] on any malformed/short input,
/// never a partial value (mirrors `ApprovalResponse::dek`'s fail-closed decode).
pub fn decode_partial(zf_b64: &str) -> Result<Zeroizing<[u8; XCOORD_LEN]>, ThresholdError> {
    let bytes = Zeroizing::new(B64.decode(zf_b64).map_err(|_| ThresholdError::Base64)?);
    let arr: [u8; XCOORD_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ThresholdError::ShortPartial)?;
    Ok(Zeroizing::new(arr))
}

/// The at-rest v2 account record (§5). Persisted per account by the daemon's CLI
/// `account add`; the decrypt path is selected by [`Self::version`] alone (R3:
/// never from any network field). Byte fields are base64 in JSON, matching the
/// existing account store's `token_b64` convention.
///
/// What is deliberately absent: no `K`, no `Z_M`, no `Z_F`, and no `e` — only the
/// public `E` survives account-add, which is the linchpin of the CDH argument in
/// §11 (once `e` is gone, `Z_F` is computable only by the phone's `f`).
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdRecord {
    /// Record version. Drives decrypt-path selection; MUST be
    /// [`THRESHOLD_RECORD_VERSION`] for the v2 path.
    pub version: u8,
    /// Stable account id, also folded into the KDF for cross-account separation.
    pub account_id: String,
    /// `E = e·G`, ANSI X9.63 (65 bytes), base64. The per-account ECDH base.
    pub ephemeral_pub: String,
    /// AES-256-GCM nonce (12 bytes), base64.
    pub aead_nonce: String,
    /// AES-256-GCM `ciphertext ‖ tag` of the token under `K`, base64.
    pub token_ct: String,
    /// Which pinned phone Secure-Enclave key `F` this was wrapped to.
    pub se_key_id: String,
    /// Combiner id, [`KDF_ALGO_ID`].
    pub kdf_algo: String,
    /// Which SE ECDH output shape `Z_F` is (NV-2).
    pub ecdh_algo: EcdhAlgo,
}

impl ThresholdRecord {
    /// Account-add (a Mac-only, human-present CLI ceremony; §5). Mint a fresh
    /// per-account `e`/`E` (R4: unique base per account), derive `K` from the two
    /// partials, and seal the token. `m` is the Mac share; `phone_f` is the pinned
    /// Secure-Enclave public key `F`. The ephemeral `e`, `Z_M`, `Z_F`, and `K` are
    /// all transient and dropped (zeroized) as this returns.
    pub fn seal(
        account_id: &str,
        m: &MacShare,
        phone_f: &P256Point,
        algo: EcdhAlgo,
        se_key_id: &str,
        token: &[u8],
    ) -> Result<Self, ThresholdError> {
        // Fresh ephemeral per account => unique E (R4).
        let e = MacShare::generate();
        let e_point = e.public_point();
        let e_x963 = *e_point.as_x963();

        // Z_M = x(m·E); Z_F = x(e·F) = x(f·E). The Mac computes both here because
        // it holds e and the pinned public F — no phone, no f (§5).
        let zm = m.partial(&e_point, algo, &e_x963);
        let zf = e.partial(phone_f, algo, &e_x963);
        let k = combine(&zm, &zf, &e_x963, account_id);

        let mut nonce = [0u8; TOKEN_NONCE_LEN];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let ct = aead_seal(&k, &nonce, token)?;

        Ok(Self {
            version: THRESHOLD_RECORD_VERSION,
            account_id: account_id.to_string(),
            ephemeral_pub: B64.encode(e_x963),
            aead_nonce: B64.encode(nonce),
            token_ct: B64.encode(&ct),
            se_key_id: se_key_id.to_string(),
            kdf_algo: KDF_ALGO_ID.to_string(),
            ecdh_algo: algo,
        })
    }

    /// Fail closed unless this is a v2 record (R3, no downgrade). Every decrypt
    /// path calls this first, so a record whose version was tampered to anything
    /// other than [`THRESHOLD_RECORD_VERSION`] yields no token.
    pub fn require_v2(&self) -> Result<(), ThresholdError> {
        if self.version == THRESHOLD_RECORD_VERSION {
            Ok(())
        } else {
            Err(ThresholdError::BadRecordVersion {
                found: self.version,
            })
        }
    }

    /// The validated on-curve base point `E` (R2, Mac-side check at load).
    pub fn ephemeral_point(&self) -> Result<P256Point, ThresholdError> {
        let bytes = B64
            .decode(&self.ephemeral_pub)
            .map_err(|_| ThresholdError::Base64)?;
        P256Point::from_x963(&bytes)
    }

    /// The Mac's per-request partial `Z_M = x(m·E)` (shaped per `ecdh_algo`).
    /// Computed with `m` held for only the span of this call (§10). The `E` it
    /// agrees against is validated on-curve here before the scalar mult.
    pub fn mac_partial(&self, m: &MacShare) -> Result<Zeroizing<[u8; XCOORD_LEN]>, ThresholdError> {
        let e_point = self.ephemeral_point()?;
        Ok(m.partial(&e_point, self.ecdh_algo, e_point.as_x963()))
    }

    /// The daemon's full per-request decrypt (§6, steps 9–13). Given the Mac share
    /// `m` and the phone's partial `zf` (`Z_F = x(f·E)`), recompute `K` and open
    /// the token. Fails closed if the record is not v2 (R3), if `E` is off-curve
    /// (R2), or if `zf` is wrong/absent (the GCM tag fails). The token lands in a
    /// `Zeroizing` buffer.
    pub fn decrypt(
        &self,
        m: &MacShare,
        zf: &[u8; XCOORD_LEN],
    ) -> Result<Zeroizing<Vec<u8>>, ThresholdError> {
        self.require_v2()?;
        let e_point = self.ephemeral_point()?;
        let e_x963 = e_point.as_x963();
        let zm = m.partial(&e_point, self.ecdh_algo, e_x963);
        let k = combine(&zm, zf, e_x963, &self.account_id);

        let nonce_bytes = B64
            .decode(&self.aead_nonce)
            .map_err(|_| ThresholdError::Base64)?;
        let nonce: [u8; TOKEN_NONCE_LEN] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ThresholdError::TokenTruncated)?;
        let ct = B64
            .decode(&self.token_ct)
            .map_err(|_| ThresholdError::Base64)?;
        aead_open(&k, &nonce, &ct)
    }
}

/// R4 store-level guard: are all records' ephemeral bases `E` distinct? The
/// "one captured partial ⇒ one account" blast-radius claim depends on it, so the
/// daemon calls this after any mutation. Records with an unparseable `E` are
/// treated as colliding (fail closed).
pub fn all_ephemerals_unique(records: &[ThresholdRecord]) -> bool {
    let mut seen: Vec<[u8; P256_X963_POINT_LEN]> = Vec::with_capacity(records.len());
    for r in records {
        match r.ephemeral_point() {
            Ok(p) => {
                let bytes = *p.as_x963();
                if seen.contains(&bytes) {
                    return false;
                }
                seen.push(bytes);
            }
            Err(_) => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic scalar from a fixed seed, for reproducible tests. The
    /// pattern stays well below the P-256 group order and non-zero.
    fn share(seed: u8) -> MacShare {
        let bytes: [u8; 32] =
            std::array::from_fn(|i| seed.wrapping_add(i as u8).wrapping_mul(3) | 1);
        MacShare::from_scalar_bytes(&bytes).expect("fixed seed is a valid scalar")
    }

    const ACCT: &str = "acct-threshold-01";

    // --- combiner ----------------------------------------------------------

    #[test]
    fn combine_is_deterministic() {
        let zm = [7u8; 32];
        let zf = [9u8; 32];
        let e = [0x04u8; 65];
        let a = combine(&zm, &zf, &e, ACCT);
        let b = combine(&zm, &zf, &e, ACCT);
        assert_eq!(*a, *b);
    }

    #[test]
    fn combine_binds_every_field() {
        let zm = [7u8; 32];
        let zf = [9u8; 32];
        let e = [0x04u8; 65];
        let base = *combine(&zm, &zf, &e, ACCT);

        // account_id separation (R4 cross-account defence).
        assert_ne!(base, *combine(&zm, &zf, &e, "other-account"));
        // E separation.
        let mut e2 = e;
        e2[1] ^= 1;
        assert_ne!(base, *combine(&zm, &zf, &e2, ACCT));
        // Z_M and Z_F are positional: swapping them changes K (the length-prefixed
        // absorb is order-sensitive, not a symmetric H(k1‖k2)).
        assert_ne!(base, *combine(&zf, &zm, &e, ACCT));
        // Either share alone determines K: changing Z_F alone changes K.
        assert_ne!(base, *combine(&zm, &[10u8; 32], &e, ACCT));
    }

    #[test]
    fn domain_prefix_is_exactly_the_v2_separator() {
        // Pin the encoding so a refactor cannot silently move the phone mirror.
        let zm = [1u8; 32];
        let zf = [2u8; 32];
        let e = [0x04u8; 65];
        let got = *combine(&zm, &zf, &e, "id");

        let mut h = Blake2b256::new();
        h.update(b"sigil.threshold.v2");
        h.update(32u64.to_be_bytes());
        h.update(zm);
        h.update(32u64.to_be_bytes());
        h.update(zf);
        h.update(65u64.to_be_bytes());
        h.update(e);
        h.update(2u64.to_be_bytes());
        h.update(b"id");
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(got, want);
    }

    // --- R2: on-curve validation ------------------------------------------

    #[test]
    fn validator_accepts_a_valid_point_and_rejects_off_curve() {
        // A real generated point is accepted and round-trips its X9.63 bytes.
        let good = share(1).public_point();
        let reparsed = P256Point::from_x963(good.as_x963()).unwrap();
        assert_eq!(reparsed.as_x963(), good.as_x963());

        // Crafted off-curve point: take a valid uncompressed encoding and flip a
        // low byte of Y so (X, Y) no longer satisfies the curve equation. The
        // validating decoder must reject it BEFORE any scalar mult (R2).
        let mut off = *good.as_x963();
        off[P256_X963_POINT_LEN - 1] ^= 1;
        assert!(matches!(
            P256Point::from_x963(&off),
            Err(ThresholdError::BadPoint)
        ));

        // Junk, wrong length, and the point at infinity are all refused.
        assert!(matches!(
            P256Point::from_x963(&[0u8; 65]),
            Err(ThresholdError::BadPoint)
        ));
        assert!(matches!(
            P256Point::from_x963(&[0x04u8; 10]),
            Err(ThresholdError::BadPoint)
        ));
        assert!(matches!(
            P256Point::from_x963(&[]),
            Err(ThresholdError::BadPoint)
        ));
    }

    #[test]
    fn a_bad_scalar_is_rejected() {
        assert_eq!(
            MacShare::from_scalar_bytes(&[0u8; 32]).err(),
            Some(ThresholdError::BadScalar)
        );
    }

    // --- 2-of-2 ECDH symmetry ---------------------------------------------

    #[test]
    fn ecdh_symmetry_gives_a_shared_zf() {
        // The phone computes Z_F = x(f·E); account-add computes x(e·F). Diffie
        // Hellman symmetry makes them identical, which is what lets the Mac seal a
        // token the phone can later help open (NV-3, proven here off-device).
        let f = share(2);
        let e = share(3);
        let e_point = e.public_point();
        let f_point = f.public_point();
        let e_x963 = *e_point.as_x963();

        let zf_phone = f.partial(&e_point, EcdhAlgo::RawX, &e_x963); // x(f·E)
        let zf_encrypt = e.partial(&f_point, EcdhAlgo::RawX, &e_x963); // x(e·F)
        assert_eq!(*zf_phone, *zf_encrypt);
    }

    // --- full round trip through the combine ------------------------------

    fn round_trip_through_combine(algo: EcdhAlgo) {
        let m = share(10); // the Mac share
        let f = share(20); // stands in for the Secure-Enclave key f
        let f_point = f.public_point();
        let token = b"ops_eyJzaWduSW5BZGRyZXNzIjoiZXhhbXBsZSJ9.example-service-token";

        // Account-add: the Mac seals with m and the pinned F.
        let rec = ThresholdRecord::seal(ACCT, &m, &f_point, algo, "se-key-1", token).unwrap();
        assert_eq!(rec.version, THRESHOLD_RECORD_VERSION);
        assert_eq!(rec.ecdh_algo, algo);

        // Per-request decrypt: the phone contributes Z_F = x(f·E); the Mac supplies
        // m. Together they recover the token (a simulated 2-of-2).
        let e_point = rec.ephemeral_point().unwrap();
        let zf = f.partial(&e_point, algo, e_point.as_x963());
        let recovered = rec.decrypt(&m, &zf).unwrap();
        assert_eq!(&recovered[..], token);
    }

    #[test]
    fn full_two_of_two_round_trip_raw_x() {
        round_trip_through_combine(EcdhAlgo::RawX);
    }

    #[test]
    fn full_two_of_two_round_trip_x963() {
        round_trip_through_combine(EcdhAlgo::X963Sha256);
    }

    #[test]
    fn the_two_algos_derive_different_keys() {
        // A record pinned to raw-x cannot be opened with x963 shaping and vice
        // versa; the shaping is part of what K commits to.
        let m = share(11);
        let f = share(21);
        let f_point = f.public_point();
        let token = b"tok";
        let rec = ThresholdRecord::seal(ACCT, &m, &f_point, EcdhAlgo::RawX, "k", token).unwrap();
        let e_point = rec.ephemeral_point().unwrap();
        // Phone applies the WRONG shaping (x963) to its partial.
        let wrong = f.partial(&e_point, EcdhAlgo::X963Sha256, e_point.as_x963());
        assert_eq!(rec.decrypt(&m, &wrong), Err(ThresholdError::Aead));
    }

    // --- neither share alone; fail closed ---------------------------------

    #[test]
    fn a_wrong_or_missing_phone_partial_fails_closed() {
        let m = share(12);
        let f = share(22);
        let rec = ThresholdRecord::seal(ACCT, &m, &f.public_point(), EcdhAlgo::RawX, "k", b"tok")
            .unwrap();

        // Wrong Z_F (an attacker who lacks f): the combined K is wrong, GCM fails.
        assert_eq!(rec.decrypt(&m, &[0u8; 32]), Err(ThresholdError::Aead));

        // A different share f' does not open account f's token.
        let other = share(99);
        let e_point = rec.ephemeral_point().unwrap();
        let zf_other = other.partial(&e_point, EcdhAlgo::RawX, e_point.as_x963());
        assert_eq!(rec.decrypt(&m, &zf_other), Err(ThresholdError::Aead));
    }

    #[test]
    fn a_wrong_mac_share_fails_closed() {
        let m = share(13);
        let f = share(23);
        let rec = ThresholdRecord::seal(ACCT, &m, &f.public_point(), EcdhAlgo::RawX, "k", b"tok")
            .unwrap();
        let e_point = rec.ephemeral_point().unwrap();
        let zf = f.partial(&e_point, EcdhAlgo::RawX, e_point.as_x963());
        // The right phone partial but the wrong Mac share still yields no token.
        let wrong_m = share(77);
        assert_eq!(rec.decrypt(&wrong_m, &zf), Err(ThresholdError::Aead));
    }

    // --- R3: version selection --------------------------------------------

    #[test]
    fn a_non_v2_version_fails_closed() {
        let m = share(14);
        let f = share(24);
        let mut rec =
            ThresholdRecord::seal(ACCT, &m, &f.public_point(), EcdhAlgo::RawX, "k", b"tok")
                .unwrap();
        let e_point = rec.ephemeral_point().unwrap();
        let zf = f.partial(&e_point, EcdhAlgo::RawX, e_point.as_x963());

        // Tamper the version: decrypt must refuse rather than mis-route.
        rec.version = 1;
        assert_eq!(
            rec.require_v2(),
            Err(ThresholdError::BadRecordVersion { found: 1 })
        );
        assert_eq!(
            rec.decrypt(&m, &zf),
            Err(ThresholdError::BadRecordVersion { found: 1 })
        );
    }

    // --- R4: unique E per account -----------------------------------------

    #[test]
    fn each_account_gets_a_unique_ephemeral() {
        let m = share(15);
        let f = share(25);
        let f_point = f.public_point();
        let a = ThresholdRecord::seal("a", &m, &f_point, EcdhAlgo::RawX, "k", b"t1").unwrap();
        let b = ThresholdRecord::seal("b", &m, &f_point, EcdhAlgo::RawX, "k", b"t2").unwrap();
        assert_ne!(
            a.ephemeral_pub, b.ephemeral_pub,
            "E must be fresh per account"
        );
        assert!(all_ephemerals_unique(&[a.clone(), b.clone()]));

        // A store with a duplicated E is flagged (fail closed).
        let dup = ThresholdRecord {
            account_id: "c".into(),
            ..a.clone()
        };
        assert!(!all_ephemerals_unique(&[a, dup]));
    }

    // --- partial decode fails closed --------------------------------------

    #[test]
    fn decode_partial_fails_closed_on_bad_input() {
        assert_eq!(decode_partial("not-base64!!"), Err(ThresholdError::Base64));
        assert_eq!(
            decode_partial(&B64.encode([0u8; 16])),
            Err(ThresholdError::ShortPartial)
        );
        let ok = decode_partial(&B64.encode([5u8; 32])).unwrap();
        assert_eq!(*ok, [5u8; 32]);
    }

    #[test]
    fn record_serializes_ecdh_algo_to_pinned_tags() {
        let m = share(16);
        let f = share(26);
        let rec =
            ThresholdRecord::seal(ACCT, &m, &f.public_point(), EcdhAlgo::RawX, "k", b"t").unwrap();
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"ecdhAlgo\":\"raw-x\""));
        assert!(json.contains("\"version\":2"));
        assert!(json.contains("\"kdfAlgo\":\"blake2b-v2\""));

        let x = ThresholdRecord::seal(ACCT, &m, &f.public_point(), EcdhAlgo::X963Sha256, "k", b"t")
            .unwrap();
        assert!(serde_json::to_string(&x)
            .unwrap()
            .contains("\"ecdhAlgo\":\"x963-sha256\""));
    }
}
