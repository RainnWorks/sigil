//! The approve proof: per-request evidence that a biometrically-gated hardware
//! key was used to authorize THIS request with THIS decision.
//!
//! This is what closes invariant 4 on the plain-gate path (see
//! `docs/security-claims.md` §20). It is the **shared crypto core** for both
//! sides, mirrored byte-for-byte by the phone's TypeScript and locked by the
//! `approveProof` category in
//! `apps/phone/src/protocol/__vectors__/sigil-vectors.json`.
//!
//! # The construction
//!
//! ```text
//! daemon, per request:  c ← random,  C = c·G          (ephemeral, RAM only)
//! phone, on approve:    Z = shape( x(f·C), algo, C )  (Secure Enclave, Face ID)
//! both:                 proof = BLAKE2b-256( "sigil.approve-proof.v1"
//!                                          ‖ len·Z
//!                                          ‖ len·request_id
//!                                          ‖ len·decision
//!                                          ‖ len·lease )
//! daemon verifies:      proof == BLAKE2b-256( … shape(x(c·F), algo, C) … )
//! ```
//!
//! `f` is the phone's non-exportable Secure-Enclave key, minted under
//! `[.privateKeyUsage, .biometryCurrentSet]`, and `F = f·G` is pinned in the
//! pairing record. ECDH commutes, so `x(f·C) = x(c·F)`: the daemon can check the
//! proof without ever holding `f`, and only the holder of `f` can produce it.
//!
//! # Why the proof is a HASH and never the raw x-coordinate
//!
//! **Do not "simplify" this by putting `Z` on the wire.** The daemon chooses the
//! point the phone multiplies its enclave key against, so the proof field is a
//! chosen-point ECDH oracle on `f`. If the raw output crossed the wire, a
//! challenge set to a sealed record's base `E` would make the plain-gate path
//! return `Z_F = x(f·E)` for that account: the exact value
//! [`crate::threshold::combine`] needs to open it. Hashing with a domain distinct
//! from [`crate::threshold::THRESHOLD_DOMAIN`] means the value returned here can
//! never be substituted into the combiner, whatever point the challenge carries.
//!
//! # Why it binds the decision and the lease
//!
//! An unbound proof would only attest "a biometric happened", leaving a captured
//! proof reusable to flip a deny into an approve or to widen a lease window. The
//! preimage covers `request_id`, the decision tag, and the requested lease TTL, so
//! a proof authorizes exactly one request, one decision, one window. The TTL bound
//! here is the one the PHONE sent (what the human consented to); the daemon still
//! clamps it down afterwards per the rule's [`crate::request::LeasePolicy`],
//! because clamping down is always safe.
//!
//! # What this does NOT prove
//!
//! The daemon cannot distinguish an enclave-held `f` from a software-held `f`:
//! there is no key attestation anywhere in this construction, and
//! `sigil-softphone` demonstrates the limit by satisfying every check below with a
//! software scalar. The honest claim is that the phone app contains no code path
//! that approves without a biometrically-gated hardware key operation, NOT that
//! the daemon verifies an enclave was used. Closing that would need pairing-time
//! `SecKeyCreateAttestation` against Apple's attestation root; it is out of scope
//! here and recorded as a residual.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::threshold::{
    shape, EcdhAlgo, P256Point, ThresholdError, P256_X963_POINT_LEN, XCOORD_LEN,
};

/// A 32-byte BLAKE2b, matching the combiner digest width. libsodium's
/// `crypto_generichash` with `outlen = 32` is the byte-exact mirror.
type Blake2b256 = Blake2b<U32>;

/// Domain separator for the approve proof. Deliberately distinct from
/// [`crate::threshold::THRESHOLD_DOMAIN`]: that distinctness is what stops a proof
/// ever being substituted for a combiner share. Absorbed raw (no length prefix),
/// exactly as the threshold and pairing domains are.
pub const APPROVE_PROOF_DOMAIN: &[u8] = b"sigil.approve-proof.v1";

/// Length of the proof that crosses the wire.
pub const PROOF_LEN: usize = 32;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ProofError {
    #[error("approve proof is not exactly 32 bytes")]
    ShortProof,
    #[error("base64 decode failed")]
    Base64,
    #[error("approve proof did not match the challenge issued for this request")]
    Mismatch,
    #[error("threshold key material is invalid: {0}")]
    Point(#[from] ThresholdError),
}

/// Length-prefix `field` into `h` (big-endian u64), the injective absorb the
/// envelope, pairing transcript, and threshold combiner all use.
fn absorb(h: &mut Blake2b256, field: &[u8]) {
    h.update((field.len() as u64).to_be_bytes());
    h.update(field);
}

/// The preimage hash, computed identically by the daemon and the phone.
///
/// `shared` is the shaped ECDH output: `x(f·C)` on the phone, `x(c·F)` on the
/// daemon. `decision` is the exact wire tag (`"approved"` / `"denied"`), which
/// callers get from [`crate::request::Decision::wire_tag`] rather than spelling
/// out. `lease_ttl_ms` is the window the phone requested, or `None` for a
/// run-once approve; the two cases are distinguishable because an absent lease
/// absorbs a zero-length field and a present one absorbs eight bytes.
pub fn approve_proof(
    shared: &[u8; XCOORD_LEN],
    request_id: &str,
    decision: &str,
    lease_ttl_ms: Option<u64>,
) -> [u8; PROOF_LEN] {
    let mut h = Blake2b256::new();
    h.update(APPROVE_PROOF_DOMAIN);
    absorb(&mut h, shared.as_slice());
    absorb(&mut h, request_id.as_bytes());
    absorb(&mut h, decision.as_bytes());
    match lease_ttl_ms {
        Some(ttl) => absorb(&mut h, &ttl.to_be_bytes()),
        None => absorb(&mut h, &[]),
    }
    let digest = h.finalize();
    let mut out = [0u8; PROOF_LEN];
    out.copy_from_slice(&digest);
    out
}

/// The daemon's per-request challenge: an ephemeral P-256 scalar `c` and its
/// public point `C = c·G`.
///
/// **RAM only, one request, one use.** It is minted in
/// `RemoteApprover::build_request`, held beside the in-flight waiter, and dropped
/// (zeroizing `c`, which `SecretKey` does on drop) when the request reaches a
/// terminal state. It is never persisted, never reused across requests, and never
/// survives a daemon restart, so a restart mid-request fails closed.
pub struct ApproveChallenge {
    secret: SecretKey,
    public_x963: [u8; P256_X963_POINT_LEN],
}

impl ApproveChallenge {
    /// Mint a fresh challenge from the platform CSPRNG.
    pub fn generate() -> Self {
        let secret = SecretKey::random(&mut rand_core::OsRng);
        let enc = secret.public_key().to_encoded_point(false);
        let mut public_x963 = [0u8; P256_X963_POINT_LEN];
        // A freshly derived public key always re-encodes as a valid 65-byte point.
        public_x963.copy_from_slice(enc.as_bytes());
        Self {
            secret,
            public_x963,
        }
    }

    /// The canonical 65-byte X9.63 encoding of `C`, as folded into the proof's
    /// X9.63 shaping and stored for reproduction.
    pub fn public_x963(&self) -> &[u8; P256_X963_POINT_LEN] {
        &self.public_x963
    }

    /// `C` in the standard-base64 X9.63 form that rides on the wire as
    /// [`crate::request::ApprovalRequest::proof_challenge`].
    pub fn to_wire(&self) -> String {
        B64.encode(self.public_x963)
    }

    /// The shaped ECDH output the phone will independently compute as
    /// `shape(x(f·C), algo, C)`. Computed here as `shape(x(c·F), algo, C)`; the two
    /// are equal because ECDH commutes.
    ///
    /// `phone_f` is the pinned `F` from the pairing record, already validated
    /// on-curve by [`P256Point::from_x963`], so no unvalidated point ever reaches
    /// a scalar multiplication.
    fn shared_with(&self, phone_f: &P256Point, algo: EcdhAlgo) -> Zeroizing<[u8; XCOORD_LEN]> {
        let shared = diffie_hellman(self.secret.to_nonzero_scalar(), phone_f.as_affine());
        let mut raw = Zeroizing::new([0u8; XCOORD_LEN]);
        raw.copy_from_slice(shared.raw_secret_bytes().as_slice());
        shape(&raw, algo, &self.public_x963)
    }

    /// The proof this challenge expects for the given binding.
    pub fn expected_proof(
        &self,
        phone_f: &P256Point,
        algo: EcdhAlgo,
        request_id: &str,
        decision: &str,
        lease_ttl_ms: Option<u64>,
    ) -> [u8; PROOF_LEN] {
        let shared = self.shared_with(phone_f, algo);
        approve_proof(&shared, request_id, decision, lease_ttl_ms)
    }

    /// Verify a base64 proof from the wire against this challenge and binding.
    ///
    /// Fails closed on a malformed, short, or non-matching proof, all without
    /// leaking which via timing: the comparison is constant-time. Every error is a
    /// denial at the call site.
    pub fn verify(
        &self,
        proof_b64: &str,
        phone_f: &P256Point,
        algo: EcdhAlgo,
        request_id: &str,
        decision: &str,
        lease_ttl_ms: Option<u64>,
    ) -> Result<(), ProofError> {
        let bytes = B64.decode(proof_b64).map_err(|_| ProofError::Base64)?;
        let got: [u8; PROOF_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProofError::ShortProof)?;
        let want = self.expected_proof(phone_f, algo, request_id, decision, lease_ttl_ms);
        if got.ct_eq(&want).into() {
            Ok(())
        } else {
            Err(ProofError::Mismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::{MacShare, ThresholdRecord};

    /// Stand in for the Secure Enclave: a software scalar `f` whose public point is
    /// the `F` a pairing pins. This is exactly the substitution `sigil-softphone`
    /// makes, and exactly why the daemon cannot prove enclave residency.
    fn phone_key() -> (MacShare, P256Point) {
        let f = MacShare::generate();
        let f_pub = f.public_point();
        (f, f_pub)
    }

    fn phone_side(
        f: &MacShare,
        challenge_x963: &[u8; P256_X963_POINT_LEN],
        algo: EcdhAlgo,
        request_id: &str,
        decision: &str,
        lease_ttl_ms: Option<u64>,
    ) -> String {
        let c_point = P256Point::from_x963(challenge_x963).expect("challenge is on-curve");
        let shared = f.partial(&c_point, algo, challenge_x963);
        B64.encode(approve_proof(&shared, request_id, decision, lease_ttl_ms))
    }

    #[test]
    fn the_two_sides_agree_because_ecdh_commutes() {
        for algo in [EcdhAlgo::RawX, EcdhAlgo::X963Sha256] {
            let (f, f_pub) = phone_key();
            let challenge = ApproveChallenge::generate();
            let proof = phone_side(&f, challenge.public_x963(), algo, "req-1", "approved", None);
            assert!(challenge
                .verify(&proof, &f_pub, algo, "req-1", "approved", None)
                .is_ok());
        }
    }

    #[test]
    fn a_proof_for_one_request_does_not_verify_for_another() {
        let (f, f_pub) = phone_key();
        let challenge = ApproveChallenge::generate();
        let proof = phone_side(
            &f,
            challenge.public_x963(),
            EcdhAlgo::RawX,
            "req-A",
            "approved",
            None,
        );
        assert_eq!(
            challenge
                .verify(&proof, &f_pub, EcdhAlgo::RawX, "req-B", "approved", None)
                .unwrap_err(),
            ProofError::Mismatch
        );
    }

    #[test]
    fn a_proof_from_a_different_challenge_does_not_verify() {
        let (f, f_pub) = phone_key();
        let seen = ApproveChallenge::generate();
        let fresh = ApproveChallenge::generate();
        let proof = phone_side(
            &f,
            seen.public_x963(),
            EcdhAlgo::RawX,
            "req-1",
            "approved",
            None,
        );
        assert_eq!(
            fresh
                .verify(&proof, &f_pub, EcdhAlgo::RawX, "req-1", "approved", None)
                .unwrap_err(),
            ProofError::Mismatch
        );
    }

    #[test]
    fn the_decision_is_bound_so_a_deny_proof_cannot_approve() {
        let (f, f_pub) = phone_key();
        let challenge = ApproveChallenge::generate();
        let proof = phone_side(
            &f,
            challenge.public_x963(),
            EcdhAlgo::RawX,
            "req-1",
            "denied",
            None,
        );
        assert_eq!(
            challenge
                .verify(&proof, &f_pub, EcdhAlgo::RawX, "req-1", "approved", None)
                .unwrap_err(),
            ProofError::Mismatch
        );
    }

    #[test]
    fn the_lease_window_is_bound_in_both_directions() {
        let (f, f_pub) = phone_key();
        let challenge = ApproveChallenge::generate();
        let proof = phone_side(
            &f,
            challenge.public_x963(),
            EcdhAlgo::RawX,
            "req-1",
            "approved",
            Some(60_000),
        );
        // Widened.
        assert!(challenge
            .verify(
                &proof,
                &f_pub,
                EcdhAlgo::RawX,
                "req-1",
                "approved",
                Some(3_600_000)
            )
            .is_err());
        // Stripped entirely.
        assert!(challenge
            .verify(&proof, &f_pub, EcdhAlgo::RawX, "req-1", "approved", None)
            .is_err());
        // Unchanged.
        assert!(challenge
            .verify(
                &proof,
                &f_pub,
                EcdhAlgo::RawX,
                "req-1",
                "approved",
                Some(60_000)
            )
            .is_ok());
    }

    /// An absent lease and a zero-millisecond lease must not collide, which is why
    /// the absent case absorbs a zero-LENGTH field rather than a zero VALUE.
    #[test]
    fn an_absent_lease_is_not_a_zero_lease() {
        let shared = [7u8; XCOORD_LEN];
        assert_ne!(
            approve_proof(&shared, "req-1", "approved", None),
            approve_proof(&shared, "req-1", "approved", Some(0))
        );
    }

    /// The whole reason the proof is a hash. A challenge point set to a sealed
    /// record's base `E` must not yield anything a combiner would accept as `Z_F`.
    #[test]
    fn a_proof_is_never_usable_as_a_threshold_partial() {
        // The attack this pins: a daemon asks the plain-gate path to prove
        // against a challenge it has set to a SEALED ACCOUNT'S base point `E`,
        // hoping the answer is the combiner share for that account. Asserting
        // `proof != zf` would not prove anything (any non-identity function
        // passes that, a flipped bit included), so feed the proof to the
        // combiner as if it were the partial and require the AEAD to refuse.
        let (f, f_pub) = phone_key();
        let m = MacShare::generate();
        let record = ThresholdRecord::seal(
            "acct",
            &m,
            &f_pub,
            EcdhAlgo::RawX,
            "phone-se.v2",
            b"the-secret",
        )
        .expect("seal");

        let e = record.ephemeral_point().expect("record E is on-curve");
        let zf = f.partial(&e, EcdhAlgo::RawX, e.as_x963());
        // The real partial opens it, so the fixture is genuinely the live path.
        assert_eq!(
            &*record.decrypt(&m, &zf).expect("the real partial opens it"),
            b"the-secret"
        );

        // The proof over that same point does not, which is what the hash buys.
        let proof = approve_proof(&zf, "req-1", "approved", None);
        assert!(
            record.decrypt(&m, &proof).is_err(),
            "a proof substituted for the partial must not open the record"
        );
    }

    /// Domain separation, stated as a test so a later reader cannot fold the two
    /// hashes into one helper.
    #[test]
    fn the_proof_domain_is_distinct_from_the_threshold_domain() {
        // Distinct constants are necessary and nowhere near sufficient: what
        // must hold is that the two derivations cannot be folded together, so
        // check the OUTPUTS over one shared secret rather than the labels.
        assert_ne!(APPROVE_PROOF_DOMAIN, crate::threshold::THRESHOLD_DOMAIN);
        assert!(
            !APPROVE_PROOF_DOMAIN.starts_with(crate::threshold::THRESHOLD_DOMAIN)
                && !crate::threshold::THRESHOLD_DOMAIN.starts_with(APPROVE_PROOF_DOMAIN),
            "neither domain may prefix the other: the constants are raw, not length-prefixed"
        );

        let (f, f_pub) = phone_key();
        let m = MacShare::generate();
        let record = ThresholdRecord::seal(
            "acct",
            &m,
            &f_pub,
            EcdhAlgo::RawX,
            "phone-se.v2",
            b"the-secret",
        )
        .expect("seal");
        let e = record.ephemeral_point().expect("record E is on-curve");
        let zf = f.partial(&e, EcdhAlgo::RawX, e.as_x963());

        // One shared secret, two derivations, and the proof must not land on the
        // combiner's key material for it.
        let proof = approve_proof(&zf, "req-1", "approved", None);
        assert_ne!(proof, *zf, "the proof must not be the partial itself");
        assert!(
            record.decrypt(&m, &proof).is_err(),
            "the proof must not open what the partial opens"
        );
    }

    #[test]
    fn a_malformed_proof_fails_closed_rather_than_matching() {
        let (_f, f_pub) = phone_key();
        let challenge = ApproveChallenge::generate();
        assert_eq!(
            challenge
                .verify(
                    "!!not base64!!",
                    &f_pub,
                    EcdhAlgo::RawX,
                    "r",
                    "approved",
                    None
                )
                .unwrap_err(),
            ProofError::Base64
        );
        assert_eq!(
            challenge
                .verify(
                    &B64.encode([0u8; 16]),
                    &f_pub,
                    EcdhAlgo::RawX,
                    "r",
                    "approved",
                    None
                )
                .unwrap_err(),
            ProofError::ShortProof
        );
        assert_eq!(
            challenge
                .verify(
                    &B64.encode([0u8; 32]),
                    &f_pub,
                    EcdhAlgo::RawX,
                    "r",
                    "approved",
                    None
                )
                .unwrap_err(),
            ProofError::Mismatch
        );
    }

    #[test]
    fn every_challenge_is_fresh() {
        let a = ApproveChallenge::generate();
        let b = ApproveChallenge::generate();
        assert_ne!(a.public_x963(), b.public_x963());
    }

    #[test]
    fn the_wire_form_round_trips_through_the_validating_decoder() {
        let challenge = ApproveChallenge::generate();
        let decoded = B64.decode(challenge.to_wire()).expect("valid base64");
        let point = P256Point::from_x963(&decoded).expect("challenge is on-curve");
        assert_eq!(point.as_x963(), challenge.public_x963());
    }
}
