//! The pairing-MITM proof suite: the root of trust, executed adversarially.
//!
//! Everything Sigil does after pairing (every secret release, every SSH
//! signature, every lease) rests on the two keys pinned during the ceremony. If
//! the return channel (`PairingResponse`, phone -> Mac, over a hostile network)
//! can be made to pin an attacker's key, the attacker approves its own requests
//! forever. This file is the companion to `hostile_relay.rs`: where that suite
//! proves the *post-pairing* envelope is unbreakable, this one proves the
//! *pairing handshake itself* is MITM-safe.
//!
//! The model matches `docs/design/pairing.md`:
//!
//! * **Mac -> phone (the QR)** is optical, authenticated by physics. The phone
//!   learns the daemon's real keys and the 256-bit one-time secret with
//!   certainty. We do not attack this leg (a MITM here needs a second camera in
//!   the room, not a network position).
//! * **phone -> Mac (the response)** is a network message on a fully hostile
//!   transport that can read, drop, reorder, duplicate, mutate, and manufacture
//!   messages and knows both parties' *public* keys. Every attack below is
//!   mounted here, and every one must be rejected, fail closed, and leave the
//!   one-time secret unburned unless a *cryptographically valid* response
//!   consumed it.
//!
//! If any `#[test]` here starts failing, the product's root of trust is broken.

use sigil_proto::{
    fingerprint_words, verify_sas, DaemonPairing, DeviceIdentity, HandshakeError, PairingPayload,
    PairingResponse, PairingState, PhonePairing, PAIRING_SECRET_TTL_MS,
};

const NOW: u64 = 1_720_000_000_000;

fn endpoints() -> Vec<String> {
    vec![
        "lan://sigil.local:4823".to_string(),
        "https://tide.example.net:4823".to_string(),
    ]
}

/// A freshly minted pairing: the daemon driver plus the QR payload the phone
/// would scan optically. The payload carries the one-time secret, so anything
/// built from it models a party that legitimately saw the QR.
fn mint() -> (DaemonPairing, PairingPayload) {
    DaemonPairing::mint(DeviceIdentity::generate(), endpoints(), NOW)
}

/// Drive the honest phone side to a valid response the daemon will accept.
fn honest_response(payload: &PairingPayload) -> (PhonePairing, PairingResponse) {
    let mut phone = PhonePairing::scan(DeviceIdentity::generate(), payload.clone(), NOW).unwrap();
    let resp = phone.respond().unwrap();
    (phone, resp)
}

// ===========================================================================
// Baseline: the honest ceremony completes and pins the real phone.
// ===========================================================================

#[test]
fn honest_ceremony_pins_the_real_phone() {
    let (mut daemon, payload) = mint();
    let (phone, resp) = honest_response(&payload);
    let pinned = daemon.receive_response(&resp, NOW + 1_000).unwrap();
    assert_eq!(pinned, phone.phone_identity());
    assert_eq!(daemon.state(), PairingState::ResponseReceived);
    // Both screens show the same six words over the same pinned pair.
    assert_eq!(daemon.sas_words().unwrap(), phone.sas_words());
}

// ===========================================================================
// The core MITM: key substitution on the return channel.
//
// A network attacker who never saw the QR wants the daemon to pin *its* key so
// it can approve its own requests. It can only mutate the response in flight.
// The confirmation tag is keyed by the secret (which the attacker lacks) over a
// transcript that binds the phone identity, so every substitution is rejected
// with BadTag and the secret is never burned.
// ===========================================================================

#[test]
fn full_phone_identity_substitution_is_rejected() {
    let (mut daemon, payload) = mint();
    let (_phone, mut resp) = honest_response(&payload);

    // The classic MITM: replace the phone's whole identity with the attacker's.
    resp.phone = DeviceIdentity::generate().peer_identity();

    assert_eq!(
        daemon.receive_response(&resp, NOW),
        Err(HandshakeError::BadTag)
    );
    // Failed attempt must NOT consume the one-time secret.
    assert_eq!(daemon.state(), PairingState::Init);
}

#[test]
fn phone_agreement_key_substitution_alone_is_rejected() {
    // The attacker keeps the real verifying key but swaps in its own X25519
    // agreement key, hoping the DEK will later be sealed to a box it can open.
    let (mut daemon, payload) = mint();
    let (_phone, mut resp) = honest_response(&payload);
    let attacker = DeviceIdentity::generate().peer_identity();
    resp.phone.agreement = attacker.agreement;
    assert_eq!(
        daemon.receive_response(&resp, NOW),
        Err(HandshakeError::BadTag)
    );
    assert_eq!(daemon.state(), PairingState::Init);
}

#[test]
fn phone_verifying_key_substitution_alone_is_rejected() {
    // The attacker keeps the real agreement key but swaps in its own Ed25519
    // verifying key, hoping to forge future response signatures.
    let (mut daemon, payload) = mint();
    let (_phone, mut resp) = honest_response(&payload);
    let attacker = DeviceIdentity::generate().peer_identity();
    resp.phone.verifying = attacker.verifying;
    assert_eq!(
        daemon.receive_response(&resp, NOW),
        Err(HandshakeError::BadTag)
    );
    assert_eq!(daemon.state(), PairingState::Init);
}

// ===========================================================================
// Tag forgery / stripping.
// ===========================================================================

#[test]
fn forged_random_tag_is_rejected() {
    let (mut daemon, payload) = mint();
    let (_phone, mut resp) = honest_response(&payload);
    // Attacker guesses a tag (no secret => cannot compute the real one).
    resp.tag = [0xAB; 32];
    assert_eq!(
        daemon.receive_response(&resp, NOW),
        Err(HandshakeError::BadTag)
    );
    assert_eq!(daemon.state(), PairingState::Init);
}

#[test]
fn stripped_zero_tag_is_rejected() {
    let (mut daemon, payload) = mint();
    let (_phone, mut resp) = honest_response(&payload);
    // "Strip" the tag to all zeros: still a wrong MAC, still rejected.
    resp.tag = [0u8; 32];
    assert_eq!(
        daemon.receive_response(&resp, NOW),
        Err(HandshakeError::BadTag)
    );
}

#[test]
fn single_bit_flip_in_tag_is_rejected() {
    let (mut daemon, payload) = mint();
    let (_phone, mut resp) = honest_response(&payload);
    resp.tag[17] ^= 0x01;
    assert_eq!(
        daemon.receive_response(&resp, NOW),
        Err(HandshakeError::BadTag)
    );
}

// ===========================================================================
// Nonce tamper: the nonce is bound into the transcript, so mutating it in
// flight invalidates the tag the honest phone computed over the original nonce.
// ===========================================================================

#[test]
fn nonce_tamper_is_rejected() {
    let (mut daemon, payload) = mint();
    let (_phone, mut resp) = honest_response(&payload);
    resp.nonce[0] ^= 0x01;
    assert_eq!(
        daemon.receive_response(&resp, NOW),
        Err(HandshakeError::BadTag)
    );
}

// ===========================================================================
// Wrong secret: an attacker that never saw the QR has no secret. Even building
// a perfectly well-formed response with its own (guessed) secret fails, because
// the daemon MACs with the real secret it minted.
// ===========================================================================

#[test]
fn response_built_without_the_qr_secret_is_rejected() {
    let daemon_id = DeviceIdentity::generate();
    let daemon_pub = daemon_id.peer_identity();
    let (mut daemon, _payload) = DaemonPairing::mint(daemon_id, endpoints(), NOW);

    // Attacker fabricates a payload with the RIGHT public fields but a WRONG
    // secret (it never optically saw the real one), and responds to it.
    let forged_payload = PairingPayload {
        daemon: daemon_pub,
        endpoints: endpoints(),
        secret: sigil_proto::PairingSecret::generate(),
        created_at: NOW,
    };
    let attacker_phone = DeviceIdentity::generate();
    let resp = PairingResponse::create(&forged_payload, &attacker_phone.peer_identity());

    assert_eq!(
        daemon.receive_response(&resp, NOW),
        Err(HandshakeError::BadTag)
    );
}

// ===========================================================================
// Transcript binding: mutate EVERY bound field independently and confirm the
// tag no longer verifies. This is the exhaustive proof that each field named in
// `pairing_transcript` actually earns its place.
// ===========================================================================

#[test]
fn transcript_binds_daemon_identity() {
    let (_d, payload) = mint();
    let (_phone, resp) = honest_response(&payload);
    // A response tagged for this pairing must not verify against a different
    // daemon identity, and must verify against the honest one.
    let other_daemon = DeviceIdentity::generate().peer_identity();
    assert!(
        !resp.verify(
            &other_daemon,
            &payload.endpoints,
            payload.created_at,
            &payload.secret
        ),
        "a swapped daemon identity must break the tag"
    );
    assert!(
        resp.verify(
            &payload.daemon,
            &payload.endpoints,
            payload.created_at,
            &payload.secret
        ),
        "the honest daemon identity must verify"
    );
}

#[test]
fn transcript_binds_endpoints() {
    let (_d, payload) = mint();
    let (_phone, resp) = honest_response(&payload);
    let mut tampered = payload.endpoints.clone();
    tampered.push("https://attacker.example.net:4823".to_string());
    assert!(
        !resp.verify(
            &payload.daemon,
            &tampered,
            payload.created_at,
            &payload.secret
        ),
        "an added endpoint must break the tag"
    );
    let mutated = vec!["lan://evil.local:4823".to_string()];
    assert!(
        !resp.verify(
            &payload.daemon,
            &mutated,
            payload.created_at,
            &payload.secret
        ),
        "a rewritten endpoint must break the tag"
    );
}

#[test]
fn transcript_binds_created_at() {
    let (_d, payload) = mint();
    let (_phone, resp) = honest_response(&payload);
    assert!(
        !resp.verify(
            &payload.daemon,
            &payload.endpoints,
            payload.created_at + 1,
            &payload.secret
        ),
        "a shifted created_at must break the tag"
    );
}

#[test]
fn transcript_binds_phone_identity_and_nonce() {
    let (_d, payload) = mint();
    let (_phone, mut resp) = honest_response(&payload);

    // Phone verifying key.
    let mut r = resp.clone();
    r.phone.verifying = DeviceIdentity::generate().peer_identity().verifying;
    assert!(!r.verify(
        &payload.daemon,
        &payload.endpoints,
        payload.created_at,
        &payload.secret
    ));

    // Phone agreement key.
    let mut r = resp.clone();
    r.phone.agreement = DeviceIdentity::generate().peer_identity().agreement;
    assert!(!r.verify(
        &payload.daemon,
        &payload.endpoints,
        payload.created_at,
        &payload.secret
    ));

    // Nonce.
    resp.nonce[31] ^= 0x80;
    assert!(!resp.verify(
        &payload.daemon,
        &payload.endpoints,
        payload.created_at,
        &payload.secret
    ));
}

// ===========================================================================
// Expiry: a photographed QR is only useful for the secret's lifetime. Expiry is
// checked BEFORE the tag, so a late-but-valid response is refused for expiry.
// ===========================================================================

#[test]
fn expired_response_is_rejected_before_the_tag() {
    let (mut daemon, payload) = mint();
    // Let the phone scan with a relaxed QR TTL so only the daemon-side expiry
    // fires here.
    let mut phone = PhonePairing::scan(DeviceIdentity::generate(), payload, NOW)
        .unwrap()
        .with_qr_ttl(u64::MAX);
    let resp = phone.respond().unwrap();
    let late = NOW + PAIRING_SECRET_TTL_MS + 1;
    assert_eq!(
        daemon.receive_response(&resp, late),
        Err(HandshakeError::SecretExpired {
            age_ms: PAIRING_SECRET_TTL_MS + 1,
            limit_ms: PAIRING_SECRET_TTL_MS,
        })
    );
    // Even expiry does not burn the secret; the state is untouched.
    assert_eq!(daemon.state(), PairingState::Init);
}

#[test]
fn phone_rejects_a_stale_qr_at_scan() {
    let (_d, payload) = mint();
    let late = payload.created_at + PAIRING_SECRET_TTL_MS + 1;
    assert!(matches!(
        PhonePairing::scan(DeviceIdentity::generate(), payload, late),
        Err(HandshakeError::SecretExpired { .. })
    ));
}

// ===========================================================================
// Secret-exhaustion resistance and one-time use.
// ===========================================================================

#[test]
fn a_flood_of_bad_responses_never_burns_the_secret() {
    let (mut daemon, payload) = mint();
    let (_phone, good) = honest_response(&payload);

    // The relay sprays 100 garbage responses. None consumes the secret.
    for i in 0..100u8 {
        let mut junk = good.clone();
        junk.tag[0] = i;
        junk.phone = DeviceIdentity::generate().peer_identity();
        assert_eq!(
            daemon.receive_response(&junk, NOW),
            Err(HandshakeError::BadTag)
        );
        assert_eq!(daemon.state(), PairingState::Init);
    }
    // The honest response still succeeds afterwards: the secret survived.
    assert!(daemon.receive_response(&good, NOW).is_ok());
}

#[test]
fn a_second_valid_response_is_refused_after_the_first() {
    // Two phones scanned the same QR (secret leaked to a second scanner). The
    // first valid response burns the secret; the second, though its tag is
    // perfect, is refused as SecretConsumed.
    let (mut daemon, payload) = mint();
    let mut phone_a = PhonePairing::scan(DeviceIdentity::generate(), payload.clone(), NOW).unwrap();
    let mut phone_b = PhonePairing::scan(DeviceIdentity::generate(), payload, NOW).unwrap();
    let resp_a = phone_a.respond().unwrap();
    let resp_b = phone_b.respond().unwrap();

    assert!(daemon.receive_response(&resp_a, NOW).is_ok());
    assert_eq!(
        daemon.receive_response(&resp_b, NOW),
        Err(HandshakeError::SecretConsumed)
    );
}

#[test]
fn the_phone_emits_exactly_one_response() {
    let (_d, payload) = mint();
    let mut phone = PhonePairing::scan(DeviceIdentity::generate(), payload, NOW).unwrap();
    assert!(phone.respond().is_ok());
    assert!(matches!(
        phone.respond(),
        Err(HandshakeError::SecretConsumed)
    ));
}

// ===========================================================================
// Cross-pairing replay: a response captured from one pairing is worthless
// against any other, because both the daemon identity and the secret differ.
// ===========================================================================

#[test]
fn a_captured_response_is_worthless_against_a_fresh_pairing() {
    let (_daemon_a, payload_a) = mint();
    let (_phone_a, resp_a) = honest_response(&payload_a);

    // A brand-new pairing B (different daemon identity, different secret).
    let (mut daemon_b, _payload_b) = mint();
    assert_eq!(
        daemon_b.receive_response(&resp_a, NOW),
        Err(HandshakeError::BadTag)
    );
    assert_eq!(daemon_b.state(), PairingState::Init);
}

// ===========================================================================
// SAS: the human backstop. Even if the confirmation tag's assumptions failed
// (the secret leaked and the attacker forged a valid response with its OWN
// key), the six words computed over the two PINNED identities diverge on the
// two screens, and the human catches it.
// ===========================================================================

#[test]
fn sas_catches_a_leaked_secret_mitm() {
    // The attacker photographed the QR, so it HAS the secret and can forge a
    // response that the daemon accepts, pinning the attacker's key.
    let (mut daemon, payload) = mint();
    let honest_phone = DeviceIdentity::generate().peer_identity();
    let attacker = DeviceIdentity::generate().peer_identity();

    let forged = PairingResponse::create(&payload, &attacker);
    // The tag verifies (the attacker had the secret), so the daemon pins the
    // attacker. This is the one case the tag alone cannot stop.
    let pinned = daemon.receive_response(&forged, NOW).unwrap();
    assert_eq!(pinned, attacker);

    // But the daemon's SAS words are over (daemon, attacker), while the honest
    // phone's screen shows (daemon, honest_phone). They diverge, so the human
    // reading both screens aloud sees the mismatch and aborts.
    let daemon_words = daemon.sas_words().unwrap();
    let honest_words = fingerprint_words(&payload.daemon, &honest_phone);
    assert_ne!(
        daemon_words, honest_words,
        "SAS must diverge when the daemon pinned the attacker's key"
    );
    assert!(!verify_sas(&payload.daemon, &honest_phone, &daemon_words));
}

#[test]
fn sas_words_diverge_whenever_the_pinned_pair_differs() {
    let daemon_a = DeviceIdentity::generate().peer_identity();
    let daemon_b = DeviceIdentity::generate().peer_identity();
    let phone = DeviceIdentity::generate().peer_identity();

    let a = fingerprint_words(&daemon_a, &phone);
    let b = fingerprint_words(&daemon_b, &phone);
    assert_ne!(a, b);
    assert!(verify_sas(&daemon_a, &phone, &a));
    assert!(!verify_sas(&daemon_b, &phone, &a));
}
