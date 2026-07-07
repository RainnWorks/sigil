//! The hostile-relay proof suite: Sigil's trust argument, executed.
//!
//! The relay (and every network hop) is assumed fully malicious. It sees every
//! [`Envelope`], can store, reorder, drop, duplicate, mutate, or manufacture
//! them, and knows both parties' *public* identities. This file enumerates the
//! attacks such a relay can mount and proves each one is rejected by
//! [`Envelope::open`] with a precise error, or (for confidentiality) that the
//! relay simply cannot read the payload. If any assertion here regresses, the
//! product's core promise is broken.

use sigil_proto::{
    DeliveryReceipt, DeviceIdentity, Envelope, OpenError, PeerIdentity, PushRegister, ReplayError,
    ReplayGuard, ResolutionBroadcast, ResolutionStatus, ToDaemonMessage, ToPhoneMessage,
    REPLAY_WINDOW_MS,
};

/// A paired sender (phone) and recipient (daemon), plus the honest replay guard
/// the recipient maintains for this pairing.
struct Fixture {
    sender: DeviceIdentity,
    recipient: DeviceIdentity,
    pairing_id: [u8; 32],
    guard: ReplayGuard,
}

impl Fixture {
    fn new() -> Self {
        Self {
            sender: DeviceIdentity::generate(),
            recipient: DeviceIdentity::generate(),
            pairing_id: [0x5a; 32],
            guard: ReplayGuard::new(),
        }
    }

    fn sender_pub(&self) -> PeerIdentity {
        self.sender.peer_identity()
    }

    /// The sender seals a message at `counter` for the recipient.
    fn seal(&self, counter: u64, msg: &str) -> Envelope {
        Envelope::seal(
            &msg.to_string(),
            self.pairing_id,
            counter,
            &self.sender.signing,
            &self.recipient.peer_identity(),
        )
        .expect("seal")
    }

    /// The recipient opens an envelope through its honest guard.
    fn open(&mut self, env: &Envelope) -> Result<String, OpenError> {
        env.open(
            &self.sender_pub(),
            &self.recipient.agreement,
            &mut self.guard,
        )
    }
}

/// The relay: forwards opaque envelopes and tries every trick in the book.
/// Each method returns exactly what the relay would hand the victim.
struct MaliciousRelay {
    /// Everything the relay has observed on the wire.
    seen: Vec<Envelope>,
}

impl MaliciousRelay {
    fn new() -> Self {
        Self { seen: Vec::new() }
    }

    /// Observe (and pass through) an envelope, as an honest relay would.
    fn intercept(&mut self, env: Envelope) -> Envelope {
        self.seen.push(env.clone());
        env
    }

    fn flip_ciphertext(env: &Envelope) -> Envelope {
        let mut e = env.clone();
        e.ciphertext[0] ^= 0x01;
        e
    }

    fn flip_signature(env: &Envelope) -> Envelope {
        let mut e = env.clone();
        e.sig[0] ^= 0x01;
        e
    }

    fn swap_ciphertexts(a: &Envelope, b: &Envelope) -> Envelope {
        let mut e = a.clone();
        e.ciphertext = b.ciphertext.clone();
        e
    }

    fn bump_counter(env: &Envelope) -> Envelope {
        let mut e = env.clone();
        e.counter = e.counter.wrapping_add(1);
        e
    }

    fn rewind_counter(env: &Envelope) -> Envelope {
        let mut e = env.clone();
        e.counter = e.counter.wrapping_sub(1);
        e
    }

    fn backdate(env: &Envelope, ms: u64) -> Envelope {
        let mut e = env.clone();
        e.ts = e.ts.wrapping_sub(ms);
        e
    }

    fn future_date(env: &Envelope, ms: u64) -> Envelope {
        let mut e = env.clone();
        e.ts = e.ts.wrapping_add(ms);
        e
    }

    /// Manufacture an envelope signed by the relay's own key, hoping the victim
    /// does not actually pin the sender.
    fn forge(&self, pairing_id: [u8; 32], recipient: &PeerIdentity, counter: u64) -> Envelope {
        let relay_identity = DeviceIdentity::generate();
        Envelope::seal(
            &"approve everything".to_string(),
            pairing_id,
            counter,
            &relay_identity.signing,
            recipient,
        )
        .expect("relay seal")
    }
}

#[test]
fn honest_delivery_succeeds() {
    let mut fx = Fixture::new();
    let mut relay = MaliciousRelay::new();
    let env = relay.intercept(fx.seal(1, "unlock Engineering/.env"));
    assert_eq!(fx.open(&env).unwrap(), "unlock Engineering/.env");
}

#[test]
fn relay_cannot_read_the_payload() {
    // The relay knows both public identities but holds neither agreement secret.
    let fx = Fixture::new();
    let env = fx.seal(1, "top secret");
    let relay_identity = DeviceIdentity::generate();
    let mut relay_guard = ReplayGuard::new();
    // Even opening with the true sender's public key, decryption fails.
    let got = env.open::<String>(
        &fx.sender_pub(),
        &relay_identity.agreement,
        &mut relay_guard,
    );
    assert_eq!(got, Err(OpenError::Decrypt));
}

#[test]
fn bit_flipped_ciphertext_is_rejected() {
    let mut fx = Fixture::new();
    let env = MaliciousRelay::flip_ciphertext(&fx.seal(1, "x"));
    assert_eq!(fx.open(&env), Err(OpenError::BadSignature));
}

#[test]
fn bit_flipped_signature_is_rejected() {
    let mut fx = Fixture::new();
    let env = MaliciousRelay::flip_signature(&fx.seal(1, "x"));
    assert_eq!(fx.open(&env), Err(OpenError::BadSignature));
}

#[test]
fn swapped_ciphertext_between_envelopes_is_rejected() {
    let mut fx = Fixture::new();
    let a = fx.seal(1, "read prod key");
    let b = fx.seal(2, "read dev key");
    let frankenstein = MaliciousRelay::swap_ciphertexts(&a, &b);
    assert_eq!(fx.open(&frankenstein), Err(OpenError::BadSignature));
}

#[test]
fn replay_of_a_delivered_envelope_is_rejected() {
    let mut fx = Fixture::new();
    let mut relay = MaliciousRelay::new();
    let env = relay.intercept(fx.seal(1, "x"));
    assert!(fx.open(&env).is_ok());
    // The relay resends the exact bytes it saw.
    let resent = relay.seen[0].clone();
    assert_eq!(
        fx.open(&resent),
        Err(OpenError::Replay(ReplayError::DuplicateRequest))
    );
}

#[test]
fn forged_envelope_from_relay_key_is_rejected() {
    let mut fx = Fixture::new();
    let relay = MaliciousRelay::new();
    let forged = relay.forge(fx.pairing_id, &fx.recipient.peer_identity(), 1);
    // Signed by the relay, not the pinned sender.
    assert_eq!(fx.open(&forged), Err(OpenError::BadSignature));
}

#[test]
fn bumped_counter_is_rejected() {
    let mut fx = Fixture::new();
    let env = MaliciousRelay::bump_counter(&fx.seal(1, "x"));
    assert_eq!(fx.open(&env), Err(OpenError::BadSignature));
}

#[test]
fn rewound_counter_is_rejected() {
    let mut fx = Fixture::new();
    let env = MaliciousRelay::rewind_counter(&fx.seal(5, "x"));
    assert_eq!(fx.open(&env), Err(OpenError::BadSignature));
}

#[test]
fn a_genuinely_old_lower_counter_message_is_rejected() {
    // The counter gate does not rely on the signature alone: even a validly
    // signed but stale-counter envelope (a captured earlier approval) is
    // refused once a higher counter has been accepted.
    let mut fx = Fixture::new();
    let newer = fx.seal(9, "newer");
    assert!(fx.open(&newer).is_ok());
    let older = fx.seal(4, "older but validly signed");
    assert_eq!(
        fx.open(&older),
        Err(OpenError::Replay(ReplayError::CounterRegression {
            got: 4,
            last: 9
        }))
    );
}

#[test]
fn backdated_timestamp_is_rejected() {
    let mut fx = Fixture::new();
    let env = MaliciousRelay::backdate(&fx.seal(1, "x"), REPLAY_WINDOW_MS + 10_000);
    // Mutating ts breaks the signature that covers it.
    assert_eq!(fx.open(&env), Err(OpenError::BadSignature));
}

#[test]
fn future_dated_timestamp_is_rejected() {
    let mut fx = Fixture::new();
    let env = MaliciousRelay::future_date(&fx.seal(1, "x"), REPLAY_WINDOW_MS + 10_000);
    assert_eq!(fx.open(&env), Err(OpenError::BadSignature));
}

#[test]
fn an_envelope_held_past_the_window_is_rejected() {
    // A relay cannot alter ts (that breaks the signature), so its remaining
    // timing attack is to *hold* a valid envelope and deliver it late. The
    // freshness gate rejects it. We drive the recipient's guard with the real
    // envelope fields and a clock advanced past the window.
    let fx = Fixture::new();
    let env = fx.seal(1, "x");
    let mut guard = ReplayGuard::new();
    let late_now = env.ts + REPLAY_WINDOW_MS + 1;
    assert_eq!(
        guard.check_and_record(
            env.request_id,
            env.counter,
            env.ts,
            late_now,
            REPLAY_WINDOW_MS
        ),
        Err(ReplayError::TimestampOutOfWindow {
            ts: env.ts,
            now: late_now,
            window_ms: REPLAY_WINDOW_MS,
        })
    );
}

#[test]
fn reordering_queued_envelopes_is_caught() {
    // The relay queues two envelopes and delivers them out of order.
    let mut fx = Fixture::new();
    let mut relay = MaliciousRelay::new();
    let first = relay.intercept(fx.seal(1, "first"));
    let second = relay.intercept(fx.seal(2, "second"));

    // Deliver the later one first: it is accepted.
    assert_eq!(fx.open(&second).unwrap(), "second");
    // Now the earlier one arrives; its counter has been overtaken.
    assert_eq!(
        fx.open(&first),
        Err(OpenError::Replay(ReplayError::CounterRegression {
            got: 1,
            last: 2
        }))
    );
}

// --- the push-registration message type rides the same hostile-relay proofs ---

#[test]
fn push_register_rides_the_sealed_signed_replay_protected_envelope() {
    // A PushRegister is not special to the envelope: sealed, it is confidential to
    // the relay, its signature covers every field, and it is single-use. Delivered
    // honestly it opens and classifies as a Push; a tampered or replayed copy is
    // rejected exactly as any other payload.
    let sender = DeviceIdentity::generate();
    let recipient = DeviceIdentity::generate();
    let pairing_id = [0x5a; 32];
    let mut guard = ReplayGuard::new();

    let pr = PushRegister::new("a1b2c3d4", "apns");
    let env = Envelope::seal(
        &pr,
        pairing_id,
        1,
        &sender.signing,
        &recipient.peer_identity(),
    )
    .expect("seal");

    // The relay cannot read it: opened with a stranger's agreement secret it fails
    // to decrypt even with the true sender's public key.
    let stranger = DeviceIdentity::generate();
    assert_eq!(
        env.open::<PushRegister>(
            &sender.peer_identity(),
            &stranger.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::Decrypt)
    );

    // A bit-flip in the ciphertext breaks the signature.
    let tampered = MaliciousRelay::flip_ciphertext(&env);
    assert_eq!(
        tampered.open::<PushRegister>(
            &sender.peer_identity(),
            &recipient.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::BadSignature)
    );

    // Honest delivery opens to a Value, and the daemon's demux classifies it as a
    // Push carrying the registered token.
    let value: serde_json::Value = env
        .open(&sender.peer_identity(), &recipient.agreement, &mut guard)
        .expect("open");
    assert_eq!(
        ToDaemonMessage::from_value(value).unwrap(),
        ToDaemonMessage::Push(pr)
    );

    // The exact bytes replayed are rejected (single-use request id).
    assert_eq!(
        env.open::<serde_json::Value>(&sender.peer_identity(), &recipient.agreement, &mut guard),
        Err(OpenError::Replay(ReplayError::DuplicateRequest))
    );
}

// --- the delivery receipt (task #41) rides the same hostile-relay proofs -------

#[test]
fn delivery_receipt_rides_the_sealed_signed_replay_protected_envelope() {
    // A DeliveryReceipt is not special to the envelope: sealed, it is confidential
    // to the relay, its signature covers every field, and it is single-use.
    // Delivered honestly it opens and classifies as a Delivered receipt; a tampered
    // or replayed copy is rejected exactly as any other payload. Because it passes
    // the same guard, a hostile relay can neither forge it nor replay it to re-touch
    // the daemon's delivery state.
    let sender = DeviceIdentity::generate();
    let recipient = DeviceIdentity::generate();
    let pairing_id = [0x33; 32];
    let mut guard = ReplayGuard::new();

    let receipt = DeliveryReceipt::new("req-XYZ");
    let env = Envelope::seal(
        &receipt,
        pairing_id,
        1,
        &sender.signing,
        &recipient.peer_identity(),
    )
    .expect("seal");

    // A bit-flip in the ciphertext breaks the signature (no forged receipt).
    let tampered = MaliciousRelay::flip_ciphertext(&env);
    assert_eq!(
        tampered.open::<serde_json::Value>(
            &sender.peer_identity(),
            &recipient.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::BadSignature)
    );

    // Honest delivery opens to a Value, and the daemon's demux classifies it as a
    // Delivered receipt for the acknowledged request id.
    let value: serde_json::Value = env
        .open(&sender.peer_identity(), &recipient.agreement, &mut guard)
        .expect("open");
    assert_eq!(
        ToDaemonMessage::from_value(value).unwrap(),
        ToDaemonMessage::Delivered(receipt)
    );

    // The exact bytes replayed are rejected (single-use request id): a relay cannot
    // replay a receipt to re-mark delivery.
    assert_eq!(
        env.open::<serde_json::Value>(&sender.peer_identity(), &recipient.agreement, &mut guard),
        Err(OpenError::Replay(ReplayError::DuplicateRequest))
    );
}

// --- the resolution broadcast (#36 multi-device) rides the same proofs ---------

#[test]
fn resolution_broadcast_rides_the_sealed_signed_replay_protected_envelope() {
    // A ResolutionBroadcast is the daemon->phone sibling of the DeliveryReceipt:
    // sealed, it is confidential to the relay, its signature covers every field,
    // and it is single-use. Delivered honestly it opens and the phone's demux
    // classifies it as a Resolution; a tampered or replayed copy is rejected
    // exactly as any other payload, so a hostile relay can neither FORGE a
    // dismissal (to hide a real pending prompt from the human) nor REPLAY one. And
    // even a forged-but-valid dismissal only ever fails closed: hiding a prompt
    // withholds a release, it can never cause one.
    let sender = DeviceIdentity::generate(); // the daemon, on ToPhone
    let recipient = DeviceIdentity::generate(); // a paired phone
    let pairing_id = [0x7c; 32];
    let mut guard = ReplayGuard::new();

    let rb = ResolutionBroadcast::new("req-RING", ResolutionStatus::Settled);
    let env = Envelope::seal(
        &rb,
        pairing_id,
        1,
        &sender.signing,
        &recipient.peer_identity(),
    )
    .expect("seal");

    // The relay cannot read it: opened with a stranger's agreement secret it fails
    // to decrypt even with the true sender's public key.
    let stranger = DeviceIdentity::generate();
    assert_eq!(
        env.open::<ResolutionBroadcast>(
            &sender.peer_identity(),
            &stranger.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::Decrypt)
    );

    // A bit-flip in the ciphertext breaks the signature (no forged dismissal).
    let tampered = MaliciousRelay::flip_ciphertext(&env);
    assert_eq!(
        tampered.open::<serde_json::Value>(
            &sender.peer_identity(),
            &recipient.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::BadSignature)
    );

    // A forged envelope from a key the phone does not pin is rejected: the relay
    // cannot manufacture a dismissal for a request the human should still see.
    let forged = MaliciousRelay::new().forge(pairing_id, &recipient.peer_identity(), 1);
    assert_eq!(
        forged.open::<serde_json::Value>(
            &recipient.peer_identity(), // phone still pins the DAEMON, not this key
            &recipient.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::BadSignature)
    );

    // Honest delivery opens to a Value, and the phone's demux classifies it as a
    // Resolution for the settled request id.
    let value: serde_json::Value = env
        .open(&sender.peer_identity(), &recipient.agreement, &mut guard)
        .expect("open");
    assert_eq!(
        ToPhoneMessage::from_value(value).unwrap(),
        ToPhoneMessage::Resolution(rb)
    );

    // The exact bytes replayed are rejected (single-use request id): a relay cannot
    // replay a resolution to re-dismiss (or, at scale, to suppress) a later prompt.
    assert_eq!(
        env.open::<serde_json::Value>(&sender.peer_identity(), &recipient.agreement, &mut guard),
        Err(OpenError::Replay(ReplayError::DuplicateRequest))
    );
}

#[test]
fn dropping_an_envelope_changes_no_state() {
    // The relay silently drops one message. The caller sees nothing for it, and
    // the recipient's state is untouched: a later message still opens cleanly.
    let mut fx = Fixture::new();
    let _dropped = fx.seal(1, "never delivered");
    // The recipient never saw counter 1; a subsequent message is unaffected.
    let next = fx.seal(2, "delivered");
    assert_eq!(fx.open(&next).unwrap(), "delivered");
    // And a first message at counter 1 would still be accepted afterwards only
    // if it had not been overtaken; here counter 2 was accepted, so the dropped
    // one, if it ever arrived, would now be refused.
    assert_eq!(
        fx.open(&_dropped),
        Err(OpenError::Replay(ReplayError::CounterRegression {
            got: 1,
            last: 2
        }))
    );
}
