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
    ApprovalRequest, ApprovalResponse, DeliveryReceipt, DeviceIdentity, Envelope, InstallLease,
    LeaseListReply, LeasePolicy, LeaseQuery, LeaseRevoke, LeaseRevokeReply, LeaseRow, OpenError,
    PeerIdentity, Provenance, PushRegister, ReplayError, ReplayGuard, RequestKind,
    ResolutionBroadcast, ResolutionStatus, ToDaemonMessage, ToPhoneMessage, REPLAY_WINDOW_MS,
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
fn a_genuinely_lower_counter_message_is_now_accepted() {
    // The monotonic-counter gate has been retired (task #67): a per-session
    // in-memory counter reset to 0 on any daemon restart or phone session
    // recreation, so a guard that remembered a higher counter dropped a genuine,
    // user-approved envelope as a false "replay". A validly signed envelope that
    // rides a lower (or reset) counter but carries a fresh timestamp and its own
    // unique request id is now ACCEPTED. Replay is still fully covered:
    // identical-bytes resend is caught by the single-use id
    // (replay_of_a_delivered_envelope_is_rejected) and a held-late envelope by
    // the freshness window (an_envelope_held_past_the_window_is_rejected).
    let mut fx = Fixture::new();
    let newer = fx.seal(9, "newer");
    assert_eq!(fx.open(&newer).unwrap(), "newer");
    let lower = fx.seal(4, "genuine but lower counter");
    assert_eq!(fx.open(&lower).unwrap(), "genuine but lower counter");
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
fn reordering_distinct_envelopes_is_accepted() {
    // With the counter ungated, two DISTINCT genuine envelopes delivered out of
    // order both open: each carries its own unique request id and a fresh
    // timestamp, so order no longer decides acceptance. This is the behaviour the
    // fix intends (a reset/lower counter must not drop a real approval). The
    // relay still cannot REPLAY: resending identical bytes is caught by the
    // single-use id (replay_of_a_delivered_envelope_is_rejected), and holding a
    // captured envelope past the window is caught by freshness
    // (an_envelope_held_past_the_window_is_rejected).
    let mut fx = Fixture::new();
    let mut relay = MaliciousRelay::new();
    let first = relay.intercept(fx.seal(1, "first"));
    let second = relay.intercept(fx.seal(2, "second"));

    // Deliver the later one first: accepted.
    assert_eq!(fx.open(&second).unwrap(), "second");
    // The earlier, distinct envelope still opens; it is a real message, not a
    // replay of the one already delivered.
    assert_eq!(fx.open(&first).unwrap(), "first");
    // But the exact bytes of an already-delivered envelope cannot be replayed.
    assert_eq!(
        fx.open(&relay.seen[1].clone()),
        Err(OpenError::Replay(ReplayError::DuplicateRequest))
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
    let dropped = fx.seal(1, "never delivered");
    // The recipient never saw the first envelope; a subsequent message is
    // unaffected and opens.
    let next = fx.seal(2, "delivered");
    assert_eq!(fx.open(&next).unwrap(), "delivered");
    // Dropping changed no guard state: if the "dropped" envelope later arrives
    // within its freshness window it is a distinct, genuine, unseen message and
    // opens on its own merit (the counter no longer gates it). Delivery order and
    // gaps do not poison the guard.
    assert_eq!(fx.open(&dropped).unwrap(), "never delivered");
}

// ===========================================================================
// The lease grant (security review F8).
//
// A lease response is the highest-value message on this wire: it does not settle
// one command, it opens a window, and since the RAM-cache path landed that window
// can hold unsealed credential values. So the relay's ability to touch a lease
// deserves its own proofs rather than resting on "it rides inside an envelope".
//
// The daemon remains the sole lease authority regardless of what arrives here
// (`daemon.rs::fulfill` clamps every ttl through the matched rule's policy, and a
// run-once rule yields no lease at all). These tests cover the transport half:
// the relay can withhold a grant, and can do nothing else to it.
// ===========================================================================

/// Seal an approve-with-lease from the phone, as the daemon would receive it.
fn open_response(fx: &mut Fixture, env: &Envelope) -> Result<ApprovalResponse, OpenError> {
    env.open(
        &fx.sender.peer_identity(),
        &fx.recipient.agreement,
        &mut fx.guard,
    )
}

fn seal_lease_response(fx: &Fixture, counter: u64, ttl_ms: u64) -> Envelope {
    let resp =
        ApprovalResponse::approve_gate("req-lease-1", 1_000).with_lease(InstallLease { ttl_ms });
    Envelope::seal(
        &resp,
        fx.pairing_id,
        counter,
        &fx.sender.signing,
        &fx.recipient.peer_identity(),
    )
    .expect("seal")
}

#[test]
fn relay_cannot_forge_a_lease_grant() {
    // The attack that would matter most: manufacture an approve carrying a
    // window for a request the human never saw. Forgery needs the phone's
    // signing key, which the relay does not have.
    let mut fx = Fixture::new();
    let forger = DeviceIdentity::generate();
    let resp = ApprovalResponse::approve_gate("req-lease-1", 1_000)
        .with_lease(InstallLease { ttl_ms: 900_000 });
    let forged = Envelope::seal(
        &resp,
        fx.pairing_id,
        1,
        &forger.signing,
        &fx.recipient.peer_identity(),
    )
    .expect("seal");
    assert_eq!(
        open_response(&mut fx, &forged),
        Err(OpenError::BadSignature),
        "a lease grant not signed by the paired phone must never open"
    );
}

#[test]
fn relay_cannot_lengthen_a_lease_window() {
    // The subtler attack: take a genuine 60s grant and stretch it. The ttl rides
    // inside the signed ciphertext, so any edit is a signature failure; the relay
    // cannot reach the field at all.
    let mut fx = Fixture::new();
    let honest = seal_lease_response(&fx, 1, 60_000);
    let stretched = MaliciousRelay::flip_ciphertext(&honest);
    assert_eq!(
        open_response(&mut fx, &stretched),
        Err(OpenError::BadSignature),
        "editing the ttl breaks the signature"
    );

    // And the honest one still opens with exactly the ttl the phone chose.
    let got = open_response(&mut fx, &honest).expect("open");
    assert_eq!(got.lease.expect("a lease grant").ttl_ms, 60_000);
}

#[test]
fn relay_cannot_attach_a_lease_to_a_deny() {
    // A deny and an approve-with-window are different authorizations. The relay
    // holds a real deny and wants it to become a window; it cannot re-seal.
    let mut fx = Fixture::new();
    let deny = ApprovalResponse::deny("req-lease-1", 1_000);
    let sealed = Envelope::seal(
        &deny,
        fx.pairing_id,
        1,
        &fx.sender.signing,
        &fx.recipient.peer_identity(),
    )
    .expect("seal");
    // Substituting the payload wholesale is the same signature failure.
    let swapped = MaliciousRelay::flip_ciphertext(&sealed);
    assert_eq!(
        open_response(&mut fx, &swapped),
        Err(OpenError::BadSignature)
    );
    // Delivered honestly it is still a deny, carrying no window.
    let got = open_response(&mut fx, &sealed).expect("open");
    assert!(got.lease.is_none(), "a deny never carries a lease");
}

#[test]
fn a_lease_grant_cannot_be_replayed_to_reopen_an_expired_window() {
    // The replay that would silently re-arm a window after it lapsed: keep the
    // approve that opened it and re-deliver it later. Single-use request ids stop
    // it, so re-opening always costs a fresh human approval.
    let mut fx = Fixture::new();
    let env = seal_lease_response(&fx, 1, 900_000);
    let first = open_response(&mut fx, &env).expect("the genuine grant opens once");
    assert_eq!(first.lease.expect("a lease grant").ttl_ms, 900_000);

    assert_eq!(
        open_response(&mut fx, &env),
        Err(OpenError::Replay(ReplayError::DuplicateRequest)),
        "re-delivering a lease grant must never re-open the window"
    );
}

// --- the lease coverage label rides the same hostile-relay proofs -------------

#[test]
fn the_lease_coverage_label_rides_inside_the_seal() {
    // The coverage label tells the human how wide a lease window is. It is
    // consent-bearing text, so it must be exactly as protected as the rest of the
    // request: invisible to the relay, covered by the signature, single-use. It
    // rides as a field of the request's lease policy, inside the same seal, over
    // no new transport.
    let sender = DeviceIdentity::generate(); // the daemon, sending a request
    let recipient = DeviceIdentity::generate(); // the phone
    let pairing_id = [0x3c; 32];
    let mut guard = ReplayGuard::new();

    let covers = "op with --account rowmhq.1password.eu";
    let req = ApprovalRequest {
        request_id: "01920000-0000-7000-8000-00000000c0de".into(),
        kind: RequestKind::SecretRead,
        command: vec!["op".into(), "read".into(), "op://Engineering/.env".into()],
        secrets: Vec::new(),
        ssh: None,
        provenance: Provenance {
            process_chain: vec!["zsh".into(), "op".into()],
            cwd: "/Projects/rowm".into(),
            machine: "mac".into(),
            requested_at: 1,
        },
        lease_policy: LeasePolicy::leasable(900).with_covers(covers),
        reason: None,
        threshold: None,
        expires_at: 2,
        timeout_ms: 1,
    };
    let env = Envelope::seal(
        &req,
        pairing_id,
        1,
        &sender.signing,
        &recipient.peer_identity(),
    )
    .expect("seal");

    // Not relay-visible: the label appears nowhere on the wire, and the relay
    // cannot decrypt it even knowing the true sender's public identity.
    let on_the_wire = serde_json::to_string(&env).expect("serialize");
    assert!(!on_the_wire.contains(covers));
    assert!(!on_the_wire.contains("rowmhq"));
    let stranger = DeviceIdentity::generate();
    assert_eq!(
        env.open::<ApprovalRequest>(
            &sender.peer_identity(),
            &stranger.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::Decrypt)
    );

    // Tampering is rejected: a relay cannot rewrite the breadth the human is shown.
    let tampered = MaliciousRelay::flip_ciphertext(&env);
    assert_eq!(
        tampered.open::<ApprovalRequest>(
            &sender.peer_identity(),
            &recipient.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::BadSignature)
    );

    // Honest delivery reproduces the label byte-for-byte.
    let opened: ApprovalRequest = env
        .open(&sender.peer_identity(), &recipient.agreement, &mut guard)
        .expect("open");
    assert_eq!(opened.lease_policy.covers(), covers);
    assert_eq!(opened, req);

    // And the exact bytes cannot be replayed to re-prompt with the same consent.
    assert_eq!(
        env.open::<ApprovalRequest>(&sender.peer_identity(), &recipient.agreement, &mut guard),
        Err(OpenError::Replay(ReplayError::DuplicateRequest))
    );
}

// --- phone lease control rides the same hostile-relay proofs ------------------
//
// Lease control is the second controller over a live window: the phone can now
// LIST the daemon's windows and REVOKE one, where before only `sigil lease
// revoke` on the Mac could. That makes four new payloads the relay would like to
// touch, and the interesting one is the revoke, because a window it can kill is a
// window the human's approval no longer covers.
//
// The relay's four options and where each dies:
//
// * FORGE a revoke (or a list reply): it does not hold either signing key, so
//   nothing it manufactures opens. Proven below for both directions.
// * TAMPER with one, to re-aim it at a different window: every field is inside
//   the seal and under the signature, so a bit-flip is a `BadSignature`.
// * REPLAY one: a captured revoke is single-use inside the freshness window and
//   stale outside it. The one case that leaves -- a daemon whose in-memory guard
//   restarted inside the window -- is covered NOT here but by the instance
//   binding, exercised in `sigil::remote`'s
//   `a_replayed_revoke_cannot_kill_a_later_window_with_the_same_grant_key`.
//   That is the seam: the envelope makes a replay hard, the instance makes a
//   replay that gets through inert.
// * DROP one: it can, and that is a stated residual. A censored revoke leaves the
//   window alive until its TTL, `sigil lease revoke` on the Mac, or a daemon
//   restart. The relay cannot cause a release this way, only withhold a
//   revocation, and the phone learns of it by getting no reply.
//
// And the payloads themselves are zero-knowledge to the relay: a list carries
// rule names, a coverage label, an account label, and two clocks -- never an
// argv, a secret reference, or a secret value.

/// Seal a phone -> daemon lease revoke, as the daemon would receive it.
fn seal_revoke(fx: &Fixture, counter: u64, grant: &str, instance: &str) -> Envelope {
    Envelope::seal(
        &LeaseRevoke::new("q-1", grant, instance),
        fx.pairing_id,
        counter,
        &fx.sender.signing,
        &fx.recipient.peer_identity(),
    )
    .expect("seal")
}

const GRANT_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const INSTANCE_HEX: &str = "fedcba9876543210fedcba9876543210";

#[test]
fn relay_cannot_forge_or_tamper_a_lease_revoke() {
    let mut fx = Fixture::new();
    let env = seal_revoke(&fx, 1, GRANT_HEX, INSTANCE_HEX);

    // Not readable: the relay knows both public identities and still cannot see
    // which window is being closed.
    let on_the_wire = serde_json::to_string(&env).expect("serialize");
    assert!(!on_the_wire.contains(GRANT_HEX));
    assert!(!on_the_wire.contains(INSTANCE_HEX));
    assert!(!on_the_wire.contains("leaseRevoke"));

    // Not forgeable: a revoke signed by the relay's own key never opens, so the
    // relay cannot close a window the human wanted open.
    let forged = MaliciousRelay::new().forge(fx.pairing_id, &fx.recipient.peer_identity(), 1);
    assert_eq!(
        forged.open::<serde_json::Value>(
            &fx.sender_pub(),
            &fx.recipient.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::BadSignature),
        "a revoke not signed by the paired phone must never open"
    );

    // Not re-aimable: the target is inside the seal and under the signature, so
    // the relay cannot point a genuine revoke at a different window.
    for mutated in [
        MaliciousRelay::flip_ciphertext(&env),
        MaliciousRelay::flip_signature(&env),
        MaliciousRelay::bump_counter(&env),
    ] {
        assert_eq!(
            mutated.open::<serde_json::Value>(
                &fx.sender_pub(),
                &fx.recipient.agreement,
                &mut ReplayGuard::new()
            ),
            Err(OpenError::BadSignature)
        );
    }

    // Delivered honestly it opens once, classifies as a revoke, and names exactly
    // the window the phone chose.
    let value: serde_json::Value = env
        .open(&fx.sender_pub(), &fx.recipient.agreement, &mut fx.guard)
        .expect("open");
    match ToDaemonMessage::from_value(value).expect("classifies") {
        ToDaemonMessage::LeaseRevoke(r) => {
            assert_eq!(
                r.target(),
                Some(("q-1", GRANT_HEX.to_string(), INSTANCE_HEX.to_string()))
            );
        }
        other => panic!("expected a LeaseRevoke, got {other:?}"),
    }
}

#[test]
fn a_captured_lease_revoke_cannot_be_replayed_or_backdated() {
    // The whole point of binding freshness: a revoke the relay stored cannot be
    // re-delivered to close a window later. Inside the freshness window the
    // single-use request id catches it; outside, the timestamp does.
    let mut fx = Fixture::new();
    let env = seal_revoke(&fx, 1, GRANT_HEX, INSTANCE_HEX);
    env.open::<serde_json::Value>(&fx.sender_pub(), &fx.recipient.agreement, &mut fx.guard)
        .expect("the genuine revoke opens once");

    assert_eq!(
        env.open::<serde_json::Value>(&fx.sender_pub(), &fx.recipient.agreement, &mut fx.guard),
        Err(OpenError::Replay(ReplayError::DuplicateRequest)),
        "re-delivering a revoke must never close a second window"
    );

    // The relay's remaining timing move is to HOLD a valid revoke and deliver it
    // late (it cannot alter `ts`; that is under the signature). The freshness gate
    // rejects it before the id is even consulted, so a relay cannot bank one for
    // tomorrow's window either.
    let held = seal_revoke(&fx, 2, GRANT_HEX, INSTANCE_HEX);
    let late_now = held.ts + REPLAY_WINDOW_MS + 1;
    assert_eq!(
        ReplayGuard::new().check_and_record(
            held.request_id,
            held.counter,
            held.ts,
            late_now,
            REPLAY_WINDOW_MS
        ),
        Err(ReplayError::TimestampOutOfWindow {
            ts: held.ts,
            now: late_now,
            window_ms: REPLAY_WINDOW_MS,
        })
    );
    // And backdating it to look fresh breaks the signature that covers `ts`.
    let backdated = MaliciousRelay::backdate(&held, REPLAY_WINDOW_MS + 1_000);
    assert_eq!(
        backdated.open::<serde_json::Value>(
            &fx.sender_pub(),
            &fx.recipient.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::BadSignature)
    );
}

#[test]
fn a_lease_query_cannot_be_forged_and_a_list_reply_leaks_nothing() {
    // The query direction: a forged one would only make the daemon seal a list to
    // the pinned phone, but it must still be impossible, and the reply that comes
    // back must be opaque to the relay and unforgeable toward the phone.
    let daemon = DeviceIdentity::generate();
    let phone = DeviceIdentity::generate();
    let pairing_id = [0x6d; 32];
    let mut guard = ReplayGuard::new();

    // Phone -> daemon query: forging it fails, tampering fails, honest delivery
    // classifies as a query.
    let q = LeaseQuery::new("q-7");
    let q_env =
        Envelope::seal(&q, pairing_id, 1, &phone.signing, &daemon.peer_identity()).expect("seal");
    let forged = MaliciousRelay::new().forge(pairing_id, &daemon.peer_identity(), 1);
    assert_eq!(
        forged.open::<serde_json::Value>(
            &phone.peer_identity(),
            &daemon.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::BadSignature)
    );
    let value: serde_json::Value = q_env
        .open(&phone.peer_identity(), &daemon.agreement, &mut guard)
        .expect("open");
    assert_eq!(
        ToDaemonMessage::from_value(value).unwrap(),
        ToDaemonMessage::LeaseList(q)
    );

    // Daemon -> phone reply. It describes live windows, so the relay must learn
    // nothing from it and must not be able to manufacture one (a fabricated
    // "no active leases" would be a lie the human might act on).
    let row = LeaseRow::new(
        GRANT_HEX,
        INSTANCE_HEX,
        "op",
        "op with --account \"rowmhq.1password.eu\"",
        "rowm",
        60_000,
        5_000,
    )
    .expect("well-formed row");
    let reply = LeaseListReply::new("q-7", vec![row]);
    let r_env = Envelope::seal(
        &reply,
        pairing_id,
        2,
        &daemon.signing,
        &phone.peer_identity(),
    )
    .expect("seal");

    let on_the_wire = serde_json::to_string(&r_env).expect("serialize");
    for leak in [GRANT_HEX, INSTANCE_HEX, "rowmhq", "leaseListReply"] {
        assert!(
            !on_the_wire.contains(leak),
            "{leak} is visible to the relay"
        );
    }
    let stranger = DeviceIdentity::generate();
    assert_eq!(
        r_env.open::<LeaseListReply>(
            &daemon.peer_identity(),
            &stranger.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::Decrypt)
    );
    let tampered = MaliciousRelay::flip_ciphertext(&r_env);
    assert_eq!(
        tampered.open::<serde_json::Value>(
            &daemon.peer_identity(),
            &phone.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::BadSignature),
        "a relay cannot rewrite the list of windows the human is shown"
    );

    // Honest delivery reproduces it byte-for-byte and classifies as a list reply;
    // a replay of the same bytes is rejected, so a stale list cannot be redelivered
    // to make a live window look absent.
    let mut phone_guard = ReplayGuard::new();
    let value: serde_json::Value = r_env
        .open(&daemon.peer_identity(), &phone.agreement, &mut phone_guard)
        .expect("open");
    assert_eq!(
        ToPhoneMessage::from_value(value).unwrap(),
        ToPhoneMessage::LeaseList(reply)
    );
    assert_eq!(
        r_env.open::<serde_json::Value>(
            &daemon.peer_identity(),
            &phone.agreement,
            &mut phone_guard
        ),
        Err(OpenError::Replay(ReplayError::DuplicateRequest))
    );
}

#[test]
fn a_revoke_reply_cannot_be_forged_into_a_false_confirmation() {
    // The reply is what tells the human "that window is closed". A relay that
    // could manufacture `revoked: true` would turn the revoke control back into
    // the consent theatre this feature exists to end, so it must be exactly as
    // unforgeable as a decision.
    let daemon = DeviceIdentity::generate();
    let phone = DeviceIdentity::generate();
    let pairing_id = [0x6e; 32];

    let reply = LeaseRevokeReply::new("q-9", GRANT_HEX, true);
    let env = Envelope::seal(
        &reply,
        pairing_id,
        1,
        &daemon.signing,
        &phone.peer_identity(),
    )
    .expect("seal");

    // A relay-signed confirmation never opens.
    let forged = MaliciousRelay::new().forge(pairing_id, &phone.peer_identity(), 1);
    assert_eq!(
        forged.open::<serde_json::Value>(
            &daemon.peer_identity(),
            &phone.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::BadSignature)
    );
    // And the boolean cannot be flipped in flight, in either direction.
    let tampered = MaliciousRelay::flip_ciphertext(&env);
    assert_eq!(
        tampered.open::<serde_json::Value>(
            &daemon.peer_identity(),
            &phone.agreement,
            &mut ReplayGuard::new()
        ),
        Err(OpenError::BadSignature)
    );

    let mut guard = ReplayGuard::new();
    let value: serde_json::Value = env
        .open(&daemon.peer_identity(), &phone.agreement, &mut guard)
        .expect("open");
    assert_eq!(
        ToPhoneMessage::from_value(value).unwrap(),
        ToPhoneMessage::LeaseRevoke(reply)
    );
}
