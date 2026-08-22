//! Export the shared Rust<->TS test vectors.
//!
//! Writes `apps/phone/src/protocol/__vectors__/sigil-vectors.json` exactly per
//! `apps/phone/src/protocol/vectors.contract.ts`. The phone's
//! `verify-vectors.ts` replays the file through the TypeScript protocol
//! implementation; agreement byte-for-byte is the interop gate.
//!
//! Bin, not xtask: the export needs only `sigil-proto`'s own public API plus
//! `serde_json` (already a dependency), so a `[[bin]]` in this crate is simpler
//! than a separate workspace member with a cargo alias — no new manifest, no new
//! dependency, and the code sits next to the types it serializes. Run with:
//!
//! ```sh
//! cargo run -p sigil-proto --bin export-vectors
//! ```
//!
//! The five categories:
//!   * `canonicalBytes` — deterministic `Envelope::canonical_bytes` over fixed
//!     fields (no crypto).
//!   * `fingerprint` — six words + mailbox id over two fixed identities.
//!   * `pairingQr` — `PairingPayload::to_qr_string` over fixed inputs.
//!   * `open` — real daemon-sealed envelopes plus the expected plaintext (or the
//!     expected `OpenError`). Sealing is randomized (fresh ephemeral + nonce +
//!     uuid + clock), so these are frozen at export time; opening is
//!     deterministic, which is what the phone verifies.
//!   * `replay` — a single `ReplayGuard` threaded across steps, its accept/reject
//!     outcome computed by the real Rust guard so Rust and TS must agree.
//!   * `combiner` — the v2 threshold combiner: fixed ECDH partials `Z_M`/`Z_F` and
//!     base `E` in, the derived token key `K` and AES-256-GCM `token_ct` out, for
//!     both `ecdh_algo` shapes, so the phone's TS combiner is locked to this Rust
//!     one (`threshold.rs`).
//!   * `approveProof` — the per-request approve proof (`proof.rs`): a fixed phone
//!     key `f` and a fixed daemon challenge `C` in, the shaped ECDH output and the
//!     BLAKE2b proof out, for both `ecdh_algo` shapes and for the absent /
//!     zero / non-zero lease cases. This is what makes invariant 4 structural on
//!     the plain-gate path, so the phone's TS must reproduce it byte-for-byte.
//!   * `pairingTranscript` — the v2 pairing confirmation transcript and MAC
//!     (`pairing.rs`'s `pairing_transcript`/`confirmation_tag`): fixed daemon/
//!     phone identities, endpoints, timestamp, and nonce in (a v1 case with no
//!     `se_share_pub` and a v2 case with one), the expected transcript and tag
//!     out, so the phone's TS transcript builder is locked to this Rust one —
//!     the piece that was NOT locked when the `seSharePub`/`se_share_pub`
//!     camelCase wire mismatch shipped.

use std::path::PathBuf;

use serde_json::{json, Value};
use uuid::Uuid;

use sigil_proto::envelope::Envelope;
use sigil_proto::identity::DeviceIdentity;
use sigil_proto::pairing::{PairingPayload, PairingSecret};
use sigil_proto::proof::approve_proof;
use sigil_proto::threshold::{aead_seal, combine, EcdhAlgo, MacShare, P256Point};
use sigil_proto::{
    fingerprint_words, mailbox_id, PeerIdentity, ReplayError, ReplayGuard, REPLAY_WINDOW_MS,
};

/// Standard base64, the exact encoding these values take on the wire. The
/// vectors carry both this and hex: hex is what a TS mirror compares bytes with,
/// base64 is what it must actually put in the envelope.
fn b64(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A deterministic 32-byte pattern from a seed, for fixed key material.
fn fixed32(seed: u8) -> [u8; 32] {
    std::array::from_fn(|i| seed.wrapping_add(i as u8).wrapping_mul(7).wrapping_add(1))
}

fn peer_json(p: &PeerIdentity) -> Value {
    json!({ "verifying": hex(&p.verifying), "agreement": hex(&p.agreement) })
}

/// A fixed input for a canonicalBytes vector.
struct CanonicalCase {
    name: &'static str,
    pairing_id: [u8; 32],
    request_id: &'static str,
    counter: u64,
    ts: u64,
    ephemeral_pub: [u8; 32],
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

/// canonicalBytes: build an envelope from fixed fields (no seal) and record the
/// hex of its canonical byte string.
fn canonical_vectors() -> Vec<Value> {
    let cases = [
        CanonicalCase {
            name: "basic",
            pairing_id: fixed32(1),
            request_id: "0190f7a1-3b2c-7d4e-8f90-1a2b3c4d5e6f",
            counter: 7,
            ts: 1_720_000_000_000,
            ephemeral_pub: fixed32(2),
            nonce: std::array::from_fn(|i| i as u8),
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03],
        },
        CanonicalCase {
            name: "empty-ciphertext",
            pairing_id: fixed32(9),
            request_id: "0190f7a1-3b2c-7d4e-8f90-abcdefabcdef",
            counter: 0,
            ts: 1_720_000_050_000,
            ephemeral_pub: fixed32(3),
            nonce: std::array::from_fn(|i| (255 - i) as u8),
            ciphertext: vec![],
        },
    ];
    cases
        .into_iter()
        .map(|c| {
            let env = Envelope {
                pairing_id: c.pairing_id,
                request_id: Uuid::parse_str(c.request_id).expect("valid uuid"),
                counter: c.counter,
                ts: c.ts,
                ephemeral_pub: c.ephemeral_pub,
                nonce: c.nonce,
                ciphertext: c.ciphertext.clone(),
                sig: [0u8; 64],
            };
            json!({
                "name": c.name,
                "pairingId": hex(&c.pairing_id),
                "requestId": c.request_id,
                "counter": c.counter,
                "ts": c.ts,
                "ephemeralPub": hex(&c.ephemeral_pub),
                "nonce": hex(&c.nonce),
                "ciphertext": hex(&c.ciphertext),
                "expected": hex(&env.canonical_bytes()),
            })
        })
        .collect()
}

/// fingerprint: six words + mailbox id over two fixed identities.
fn fingerprint_vectors() -> Vec<Value> {
    let pairs = [(fixed32(10), fixed32(20), fixed32(30), fixed32(40))];
    pairs
        .into_iter()
        .map(|(av, aa, bv, ba)| {
            let a = PeerIdentity {
                verifying: av,
                agreement: aa,
            };
            let b = PeerIdentity {
                verifying: bv,
                agreement: ba,
            };
            let words: Vec<&str> = fingerprint_words(&a, &b).to_vec();
            json!({
                "a": peer_json(&a),
                "b": peer_json(&b),
                "words": words,
                "mailboxId": hex(&mailbox_id(&a, &b)),
            })
        })
        .collect()
}

/// pairingQr: PairingPayload -> base64url string.
fn pairing_qr_vectors() -> Vec<Value> {
    let daemon = PeerIdentity {
        verifying: fixed32(100),
        agreement: fixed32(110),
    };
    let secret = PairingSecret(fixed32(120));
    let endpoints = vec![
        "lan://sigil.local:4823".to_string(),
        "https://tide.example.net:4823".to_string(),
    ];
    let created_at = 1_720_000_000_000u64;
    let payload = PairingPayload {
        daemon,
        endpoints: endpoints.clone(),
        secret: secret.clone(),
        created_at,
    };
    vec![json!({
        "daemon": peer_json(&daemon),
        "endpoints": endpoints,
        "secret": hex(secret.as_bytes()),
        "createdAt": created_at,
        "expected": payload.to_qr_string().expect("qr encode"),
    })]
}

/// pairingTranscript: the v2 pairing confirmation transcript and MAC
/// (`pairing.rs`'s `pairing_transcript`/`confirmation_tag`, exported via
/// `pairing_confirmation_vector` since production never needs a fixed nonce).
/// Locks the exact construction the phone's TS mirror
/// (`pairingTranscript`/`deriveSubkey`/`confirmationTag` in
/// `pairing-handshake.ts`) must reproduce byte-for-byte, INCLUDING the
/// `se_share_pub` (v2 threshold share) case: this is the piece that was not
/// locked when the `seSharePub`/`se_share_pub` camelCase wire mismatch
/// shipped, so nothing caught two sides computing different transcripts until
/// a real device did.
fn pairing_transcript_vectors() -> Vec<Value> {
    let secret = PairingSecret(fixed32(50));
    let daemon = PeerIdentity {
        verifying: fixed32(100),
        agreement: fixed32(101),
    };
    let endpoints = vec![
        "lan://sigil.local:4823".to_string(),
        "https://tide.example.net:4823".to_string(),
    ];
    let created_at = 1_720_000_000_000u64;
    let phone = PeerIdentity {
        verifying: fixed32(150),
        agreement: fixed32(151),
    };
    let nonce = fixed32(60);
    // Same fixed share used by `combiner_vectors`'s pattern, new seed: a
    // deterministic on-curve P-256 X9.63 point, standard base64.
    let se_share = fixed_share(0x44);
    let se_share_b64 = {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        STANDARD.encode(se_share.public_point().as_x963())
    };

    [
        ("v1-no-share", None),
        ("v2-with-se-share", Some(se_share_b64.as_str())),
    ]
    .into_iter()
    .map(|(name, share)| {
        let (transcript, tag) = sigil_proto::pairing_confirmation_vector(
            &secret, &daemon, &endpoints, created_at, &phone, &nonce, share,
        );
        json!({
            "name": name,
            "secret": hex(secret.as_bytes()),
            "daemon": peer_json(&daemon),
            "endpoints": endpoints,
            "createdAt": created_at,
            "phone": peer_json(&phone),
            "nonce": hex(&nonce),
            "seSharePub": share,
            "expectedTranscript": hex(&transcript),
            "expectedTag": hex(&tag),
        })
    })
    .collect()
}

/// open: real sealed envelopes plus expected plaintext or error.
fn open_vectors() -> Vec<Value> {
    let sender = DeviceIdentity::generate();
    let recipient = DeviceIdentity::generate();
    let sender_pub = sender.peer_identity();
    let recipient_secret = hex(&recipient.agreement.to_bytes());

    let payload = "unlock Engineering/.env".to_string();
    let env = Envelope::seal(
        &payload,
        fixed32(200),
        1,
        &sender.signing,
        &recipient.peer_identity(),
    )
    .expect("seal");
    let wire = serde_json::to_value(&env).expect("envelope wire");
    let now = env.ts;

    // roundtrip: the real recipient opens it.
    let roundtrip = json!({
        "name": "roundtrip",
        "sender": peer_json(&sender_pub),
        "recipientAgreementSecret": recipient_secret,
        "now": now,
        "envelope": wire,
        "expectOk": true,
        "expectedPayloadJson": serde_json::to_string(&payload).unwrap(),
        "expectError": Value::Null,
    });

    // badSignature: verify against a different sender key. The signature is the
    // real sender's, so the wrong verifying key rejects it before decryption.
    let stranger = DeviceIdentity::generate().peer_identity();
    let bad_sig = json!({
        "name": "wrong-sender-key",
        "sender": peer_json(&stranger),
        "recipientAgreementSecret": recipient_secret,
        "now": now,
        "envelope": wire,
        "expectOk": false,
        "expectedPayloadJson": Value::Null,
        "expectError": "badSignature",
    });

    // decrypt: correct signature, wrong recipient secret -> AEAD open fails.
    let other_recipient = DeviceIdentity::generate();
    let decrypt = json!({
        "name": "wrong-recipient",
        "sender": peer_json(&sender_pub),
        "recipientAgreementSecret": hex(&other_recipient.agreement.to_bytes()),
        "now": now,
        "envelope": wire,
        "expectOk": false,
        "expectedPayloadJson": Value::Null,
        "expectError": "decrypt",
    });

    vec![roundtrip, bad_sig, decrypt]
}

/// One replay case: run the real Rust `ReplayGuard` across the steps and record
/// each step's accept/reject so the TS guard must reproduce it exactly.
struct Step {
    request_id: &'static str,
    counter: u64,
    ts: u64,
    now: u64,
}

fn replay_case(name: &str, window_ms: u64, steps: &[Step]) -> Value {
    let mut guard = ReplayGuard::new();
    let step_json: Vec<Value> = steps
        .iter()
        .map(|s| {
            let id = Uuid::parse_str(s.request_id).expect("valid uuid");
            let res = guard.check_and_record(id, s.counter, s.ts, s.now, window_ms);
            let (ok, err) = match res {
                Ok(()) => (true, Value::Null),
                Err(ReplayError::DuplicateRequest) => (false, json!("duplicateRequest")),
                Err(ReplayError::TimestampOutOfWindow { .. }) => {
                    (false, json!("timestampOutOfWindow"))
                }
            };
            json!({
                "requestId": s.request_id,
                "counter": s.counter,
                "ts": s.ts,
                "now": s.now,
                "expectOk": ok,
                "expectError": err,
            })
        })
        .collect();
    json!({ "name": name, "windowMs": window_ms, "steps": step_json })
}

fn replay_vectors() -> Vec<Value> {
    let id_a = "0190f7a1-0000-7000-8000-000000000001";
    let id_b = "0190f7a1-0000-7000-8000-000000000002";
    let id_c = "0190f7a1-0000-7000-8000-000000000003";
    let base = 1_720_000_000_000u64;
    vec![
        // The counter is ungated: a lower (or reset) counter with a fresh
        // timestamp and a new request id is now ACCEPTED, where the retired
        // monotonic gate would have rejected the middle step. This case pins the
        // fix so Rust and TS agree the counter no longer decides acceptance.
        replay_case(
            "counter-is-ungated",
            REPLAY_WINDOW_MS,
            &[
                Step {
                    request_id: id_a,
                    counter: 5,
                    ts: base,
                    now: base,
                },
                Step {
                    request_id: id_b,
                    counter: 3,
                    ts: base,
                    now: base,
                },
                Step {
                    request_id: id_c,
                    counter: 0,
                    ts: base,
                    now: base,
                },
            ],
        ),
        replay_case(
            "duplicate-request-id",
            REPLAY_WINDOW_MS,
            &[
                Step {
                    request_id: id_a,
                    counter: 1,
                    ts: base,
                    now: base,
                },
                Step {
                    request_id: id_a,
                    counter: 2,
                    ts: base,
                    now: base,
                },
            ],
        ),
        replay_case(
            "timestamp-out-of-window",
            REPLAY_WINDOW_MS,
            &[Step {
                request_id: id_a,
                counter: 1,
                ts: base,
                now: base + REPLAY_WINDOW_MS + 1,
            }],
        ),
        // Age-eviction is safe: after an id is accepted and the clock advances
        // past the window, replaying that id can only carry its original stale
        // ts, so the freshness gate rejects it before the single-use check. Both
        // guards must agree the late replay is a timestamp rejection.
        replay_case(
            "aged-out-replay-fails-freshness",
            REPLAY_WINDOW_MS,
            &[
                Step {
                    request_id: id_a,
                    counter: 1,
                    ts: base,
                    now: base,
                },
                Step {
                    request_id: id_a,
                    counter: 1,
                    ts: base,
                    now: base + REPLAY_WINDOW_MS * 3,
                },
            ],
        ),
    ]
}

/// A deterministic P-256 scalar from a fixed seed, so the combiner vectors are
/// reproducible. The pattern stays non-zero and below the group order.
fn fixed_share(seed: u8) -> MacShare {
    let bytes: [u8; 32] = std::array::from_fn(|i| seed.wrapping_add(i as u8).wrapping_mul(3) | 1);
    MacShare::from_scalar_bytes(&bytes).expect("fixed seed is a valid P-256 scalar")
}

/// combiner: the v2 threshold combiner (`threshold.rs`), locked to the phone's TS
/// mirror. Fixed scalars `m`, `f`, `e` derive the two ECDH partials `Z_M = x(m·E)`
/// and `Z_F = x(f·E)`; the phone replays `combine(Z_M, Z_F, E, account_id)` and
/// must reproduce `K` (and the AES-256-GCM `token_ct` under it) byte-for-byte. Both
/// `ecdh_algo` shapes (`raw-x` and the NV-7 `x963-sha256`) are pinned.
fn combiner_vectors() -> Vec<Value> {
    let m = fixed_share(0x11);
    let f = fixed_share(0x22);
    let e = fixed_share(0x33);
    let e_point = e.public_point();
    let e_x963 = *e_point.as_x963();
    let account_id = "acct-threshold-01";
    let token: &[u8] = b"ops_eyJzaWduSW5BZGRyZXNzIjoiZXhhbXBsZSJ9.demo-service-account-token";
    let nonce: [u8; 12] = std::array::from_fn(|i| (0xA0 + i as u8) ^ 0x5A);

    [
        ("raw-x", EcdhAlgo::RawX),
        ("x963-sha256", EcdhAlgo::X963Sha256),
    ]
    .into_iter()
    .map(|(name, algo)| {
        // Z_M is the Mac's shaped partial; Z_F stands in for the Secure
        // Enclave's shaped x(f·E). Both are combiner INPUTS the phone is given.
        let zm = m.partial(&e_point, algo, &e_x963);
        let zf = f.partial(&e_point, algo, &e_x963);
        let k = combine(&zm, &zf, &e_x963, account_id);
        let token_ct = aead_seal(&k, &nonce, token).expect("aead seal");
        json!({
            "name": name,
            "ecdhAlgo": name,
            "zm": hex(&*zm),
            "zf": hex(&*zf),
            "ephemeralPub": hex(&e_x963),
            "accountId": account_id,
            "expectedK": hex(&*k),
            "aeadNonce": hex(&nonce),
            "token": hex(token),
            "expectedTokenCt": hex(&token_ct),
        })
    })
    .collect()
}

/// approveProof: the per-request approve proof (`proof.rs`), locked to the phone's
/// TS mirror. A fixed phone key `f` (standing in for the Secure Enclave) and a
/// fixed daemon challenge scalar `c` give a deterministic `C = c·G`; `seRawX` is
/// what the enclave returns for `x(f·C)`, `shared` is that after the record's
/// ECDH shaping, and `expectedProof` is the BLAKE2b over the bound preimage.
///
/// The `leaseTtlMs: null` and `leaseTtlMs: 0` cases are both present on purpose:
/// an absent lease absorbs a zero-LENGTH field and a zero lease absorbs eight
/// zero bytes, so a TS mirror that conflates them produces a proof the daemon
/// denies. That is the single easiest thing to get wrong here.
fn approve_proof_vectors() -> Vec<Value> {
    // Distinct seeds from `combiner_vectors`, so a mirror that crosses the two
    // categories' fixtures fails rather than accidentally agreeing.
    let f = fixed_share(0x44);
    let c = fixed_share(0x55);
    let c_point = c.public_point();
    let c_x963 = *c_point.as_x963();
    let request_id = "01920000-0000-7000-8000-0000000000aa";

    let cases: [(&str, EcdhAlgo, &str, Option<u64>); 4] = [
        ("raw-x/no-lease", EcdhAlgo::RawX, "approved", None),
        ("raw-x/lease", EcdhAlgo::RawX, "approved", Some(900_000)),
        ("raw-x/zero-lease", EcdhAlgo::RawX, "approved", Some(0)),
        (
            "x963-sha256/no-lease",
            EcdhAlgo::X963Sha256,
            "approved",
            None,
        ),
    ];

    cases
        .into_iter()
        .map(|(name, algo, decision, lease_ttl_ms)| {
            // What the Secure Enclave hands back: the RAW x-coordinate, unshaped.
            // `RawX` shaping is the identity, so this is the bare agreement.
            let raw_x = f.partial(&c_point, EcdhAlgo::RawX, &[]);
            // What both sides fold into the proof, after the record's shaping.
            let shared = f.partial(&c_point, algo, &c_x963);
            let proof = approve_proof(&shared, request_id, decision, lease_ttl_ms);

            // The daemon reaches the same value from the other side (x(c·F)).
            // Asserted here so a broken vector cannot ship silently.
            let f_pub = f.public_point();
            let daemon_side = c.partial(&f_pub, algo, &c_x963);
            assert_eq!(*shared, *daemon_side, "ECDH must commute for {name}");
            // And the challenge must survive the validating decoder the phone uses.
            assert_eq!(
                P256Point::from_x963(&c_x963)
                    .expect("challenge on-curve")
                    .as_x963(),
                &c_x963
            );

            json!({
                "name": name,
                "ecdhAlgo": match algo {
                    EcdhAlgo::RawX => "raw-x",
                    EcdhAlgo::X963Sha256 => "x963-sha256",
                },
                "challengePub": hex(&c_x963),
                "challengePubB64": b64(&c_x963),
                "seRawX": hex(&*raw_x),
                "shared": hex(&*shared),
                "requestId": request_id,
                "decision": decision,
                "leaseTtlMs": lease_ttl_ms,
                "expectedProof": hex(&proof),
                "expectedProofB64": b64(&proof),
            })
        })
        .collect()
}

fn main() {
    let doc = json!({
        "version": 2,
        "canonicalBytes": canonical_vectors(),
        "fingerprint": fingerprint_vectors(),
        "pairingQr": pairing_qr_vectors(),
        "open": open_vectors(),
        "replay": replay_vectors(),
        "combiner": combiner_vectors(),
        "approveProof": approve_proof_vectors(),
        "pairingTranscript": pairing_transcript_vectors(),
    });

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/phone/src/protocol/__vectors__/sigil-vectors.json");
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir).expect("create __vectors__ dir");
    }
    let mut json = serde_json::to_string_pretty(&doc).expect("serialize vectors");
    json.push('\n');
    std::fs::write(&out, json).expect("write vectors file");
    eprintln!(
        "wrote {} ({} bytes)",
        out.display(),
        out.metadata().map(|m| m.len()).unwrap_or(0)
    );
}
