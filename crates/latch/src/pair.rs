//! The daemon side of a real, cross-process pairing over the blind relay.
//!
//! `latch pair` mints a fresh daemon identity and a one-time pairing secret,
//! renders the [`PairingPayload`](latch_proto::PairingPayload) as a scannable QR
//! (and a base64url line),
//! waits on the relay rendezvous mailbox for the phone's `PairingResponse`,
//! verifies its MAC (pinning the phone), has the human confirm the six SAS
//! words, seals the keystore's DEK to the phone (the same key `latch account
//! add` encrypts tokens under, so a later approval returns a DEK that actually
//! decrypts them), and persists the result so the daemon can arm the phone
//! factor with no `--dev-insecure` (see [`crate::pairing_store`]).
//!
//! The ceremony is written against a [`PairChannel`] so it is exercised
//! end-to-end headlessly (in-process, with the softphone) as well as over the
//! real relay via [`RendezvousWs`]. The transport is never the security layer:
//! message 1 (the response) is authenticated by its pairing MAC, and message 3
//! (the DEK) is a standard sealed [`Envelope`](latch_proto::Envelope).

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use latch_proto::identity::DeviceIdentity;
use latch_proto::pairing::{DaemonPairing, Dek};
use latch_proto::{rendezvous_mailbox, PairingResponse, TransportError};

use crate::pairing_store::{NewPairing, NewPhoneShare};

/// The opaque-string channel the pairing ceremony runs over: send toward the
/// phone, receive from the phone. Implemented by [`RendezvousWs`] for the real
/// relay and by an in-memory pair in tests.
pub trait PairChannel {
    fn send(&self, payload: String) -> Result<(), TransportError>;
    fn recv(&self, timeout: Duration) -> Result<Option<String>, TransportError>;
}

impl PairChannel for latch_relay_client::RendezvousWs {
    fn send(&self, payload: String) -> Result<(), TransportError> {
        latch_relay_client::RendezvousWs::send(self, payload)
    }
    fn recv(&self, timeout: Duration) -> Result<Option<String>, TransportError> {
        latch_relay_client::RendezvousWs::recv(self, timeout)
    }
}

/// Render a QR payload string as a terminal QR using unicode half-blocks, with a
/// quiet zone so a phone camera can lock on. Delegates to [`crate::qr`], the one
/// place QR rendering lives, so the pairing QR, `latch qr`, and the PNG output
/// all come from the same matrix (error-correction Q, 4-module quiet zone).
pub fn render_qr(data: &str) -> Result<String> {
    crate::qr::render_terminal(data)
}

/// Decode the phone's response line: base64url(JSON) as the softphone and the
/// iOS approver emit it, with raw JSON accepted as a fallback.
fn decode_response(line: &str) -> Result<PairingResponse> {
    let line = line.trim();
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(line) {
        if let Ok(resp) = serde_json::from_slice::<PairingResponse>(&bytes) {
            return Ok(resp);
        }
    }
    serde_json::from_str::<PairingResponse>(line)
        .context("the phone's response was neither base64url nor JSON")
}

/// The knobs the ceremony needs, so the same core serves the interactive CLI and
/// the headless test.
pub struct CeremonyOpts<'a> {
    /// The relay base URL, carried to the phone in the QR endpoints and
    /// persisted for the approval transport.
    pub relay_url: String,
    /// How long to wait for the phone's response before failing closed.
    pub response_timeout: Duration,
    /// Grace period to keep the channel open after sending the DEK, so the
    /// transport flushes it to the phone before teardown. Zero in tests.
    pub flush_grace: Duration,
    /// Wall clock source (unix ms). Real uses `now_ms`; tests pin it.
    pub now: &'a dyn Fn() -> u64,
    /// Build the channel once the rendezvous mailbox is known.
    pub make_channel: &'a mut dyn FnMut([u8; 32]) -> Result<Box<dyn PairChannel>>,
    /// Show the QR (unicode) and its base64url line to the human.
    pub present_qr: &'a mut dyn FnMut(&str, &str),
    /// Confirm the six SAS words match the phone's screen. Returns false to
    /// cancel.
    pub confirm_sas: &'a mut dyn FnMut(&[&'static str; 6]) -> bool,
    /// How long to wait, after the DEK is delivered, for the phone's sealed
    /// [`ThresholdShare`](latch_proto::ThresholdShare) (its v2 Secure-Enclave
    /// share `F`). The phone sends it only if it has a Secure Enclave, so this is
    /// best-effort: a timeout means a v1-only pairing, not a failure. Zero skips
    /// the wait entirely (a pure v1 pairing).
    pub share_wait: Duration,
    /// The keystore's DEK: the single key `latch account add` seals tokens
    /// under. The ceremony delivers *this* key to the phone so a later approval
    /// returns a DEK that actually decrypts the stored token ciphertext. It is
    /// never a fresh key: sealing under one DEK and unlocking with another is
    /// exactly the divergence this field exists to prevent.
    pub dek: &'a crate::secrets::Dek,
}

/// Run the full daemon-side ceremony and return what to persist. The keystore's
/// DEK ([`CeremonyOpts::dek`]) is delivered to the phone and dropped (zeroized)
/// here; it is deliberately absent from the returned [`NewPairing`].
pub fn run_ceremony(daemon_identity: DeviceIdentity, opts: CeremonyOpts<'_>) -> Result<NewPairing> {
    // Keep a copy of the daemon identity to persist: `mint` consumes the one we
    // pass it. Rebuilding from the secret bytes yields the same pinned keys.
    let retained = DeviceIdentity::from_secret_bytes(&daemon_identity.to_secret_bytes()[..])
        .context("cloning the daemon identity")?;

    let endpoints = vec![opts.relay_url.clone()];
    let (mut daemon, payload) = DaemonPairing::mint(daemon_identity, endpoints, (opts.now)());
    let mailbox = rendezvous_mailbox(&payload.daemon, &payload.secret);

    let qr_b64 = payload
        .to_qr_string()
        .context("encoding the pairing payload")?;
    let qr_unicode = render_qr(&qr_b64)?;
    (opts.present_qr)(&qr_unicode, &qr_b64);

    let channel = (opts.make_channel)(mailbox)?;

    // 1. Await the phone's PairingResponse (message 1).
    let deadline = Instant::now() + opts.response_timeout;
    let raw = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for the phone to scan and respond");
        }
        match channel
            .recv(remaining)
            .context("waiting for the phone response")?
        {
            Some(s) => break s,
            None => continue,
        }
    };
    let resp = decode_response(&raw)?;

    // 2. Verify + pin the phone (message 1 checked: not-consumed, not-expired,
    //    tag valid). A bad tag or expiry fails here, loudly.
    daemon
        .receive_response(&resp, (opts.now)())
        .context("verifying the phone's pairing response")?;

    // 3. SAS: the human backstop. Cancel unless both screens matched.
    let words = daemon
        .sas_words()
        .context("computing the SAS words (no phone pinned)")?;
    if !(opts.confirm_sas)(&words) {
        bail!("pairing cancelled: the SAS words were not confirmed");
    }
    daemon.confirm().context("confirming the SAS")?;

    // 4. Deliver the KEYSTORE's DEK, sealed to the phone (message 3), then erase
    //    the transport copy. This must be the same key `latch account add` seals
    //    tokens under, never a fresh one, or a real approval would return a DEK
    //    that cannot decrypt the stored token. `Dek::from_bytes` copies into a
    //    proto `Dek`, which is `ZeroizeOnDrop`; the keystore's own copy is the
    //    caller's `Zeroizing` and outlives this call.
    let dek = Dek::from_bytes(**opts.dek);
    let env = daemon.deliver_dek(&dek, 1).context("sealing the DEK")?;
    let env_wire = serde_json::to_string(&env).context("serializing the DEK envelope")?;
    channel
        .send(env_wire)
        .context("sending the DEK to the phone")?;
    drop(dek);

    // Let the transport flush the DEK before the channel is torn down.
    if !opts.flush_grace.is_zero() {
        std::thread::sleep(opts.flush_grace);
    }

    let phone = daemon
        .phone()
        .expect("phone is pinned once the response verified");

    // 5. v2 (best-effort): after opening the DEK, the phone may deliver its
    //    Secure-Enclave threshold share F as a sealed `ThresholdShare` on the
    //    rendezvous mailbox. Open it (the same signed + replay-guarded envelope
    //    path as the DEK, reversed), validate F on-curve (R2), and pin it, so this
    //    one pairing arms both v1 (DEK) and v2 (threshold) accounts. A phone with
    //    no Secure Enclave never sends it; a timeout is a v1-only pairing, not a
    //    failure.
    let phone_share = receive_phone_share(channel.as_ref(), opts.share_wait, &phone, &retained);

    let sas_words: [String; 6] = std::array::from_fn(|i| words[i].to_string());
    Ok(NewPairing {
        daemon_identity: retained,
        phone,
        relay_url: opts.relay_url,
        sas_words,
        paired_at: (opts.now)(),
        phone_share,
    })
}

/// Receive and open the phone's sealed [`ThresholdShare`](latch_proto::ThresholdShare)
/// on the rendezvous channel, returning the validated share to persist, or `None`
/// (best-effort) on timeout, a malformed/unauthenticated envelope, or an
/// off-curve `F`. The envelope is signed by the pinned phone and sealed to the
/// daemon, opened via the same signature + replay + decrypt path as every other
/// message; then `F` is validated on-curve (R2) before it is pinned. A failure
/// never aborts a pairing whose v1 DEK already landed.
fn receive_phone_share(
    channel: &dyn PairChannel,
    share_wait: Duration,
    phone: &latch_proto::PeerIdentity,
    daemon_identity: &DeviceIdentity,
) -> Option<NewPhoneShare> {
    if share_wait.is_zero() {
        return None;
    }
    let wire = match channel.recv(share_wait) {
        Ok(Some(w)) => w,
        _ => return None,
    };
    let env: latch_proto::Envelope = serde_json::from_str(&wire).ok()?;
    let mut guard = latch_proto::ReplayGuard::new();
    let share: latch_proto::ThresholdShare = env
        .open(phone, &daemon_identity.agreement, &mut guard)
        .ok()?;
    // Validate F on-curve before pinning it (R2); store the canonical encoding.
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&share.f_x963)
        .ok()?;
    let point = latch_proto::P256Point::from_x963(&raw).ok()?;
    Some(NewPhoneShare {
        se_key_id: share.se_key_id,
        f_x963: point.as_x963().to_vec(),
        ecdh_algo: share.ecdh_algo,
    })
}

/// Build the real relay channel: an outbound WebSocket attach to `relay_url` for
/// the rendezvous `mailbox`.
pub fn relay_channel(relay_url: &str, mailbox: [u8; 32]) -> Result<Box<dyn PairChannel>> {
    let ws = latch_relay_client::RendezvousWs::connect(relay_url, mailbox)
        .map_err(|e| anyhow::anyhow!("attaching to relay {relay_url}: {e}"))?;
    Ok(Box::new(ws))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use latch_proto::Envelope;
    use latch_softphone::{Pairing, Policy};

    const NOW: u64 = 1_720_000_000_000;

    /// An in-process duplex the ceremony runs over: the daemon sends toward the
    /// phone (`d2p`) and receives from the phone (`p2d`).
    struct MemChannel {
        d2p: Arc<Mutex<VecDeque<String>>>,
        p2d: Arc<Mutex<VecDeque<String>>>,
    }
    impl PairChannel for MemChannel {
        fn send(&self, payload: String) -> Result<(), TransportError> {
            self.d2p.lock().unwrap().push_back(payload);
            Ok(())
        }
        fn recv(&self, timeout: Duration) -> Result<Option<String>, TransportError> {
            let deadline = Instant::now() + timeout;
            loop {
                if let Some(s) = self.p2d.lock().unwrap().pop_front() {
                    return Ok(Some(s));
                }
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    #[test]
    fn full_ceremony_over_an_in_memory_channel_pins_and_persists() {
        let d2p = Arc::new(Mutex::new(VecDeque::<String>::new()));
        let p2d = Arc::new(Mutex::new(VecDeque::<String>::new()));
        // Hand the QR to the phone thread once the daemon renders it.
        let (qr_tx, qr_rx) = std::sync::mpsc::channel::<String>();

        // The phone: wait for the QR, scan, respond, then open the DEK.
        let phone_thread = {
            let d2p = d2p.clone();
            let p2d = p2d.clone();
            std::thread::spawn(move || {
                let qr = qr_rx.recv().expect("daemon rendered a QR");
                let phone_id = DeviceIdentity::generate();
                let (mut pairing, resp) =
                    Pairing::scan(phone_id, &qr, NOW + 1_000, Policy::Approve).unwrap();
                // Message 1: base64url(JSON), exactly as the CLI/app emits it.
                let resp_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&resp).unwrap());
                p2d.lock().unwrap().push_back(resp_b64);
                pairing.confirm().unwrap();
                // Message 3: the DEK envelope the daemon seals back.
                let env_wire = loop {
                    if let Some(s) = d2p.lock().unwrap().pop_front() {
                        break s;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                };
                let env: Envelope = serde_json::from_str(&env_wire).unwrap();
                let sp = pairing.receive_dek(&env).unwrap();
                sp.phone_identity()
            })
        };

        let daemon_id = DeviceIdentity::generate();
        let daemon_pub = daemon_id.peer_identity();

        let mut make_channel = |_mailbox: [u8; 32]| -> Result<Box<dyn PairChannel>> {
            Ok(Box::new(MemChannel {
                d2p: d2p.clone(),
                p2d: p2d.clone(),
            }))
        };
        let mut present_qr = |_unicode: &str, b64: &str| {
            qr_tx.send(b64.to_string()).unwrap();
        };
        let mut confirm = |_w: &[&'static str; 6]| true;
        let clock = || NOW;
        let dek = crate::secrets::generate_dek();

        let opts = CeremonyOpts {
            relay_url: "ws://relay.test".into(),
            response_timeout: Duration::from_secs(5),
            flush_grace: Duration::ZERO,
            now: &clock,
            make_channel: &mut make_channel,
            present_qr: &mut present_qr,
            confirm_sas: &mut confirm,
            share_wait: Duration::ZERO,
            dek: &dek,
        };
        let np = run_ceremony(daemon_id, opts).expect("ceremony completes");

        let phone_pub = phone_thread.join().unwrap();
        // The daemon pinned exactly the phone that responded, and kept its own
        // identity for persistence.
        assert_eq!(np.phone, phone_pub);
        assert_eq!(np.daemon_identity.peer_identity(), daemon_pub);
        assert_eq!(np.relay_url, "ws://relay.test");
        // The recorded SAS words are the real fingerprint of the pinned pair.
        let expected = latch_proto::fingerprint_words(&daemon_pub, &phone_pub);
        let recorded: Vec<&str> = np.sas_words.iter().map(String::as_str).collect();
        assert_eq!(recorded, expected.to_vec());
    }

    #[test]
    fn a_declined_sas_cancels_the_pairing() {
        let d2p = Arc::new(Mutex::new(VecDeque::<String>::new()));
        let p2d = Arc::new(Mutex::new(VecDeque::<String>::new()));
        let (qr_tx, qr_rx) = std::sync::mpsc::channel::<String>();
        let phone_thread = {
            let p2d = p2d.clone();
            std::thread::spawn(move || {
                let qr = qr_rx.recv().unwrap();
                let phone_id = DeviceIdentity::generate();
                let (_pairing, resp) =
                    Pairing::scan(phone_id, &qr, NOW + 1_000, Policy::Approve).unwrap();
                let resp_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&resp).unwrap());
                p2d.lock().unwrap().push_back(resp_b64);
            })
        };
        let daemon_id = DeviceIdentity::generate();
        let mut make_channel = |_m: [u8; 32]| -> Result<Box<dyn PairChannel>> {
            Ok(Box::new(MemChannel {
                d2p: d2p.clone(),
                p2d: p2d.clone(),
            }))
        };
        let mut present_qr = |_u: &str, b64: &str| qr_tx.send(b64.to_string()).unwrap();
        let mut confirm = |_w: &[&'static str; 6]| false; // human says the words differ
        let clock = || NOW;
        let dek = crate::secrets::generate_dek();
        let opts = CeremonyOpts {
            relay_url: "ws://relay.test".into(),
            response_timeout: Duration::from_secs(5),
            flush_grace: Duration::ZERO,
            now: &clock,
            make_channel: &mut make_channel,
            present_qr: &mut present_qr,
            confirm_sas: &mut confirm,
            share_wait: Duration::ZERO,
            dek: &dek,
        };
        let err = match run_ceremony(daemon_id, opts) {
            Err(e) => e,
            Ok(_) => panic!("expected the pairing to be cancelled at SAS"),
        };
        assert!(err.to_string().contains("SAS"), "cancelled at SAS: {err}");
        phone_thread.join().unwrap();
    }

    /// The regression for the DEK-divergence bug: the ceremony must deliver the
    /// *keystore* DEK (the one `latch account add` seals tokens under), not a
    /// fresh key. This drives the real seam end to end — provision a keystore
    /// DEK, seal a known token under it, run the ceremony passing that DEK, have
    /// the phone recover the delivered DEK, and assert the recovered DEK
    /// decrypts the token back to plaintext.
    ///
    /// Against the old `Dek::generate()` code the phone recovers a *different*
    /// key and `decrypt_token` fails (AEAD error), so this test fails pre-fix
    /// and passes post-fix.
    #[test]
    fn delivered_dek_decrypts_a_token_sealed_under_the_keystore_dek() {
        use crate::keystore::{Keystore, MemoryKeystore};
        use crate::secrets::{decrypt_token, encrypt_token};
        use latch_proto::pairing::PhonePairing;
        use latch_proto::{PairingPayload, ReplayGuard};
        use zeroize::Zeroizing;

        const TOKEN: &[u8] = b"ops_eyJzaWduSW5BZGRyZXNzIjoi.example.account.token";

        // 1. Provision the keystore DEK and seal a known token under it, exactly
        //    as `latch account add` does.
        let ks = MemoryKeystore::new();
        ks.ensure_dek().unwrap();
        let keystore_dek = ks.unwrap_dek("seal the account token").unwrap();
        let ciphertext = encrypt_token(&keystore_dek, TOKEN).unwrap();

        let d2p = Arc::new(Mutex::new(VecDeque::<String>::new()));
        let p2d = Arc::new(Mutex::new(VecDeque::<String>::new()));
        let (qr_tx, qr_rx) = std::sync::mpsc::channel::<String>();

        // The phone: scan, respond, confirm, then open the delivered DEK and
        // return its raw bytes so the test can try to decrypt with them.
        let phone_thread = {
            let d2p = d2p.clone();
            let p2d = p2d.clone();
            std::thread::spawn(move || -> [u8; 32] {
                let qr = qr_rx.recv().expect("daemon rendered a QR");
                let phone_id = DeviceIdentity::generate();
                let payload = PairingPayload::from_qr_string(&qr).unwrap();
                let mut phone = PhonePairing::scan(phone_id, payload, NOW + 1_000).unwrap();
                let resp = phone.respond().unwrap();
                let resp_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&resp).unwrap());
                p2d.lock().unwrap().push_back(resp_b64);
                phone.confirm().unwrap();
                let env_wire = loop {
                    if let Some(s) = d2p.lock().unwrap().pop_front() {
                        break s;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                };
                let env: Envelope = serde_json::from_str(&env_wire).unwrap();
                let mut guard = ReplayGuard::new();
                let recovered = phone.receive_dek(&env, &mut guard).unwrap();
                *recovered.as_bytes()
            })
        };

        let daemon_id = DeviceIdentity::generate();
        let mut make_channel = |_mailbox: [u8; 32]| -> Result<Box<dyn PairChannel>> {
            Ok(Box::new(MemChannel {
                d2p: d2p.clone(),
                p2d: p2d.clone(),
            }))
        };
        let mut present_qr = |_unicode: &str, b64: &str| {
            qr_tx.send(b64.to_string()).unwrap();
        };
        let mut confirm = |_w: &[&'static str; 6]| true;
        let clock = || NOW;

        let opts = CeremonyOpts {
            relay_url: "ws://relay.test".into(),
            response_timeout: Duration::from_secs(5),
            flush_grace: Duration::ZERO,
            now: &clock,
            make_channel: &mut make_channel,
            present_qr: &mut present_qr,
            confirm_sas: &mut confirm,
            share_wait: Duration::ZERO,
            dek: &keystore_dek,
        };
        run_ceremony(daemon_id, opts).expect("ceremony completes");

        let recovered_bytes = phone_thread.join().unwrap();
        let recovered_dek: crate::secrets::Dek = Zeroizing::new(recovered_bytes);

        // The phone recovered the very key the daemon sealed the token with.
        assert_eq!(
            &recovered_dek[..],
            &keystore_dek[..],
            "the delivered DEK diverged from the keystore DEK"
        );
        // The whole point: that recovered DEK decrypts the stored token.
        let plaintext = decrypt_token(&recovered_dek, &ciphertext)
            .expect("the phone-delivered DEK must decrypt the account token");
        assert_eq!(&plaintext[..], TOKEN);
    }

    #[test]
    fn ceremony_pins_the_phone_threshold_share_after_the_dek() {
        // The v2 pairing tail: after the daemon delivers the DEK, the phone seals
        // its SE share F as a `ThresholdShare` on the rendezvous mailbox; the
        // ceremony opens it (signed by the pinned phone), validates F on-curve, and
        // persists it, so one pairing arms both v1 (DEK) and v2 (threshold).
        use base64::engine::general_purpose::STANDARD as B64S;
        use latch_proto::pairing::PhonePairing;
        use latch_proto::threshold::{EcdhAlgo, MacShare};
        use latch_proto::{mailbox_id, Envelope, PairingPayload, ThresholdShare};

        // The phone's SE share f (software stand-in) and its public F.
        let f = MacShare::generate();
        let f_x963 = *f.public_point().as_x963();
        let f_b64 = B64S.encode(f_x963);

        let d2p = Arc::new(Mutex::new(VecDeque::<String>::new()));
        let p2d = Arc::new(Mutex::new(VecDeque::<String>::new()));
        let (qr_tx, qr_rx) = std::sync::mpsc::channel::<String>();

        // The phone: respond (message 1), wait for the DEK on d2p (message 3),
        // then seal a ThresholdShare signed by its pinned identity and submit it
        // on the rendezvous channel (message 4) — exactly as apps/phone does.
        let phone_thread = {
            let d2p = d2p.clone();
            let p2d = p2d.clone();
            let f_b64 = f_b64.clone();
            std::thread::spawn(move || {
                let qr = qr_rx.recv().expect("daemon rendered a QR");
                let payload = PairingPayload::from_qr_string(&qr).unwrap();
                let daemon_pub = payload.daemon;
                let phone_id = DeviceIdentity::generate();
                let phone_pub = phone_id.peer_identity();
                let mut phone = PhonePairing::scan(
                    DeviceIdentity::from_secret_bytes(&phone_id.to_secret_bytes()[..]).unwrap(),
                    payload,
                    NOW + 1_000,
                )
                .unwrap();
                let resp = phone.respond().unwrap();
                p2d.lock()
                    .unwrap()
                    .push_back(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&resp).unwrap()));
                // Wait for the DEK before sending the share (mirrors the phone).
                loop {
                    if d2p.lock().unwrap().pop_front().is_some() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                let share = ThresholdShare {
                    se_key_id: "latch-se-test".into(),
                    f_x963: f_b64,
                    ecdh_algo: EcdhAlgo::RawX,
                };
                let pairing_id = mailbox_id(&phone_pub, &daemon_pub);
                let env =
                    Envelope::seal(&share, pairing_id, 1, &phone_id.signing, &daemon_pub).unwrap();
                p2d.lock()
                    .unwrap()
                    .push_back(serde_json::to_string(&env).unwrap());
            })
        };

        let daemon_id = DeviceIdentity::generate();
        let mut make_channel = |_m: [u8; 32]| -> Result<Box<dyn PairChannel>> {
            Ok(Box::new(MemChannel {
                d2p: d2p.clone(),
                p2d: p2d.clone(),
            }))
        };
        let mut present_qr = |_u: &str, b64: &str| qr_tx.send(b64.to_string()).unwrap();
        let mut confirm = |_w: &[&'static str; 6]| true;
        let clock = || NOW;
        let dek = crate::secrets::generate_dek();
        let opts = CeremonyOpts {
            relay_url: "ws://relay.test".into(),
            response_timeout: Duration::from_secs(5),
            flush_grace: Duration::ZERO,
            now: &clock,
            make_channel: &mut make_channel,
            present_qr: &mut present_qr,
            confirm_sas: &mut confirm,
            share_wait: Duration::from_secs(5),
            dek: &dek,
        };
        let np = run_ceremony(daemon_id, opts).expect("ceremony completes");
        phone_thread.join().unwrap();

        let share = np
            .phone_share
            .expect("F pinned from the sealed ThresholdShare");
        assert_eq!(share.f_x963, f_x963.to_vec(), "the exact F is persisted");
        assert_eq!(share.se_key_id, "latch-se-test");
        assert_eq!(share.ecdh_algo, EcdhAlgo::RawX);
    }

    #[test]
    fn ceremony_without_a_share_stays_v1_only() {
        // A phone with no Secure Enclave never sends a ThresholdShare; the daemon
        // waits out `share_wait` and pairs v1-only (phone_share is None).
        use latch_proto::pairing::PhonePairing;
        use latch_proto::PairingPayload;

        let d2p = Arc::new(Mutex::new(VecDeque::<String>::new()));
        let p2d = Arc::new(Mutex::new(VecDeque::<String>::new()));
        let (qr_tx, qr_rx) = std::sync::mpsc::channel::<String>();
        let phone_thread = {
            let p2d = p2d.clone();
            std::thread::spawn(move || {
                let qr = qr_rx.recv().unwrap();
                let payload = PairingPayload::from_qr_string(&qr).unwrap();
                let mut phone =
                    PhonePairing::scan(DeviceIdentity::generate(), payload, NOW + 1_000).unwrap();
                let resp = phone.respond().unwrap();
                p2d.lock()
                    .unwrap()
                    .push_back(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&resp).unwrap()));
            })
        };
        let daemon_id = DeviceIdentity::generate();
        let mut make_channel = |_m: [u8; 32]| -> Result<Box<dyn PairChannel>> {
            Ok(Box::new(MemChannel {
                d2p: d2p.clone(),
                p2d: p2d.clone(),
            }))
        };
        let mut present_qr = |_u: &str, b64: &str| qr_tx.send(b64.to_string()).unwrap();
        let mut confirm = |_w: &[&'static str; 6]| true;
        let clock = || NOW;
        let dek = crate::secrets::generate_dek();
        let opts = CeremonyOpts {
            relay_url: "ws://relay.test".into(),
            response_timeout: Duration::from_secs(5),
            flush_grace: Duration::ZERO,
            now: &clock,
            make_channel: &mut make_channel,
            present_qr: &mut present_qr,
            confirm_sas: &mut confirm,
            // A short wait so the test does not linger; the phone sends no share.
            share_wait: Duration::from_millis(50),
            dek: &dek,
        };
        let np = run_ceremony(daemon_id, opts).expect("ceremony completes");
        phone_thread.join().unwrap();
        assert!(np.phone_share.is_none(), "no SE share => v1-only pairing");
    }

    #[test]
    fn render_qr_produces_scannable_block_output() {
        let qr = render_qr("LATCH-TEST-PAYLOAD-abc123").unwrap();
        assert!(!qr.is_empty());
        // Unicode half-block glyphs are what a terminal QR is made of.
        assert!(qr.contains('\u{2588}') || qr.contains('\u{2580}') || qr.contains('\u{2584}'));
    }

    #[test]
    fn decode_response_accepts_base64url_and_raw_json() {
        // Build a real response to round-trip both encodings.
        let daemon = DeviceIdentity::generate();
        let (mut d, payload) = DaemonPairing::mint(daemon, vec!["ws://r".into()], NOW);
        let phone = DeviceIdentity::generate();
        let (_p, resp) = Pairing::scan_payload(phone, payload, NOW, Policy::Approve).unwrap();
        d.receive_response(&resp, NOW).unwrap();

        let json = serde_json::to_vec(&resp).unwrap();
        let b64 = URL_SAFE_NO_PAD.encode(&json);
        assert_eq!(decode_response(&b64).unwrap().tag, resp.tag);
        let raw = String::from_utf8(json).unwrap();
        assert_eq!(decode_response(&raw).unwrap().tag, resp.tag);
        assert!(decode_response("not a response").is_err());
    }
}
