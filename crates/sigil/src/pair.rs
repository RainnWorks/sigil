//! The daemon side of a real, cross-process pairing over the blind relay.
//!
//! `sigil pair` mints a fresh daemon identity and a one-time pairing secret,
//! renders the [`PairingPayload`](sigil_proto::PairingPayload) as a scannable QR
//! (and a base64url line),
//! waits on the relay rendezvous mailbox for the phone's `PairingResponse`,
//! verifies its MAC (pinning the phone), has the human confirm the six SAS
//! words, seals the keystore's DEK to the phone (the same key `sigil account
//! add` encrypts tokens under, so a later approval returns a DEK that actually
//! decrypts them), and persists the result so the daemon can arm the phone
//! factor with no `--dev-insecure` (see [`crate::pairing_store`]).
//!
//! The ceremony is written against a [`PairChannel`] so it is exercised
//! end-to-end headlessly (in-process, with the softphone) as well as over the
//! real relay via the HTTP [`Rendezvous`](sigil_relay_client::Rendezvous). The
//! transport is never the security layer: message 1 (the response) is
//! authenticated by its pairing MAC, and message 3 (the DEK) is a standard sealed
//! [`Envelope`](sigil_proto::Envelope).

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use sigil_proto::identity::DeviceIdentity;
use sigil_proto::pairing::DaemonPairing;
use sigil_proto::{rendezvous_mailbox, PairingResponse, TransportError};

use crate::pairing_store::{NewPairing, NewPhoneShare};

/// The Sigil-operated shared relay, used when the operator gives neither
/// `--relay <url>` nor `$SIGIL_RELAY_URL`. It is a blind mailbox (opaque
/// envelopes, key-hash mailboxes, no accounts -- see the design brief's Trust
/// model), so defaulting to it costs nothing beyond routing metadata; a
/// self-hosted relay via either override still takes priority. Callers that
/// use this default must say so out loud (never silently), so the human
/// always knows which relay a pairing crossed.
pub const DEFAULT_RELAY_URL: &str = "https://relay.rainn.works";

/// The opaque-string channel the pairing ceremony runs over: send toward the
/// phone, receive from the phone. Implemented by the HTTP
/// [`Rendezvous`](sigil_relay_client::Rendezvous) for the real relay and by an
/// in-memory pair in tests.
pub trait PairChannel {
    fn send(&self, payload: String) -> Result<(), TransportError>;
    fn recv(&self, timeout: Duration) -> Result<Option<String>, TransportError>;
}

impl PairChannel for sigil_relay_client::Rendezvous {
    fn send(&self, payload: String) -> Result<(), TransportError> {
        sigil_relay_client::Rendezvous::send(self, &payload)
    }
    fn recv(&self, timeout: Duration) -> Result<Option<String>, TransportError> {
        sigil_relay_client::Rendezvous::recv(self, timeout)
    }
}

/// Render a QR payload string as a terminal QR using unicode half-blocks, with a
/// quiet zone so a phone camera can lock on. Delegates to [`crate::qr`], the one
/// place QR rendering lives, so the pairing QR, `sigil qr`, and the PNG output
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
    /// Arm the pairing: prove a live hardware presence (Touch ID) and provision
    /// the Mac threshold share `m`. Called exactly once, and only after
    /// [`Self::confirm_sas`] has returned `true` -- never before. On a Secure
    /// Enclave keystore the presence check is where Touch ID fires, so the
    /// biometric gates authorizing *this confirmed device*, not just starting the
    /// ceremony: a same-UID process that can drive the pipe up to this point still
    /// cannot complete a pairing without a live biometric at the moment the human
    /// has already compared the SAS words. There is no key handed to the phone: at
    /// rest everything is threshold-sealed and opened per-approval with the phone's
    /// partial, so provisioning `m` (idempotently) is all that arms this daemon.
    pub arm_after_sas: &'a mut dyn FnMut() -> Result<()>,
}

/// Run the full daemon-side ceremony and return what to persist. The pairing is
/// armed ([`CeremonyOpts::arm_after_sas`]) only after the SAS is confirmed: a live
/// hardware presence is proven and the Mac threshold share `m` is provisioned. No
/// key is handed to the phone -- at rest everything is threshold-sealed.
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

    // 4. ONLY NOW -- after a human has confirmed the SAS -- arm the pairing: prove
    //    a live hardware presence (on a Secure Enclave keystore this is the Touch
    //    ID prompt) and provision the Mac threshold share `m`. Placing it here
    //    rather than at ceremony start means the biometric gates authorizing this
    //    specific confirmed device. Nothing is sealed to the phone: at rest every
    //    secret is threshold-sealed and opened per-approval with the phone's
    //    partial `F`, which the response already pinned.
    (opts.arm_after_sas)().context("arming the pairing (presence + threshold share)")?;

    // Let the transport settle before the channel is torn down.
    if !opts.flush_grace.is_zero() {
        std::thread::sleep(opts.flush_grace);
    }

    let phone = daemon
        .phone()
        .expect("phone is pinned once the response verified");
    // When the phone's response carried its Secure-Enclave threshold share F
    // (already tag-bound and on-curve-validated by `receive_response`), pin F, so
    // this pairing arms both the Mac share `m` (provisioned above) and the phone
    // share `F` together. The wire carries only F; the Mac names the key locally
    // and defaults its ECDH shape (NV-2/NV-7).
    let phone_share = daemon.phone_se_share().map(|f| NewPhoneShare {
        se_key_id: crate::threshold::DEFAULT_SE_KEY_ID.to_string(),
        f_x963: f.to_vec(),
        ecdh_algo: crate::threshold::DEFAULT_ECDH_ALGO,
    });
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

/// Build the real relay channel: the daemon side of the HTTP rendezvous on
/// `relay_url` for the rendezvous `mailbox` (send `to-phone`, receive
/// `to-daemon`).
pub fn relay_channel(relay_url: &str, mailbox: [u8; 32]) -> Result<Box<dyn PairChannel>> {
    let rv = sigil_relay_client::Rendezvous::daemon(relay_url, mailbox)
        .map_err(|e| anyhow::anyhow!("reaching relay {relay_url}: {e}"))?;
    Ok(Box::new(rv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use sigil_softphone::{Pairing, Policy};

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
                // The ceremony delivers no key: after SAS confirmation the phone
                // just finishes (it holds only its identity / SE share).
                let sp = pairing.finish().unwrap();
                let _ = &d2p; // no envelope is sent back anymore
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
        let mut arm_after_sas = || -> Result<()> { Ok(()) };

        let opts = CeremonyOpts {
            relay_url: "ws://relay.test".into(),
            response_timeout: Duration::from_secs(5),
            flush_grace: Duration::ZERO,
            now: &clock,
            make_channel: &mut make_channel,
            present_qr: &mut present_qr,
            confirm_sas: &mut confirm,
            arm_after_sas: &mut arm_after_sas,
        };
        let np = run_ceremony(daemon_id, opts).expect("ceremony completes");

        let phone_pub = phone_thread.join().unwrap();
        // The daemon pinned exactly the phone that responded, and kept its own
        // identity for persistence.
        assert_eq!(np.phone, phone_pub);
        assert_eq!(np.daemon_identity.peer_identity(), daemon_pub);
        assert_eq!(np.relay_url, "ws://relay.test");
        // The recorded SAS words are the real fingerprint of the pinned pair.
        let expected = sigil_proto::fingerprint_words(&daemon_pub, &phone_pub);
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
        let mut arm_after_sas = || -> Result<()> { Ok(()) };
        let opts = CeremonyOpts {
            relay_url: "ws://relay.test".into(),
            response_timeout: Duration::from_secs(5),
            flush_grace: Duration::ZERO,
            now: &clock,
            make_channel: &mut make_channel,
            present_qr: &mut present_qr,
            confirm_sas: &mut confirm,
            arm_after_sas: &mut arm_after_sas,
        };
        let err = match run_ceremony(daemon_id, opts) {
            Err(e) => e,
            Ok(_) => panic!("expected the pairing to be cancelled at SAS"),
        };
        assert!(err.to_string().contains("SAS"), "cancelled at SAS: {err}");
        phone_thread.join().unwrap();
    }

    /// Ordering guard for #48: arming the pairing -- on a Secure Enclave keystore,
    /// the Touch ID moment, plus provisioning the Mac threshold share -- must fire
    /// *only after* the SAS is confirmed, never before. A same-UID caller that can
    /// drive the ceremony's `confirm_sas` decision to `false` (a hostile GUI, or a
    /// stdin writer that sends anything but "confirm" on the `--json` path) must
    /// not be able to make the ceremony reach `arm_after_sas` at all: no biometric
    /// prompt. Counts arm invocations and asserts zero on the declined path, so a
    /// future refactor that moved arming back ahead of the SAS gate would fail here.
    #[test]
    fn arm_after_sas_never_fires_when_the_sas_is_declined() {
        use std::sync::atomic::{AtomicUsize, Ordering};

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
        let mut confirm = |_w: &[&'static str; 6]| false; // the SAS did not match
        let clock = || NOW;
        let arms = AtomicUsize::new(0);
        let mut arm_after_sas = || -> Result<()> {
            arms.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        let opts = CeremonyOpts {
            relay_url: "ws://relay.test".into(),
            response_timeout: Duration::from_secs(5),
            flush_grace: Duration::ZERO,
            now: &clock,
            make_channel: &mut make_channel,
            present_qr: &mut present_qr,
            confirm_sas: &mut confirm,
            arm_after_sas: &mut arm_after_sas,
        };
        assert!(
            run_ceremony(daemon_id, opts).is_err(),
            "a declined SAS must fail the ceremony closed"
        );
        assert_eq!(
            arms.load(Ordering::SeqCst),
            0,
            "arm_after_sas (the Touch ID + share-provision moment) must never fire when the SAS is declined"
        );
        phone_thread.join().unwrap();
    }

    #[test]
    fn ceremony_pins_the_phone_threshold_share_f_when_sent() {
        // When the phone's pairing response carries its v2 SE share F (tag-bound
        // and on-curve-validated in receive_response), run_ceremony persists it in
        // the returned NewPairing so v2 account-add can wrap tokens to it.
        use base64::engine::general_purpose::STANDARD as B64S;
        use sigil_proto::pairing::PhonePairing;
        use sigil_proto::threshold::MacShare;
        use sigil_proto::PairingPayload;

        // The phone's SE share f (software stand-in) and its public F.
        let f = MacShare::generate();
        let f_x963 = *f.public_point().as_x963();
        let f_b64 = B64S.encode(f_x963);

        let d2p = Arc::new(Mutex::new(VecDeque::<String>::new()));
        let p2d = Arc::new(Mutex::new(VecDeque::<String>::new()));
        let (qr_tx, qr_rx) = std::sync::mpsc::channel::<String>();

        let phone_thread = {
            let p2d = p2d.clone();
            let f_b64 = f_b64.clone();
            std::thread::spawn(move || {
                let qr = qr_rx.recv().expect("daemon rendered a QR");
                let payload = PairingPayload::from_qr_string(&qr).unwrap();
                let mut phone =
                    PhonePairing::scan(DeviceIdentity::generate(), payload, NOW + 1_000)
                        .unwrap()
                        .with_se_share(&f_b64);
                let resp = phone.respond().unwrap();
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
        let mut confirm = |_w: &[&'static str; 6]| true;
        let clock = || NOW;
        let mut arm_after_sas = || -> Result<()> { Ok(()) };
        let opts = CeremonyOpts {
            relay_url: "ws://relay.test".into(),
            response_timeout: Duration::from_secs(5),
            flush_grace: Duration::ZERO,
            now: &clock,
            make_channel: &mut make_channel,
            present_qr: &mut present_qr,
            confirm_sas: &mut confirm,
            arm_after_sas: &mut arm_after_sas,
        };
        let np = run_ceremony(daemon_id, opts).expect("ceremony completes");
        phone_thread.join().unwrap();

        let share = np.phone_share.expect("F was pinned");
        assert_eq!(share.f_x963, f_x963.to_vec(), "the exact F is persisted");
        assert_eq!(share.se_key_id, crate::threshold::DEFAULT_SE_KEY_ID);
        assert_eq!(share.ecdh_algo, crate::threshold::DEFAULT_ECDH_ALGO);
    }

    #[test]
    fn render_qr_produces_scannable_block_output() {
        let qr = render_qr("SIGIL-TEST-PAYLOAD-abc123").unwrap();
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
