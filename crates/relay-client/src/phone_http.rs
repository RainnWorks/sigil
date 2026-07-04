//! [`PhoneRelay`]: the approver's HTTPS [`Transport`].
//!
//! The phone has no inbound connection; it polls. `recv(ToPhone)` drains
//! `GET /mailbox/{id}/pending` (drain-on-read: the relay removes what it hands
//! back) and buffers the batch, returning one envelope at a time so the
//! [`Transport`] contract (one per `recv`) is preserved. `send(ToDaemon)` posts
//! the opaque envelope to `POST /mailbox/{id}/submit`.
//!
//! Blocking is deliberate: the approver's serve loop is one thread doing one
//! round trip at a time, so a synchronous client is the right shape and needs no
//! async runtime. Any transport error fails closed — the approver drops that one
//! turn and keeps serving; the daemon's request simply times out and is retried.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

use latch_proto::envelope::Envelope;
use latch_proto::{Direction, Transport, TransportError};

use crate::{mailbox_hex, wire};

/// Per-poll HTTP timeout. `/pending` returns immediately with whatever is
/// queued (it is not a long-poll), so this only bounds a stalled connection.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// Delay between empty `/pending` polls, trading latency for request volume.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// The `/pending` response body (`RESP.pending` in `shared/protocol.ts`).
#[derive(Deserialize)]
struct Pending {
    envelopes: Vec<String>,
    #[allow(dead_code)]
    depth: i64,
}

/// A phone-side [`Transport`] that polls the blind relay over HTTPS.
pub struct PhoneRelay {
    base: String,
    mailbox_hex: String,
    /// Envelopes drained from `/pending` but not yet returned by `recv`.
    buffer: Mutex<VecDeque<Envelope>>,
    client: reqwest::blocking::Client,
    poll_interval: Duration,
}

impl PhoneRelay {
    /// Build a phone transport against the `http(s)://host` relay `base` for
    /// `mailbox`.
    pub fn new(base: &str, mailbox: [u8; 32]) -> Result<Self, TransportError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| TransportError::Backend(format!("building http client: {e}")))?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            mailbox_hex: mailbox_hex(&mailbox),
            buffer: Mutex::new(VecDeque::new()),
            client,
            poll_interval: POLL_INTERVAL,
        })
    }

    /// Override the empty-poll delay (tests use a short one).
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    fn pending_url(&self) -> String {
        format!("{}/mailbox/{}/pending", self.base, self.mailbox_hex)
    }

    fn submit_url(&self) -> String {
        format!("{}/mailbox/{}/submit", self.base, self.mailbox_hex)
    }

    /// GET `/pending` once and append any envelopes to the buffer.
    fn poll_pending(&self) -> Result<(), TransportError> {
        let resp = self
            .client
            .get(self.pending_url())
            .send()
            .map_err(|e| TransportError::Backend(format!("GET pending: {e}")))?;
        if !resp.status().is_success() {
            return Err(TransportError::Backend(format!(
                "GET pending: status {}",
                resp.status()
            )));
        }
        let body = resp
            .text()
            .map_err(|e| TransportError::Backend(format!("reading pending body: {e}")))?;
        let parsed: Pending = serde_json::from_str(&body)
            .map_err(|e| TransportError::Backend(format!("parsing pending body: {e}")))?;
        let mut buf = self.buffer.lock().map_err(|_| TransportError::Closed)?;
        for s in parsed.envelopes {
            match wire::wire_to_envelope(&s) {
                Ok(env) => buf.push_back(env),
                Err(e) => eprintln!("latch relay: dropped an undecodable pending envelope: {e}"),
            }
        }
        Ok(())
    }

    fn pop_buffered(&self) -> Result<Option<Envelope>, TransportError> {
        Ok(self
            .buffer
            .lock()
            .map_err(|_| TransportError::Closed)?
            .pop_front())
    }
}

impl Transport for PhoneRelay {
    fn send(
        &self,
        _mailbox: [u8; 32],
        dir: Direction,
        env: &Envelope,
    ) -> Result<(), TransportError> {
        if dir != Direction::ToDaemon {
            return Err(TransportError::Backend(
                "phone relay only sends ToDaemon".into(),
            ));
        }
        let wire = wire::envelope_to_wire(env)
            .map_err(|e| TransportError::Backend(format!("serializing envelope: {e}")))?;
        let resp = self
            .client
            .post(self.submit_url())
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(wire)
            .send()
            .map_err(|e| TransportError::Backend(format!("POST submit: {e}")))?;
        if !resp.status().is_success() {
            return Err(TransportError::Backend(format!(
                "POST submit: status {}",
                resp.status()
            )));
        }
        Ok(())
    }

    fn recv(
        &self,
        _mailbox: [u8; 32],
        dir: Direction,
        timeout: Duration,
    ) -> Result<Option<Envelope>, TransportError> {
        if dir != Direction::ToPhone {
            return Err(TransportError::Backend(
                "phone relay only receives ToPhone".into(),
            ));
        }
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(env) = self.pop_buffered()? {
                return Ok(Some(env));
            }
            self.poll_pending()?;
            if let Some(env) = self.pop_buffered()? {
                return Ok(Some(env));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            std::thread::sleep(self.poll_interval.min(remaining));
        }
    }
}
