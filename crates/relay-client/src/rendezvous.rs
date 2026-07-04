//! A raw, opaque-string client for the blind relay, used only by the pairing
//! rendezvous.
//!
//! The steady-state [`DaemonRelay`](crate::DaemonRelay) /
//! [`PhoneRelay`](crate::PhoneRelay) transports (de)serialize
//! [`Envelope`](latch_proto::Envelope)s, but the first pairing message (the
//! phone's `PairingResponse`) is authenticated by its own MAC, not by an
//! envelope seal, so it cannot ride those typed transports. This client speaks
//! the same two relay endpoints (`POST /mailbox/{id}/submit`,
//! `GET /mailbox/{id}/pending`) with an entirely opaque UTF-8 payload, exactly
//! as the relay itself treats it. It carries pairing traffic on the
//! [`rendezvous_mailbox`](latch_proto::rendezvous_mailbox), which is distinct
//! from any steady-state mailbox.
//!
//! Blocking, like the phone side: pairing is a short, human-paced ceremony done
//! one round trip at a time, so a synchronous client needs no runtime.

use std::time::{Duration, Instant};

use serde::Deserialize;

use latch_proto::TransportError;

use crate::mailbox_hex;

/// Per-request HTTP timeout. `/pending` returns immediately with whatever is
/// queued, so this only bounds a stalled connection.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// The `/pending` response body (`RESP.pending` in `shared/protocol.ts`).
#[derive(Deserialize)]
struct Pending {
    envelopes: Vec<String>,
    #[allow(dead_code)]
    depth: i64,
}

/// A blocking client for one rendezvous mailbox on the blind relay.
pub struct Rendezvous {
    base: String,
    mailbox_hex: String,
    client: reqwest::blocking::Client,
}

impl Rendezvous {
    /// Build a client against the `http(s)://host` relay `base` for `mailbox`.
    pub fn new(base: &str, mailbox: [u8; 32]) -> Result<Self, TransportError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| TransportError::Backend(format!("building http client: {e}")))?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            mailbox_hex: mailbox_hex(&mailbox),
            client,
        })
    }

    fn pending_url(&self) -> String {
        format!("{}/mailbox/{}/pending", self.base, self.mailbox_hex)
    }

    fn submit_url(&self) -> String {
        format!("{}/mailbox/{}/submit", self.base, self.mailbox_hex)
    }

    /// POST one opaque payload to the mailbox.
    pub fn submit(&self, payload: &str) -> Result<(), TransportError> {
        let resp = self
            .client
            .post(self.submit_url())
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(payload.to_string())
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

    /// GET and drain everything currently queued for the mailbox (drain-on-read:
    /// the relay removes what it returns).
    pub fn poll(&self) -> Result<Vec<String>, TransportError> {
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
        Ok(parsed.envelopes)
    }

    /// Poll until one payload arrives or `timeout` elapses, sleeping `interval`
    /// between empty polls. Returns the first payload, or `None` on timeout. If
    /// a single poll returns several, the extras are dropped: the pairing
    /// ceremony is strictly one message per direction.
    pub fn wait(
        &self,
        timeout: Duration,
        interval: Duration,
    ) -> Result<Option<String>, TransportError> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut batch = self.poll()?;
            if !batch.is_empty() {
                return Ok(Some(batch.remove(0)));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            std::thread::sleep(interval.min(remaining));
        }
    }
}
