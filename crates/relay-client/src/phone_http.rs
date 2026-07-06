//! [`PhoneRelay`]: the approver's HTTP [`Transport`] to the v4 stateless relay.
//!
//! The phone has no inbound connection; it deposits and drains. `send(ToDaemon)`
//! POSTs `/mailbox/{id}/to-daemon`; `recv(ToPhone)` short-polls
//! `GET /mailbox/{id}/to-phone` (drain-on-read), buffering the batch and
//! returning one envelope per call so the [`Transport`] contract is preserved.
//!
//! Used by the reference softphone in the end-to-end tests; the real iOS approver
//! speaks the same wire from TypeScript. Blocking is deliberate: the approver's
//! serve loop is one thread doing one round trip at a time. A transient poll
//! error (network blip, a 5xx) is retried with backoff inside `recv` rather
//! than dropping the turn outright; only running out the deadline with
//! nothing received fails closed.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use latch_proto::envelope::Envelope;
use latch_proto::{Direction, Transport, TransportError};

use crate::http::{HttpMailbox, Slot};
use crate::wire;

/// Delay between empty `to-phone` polls, trading latency for request volume.
const POLL_INTERVAL: Duration = Duration::from_millis(2000);

/// Ceiling on the backoff after consecutive transient poll errors, so a
/// prolonged relay outage still polls often enough to catch it recovering
/// before the caller's deadline.
const MAX_POLL_BACKOFF: Duration = Duration::from_secs(10);

/// A phone-side [`Transport`] over plain HTTP to the blind relay.
pub struct PhoneRelay {
    http: HttpMailbox,
    /// Envelopes drained from `to-phone` but not yet returned by `recv`.
    buffer: Mutex<VecDeque<Envelope>>,
    poll_interval: Duration,
}

impl PhoneRelay {
    /// Build a phone transport against the `http(s)://host` relay `base` for
    /// `mailbox`.
    pub fn new(base: &str, mailbox: [u8; 32]) -> Result<Self, TransportError> {
        Ok(Self {
            http: HttpMailbox::new(base, mailbox)?,
            buffer: Mutex::new(VecDeque::new()),
            poll_interval: POLL_INTERVAL,
        })
    }

    /// Override the empty-poll delay (tests use a short one).
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// GET `to-phone` once and append any envelopes to the buffer.
    fn poll_to_phone(&self) -> Result<(), TransportError> {
        let drained = self.http.drain(Slot::ToPhone)?;
        let mut buf = self.buffer.lock().map_err(|_| TransportError::Closed)?;
        for s in drained {
            match wire::wire_to_envelope(&s) {
                Ok(env) => buf.push_back(env),
                Err(e) => eprintln!("latch relay: dropped an undecodable to-phone envelope: {e}"),
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
        self.http.deposit(Slot::ToDaemon, &wire, None)
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
        let mut backoff = self.poll_interval;
        loop {
            if let Some(env) = self.pop_buffered()? {
                return Ok(Some(env));
            }
            // Same discipline as `DaemonRelay::recv`: a transient poll error
            // retries with backoff up to the deadline instead of dropping the
            // turn on the first blip.
            match self.poll_to_phone() {
                Ok(()) => backoff = self.poll_interval,
                Err(e) => eprintln!("latch relay: to-phone poll failed, retrying: {e}"),
            }
            if let Some(env) = self.pop_buffered()? {
                return Ok(Some(env));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            std::thread::sleep(backoff.min(remaining));
            backoff = (backoff * 2).min(MAX_POLL_BACKOFF);
        }
    }
}
