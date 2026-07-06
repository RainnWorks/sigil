//! [`PhoneRelay`]: the approver's HTTP [`Transport`] to the v4 stateless relay.
//!
//! The phone has no inbound connection; it deposits and drains. `send(ToDaemon)`
//! POSTs `/mailbox/{id}/to-daemon`; `recv(ToPhone)` long-polls
//! `GET /mailbox/{id}/to-phone`: the relay HOLDS an empty request open
//! server-side (up to its own ~25s hold) rather than answering empty
//! immediately, so the client just issues the next GET the instant one
//! returns -- no client-side sleep between polls. Buffers the drained batch
//! and returns one envelope per call so the [`Transport`] contract is
//! preserved.
//!
//! Used by the reference softphone in the end-to-end tests; the real iOS approver
//! speaks the same wire from TypeScript. Blocking is deliberate: the approver's
//! serve loop is one thread doing one round trip at a time. A transient poll
//! ERROR (network blip, a 5xx) is retried with backoff inside `recv` rather
//! than dropping the turn outright; only running out the deadline with
//! nothing received fails closed. An empty long-poll return (the relay's
//! hold simply elapsed) is NOT an error and never engages the backoff.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use latch_proto::envelope::Envelope;
use latch_proto::{Direction, Transport, TransportError};

use crate::http::{HttpMailbox, Slot};
use crate::wire;

/// Initial backoff after a transient poll error (network blip, a 5xx); the
/// relay's own long-poll hold does the "wait for real work" job now, so this
/// only paces retries of actual failures, not the empty-slot common case.
const ERROR_BACKOFF_INITIAL: Duration = Duration::from_millis(500);

/// Ceiling on the backoff after consecutive transient poll errors, so a
/// prolonged relay outage still polls often enough to catch it recovering
/// before the caller's deadline.
const MAX_POLL_BACKOFF: Duration = Duration::from_secs(10);

/// A phone-side [`Transport`] over plain HTTP to the blind relay.
pub struct PhoneRelay {
    http: HttpMailbox,
    /// Envelopes drained from `to-phone` but not yet returned by `recv`.
    buffer: Mutex<VecDeque<Envelope>>,
    error_backoff_initial: Duration,
}

impl PhoneRelay {
    /// Build a phone transport against the `http(s)://host` relay `base` for
    /// `mailbox`.
    pub fn new(base: &str, mailbox: [u8; 32]) -> Result<Self, TransportError> {
        Ok(Self {
            http: HttpMailbox::new(base, mailbox)?,
            buffer: Mutex::new(VecDeque::new()),
            error_backoff_initial: ERROR_BACKOFF_INITIAL,
        })
    }

    /// Override the initial error-retry backoff (tests use a short one).
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.error_backoff_initial = interval;
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
        let mut backoff = self.error_backoff_initial;
        loop {
            if let Some(env) = self.pop_buffered()? {
                return Ok(Some(env));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            // Same discipline as `DaemonRelay::recv`: `poll_to_phone` now
            // long-polls (the GET itself is the wait), so a transient poll
            // ERROR retries with backoff up to the deadline instead of
            // dropping the turn on the first blip, while an empty return
            // (the hold elapsed, nothing yet) just re-issues immediately.
            match self.poll_to_phone() {
                Ok(()) => {
                    backoff = self.error_backoff_initial;
                    if let Some(env) = self.pop_buffered()? {
                        return Ok(Some(env));
                    }
                }
                Err(e) => {
                    eprintln!("latch relay: to-phone poll failed, retrying: {e}");
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Ok(None);
                    }
                    std::thread::sleep(backoff.min(remaining));
                    backoff = (backoff * 2).min(MAX_POLL_BACKOFF);
                }
            }
        }
    }
}
