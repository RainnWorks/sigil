//! [`DaemonRelay`]: the daemon's HTTP [`Transport`] to the v4 stateless relay.
//!
//! The daemon deposits a sealed request toward the phone and short-polls for the
//! phone's sealed reply. There is no held socket and no daemon-side buffer: the
//! relay holds the deposited request in memory for a short TTL (evicted on read),
//! so a single POST is enough and the daemon only polls while it is actually
//! awaiting a decision.
//!
//! * `deposit_to_phone` POSTs `/mailbox/{id}/to-phone` with the sealed request
//!   and, when the phone has registered one, its push token as a [`PushHint`].
//!   The RELAY (not the daemon) rings the doorbell with that token and forgets
//!   it; the daemon holds no Apple secret and signs nothing.
//! * `recv(ToDaemon)` short-polls `GET /mailbox/{id}/to-daemon`, buffering the
//!   drained batch and returning one envelope per call. This slot also carries an
//!   unsolicited `PushRegister`; the caller demultiplexes it.
//!
//! Any transport error fails closed: the approval simply times out and the phone
//! retries, exactly as the design intends.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use latch_proto::envelope::Envelope;
use latch_proto::{Direction, PushHint, Transport, TransportError};

use crate::http::{HttpMailbox, Slot};
use crate::wire;

/// Delay between empty `to-daemon` polls, trading latency for request volume.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// A daemon-side [`Transport`] over plain HTTP to the blind relay.
pub struct DaemonRelay {
    mailbox: [u8; 32],
    http: HttpMailbox,
    /// Envelopes drained from `to-daemon` but not yet returned by `recv`.
    buffer: Mutex<VecDeque<Envelope>>,
    poll_interval: Duration,
}

impl DaemonRelay {
    /// Build a daemon transport against the `http(s)://host` relay `base` for
    /// `mailbox`. Connectionless: no background thread, no attach.
    pub fn new(base: &str, mailbox: [u8; 32]) -> Result<Self, TransportError> {
        Ok(Self {
            mailbox,
            http: HttpMailbox::new(base, mailbox)?,
            buffer: Mutex::new(VecDeque::new()),
            poll_interval: POLL_INTERVAL,
        })
    }

    /// The mailbox this relay routes on.
    pub fn mailbox(&self) -> [u8; 32] {
        self.mailbox
    }

    /// Override the empty-poll delay (tests use a short one).
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// GET `to-daemon` once and append any envelopes to the buffer.
    fn poll_to_daemon(&self) -> Result<(), TransportError> {
        let drained = self.http.drain(Slot::ToDaemon)?;
        let mut buf = self.buffer.lock().map_err(|_| TransportError::Closed)?;
        for s in drained {
            match wire::wire_to_envelope(&s) {
                Ok(env) => buf.push_back(env),
                Err(e) => eprintln!("latch relay: dropped an undecodable to-daemon envelope: {e}"),
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

impl Transport for DaemonRelay {
    fn send(
        &self,
        _mailbox: [u8; 32],
        dir: Direction,
        env: &Envelope,
    ) -> Result<(), TransportError> {
        if dir != Direction::ToPhone {
            return Err(TransportError::Backend(
                "daemon relay only sends ToPhone".into(),
            ));
        }
        self.deposit_to_phone(self.mailbox, env, None)
    }

    fn deposit_to_phone(
        &self,
        _mailbox: [u8; 32],
        env: &Envelope,
        hint: Option<PushHint>,
    ) -> Result<(), TransportError> {
        let wire = wire::envelope_to_wire(env)
            .map_err(|e| TransportError::Backend(format!("serializing envelope: {e}")))?;
        self.http.deposit(Slot::ToPhone, &wire, hint.as_ref())
    }

    fn recv(
        &self,
        _mailbox: [u8; 32],
        dir: Direction,
        timeout: Duration,
    ) -> Result<Option<Envelope>, TransportError> {
        if dir != Direction::ToDaemon {
            return Err(TransportError::Backend(
                "daemon relay only receives ToDaemon".into(),
            ));
        }
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(env) = self.pop_buffered()? {
                return Ok(Some(env));
            }
            self.poll_to_daemon()?;
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
