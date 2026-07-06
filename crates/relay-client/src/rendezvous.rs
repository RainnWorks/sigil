//! A raw, opaque-string client for the pairing rendezvous on the v4 relay.
//!
//! The steady-state [`DaemonRelay`](crate::DaemonRelay) /
//! [`PhoneRelay`](crate::PhoneRelay) transports (de)serialize
//! [`Envelope`](latch_proto::Envelope)s, but the first pairing message (the
//! phone's `PairingResponse`) is authenticated by its own MAC, not by an envelope
//! seal, so it cannot ride those typed transports. This client speaks the same
//! two relay slots (`POST`/`GET /mailbox/{id}/to-phone` and `.../to-daemon`) with
//! an entirely opaque payload, on the
//! [`rendezvous_mailbox`](latch_proto::rendezvous_mailbox), distinct from any
//! steady-state mailbox.
//!
//! Direction is role-fixed, mirroring the steady state: the daemon side sends
//! toward the phone (`to-phone`) and receives from the phone (`to-daemon`); the
//! phone side is the mirror. Blocking, like the rest of the ceremony. `recv`
//! long-polls just like the steady-state transports: an empty slot holds the
//! GET open server-side (up to the relay's own ~25s hold) rather than
//! answering empty immediately, so this client re-issues the next GET the
//! instant one returns rather than sleeping a fixed interval first.

use std::time::{Duration, Instant};

use latch_proto::TransportError;

use crate::http::{HttpMailbox, Slot};

/// A blocking client for one rendezvous mailbox, fixed to one party's direction
/// pair (send toward the peer, receive from the peer).
pub struct Rendezvous {
    http: HttpMailbox,
    send_slot: Slot,
    recv_slot: Slot,
}

impl Rendezvous {
    /// The daemon side of the ceremony: send `to-phone`, receive `to-daemon`.
    pub fn daemon(base: &str, mailbox: [u8; 32]) -> Result<Self, TransportError> {
        Ok(Self {
            http: HttpMailbox::new(base, mailbox)?,
            send_slot: Slot::ToPhone,
            recv_slot: Slot::ToDaemon,
        })
    }

    /// The phone side of the ceremony: send `to-daemon`, receive `to-phone`.
    pub fn phone(base: &str, mailbox: [u8; 32]) -> Result<Self, TransportError> {
        Ok(Self {
            http: HttpMailbox::new(base, mailbox)?,
            send_slot: Slot::ToDaemon,
            recv_slot: Slot::ToPhone,
        })
    }

    /// POST one opaque payload toward the peer.
    pub fn send(&self, payload: &str) -> Result<(), TransportError> {
        self.http.deposit(self.send_slot, payload, None)
    }

    /// Poll until one payload arrives or `timeout` elapses. Returns the first
    /// payload, or `None` on timeout. If a single drain returns several the extras
    /// are dropped: the ceremony is strictly one message per direction. Each
    /// `drain` is itself a long-poll GET (the relay holds an empty slot open
    /// server-side rather than answering empty immediately), so an empty
    /// result just means "the hold elapsed, nothing yet" -- re-issue at once,
    /// no client-side sleep.
    pub fn recv(&self, timeout: Duration) -> Result<Option<String>, TransportError> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut batch = self.http.drain(self.recv_slot)?;
            if !batch.is_empty() {
                return Ok(Some(batch.remove(0)));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
        }
    }
}
