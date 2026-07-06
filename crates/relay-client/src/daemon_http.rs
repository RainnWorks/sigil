//! [`DaemonRelay`]: the daemon's HTTP [`Transport`] to the v4 stateless relay.
//!
//! The daemon deposits a sealed request toward the phone and long-polls for the
//! phone's sealed reply. There is no held socket and no daemon-side buffer: the
//! relay holds the deposited request in memory for a short TTL (evicted on read),
//! so a single POST is enough and the daemon only polls while it is actually
//! awaiting a decision.
//!
//! * `deposit_to_phone` POSTs `/mailbox/{id}/to-phone` with the sealed request
//!   and, when the phone has registered one, its push token as a [`PushHint`].
//!   The RELAY (not the daemon) rings the doorbell with that token and forgets
//!   it; the daemon holds no Apple secret and signs nothing.
//! * `recv(ToDaemon)` long-polls `GET /mailbox/{id}/to-daemon`: the relay HOLDS
//!   an empty request open server-side (up to its own ~25s hold) rather than
//!   answering empty immediately, so the client just issues the next GET the
//!   instant one returns -- no client-side sleep between polls, no idle-poll
//!   volume, and the doorbell is genuinely the wakeup rather than racing a
//!   fixed interval. This slot also carries an unsolicited `PushRegister`; the
//!   caller demultiplexes it.
//!
//! A transient poll error (network blip, a 5xx) is retried with backoff inside
//! `recv` rather than failing the round trip outright; only running out the
//! deadline with nothing received fails closed, exactly as the design intends.
//! An empty long-poll return (the relay's hold simply elapsed) is NOT an error
//! and never engages the backoff -- it just means "re-issue".

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use latch_proto::envelope::Envelope;
use latch_proto::{Direction, PushHint, Transport, TransportError};

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

/// A daemon-side [`Transport`] over plain HTTP to the blind relay.
pub struct DaemonRelay {
    mailbox: [u8; 32],
    http: HttpMailbox,
    /// Envelopes drained from `to-daemon` but not yet returned by `recv`.
    buffer: Mutex<VecDeque<Envelope>>,
    error_backoff_initial: Duration,
}

impl DaemonRelay {
    /// Build a daemon transport against the `http(s)://host` relay `base` for
    /// `mailbox`. Connectionless: no background thread, no attach.
    pub fn new(base: &str, mailbox: [u8; 32]) -> Result<Self, TransportError> {
        Ok(Self {
            mailbox,
            http: HttpMailbox::new(base, mailbox)?,
            buffer: Mutex::new(VecDeque::new()),
            error_backoff_initial: ERROR_BACKOFF_INITIAL,
        })
    }

    /// The mailbox this relay routes on.
    pub fn mailbox(&self) -> [u8; 32] {
        self.mailbox
    }

    /// Override the initial error-retry backoff (tests use a short one).
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.error_backoff_initial = interval;
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
        let mut backoff = self.error_backoff_initial;
        loop {
            if let Some(env) = self.pop_buffered()? {
                return Ok(Some(env));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            // `poll_to_daemon` now long-polls: the relay holds an empty
            // request open server-side (up to its own ~25s) rather than
            // answering empty immediately, so this GET itself is the wait.
            // A transient poll ERROR (network blip, a 5xx) must not deny a
            // legitimate approval outright: retry with backoff up to the
            // deadline. An empty return is not an error -- it is just the
            // hold elapsing with nothing yet -- and re-issues immediately,
            // no sleep, since the relay already did the waiting.
            match self.poll_to_daemon() {
                Ok(()) => {
                    backoff = self.error_backoff_initial;
                    if let Some(env) = self.pop_buffered()? {
                        return Ok(Some(env));
                    }
                    // Empty long-poll: go straight back to the top and issue
                    // the next GET. `pop_buffered`'s own error (a poisoned
                    // mutex) is the one thing here that is never going to
                    // resolve by retrying, hence the early `?` above.
                }
                Err(e) => {
                    eprintln!("latch relay: to-daemon poll failed, retrying: {e}");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A raw-socket fake relay that answers the first `to-daemon` GET with a
    /// transient 500, then the second with a real envelope. No mocking crate
    /// in the dependency tree, so this is hand-rolled HTTP/1.1 framing over a
    /// `TcpListener`, `Connection: close` per response so parsing a request
    /// need not go further than finding the blank line.
    fn spawn_flaky_relay() -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake relay");
        let addr = listener.local_addr().expect("local_addr");
        let identity = latch_proto::identity::DeviceIdentity::generate();
        let peer = identity.peer_identity();
        let env = Envelope::seal(&"payload", [7u8; 32], 1, &identity.signing, &peer)
            .expect("seal test envelope");
        let env_json = serde_json::to_string(&env).expect("serialize test envelope");
        let handle = std::thread::spawn(move || {
            for ok in [false, true] {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf); // discard the request line/headers
                let body = if ok {
                    format!(
                        "{{\"envelopes\":[{}]}}",
                        serde_json::to_string(&env_json).unwrap()
                    )
                } else {
                    String::new()
                };
                let status = if ok {
                    "200 OK"
                } else {
                    "500 Internal Server Error"
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        (format!("http://{addr}"), handle)
    }

    #[test]
    fn recv_survives_one_transient_poll_error_and_returns_the_envelope() {
        let (base, server) = spawn_flaky_relay();
        let relay = DaemonRelay::new(&base, [7u8; 32])
            .expect("build relay")
            .with_poll_interval(Duration::from_millis(20));
        let got = relay
            .recv([7u8; 32], Direction::ToDaemon, Duration::from_secs(5))
            .expect("recv must retry past the transient 500, not error out");
        assert!(
            got.is_some(),
            "the envelope from the second poll must surface"
        );
        server.join().expect("fake relay thread");
    }
}
