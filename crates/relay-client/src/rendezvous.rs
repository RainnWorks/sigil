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
//! instant one returns rather than sleeping a fixed interval first. A
//! transient poll error (network blip, a 5xx) is retried with backoff up to
//! the deadline, same discipline as [`DaemonRelay`](crate::DaemonRelay) /
//! [`PhoneRelay`](crate::PhoneRelay) -- a pairing (a human-supervised, ~10-min
//! window) should not abort on one flaky-network blip any more than a
//! steady-state approval does. An empty long-poll is still not an error and
//! never engages the backoff.

use std::time::{Duration, Instant};

use latch_proto::TransportError;

use crate::http::{HttpMailbox, Slot};

/// Initial backoff after a transient poll error (network blip, a 5xx); the
/// relay's own long-poll hold does the "wait for real work" job, so this only
/// paces retries of actual failures, not the empty-slot common case.
const ERROR_BACKOFF_INITIAL: Duration = Duration::from_millis(500);

/// Ceiling on the backoff after consecutive transient poll errors, so a
/// prolonged relay outage still retries often enough to catch it recovering
/// before the caller's deadline.
const MAX_POLL_BACKOFF: Duration = Duration::from_secs(10);

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
    /// no client-side sleep. A transient drain ERROR (network blip, a 5xx)
    /// retries with backoff up to `timeout` instead of aborting the ceremony
    /// on one blip; only running out the deadline with nothing received
    /// returns `None`.
    pub fn recv(&self, timeout: Duration) -> Result<Option<String>, TransportError> {
        let deadline = Instant::now() + timeout;
        let mut backoff = ERROR_BACKOFF_INITIAL;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            match self.http.drain(self.recv_slot) {
                Ok(mut batch) if !batch.is_empty() => return Ok(Some(batch.remove(0))),
                // Empty long-poll: the hold elapsed with nothing yet. Not an
                // error, never engages the backoff -- reset it (so a stale
                // error's backoff never lingers past a subsequent success)
                // and go straight back to the top for the next GET.
                Ok(_) => backoff = ERROR_BACKOFF_INITIAL,
                Err(e) => {
                    eprintln!("latch relay: rendezvous poll failed, retrying: {e}");
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
    /// transient 500, then the second with a real payload. Same hand-rolled
    /// HTTP/1.1 framing as `daemon_http`'s equivalent fixture (no mocking
    /// crate in the tree); `Connection: close` per response so parsing a
    /// request need not go further than finding the blank line.
    fn spawn_flaky_relay() -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake relay");
        let addr = listener.local_addr().expect("local_addr");
        let handle = std::thread::spawn(move || {
            for ok in [false, true] {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf); // discard the request line/headers
                let body = if ok {
                    "{\"envelopes\":[\"rendezvous-payload\"]}".to_string()
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
    fn recv_survives_one_transient_poll_error_and_returns_the_payload() {
        let (base, server) = spawn_flaky_relay();
        let rv = Rendezvous::daemon(&base, [3u8; 32]).expect("build rendezvous client");
        let got = rv
            .recv(Duration::from_secs(5))
            .expect("recv must retry past the transient 500, not error out");
        assert_eq!(
            got.as_deref(),
            Some("rendezvous-payload"),
            "the payload from the second poll must surface"
        );
        server.join().expect("fake relay thread");
    }
}
