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
//! than dropping the turn outright; only running out the deadline with nothing
//! received fails closed.
//!
//! Same footgun and same discipline as [`crate::daemon_http`]: the no-sleep
//! design assumes the relay actually HOLDS each GET for its ~25s. A GET that
//! returns EMPTY *fast* (a slot evicted when a second GET races it, a
//! short/misconfigured hold, any short-circuit edge) would, re-issued with zero
//! delay, become a hammer pinned against the relay's rate limit. So `recv` TIMES
//! each GET: a fast empty (returned in less than the expected hold) engages an
//! exponential, jittered, capped backoff before the next GET, exactly like a
//! transient error or a 429 does; a full-length hold or any payload resets it.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sigil_proto::envelope::Envelope;
use sigil_proto::{Direction, Transport, TransportError};

use crate::http::{DrainOutcome, HttpMailbox, Slot};
use crate::wire;

/// Base backoff engaged by any *fast* GET return -- a transient error, a 429
/// with no `Retry-After`, or an empty return that clearly did not hold. The
/// series doubles from here per consecutive fast return and resets the instant
/// a GET actually holds or delivers.
const POLL_BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// Ceiling on the backoff after consecutive fast returns, so a pathological
/// relay (short-circuiting empties, or rate-limiting us) settles at roughly one
/// GET every [`MAX_POLL_BACKOFF`] rather than a hammer, while still polling
/// often enough to catch a recovery before the caller's deadline.
const MAX_POLL_BACKOFF: Duration = Duration::from_secs(15);

/// The threshold that separates a genuine long-poll hold from a fast return. A
/// real hold runs ~`LONG_POLL_MS` (~25s, under the 35s HTTP timeout); an empty
/// GET that came back sooner than this did not actually hold, so its return is
/// "fast" and must engage the backoff instead of re-issuing instantly.
const MIN_HOLD: Duration = Duration::from_secs(20);

/// A phone-side [`Transport`] over plain HTTP to the blind relay.
pub struct PhoneRelay {
    http: HttpMailbox,
    /// Envelopes drained from `to-phone` but not yet returned by `recv`.
    buffer: Mutex<VecDeque<Envelope>>,
    /// Base of the fast-return backoff series (tests use a short one).
    poll_backoff_base: Duration,
    /// A GET returning empty in less than this "did not hold" and backs off
    /// (a field, not the const, only so tests can shrink the real 20s hold).
    min_hold: Duration,
}

impl PhoneRelay {
    /// Build a phone transport against the `http(s)://host` relay `base` for
    /// `mailbox`.
    pub fn new(base: &str, mailbox: [u8; 32]) -> Result<Self, TransportError> {
        Ok(Self {
            http: HttpMailbox::new(base, mailbox)?,
            buffer: Mutex::new(VecDeque::new()),
            poll_backoff_base: POLL_BACKOFF_INITIAL,
            min_hold: MIN_HOLD,
        })
    }

    /// Override the base fast-return backoff (tests use a short one).
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_backoff_base = interval;
        self
    }

    /// Shrink the "did this GET actually hold?" threshold so a test needn't
    /// hold a real 20s to exercise the full-hold path.
    #[cfg(test)]
    fn with_min_hold(mut self, min_hold: Duration) -> Self {
        self.min_hold = min_hold;
        self
    }

    /// GET `to-phone` once, appending any envelopes to the buffer. Returns the
    /// raw [`DrainOutcome`] so `recv` can pace against a 429 vs an empty hold;
    /// the empty-vs-payload distinction is then just whether the buffer grew.
    fn poll_to_phone(&self) -> Result<DrainOutcome, TransportError> {
        let outcome = self.http.poll_slot(Slot::ToPhone)?;
        if let DrainOutcome::Envelopes(drained) = &outcome {
            let mut buf = self.buffer.lock().map_err(|_| TransportError::Closed)?;
            for s in drained {
                match wire::wire_to_envelope(s) {
                    Ok(env) => buf.push_back(env),
                    Err(e) => {
                        eprintln!("sigil relay: dropped an undecodable to-phone envelope: {e}")
                    }
                }
            }
        }
        Ok(outcome)
    }

    fn pop_buffered(&self) -> Result<Option<Envelope>, TransportError> {
        Ok(self
            .buffer
            .lock()
            .map_err(|_| TransportError::Closed)?
            .pop_front())
    }

    /// Sleep out one backoff step against `deadline`, returning the *next*
    /// (doubled, capped) backoff to carry forward. `current` is the un-jittered
    /// backoff from the previous consecutive fast return, or `None` to start a
    /// fresh series at `initial`. Never sleeps past the deadline.
    fn back_off(
        &self,
        current: Option<Duration>,
        initial: Duration,
        deadline: Instant,
    ) -> Option<Duration> {
        let step = current.unwrap_or(initial);
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !remaining.is_zero() {
            std::thread::sleep(jittered(step).min(remaining));
        }
        Some((step.saturating_mul(2)).min(MAX_POLL_BACKOFF))
    }

    /// Back off after a 429. Honors a relay-supplied `Retry-After` (floored at
    /// the base so a `Retry-After: 0` cannot re-create the hammer, capped at the
    /// deadline) and still advances the exponential series so consecutive 429s
    /// escalate. With no `Retry-After` it is exactly the ordinary fast-return
    /// backoff.
    fn back_off_rate_limited(
        &self,
        current: Option<Duration>,
        retry_after: Option<Duration>,
        deadline: Instant,
    ) -> Option<Duration> {
        let step = current.unwrap_or(self.poll_backoff_base);
        let next = Some((step.saturating_mul(2)).min(MAX_POLL_BACKOFF));
        match retry_after {
            Some(ra) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if !remaining.is_zero() {
                    std::thread::sleep(ra.max(self.poll_backoff_base).min(remaining));
                }
                next
            }
            None => self.back_off(current, self.poll_backoff_base, deadline),
        }
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
        // `None` == "the last GET held or delivered": the next fast return
        // starts a fresh backoff series at `poll_backoff_base`. `Some(d)` is
        // the (un-jittered) backoff carried across consecutive fast returns.
        let mut backoff: Option<Duration> = None;
        loop {
            if let Some(env) = self.pop_buffered()? {
                return Ok(Some(env));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            // The relay is meant to HOLD this GET for its ~25s: the GET itself
            // is the wait. Time it so a *fast* empty return (the hold that did
            // not happen) is paced instead of hammered.
            let started = Instant::now();
            match self.poll_to_phone() {
                Ok(outcome) => {
                    if let Some(env) = self.pop_buffered()? {
                        // A real payload: reset the series and deliver it.
                        return Ok(Some(env));
                    }
                    match outcome {
                        DrainOutcome::Envelopes(_) => {
                            // Empty return. If the GET actually held for ~the
                            // expected duration, the relay did the waiting:
                            // reset the series and re-issue promptly. If it
                            // came back fast, the hold did not happen, so back
                            // off before the next GET rather than hammering.
                            if started.elapsed() >= self.min_hold {
                                backoff = None;
                            } else {
                                backoff = self.back_off(backoff, self.poll_backoff_base, deadline);
                            }
                        }
                        DrainOutcome::RateLimited { retry_after } => {
                            // 429 is a fast return that MUST back off. Respect a
                            // relay-supplied `Retry-After`; otherwise fall into
                            // the same exponential series, still advancing it so
                            // repeated 429s escalate rather than settle at a
                            // relay-chosen floor.
                            eprintln!("sigil relay: to-phone poll was rate-limited (429)");
                            backoff = self.back_off_rate_limited(backoff, retry_after, deadline);
                        }
                    }
                }
                Err(e) => {
                    // A transient error (network blip, a 5xx) must not drop the
                    // turn outright: back off and retry up to the deadline.
                    // `pop_buffered`'s own error (a poisoned mutex) is the one
                    // thing that never resolves by retrying, hence the early `?`
                    // on it above.
                    eprintln!("sigil relay: to-phone poll failed, retrying: {e}");
                    backoff = self.back_off(backoff, self.poll_backoff_base, deadline);
                }
            }
        }
    }
}

/// Spread a backoff by +/-25% so many clients (or many retries) do not
/// re-issue in lockstep. Derived from the wall clock rather than pulling an rng
/// crate into the dependency tree; the exactness of the jitter does not matter,
/// only that consecutive sleeps de-correlate.
fn jittered(d: Duration) -> Duration {
    let base_ms = d.as_millis() as u64;
    if base_ms == 0 {
        return d;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.subsec_nanos())
        .unwrap_or(0) as u64;
    let span = base_ms / 2; // full jitter window == 50% of the base
    let offset = (nanos % 1000) * span / 1000; // 0..span
    let ms = base_ms - span / 2 + offset; // base-25% ..= base+25%
    Duration::from_millis(ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    /// One scripted response for a fake relay's next `to-phone` GET.
    #[derive(Clone)]
    enum Step {
        /// 200 `{"envelopes":[]}` after holding for `Duration` (a zero hold is
        /// the fast-empty footgun; a long hold is a real long-poll).
        EmptyAfter(Duration),
        /// 429, with an optional `Retry-After: <secs>` header.
        RateLimited(Option<u64>),
        /// 500: a transient error.
        ServerError,
        /// 200 carrying the sealed test envelope.
        Envelope,
    }

    /// A test-sealed envelope's wire JSON, reused across steps.
    fn env_wire_json() -> String {
        let identity = sigil_proto::identity::DeviceIdentity::generate();
        let peer = identity.peer_identity();
        let env = Envelope::seal(&"payload", [7u8; 32], 1, &identity.signing, &peer)
            .expect("seal test envelope");
        serde_json::to_string(&env).expect("serialize test envelope")
    }

    /// A raw-socket fake relay that plays `script`, one connection per step, and
    /// records the `Instant` each GET arrived so a test can assert the client's
    /// pacing between successive GETs. No mocking crate in the tree, so this is
    /// hand-rolled HTTP/1.1, `Connection: close` per response.
    fn spawn_scripted_relay(
        script: Vec<Step>,
    ) -> (
        String,
        Arc<Mutex<Vec<Instant>>>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake relay");
        let addr = listener.local_addr().expect("local_addr");
        let arrivals = Arc::new(Mutex::new(Vec::new()));
        let arrivals_thread = arrivals.clone();
        let env_json = env_wire_json();
        let handle = std::thread::spawn(move || {
            for step in script {
                let (mut stream, _) = listener.accept().expect("accept");
                arrivals_thread.lock().unwrap().push(Instant::now());
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf); // discard the request line/headers
                let (status, extra_headers, body) = match step {
                    Step::EmptyAfter(hold) => {
                        std::thread::sleep(hold);
                        ("200 OK", String::new(), "{\"envelopes\":[]}".to_string())
                    }
                    Step::RateLimited(retry_after) => {
                        let hdr = retry_after
                            .map(|s| format!("Retry-After: {s}\r\n"))
                            .unwrap_or_default();
                        ("429 Too Many Requests", hdr, String::new())
                    }
                    Step::ServerError => {
                        ("500 Internal Server Error", String::new(), String::new())
                    }
                    Step::Envelope => (
                        "200 OK",
                        String::new(),
                        format!(
                            "{{\"envelopes\":[{}]}}",
                            serde_json::to_string(&env_json).unwrap()
                        ),
                    ),
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        (format!("http://{addr}"), arrivals, handle)
    }

    /// Gaps between consecutive recorded GET arrivals: `gaps()[i]` is how long
    /// the client waited between issuing GET i and GET i+1.
    fn gaps(arrivals: &Arc<Mutex<Vec<Instant>>>) -> Vec<Duration> {
        let a = arrivals.lock().unwrap();
        a.windows(2).map(|w| w[1] - w[0]).collect()
    }

    #[test]
    fn recv_survives_one_transient_poll_error_and_returns_the_envelope() {
        let (base, arrivals, server) =
            spawn_scripted_relay(vec![Step::ServerError, Step::Envelope]);
        let relay = PhoneRelay::new(&base, [7u8; 32])
            .expect("build relay")
            .with_poll_interval(Duration::from_millis(20));
        let got = relay
            .recv([7u8; 32], Direction::ToPhone, Duration::from_secs(5))
            .expect("recv must retry past the transient 500, not error out");
        assert!(
            got.is_some(),
            "the envelope from the second poll must surface"
        );
        let g = gaps(&arrivals);
        assert!(
            g[0] >= Duration::from_millis(10),
            "a transient error must back off before the retry, not hammer: {g:?}"
        );
        server.join().expect("fake relay thread");
    }

    #[test]
    fn a_fast_empty_return_backs_off_with_an_increasing_delay_not_an_instant_reissue() {
        // Three empties that resolve *instantly* (the hold that never happened),
        // then the envelope. With `min_hold` set well above the zero hold, each
        // empty is classified "fast" and must engage the exponential backoff:
        // the gaps between GETs grow rather than staying pinned near zero.
        let (base, arrivals, server) = spawn_scripted_relay(vec![
            Step::EmptyAfter(Duration::ZERO),
            Step::EmptyAfter(Duration::ZERO),
            Step::EmptyAfter(Duration::ZERO),
            Step::Envelope,
        ]);
        let relay = PhoneRelay::new(&base, [7u8; 32])
            .expect("build relay")
            .with_poll_interval(Duration::from_millis(30))
            .with_min_hold(Duration::from_secs(10));
        let got = relay
            .recv([7u8; 32], Direction::ToPhone, Duration::from_secs(10))
            .expect("recv must eventually deliver the envelope");
        assert!(got.is_some(), "the envelope must surface after the empties");

        let g = gaps(&arrivals);
        assert_eq!(
            g.len(),
            3,
            "expected four GETs, three inter-GET gaps: {g:?}"
        );
        // Not an instant re-issue: the first fast-empty waited ~the base.
        assert!(
            g[0] >= Duration::from_millis(15),
            "a fast empty must back off, not hammer: {g:?}"
        );
        // Exponential: each successive wait is strictly larger (the jitter
        // windows for 30/60/120ms do not overlap).
        assert!(
            g[1] > g[0] && g[2] > g[1],
            "the fast-empty backoff must grow across consecutive empties: {g:?}"
        );
        server.join().expect("fake relay thread");
    }

    #[test]
    fn a_429_backs_off_rather_than_retrying_instantly() {
        let (base, arrivals, server) =
            spawn_scripted_relay(vec![Step::RateLimited(None), Step::Envelope]);
        let relay = PhoneRelay::new(&base, [7u8; 32])
            .expect("build relay")
            .with_poll_interval(Duration::from_millis(40));
        let got = relay
            .recv([7u8; 32], Direction::ToPhone, Duration::from_secs(10))
            .expect("recv must ride out the 429 and deliver the envelope");
        assert!(got.is_some(), "the envelope must surface after the 429");
        let g = gaps(&arrivals);
        assert!(
            g[0] >= Duration::from_millis(20),
            "a 429 must engage the backoff, not retry instantly: {g:?}"
        );
        server.join().expect("fake relay thread");
    }

    #[test]
    fn a_429_honors_a_relay_supplied_retry_after() {
        // `Retry-After: 1` must be respected even though the base backoff is far
        // shorter: the client waits ~the second the relay asked for.
        let (base, arrivals, server) =
            spawn_scripted_relay(vec![Step::RateLimited(Some(1)), Step::Envelope]);
        let relay = PhoneRelay::new(&base, [7u8; 32])
            .expect("build relay")
            .with_poll_interval(Duration::from_millis(40));
        let got = relay
            .recv([7u8; 32], Direction::ToPhone, Duration::from_secs(10))
            .expect("recv must honor Retry-After then deliver the envelope");
        assert!(got.is_some(), "the envelope must surface after the 429");
        let g = gaps(&arrivals);
        assert!(
            g[0] >= Duration::from_millis(800),
            "Retry-After: 1 must hold the next GET ~1s, not the 40ms base: {g:?}"
        );
        server.join().expect("fake relay thread");
    }

    #[test]
    fn a_real_full_length_hold_reissues_promptly_and_is_not_over_throttled() {
        // A GET that genuinely held (>= min_hold) before returning empty is the
        // normal long-poll case: it must re-issue promptly, NOT pay a backoff.
        // Base is large (400ms) and min_hold small (50ms), so if a held empty
        // wrongly engaged the backoff the next GET would arrive ~400ms late;
        // instead it arrives right after the ~120ms hold.
        let (base, arrivals, server) = spawn_scripted_relay(vec![
            Step::EmptyAfter(Duration::from_millis(120)),
            Step::Envelope,
        ]);
        let relay = PhoneRelay::new(&base, [7u8; 32])
            .expect("build relay")
            .with_poll_interval(Duration::from_millis(400))
            .with_min_hold(Duration::from_millis(50));
        let got = relay
            .recv([7u8; 32], Direction::ToPhone, Duration::from_secs(10))
            .expect("recv must deliver the envelope");
        assert!(got.is_some(), "the envelope must surface");
        let g = gaps(&arrivals);
        // GET2 arrives ~the hold (120ms) after GET1, with no added backoff.
        assert!(
            g[0] < Duration::from_millis(300),
            "a real hold must re-issue promptly, not eat the 400ms backoff: {g:?}"
        );
        server.join().expect("fake relay thread");
    }
}
