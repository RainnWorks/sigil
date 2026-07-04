//! The transport seam: move sealed [`Envelope`]s between a paired daemon and
//! phone, addressed by `mailbox_id`.
//!
//! The transport is never the security layer (that is the envelope). Its only
//! job is to carry opaque envelopes from one party's outbox to the other's
//! inbox. A mailbox has two directions, matching the blind relay's two queues:
//!
//! | [`Direction`] | producer | consumer | relay analogue (`relay/README.md`) |
//! |---------------|----------|----------|-----------------------------------|
//! | [`Direction::ToPhone`]  | daemon | phone  | daemon WS `send` frame -> phone `GET /pending` |
//! | [`Direction::ToDaemon`] | phone  | daemon | phone `POST /submit` -> daemon WS `deliver` frame |
//!
//! So the daemon sends `ToPhone` and receives `ToDaemon`; the phone sends
//! `ToDaemon` and receives `ToPhone`.
//!
//! [`LocalRelay`] is the in-process implementation: a pair of in-memory queues
//! per `(mailbox, direction)`, with a blocking [`Transport::recv`] that parks on
//! a condvar until an envelope arrives or the timeout elapses. It needs no
//! network and no relay process, so the whole approval loop runs headlessly in
//! one test. A future HTTP/WebSocket implementation of the same trait maps onto
//! the relay routes above with no change to either the daemon or the phone.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::envelope::Envelope;

/// Which mailbox queue an envelope belongs to. See the module table.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Direction {
    /// Daemon -> phone (requests).
    ToPhone,
    /// Phone -> daemon (responses).
    ToDaemon,
}

#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    /// The transport was shut down while a call was in flight.
    #[error("transport closed")]
    Closed,
    /// A backend (network relay) call failed. Unused by [`LocalRelay`].
    #[error("transport backend: {0}")]
    Backend(String),
}

/// Carries sealed envelopes between a daemon and a phone, by mailbox id.
///
/// [`recv`](Transport::recv) blocks up to `timeout` and returns `Ok(None)` on
/// timeout, so every caller can fail closed on a silent transport.
pub trait Transport: Send + Sync {
    /// Enqueue `env` for the given mailbox and direction.
    fn send(&self, mailbox: [u8; 32], dir: Direction, env: &Envelope)
        -> Result<(), TransportError>;

    /// Dequeue the next envelope for the given mailbox and direction, waiting up
    /// to `timeout`. `Ok(None)` means nothing arrived in time.
    fn recv(
        &self,
        mailbox: [u8; 32],
        dir: Direction,
        timeout: Duration,
    ) -> Result<Option<Envelope>, TransportError>;
}

/// The in-memory queues, one FIFO per `(mailbox, direction)`.
type Queues = HashMap<([u8; 32], Direction), VecDeque<Envelope>>;

#[derive(Default)]
struct Shared {
    queues: Mutex<Queues>,
    /// Woken on every `send`; `recv` re-checks its queue on each wake.
    signal: Condvar,
}

/// An in-process, loopback transport. Cloneable: every clone shares the same
/// queues, so the daemon and phone halves of a test hold clones of one relay.
#[derive(Clone, Default)]
pub struct LocalRelay {
    shared: Arc<Shared>,
}

impl LocalRelay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Non-blocking depth of a queue, for assertions and diagnostics.
    pub fn depth(&self, mailbox: [u8; 32], dir: Direction) -> usize {
        self.shared
            .queues
            .lock()
            .expect("local relay poisoned")
            .get(&(mailbox, dir))
            .map(VecDeque::len)
            .unwrap_or(0)
    }
}

impl Transport for LocalRelay {
    fn send(
        &self,
        mailbox: [u8; 32],
        dir: Direction,
        env: &Envelope,
    ) -> Result<(), TransportError> {
        let mut queues = self.shared.queues.lock().expect("local relay poisoned");
        queues
            .entry((mailbox, dir))
            .or_default()
            .push_back(env.clone());
        drop(queues);
        // Wake every waiter; each re-checks its own queue. One condvar for the
        // whole relay is fine at this scale.
        self.shared.signal.notify_all();
        Ok(())
    }

    fn recv(
        &self,
        mailbox: [u8; 32],
        dir: Direction,
        timeout: Duration,
    ) -> Result<Option<Envelope>, TransportError> {
        let deadline = Instant::now() + timeout;
        let mut queues = self.shared.queues.lock().expect("local relay poisoned");
        loop {
            if let Some(env) = queues
                .get_mut(&(mailbox, dir))
                .and_then(VecDeque::pop_front)
            {
                return Ok(Some(env));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let (guard, res) = self
                .shared
                .signal
                .wait_timeout(queues, deadline - now)
                .expect("local relay poisoned");
            queues = guard;
            if res.timed_out() {
                // Loop once more to do a final check before returning None.
                if let Some(env) = queues
                    .get_mut(&(mailbox, dir))
                    .and_then(VecDeque::pop_front)
                {
                    return Ok(Some(env));
                }
                return Ok(None);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use std::thread;

    fn sealed(pairing_id: [u8; 32]) -> Envelope {
        let sender = DeviceIdentity::generate();
        let recipient = DeviceIdentity::generate();
        Envelope::seal(
            &"hi".to_string(),
            pairing_id,
            1,
            &sender.signing,
            &recipient.peer_identity(),
        )
        .expect("seal")
    }

    #[test]
    fn send_then_recv_delivers_in_order() {
        let relay = LocalRelay::new();
        let mbx = [1u8; 32];
        let a = sealed(mbx);
        let b = sealed(mbx);
        relay.send(mbx, Direction::ToPhone, &a).unwrap();
        relay.send(mbx, Direction::ToPhone, &b).unwrap();
        assert_eq!(relay.depth(mbx, Direction::ToPhone), 2);

        let got_a = relay
            .recv(mbx, Direction::ToPhone, Duration::from_millis(50))
            .unwrap()
            .unwrap();
        let got_b = relay
            .recv(mbx, Direction::ToPhone, Duration::from_millis(50))
            .unwrap()
            .unwrap();
        assert_eq!(got_a.request_id, a.request_id);
        assert_eq!(got_b.request_id, b.request_id);
    }

    #[test]
    fn directions_are_independent() {
        let relay = LocalRelay::new();
        let mbx = [2u8; 32];
        relay.send(mbx, Direction::ToDaemon, &sealed(mbx)).unwrap();
        // Nothing was sent ToPhone, so a recv there times out.
        assert!(relay
            .recv(mbx, Direction::ToPhone, Duration::from_millis(20))
            .unwrap()
            .is_none());
        // The ToDaemon item is still there.
        assert!(relay
            .recv(mbx, Direction::ToDaemon, Duration::from_millis(20))
            .unwrap()
            .is_some());
    }

    #[test]
    fn recv_times_out_when_empty() {
        let relay = LocalRelay::new();
        let got = relay
            .recv([9u8; 32], Direction::ToPhone, Duration::from_millis(20))
            .unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn recv_wakes_on_a_late_send() {
        let relay = LocalRelay::new();
        let mbx = [3u8; 32];
        let relay2 = relay.clone();
        let waiter = thread::spawn(move || {
            relay2
                .recv(mbx, Direction::ToPhone, Duration::from_secs(2))
                .unwrap()
        });
        // Give the waiter time to park, then deliver.
        thread::sleep(Duration::from_millis(30));
        relay.send(mbx, Direction::ToPhone, &sealed(mbx)).unwrap();
        assert!(waiter.join().unwrap().is_some());
    }
}
