//! [`FallbackTransport`]: prefer a verified direct link, fall back to the relay.
//!
//! This is the selector that makes the ladder safe. It wraps the always-present
//! relay [`Transport`] and an *optional* direct primary. The daemon builds its
//! `RemoteApprover` on one of these instead of on a bare relay; the approver and
//! its owner loop are unchanged, because a `FallbackTransport` is just another
//! `Arc<dyn Transport>`.
//!
//! # Downgrade-safety, stated precisely
//!
//! 1. **No primary installed == the relay, byte-identical.** When no direct link
//!    is up (the default, and the state after any direct failure), every
//!    [`send`](Transport::send), [`deposit_to_phone`](Transport::deposit_to_phone),
//!    and [`recv`](Transport::recv) delegates straight to the relay with no
//!    added behaviour. A daemon with direct transport configured but no phone
//!    currently connected behaves exactly like today's relay-only daemon. This is
//!    the property that guarantees "the relay path stays byte-identical when
//!    direct is off/unavailable."
//!
//! 2. **A primary is only ever a *verified* link.** The selector never installs
//!    a link it was handed raw; the daemon's acceptor calls
//!    [`verify_link`](crate::discovery::verify_link) first, which reads one
//!    envelope that must open as the pinned peer. A host that completes a TCP
//!    handshake but is not the paired phone cannot pass that gate, so it never
//!    becomes the primary and the daemon never deposits a request to it.
//!
//! 3. **A mid-flight failure reverts cleanly.** A dropped connection latches the
//!    [`DirectLink`](crate::DirectLink) closed, so its `recv`/`send` error; the
//!    selector catches that error, retires the primary, and completes the call on
//!    the relay. An approval in flight when the link drops is finished over the
//!    relay, not failed.
//!
//! 4. **A hostile LAN peer cannot forge, replay, or read.** Every byte a direct
//!    link carries is still an [`Envelope`](sigil_proto::Envelope) opened at the
//!    approver/phone; the network is never trusted. The one residual an active
//!    LAN man-in-the-middle retains -- relaying the phone's genuine verification
//!    envelope to get promoted, then black-holing traffic -- is a *denial*
//!    (the approval times out and fails closed), never a forged approval or a
//!    leaked secret, and is closed by the "demote on silence" retry documented in
//!    `docs/design/direct-transport.md`. Because that retry lives in the reviewed
//!    approval loop, this crate ships with direct transport OFF by default and
//!    leaves the enable decision to the security review.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sigil_proto::envelope::Envelope;
use sigil_proto::{Direction, PushHint, Transport, TransportError};

/// How a request deposit uses the direct primary when one is installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepositPolicy {
    /// Deposit over the direct primary only; on a direct error, fall back to the
    /// relay for that deposit. This is what actually *skips* the relay when the
    /// phone is directly reachable. Safe because the primary is only ever a
    /// verified link (see the module docs); its residual (an active MITM
    /// black-holing an accepted deposit) is a bounded, fail-closed denial.
    PreferDirect,
    /// Deposit over the relay as well as the direct primary. The request always
    /// reaches the phone via the relay, so a black-holed direct link cannot even
    /// delay it; the trade is that the relay is still used on every request. The
    /// redundant copy is harmless -- if the phone answers over the direct link,
    /// the relay copy simply expires unread.
    Mirror,
}

/// A [`Transport`] that prefers a verified direct link and falls back to a relay.
pub struct FallbackTransport {
    /// Always present. The floor of the ladder; every guarantee still rests here.
    relay: Arc<dyn Transport>,
    /// The verified direct link, when one is live. `None` is the steady default.
    primary: Mutex<Option<Arc<dyn Transport>>>,
    deposit: DepositPolicy,
}

impl FallbackTransport {
    /// Wrap `relay` with no primary installed (behaves exactly like `relay`
    /// until [`install_primary`](Self::install_primary) is called).
    pub fn new(relay: Arc<dyn Transport>) -> Self {
        Self {
            relay,
            primary: Mutex::new(None),
            deposit: DepositPolicy::PreferDirect,
        }
    }

    /// Choose the deposit policy (defaults to [`DepositPolicy::PreferDirect`]).
    pub fn with_deposit_policy(mut self, policy: DepositPolicy) -> Self {
        self.deposit = policy;
        self
    }

    /// Install a *verified* direct link as the primary. The caller MUST have
    /// already proven the peer is the pinned phone (via
    /// [`verify_link`](crate::discovery::verify_link)); this method does not
    /// re-check. Replaces any existing primary.
    pub fn install_primary(&self, link: Arc<dyn Transport>) {
        *self.primary.lock().expect("fallback primary poisoned") = Some(link);
    }

    /// Retire the current primary, reverting to relay-only. Called on a direct
    /// failure or an explicit teardown.
    pub fn clear_primary(&self) {
        *self.primary.lock().expect("fallback primary poisoned") = None;
    }

    /// True while a direct primary is installed. Display/diagnostics only.
    pub fn has_primary(&self) -> bool {
        self.primary
            .lock()
            .expect("fallback primary poisoned")
            .is_some()
    }

    /// Snapshot the current primary (a cheap `Arc` clone) without holding the
    /// lock across a blocking transport call.
    fn primary_snapshot(&self) -> Option<Arc<dyn Transport>> {
        self.primary
            .lock()
            .expect("fallback primary poisoned")
            .clone()
    }

    /// Drop the primary iff it is still the same link that just failed, so a
    /// concurrent install of a fresh link is not clobbered by a stale failure.
    fn retire_if_current(&self, failed: &Arc<dyn Transport>) {
        let mut guard = self.primary.lock().expect("fallback primary poisoned");
        if let Some(current) = guard.as_ref() {
            if Arc::ptr_eq(current, failed) {
                *guard = None;
            }
        }
    }
}

impl Transport for FallbackTransport {
    fn send(
        &self,
        mailbox: [u8; 32],
        dir: Direction,
        env: &Envelope,
    ) -> Result<(), TransportError> {
        if let Some(primary) = self.primary_snapshot() {
            match primary.send(mailbox, dir, env) {
                Ok(()) => {
                    if self.deposit == DepositPolicy::Mirror {
                        // Best-effort insurance copy; a relay error here is not
                        // fatal because the direct send already succeeded.
                        let _ = self.relay.send(mailbox, dir, env);
                    }
                    return Ok(());
                }
                Err(_) => self.retire_if_current(&primary),
            }
        }
        self.relay.send(mailbox, dir, env)
    }

    fn deposit_to_phone(
        &self,
        mailbox: [u8; 32],
        env: &Envelope,
        hint: Option<PushHint>,
    ) -> Result<(), TransportError> {
        if let Some(primary) = self.primary_snapshot() {
            // A direct link needs no push doorbell (the phone is awake on the
            // live connection), so the hint is dropped on the direct path.
            match primary.deposit_to_phone(mailbox, env, None) {
                Ok(()) => {
                    if self.deposit == DepositPolicy::Mirror {
                        let _ = self.relay.deposit_to_phone(mailbox, env, hint);
                    }
                    return Ok(());
                }
                Err(_) => self.retire_if_current(&primary),
            }
        }
        self.relay.deposit_to_phone(mailbox, env, hint)
    }

    fn recv(
        &self,
        mailbox: [u8; 32],
        dir: Direction,
        timeout: Duration,
    ) -> Result<Option<Envelope>, TransportError> {
        let deadline = Instant::now() + timeout;
        if let Some(primary) = self.primary_snapshot() {
            match primary.recv(mailbox, dir, timeout) {
                // A frame arrived on the direct link: the fast, relay-skipping
                // path.
                Ok(Some(env)) => return Ok(Some(env)),
                // The direct link held for the whole window with nothing: the
                // approval is simply still pending. Return the timeout; the
                // owner loop will poll again.
                Ok(None) => return Ok(None),
                // The link failed (dropped mid-wait): retire it and spend the
                // remaining budget on the relay so an in-flight approval still
                // completes rather than being lost with the connection.
                Err(_) => {
                    self.retire_if_current(&primary);
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    return self.relay.recv(mailbox, dir, remaining);
                }
            }
        }
        self.relay.recv(mailbox, dir, timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_proto::identity::DeviceIdentity;
    use sigil_proto::LocalRelay;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn sealed(mailbox: [u8; 32]) -> Envelope {
        let sender = DeviceIdentity::generate();
        let recipient = DeviceIdentity::generate();
        Envelope::seal(
            &"x".to_string(),
            mailbox,
            1,
            &sender.signing,
            &recipient.peer_identity(),
        )
        .expect("seal")
    }

    /// A test transport that can be flipped to fail every call, to exercise the
    /// selector's fall-back-on-direct-error path deterministically.
    #[derive(Default)]
    struct Closable {
        inner: LocalRelay,
        closed: AtomicBool,
    }
    impl Closable {
        fn close(&self) {
            self.closed.store(true, Ordering::Release);
        }
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::Acquire)
        }
    }
    impl Transport for Closable {
        fn send(
            &self,
            mailbox: [u8; 32],
            dir: Direction,
            env: &Envelope,
        ) -> Result<(), TransportError> {
            if self.is_closed() {
                return Err(TransportError::Closed);
            }
            self.inner.send(mailbox, dir, env)
        }
        fn recv(
            &self,
            mailbox: [u8; 32],
            dir: Direction,
            timeout: Duration,
        ) -> Result<Option<Envelope>, TransportError> {
            if self.is_closed() {
                return Err(TransportError::Closed);
            }
            self.inner.recv(mailbox, dir, timeout)
        }
    }

    #[test]
    fn with_no_primary_it_is_exactly_the_relay() {
        let relay = Arc::new(LocalRelay::new());
        let fb = FallbackTransport::new(relay.clone());
        let mbx = [1u8; 32];
        let env = sealed(mbx);
        fb.deposit_to_phone(mbx, &env, None).expect("deposit");
        // The deposit went to the relay (ToPhone slot), observably.
        assert_eq!(relay.depth(mbx, Direction::ToPhone), 1);
        // And a recv reads straight off the relay.
        relay.send(mbx, Direction::ToDaemon, &sealed(mbx)).unwrap();
        assert!(fb
            .recv(mbx, Direction::ToDaemon, Duration::from_millis(50))
            .unwrap()
            .is_some());
    }

    #[test]
    fn a_deposit_prefers_the_direct_primary_and_skips_the_relay() {
        let relay = Arc::new(LocalRelay::new());
        let direct = Arc::new(LocalRelay::new());
        let fb = FallbackTransport::new(relay.clone());
        fb.install_primary(direct.clone());
        let mbx = [2u8; 32];
        fb.deposit_to_phone(mbx, &sealed(mbx), None)
            .expect("deposit");
        // PreferDirect: the request went out the direct link ONLY; the relay
        // never saw it (this is the "skip the relay" property).
        assert_eq!(direct.depth(mbx, Direction::ToPhone), 1);
        assert_eq!(relay.depth(mbx, Direction::ToPhone), 0);
    }

    #[test]
    fn mirror_policy_also_deposits_to_the_relay() {
        let relay = Arc::new(LocalRelay::new());
        let direct = Arc::new(LocalRelay::new());
        let fb = FallbackTransport::new(relay.clone()).with_deposit_policy(DepositPolicy::Mirror);
        fb.install_primary(direct.clone());
        let mbx = [3u8; 32];
        fb.deposit_to_phone(mbx, &sealed(mbx), None)
            .expect("deposit");
        assert_eq!(direct.depth(mbx, Direction::ToPhone), 1);
        assert_eq!(relay.depth(mbx, Direction::ToPhone), 1);
    }

    #[test]
    fn a_failed_direct_deposit_falls_back_to_the_relay_and_retires_the_primary() {
        let relay = Arc::new(LocalRelay::new());
        let direct = Arc::new(Closable::default());
        let fb = FallbackTransport::new(relay.clone());
        fb.install_primary(direct.clone());
        direct.close(); // the link drops
        let mbx = [4u8; 32];
        fb.deposit_to_phone(mbx, &sealed(mbx), None)
            .expect("deposit must succeed via the relay fallback");
        // The request reached the relay, and the dead primary was retired.
        assert_eq!(relay.depth(mbx, Direction::ToPhone), 1);
        assert!(!fb.has_primary(), "a failed primary must be retired");
    }

    #[test]
    fn a_direct_recv_failure_spends_the_rest_of_the_budget_on_the_relay() {
        let relay = Arc::new(LocalRelay::new());
        let direct = Arc::new(Closable::default());
        let fb = FallbackTransport::new(relay.clone());
        fb.install_primary(direct.clone());
        direct.close();
        let mbx = [5u8; 32];
        // A response is waiting on the relay; the direct recv errors, so the
        // selector must fall through and still deliver it.
        relay.send(mbx, Direction::ToDaemon, &sealed(mbx)).unwrap();
        let got = fb
            .recv(mbx, Direction::ToDaemon, Duration::from_millis(200))
            .expect("recv ok");
        assert!(
            got.is_some(),
            "the relay response must surface after the direct failure"
        );
        assert!(!fb.has_primary());
    }

    #[test]
    fn a_live_direct_recv_returns_the_direct_frame() {
        let relay = Arc::new(LocalRelay::new());
        let direct = Arc::new(LocalRelay::new());
        let fb = FallbackTransport::new(relay.clone());
        fb.install_primary(direct.clone());
        let mbx = [6u8; 32];
        direct.send(mbx, Direction::ToDaemon, &sealed(mbx)).unwrap();
        let got = fb
            .recv(mbx, Direction::ToDaemon, Duration::from_millis(50))
            .expect("recv ok");
        assert!(got.is_some(), "a frame on the direct link must be returned");
    }
}
