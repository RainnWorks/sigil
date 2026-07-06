//! [`DaemonRelay`]: the daemon's outbound-WebSocket [`Transport`].
//!
//! The [`Transport`] trait is synchronous and blocking (the daemon calls it from
//! a `spawn_blocking` worker), but a relay attach is one long-lived async
//! connection that must both send request frames and receive delivery frames at
//! any time. So this owns a single background thread running a current-thread
//! tokio runtime that holds the WebSocket; the sync `send`/`recv` bridge to it
//! over channels:
//!
//! * `send(ToPhone)` pushes the opaque envelope onto an unbounded channel the
//!   background task drains into `{"t":"send"}` frames.
//! * `recv(ToDaemon)` blocks on a std channel the background task feeds from
//!   inbound `deliver` frames, with the trait's timeout so a silent relay fails
//!   closed.
//!
//! # Stateless relay (v3): the daemon is the buffer
//!
//! The relay no longer stores and forwards. It is a live socket bridge: it
//! forwards a `{"t":"send"}` to the peer only if the peer is attached right now,
//! and otherwise answers `{"t":"nopeer"}`; it reports the peer connecting or
//! dropping with `{"t":"peer","state":"attached"|"detached"}`. So the pending
//! request must live in the *daemon's* RAM, not the relay's. This pump therefore
//! holds every outbound envelope in a small in-RAM [`PendingOutbox`] and
//! (re)streams it whenever the peer attaches (and optimistically on each
//! connect). A held request is bounded by [`PENDING_TTL`]; re-streaming one the
//! phone already answered is harmless, because the phone's inbound replay guard
//! rejects the duplicate. On daemon restart the RAM buffer is lost, which is the
//! correct fail-closed behavior (a request no one is waiting on is dropped).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as stdmpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use futures_util::{Sink, SinkExt, StreamExt};
use tokio::sync::mpsc as tokmpsc;
use tokio_tungstenite::tungstenite::Message;

use latch_proto::envelope::Envelope;
use latch_proto::{Direction, Transport, TransportError};

use crate::wire::InFrame;
use crate::{attach_url, mailbox_hex, wire};

/// First reconnect delay; doubles up to [`MAX_BACKOFF`] on repeated failures.
const INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(15);
/// How often the pump wakes to notice a shutdown request while otherwise idle.
const SHUTDOWN_POLL: Duration = Duration::from_millis(250);
/// How long a held outbound request stays eligible for (re)streaming. Chosen
/// above the daemon's default approval wait (120s) so a request survives a brief
/// relay or phone reconnect, but bounded so a long-dead request is never
/// resurrected onto a freshly attached phone. Re-streaming within the window is
/// safe: the phone's inbound replay guard drops a duplicate it already saw.
const PENDING_TTL: Duration = Duration::from_secs(180);

/// The daemon's in-RAM outbound buffer for the stateless relay: opaque envelope
/// wire strings held with their queue time, oldest first, pruned past
/// [`PENDING_TTL`]. This is the store-and-forward buffer moved off the relay and
/// onto the trusted daemon side.
struct PendingOutbox {
    items: VecDeque<(String, Instant)>,
    ttl: Duration,
}

impl PendingOutbox {
    fn new(ttl: Duration) -> Self {
        Self {
            items: VecDeque::new(),
            ttl,
        }
    }

    /// Drop everything queued longer ago than the TTL. Items are appended in time
    /// order, so expiry walks from the front until a live item is met.
    fn prune(&mut self, now: Instant) {
        while let Some((_, queued)) = self.items.front() {
            if now.duration_since(*queued) >= self.ttl {
                self.items.pop_front();
            } else {
                break;
            }
        }
    }

    /// Hold one outbound envelope, pruning expired holds first.
    fn push(&mut self, wire: String, now: Instant) {
        self.prune(now);
        self.items.push_back((wire, now));
    }

    /// The still-live held envelopes, oldest first, for (re)streaming.
    fn live(&mut self, now: Instant) -> Vec<String> {
        self.prune(now);
        self.items.iter().map(|(w, _)| w.clone()).collect()
    }
}

/// Write every live held envelope as a `{"t":"send"}` frame. Used on each
/// connect (optimistic) and on every `peer attached` report.
async fn flush_pending<S>(write: &mut S, pending: &mut PendingOutbox) -> Result<(), String>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    for env_wire in pending.live(Instant::now()) {
        write
            .send(Message::Text(wire::send_frame(&env_wire)))
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// A daemon-side [`Transport`] over one outbound WebSocket to the blind relay.
pub struct DaemonRelay {
    mailbox: [u8; 32],
    /// Opaque envelope wire strings queued for the phone; drained by the pump.
    to_relay: tokmpsc::UnboundedSender<String>,
    /// Envelopes delivered from the phone; fed by the pump, read by `recv`.
    from_relay: Mutex<stdmpsc::Receiver<Envelope>>,
    shutdown: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl DaemonRelay {
    /// Spawn the background connection to `base` (an `http(s)://` or `ws(s)://`
    /// relay URL) for `mailbox`, and return immediately. The first attach and
    /// every reconnect happen on the worker thread; `send`/`recv` never block on
    /// the network beyond their own channel.
    pub fn connect(base: &str, mailbox: [u8; 32]) -> Result<Self, TransportError> {
        let url = attach_url(base, &mailbox_hex(&mailbox));
        let (to_relay, to_relay_rx) = tokmpsc::unbounded_channel::<String>();
        let (from_relay_tx, from_relay_rx) = stdmpsc::channel::<Envelope>();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let worker = std::thread::Builder::new()
            .name("latch-relay-ws".into())
            .spawn(move || run_pump(url, to_relay_rx, from_relay_tx, stop))
            .map_err(|e| TransportError::Backend(format!("spawning ws worker: {e}")))?;
        Ok(Self {
            mailbox,
            to_relay,
            from_relay: Mutex::new(from_relay_rx),
            shutdown,
            worker: Mutex::new(Some(worker)),
        })
    }

    /// The mailbox this relay is attached to.
    pub fn mailbox(&self) -> [u8; 32] {
        self.mailbox
    }
}

impl Drop for DaemonRelay {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.worker.lock().ok().and_then(|mut g| g.take()) {
            let _ = handle.join();
        }
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
        let wire = wire::envelope_to_wire(env)
            .map_err(|e| TransportError::Backend(format!("serializing envelope: {e}")))?;
        // A closed channel means the pump thread is gone: fail closed.
        self.to_relay.send(wire).map_err(|_| TransportError::Closed)
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
        let rx = self.from_relay.lock().map_err(|_| TransportError::Closed)?;
        match rx.recv_timeout(timeout) {
            Ok(env) => Ok(Some(env)),
            Err(stdmpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(stdmpsc::RecvTimeoutError::Disconnected) => Err(TransportError::Closed),
        }
    }
}

/// The worker thread: build a runtime and run the reconnecting pump until asked
/// to stop. Errors here are logged, never panicked: the daemon fails closed if
/// the relay is unreachable (approvals simply time out).
fn run_pump(
    url: String,
    mut to_relay_rx: tokmpsc::UnboundedReceiver<String>,
    from_relay_tx: stdmpsc::Sender<Envelope>,
    shutdown: Arc<AtomicBool>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("latch relay: cannot build ws runtime: {e}");
            return;
        }
    };
    rt.block_on(async move {
        // The pending outbox lives ACROSS reconnects: it is the daemon's own
        // store-and-forward buffer now that the relay keeps none.
        let mut pending = PendingOutbox::new(PENDING_TTL);
        let mut backoff = INITIAL_BACKOFF;
        while !shutdown.load(Ordering::SeqCst) {
            match pump_once(
                &url,
                &mut to_relay_rx,
                &from_relay_tx,
                &mut pending,
                &shutdown,
            )
            .await
            {
                // A clean return means the sender side was dropped or shutdown
                // was requested: stop reconnecting.
                Ok(()) => break,
                Err(e) => {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    eprintln!("latch relay: websocket down ({e}); reconnecting in {backoff:?}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    });
}

/// One connection's lifetime: attach, (re)stream anything held, then pump both
/// directions until the socket drops (returns `Err`, caller reconnects) or
/// shutdown/sender-drop (returns `Ok`, caller stops).
async fn pump_once(
    url: &str,
    to_relay_rx: &mut tokmpsc::UnboundedReceiver<String>,
    from_relay_tx: &stdmpsc::Sender<Envelope>,
    pending: &mut PendingOutbox,
    shutdown: &AtomicBool,
) -> Result<(), String> {
    let (ws, _resp) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| e.to_string())?;
    let (mut write, mut read) = ws.split();

    // Optimistically stream anything held: if the peer is already attached the
    // relay forwards it; if not, it answers `nopeer` and we keep holding.
    flush_pending(&mut write, pending).await?;

    loop {
        tokio::select! {
            biased;
            outbound = to_relay_rx.recv() => match outbound {
                Some(env_wire) => {
                    // Hold it (survives a reconnect and a later peer attach), then
                    // try to send it now.
                    pending.push(env_wire.clone(), Instant::now());
                    write
                        .send(Message::Text(wire::send_frame(&env_wire)))
                        .await
                        .map_err(|e| e.to_string())?;
                }
                // The DaemonRelay was dropped: close cleanly and stop.
                None => {
                    let _ = write.send(Message::Close(None)).await;
                    return Ok(());
                }
            },
            incoming = read.next() => match incoming {
                Some(Ok(Message::Text(txt))) => match wire::parse_frame(txt.as_str()) {
                    InFrame::Deliver(env_wire) => match wire::wire_to_envelope(&env_wire) {
                        // The receiver is gone (daemon shutting down): stop.
                        Ok(env) => if from_relay_tx.send(env).is_err() {
                            return Ok(());
                        },
                        Err(e) => eprintln!(
                            "latch relay: dropped an undecodable deliver frame: {e}"
                        ),
                    },
                    // The peer just attached: stream everything held for it.
                    InFrame::PeerAttached => flush_pending(&mut write, pending).await?,
                    // No peer for our last send, or the peer dropped: keep holding.
                    // A held request re-streams on the next attach.
                    InFrame::NoPeer | InFrame::PeerDetached => {}
                    // Application-level keepalive.
                    InFrame::Ping => {
                        write.send(Message::Text(wire::pong_frame())).await.map_err(|e| e.to_string())?;
                    }
                    // ack / pong / anything else the sync API does not act on.
                    InFrame::Other => {}
                },
                Some(Ok(Message::Ping(payload))) => {
                    write.send(Message::Pong(payload)).await.map_err(|e| e.to_string())?;
                }
                Some(Ok(Message::Close(_))) | None => {
                    return Err("connection closed by relay".into());
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e.to_string()),
            },
            _ = tokio::time::sleep(SHUTDOWN_POLL) => {
                if shutdown.load(Ordering::SeqCst) {
                    let _ = write.send(Message::Close(None)).await;
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbox_holds_and_replays_in_order() {
        // The daemon's RAM buffer holds each outbound request and replays them
        // oldest-first on a peer attach; nothing is consumed by a replay, so a
        // second attach re-streams the same set (the phone dedupes duplicates).
        let mut outbox = PendingOutbox::new(Duration::from_secs(180));
        let t0 = Instant::now();
        outbox.push("env-a".into(), t0);
        outbox.push("env-b".into(), t0);
        assert_eq!(outbox.live(t0), vec!["env-a", "env-b"]);
        // A re-flush at the same instant yields the same held set.
        assert_eq!(outbox.live(t0), vec!["env-a", "env-b"]);
    }

    #[test]
    fn outbox_prunes_past_the_ttl() {
        // A held request older than the TTL is dropped, so a long-dead request is
        // never resurrected onto a freshly attached phone. Live ones survive.
        let ttl = Duration::from_secs(180);
        let mut outbox = PendingOutbox::new(ttl);
        let t0 = Instant::now();
        outbox.push("old".into(), t0);
        // Push a newer one well after the first, then observe at old+TTL.
        let t1 = t0 + Duration::from_secs(120);
        outbox.push("new".into(), t1);
        let observe = t0 + ttl; // "old" is exactly at the TTL boundary -> expired
        assert_eq!(
            outbox.live(observe),
            vec!["new"],
            "only the live hold remains"
        );
    }

    #[test]
    fn outbox_push_prunes_expired_first() {
        // Expiry is applied on push too, so the buffer stays bounded even if it is
        // never flushed.
        let ttl = Duration::from_secs(10);
        let mut outbox = PendingOutbox::new(ttl);
        let t0 = Instant::now();
        outbox.push("stale".into(), t0);
        outbox.push("fresh".into(), t0 + Duration::from_secs(11));
        assert_eq!(outbox.live(t0 + Duration::from_secs(11)), vec!["fresh"]);
    }
}
