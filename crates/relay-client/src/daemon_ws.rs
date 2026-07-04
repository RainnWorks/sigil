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
//! Reconnect/resume: on any disconnect the task redials with capped exponential
//! backoff. Envelopes queued for sending stay buffered in the channel across a
//! reconnect, and the relay flushes anything queued for the daemon on the next
//! attach (`open` in `bun/server.ts`), so a dropped connection loses no frame it
//! had not yet handed over. In-flight approvals that time out during an outage
//! fail closed and are retried by the user, exactly as the design intends.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as stdmpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc as tokmpsc;
use tokio_tungstenite::tungstenite::Message;

use latch_proto::envelope::Envelope;
use latch_proto::{Direction, Transport, TransportError};

use crate::{attach_url, mailbox_hex, wire};

/// First reconnect delay; doubles up to [`MAX_BACKOFF`] on repeated failures.
const INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(15);
/// How often the pump wakes to notice a shutdown request while otherwise idle.
const SHUTDOWN_POLL: Duration = Duration::from_millis(250);

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
        let mut backoff = INITIAL_BACKOFF;
        while !shutdown.load(Ordering::SeqCst) {
            match pump_once(&url, &mut to_relay_rx, &from_relay_tx, &shutdown).await {
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

/// One connection's lifetime: attach, then pump both directions until the socket
/// drops (returns `Err`, caller reconnects) or shutdown/sender-drop (returns
/// `Ok`, caller stops).
async fn pump_once(
    url: &str,
    to_relay_rx: &mut tokmpsc::UnboundedReceiver<String>,
    from_relay_tx: &stdmpsc::Sender<Envelope>,
    shutdown: &AtomicBool,
) -> Result<(), String> {
    let (ws, _resp) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| e.to_string())?;
    let (mut write, mut read) = ws.split();

    loop {
        tokio::select! {
            biased;
            outbound = to_relay_rx.recv() => match outbound {
                Some(env_wire) => {
                    let frame = wire::send_frame(&env_wire);
                    write
                        .send(Message::Text(frame))
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
                Some(Ok(Message::Text(txt))) => {
                    if let Some(env_wire) = wire::parse_deliver(txt.as_str()) {
                        match wire::wire_to_envelope(&env_wire) {
                            // The receiver is gone (daemon shutting down): stop.
                            Ok(env) => if from_relay_tx.send(env).is_err() {
                                return Ok(());
                            },
                            Err(e) => eprintln!(
                                "latch relay: dropped an undecodable deliver frame: {e}"
                            ),
                        }
                    }
                    // ack / err control frames carry only flow-control info the
                    // sync API does not surface; nothing to do.
                }
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
