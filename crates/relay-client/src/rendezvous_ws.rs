//! [`RendezvousWs`]: the daemon side of the pairing rendezvous, over a raw
//! outbound WebSocket carrying opaque strings.
//!
//! The relay's HTTP endpoints are direction-fixed (`POST /submit` enqueues
//! *toDaemon*, `GET /pending` drains *toPhone*), so the party being paired — the
//! daemon running `latch pair` — cannot use the HTTP [`Rendezvous`](crate::Rendezvous)
//! client to *receive* the phone's response (which lands in *toDaemon*) or
//! *send* the DEK (which must go to *toPhone*). Those are exactly the daemon's
//! WebSocket directions. This is a stripped-down [`DaemonRelay`](crate::DaemonRelay):
//! same attach + send/deliver framing, but it moves opaque strings instead of
//! typed envelopes, because the first pairing message (the `PairingResponse`) is
//! authenticated by its own MAC, not by an envelope seal.
//!
//! Pairing is a short, human-paced ceremony, so this makes one attach with a
//! bounded lifetime and does not reconnect: if the socket drops mid-pairing the
//! ceremony fails closed and the human re-runs it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as stdmpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc as tokmpsc;
use tokio_tungstenite::tungstenite::Message;

use latch_proto::TransportError;

use crate::{attach_url, mailbox_hex, wire};

/// How often the pump wakes to notice a shutdown request while otherwise idle.
const SHUTDOWN_POLL: Duration = Duration::from_millis(200);

/// A daemon-side raw-string WebSocket channel to one rendezvous mailbox.
pub struct RendezvousWs {
    to_relay: tokmpsc::UnboundedSender<String>,
    from_relay: Mutex<stdmpsc::Receiver<String>>,
    shutdown: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl RendezvousWs {
    /// Attach to `base` (an `http(s)://` or `ws(s)://` relay URL) for `mailbox`.
    /// Returns immediately; the attach happens on the worker thread.
    pub fn connect(base: &str, mailbox: [u8; 32]) -> Result<Self, TransportError> {
        let url = attach_url(base, &mailbox_hex(&mailbox));
        let (to_relay, to_relay_rx) = tokmpsc::unbounded_channel::<String>();
        let (from_relay_tx, from_relay_rx) = stdmpsc::channel::<String>();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let worker = std::thread::Builder::new()
            .name("latch-pair-ws".into())
            .spawn(move || run_pump(url, to_relay_rx, from_relay_tx, stop))
            .map_err(|e| TransportError::Backend(format!("spawning pairing ws worker: {e}")))?;
        Ok(Self {
            to_relay,
            from_relay: Mutex::new(from_relay_rx),
            shutdown,
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Send one opaque payload toward the phone (`toPhone`).
    pub fn send(&self, payload: String) -> Result<(), TransportError> {
        self.to_relay
            .send(payload)
            .map_err(|_| TransportError::Closed)
    }

    /// Block up to `timeout` for the next opaque payload from the phone
    /// (`toDaemon`). `Ok(None)` on timeout.
    pub fn recv(&self, timeout: Duration) -> Result<Option<String>, TransportError> {
        let rx = self.from_relay.lock().map_err(|_| TransportError::Closed)?;
        match rx.recv_timeout(timeout) {
            Ok(s) => Ok(Some(s)),
            Err(stdmpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(stdmpsc::RecvTimeoutError::Disconnected) => Err(TransportError::Closed),
        }
    }
}

impl Drop for RendezvousWs {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.worker.lock().ok().and_then(|mut g| g.take()) {
            let _ = handle.join();
        }
    }
}

fn run_pump(
    url: String,
    mut to_relay_rx: tokmpsc::UnboundedReceiver<String>,
    from_relay_tx: stdmpsc::Sender<String>,
    shutdown: Arc<AtomicBool>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("latch pair: cannot build ws runtime: {e}");
            return;
        }
    };
    rt.block_on(async move {
        if let Err(e) = pump_once(&url, &mut to_relay_rx, &from_relay_tx, &shutdown).await {
            if !shutdown.load(Ordering::SeqCst) {
                eprintln!("latch pair: rendezvous websocket error: {e}");
            }
        }
    });
}

async fn pump_once(
    url: &str,
    to_relay_rx: &mut tokmpsc::UnboundedReceiver<String>,
    from_relay_tx: &stdmpsc::Sender<String>,
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
                Some(payload) => {
                    let frame = wire::send_frame(&payload);
                    write.send(Message::Text(frame)).await.map_err(|e| e.to_string())?;
                }
                None => {
                    let _ = write.send(Message::Close(None)).await;
                    return Ok(());
                }
            },
            incoming = read.next() => match incoming {
                Some(Ok(Message::Text(txt))) => {
                    if let Some(payload) = wire::parse_deliver(txt.as_str()) {
                        if from_relay_tx.send(payload).is_err() {
                            return Ok(());
                        }
                    }
                }
                Some(Ok(Message::Ping(p))) => {
                    write.send(Message::Pong(p)).await.map_err(|e| e.to_string())?;
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
