//! [`DirectLink`]: a [`Transport`] over one duplex TCP connection.
//!
//! The blind relay is a store-and-forward mailbox with two one-way slots; a
//! direct link is instead a single live TCP connection both parties hold, so a
//! frame the peer writes is *pushed* to us rather than polled for. The framing is
//! deliberately tiny: `[dir: u8][len: u32 big-endian][payload: len bytes]`, where
//! `payload` is the exact opaque envelope wire the relay carries (see
//! [`crate::wire`]) and `dir` is which [`Direction`] queue the frame belongs to.
//!
//! A background reader thread owns the read half: it demultiplexes frames into a
//! per-[`Direction`] FIFO and parks [`recv`](DirectLink::recv) callers on a
//! condvar exactly like [`LocalRelay`](sigil_proto::LocalRelay). The write half
//! sits behind a mutex so the approver's deposit thread and the owner loop can
//! use one link concurrently.
//!
//! # What this pipe does and does not defend
//!
//! It bounds a frame to [`MAX_FRAME_BYTES`] so a hostile peer cannot make us
//! allocate unboundedly (the same discipline as the relay client's drain cap),
//! and it fails *closed*: a dropped connection, a truncated frame, or an
//! over-cap length makes every future [`recv`](DirectLink::recv) return
//! [`TransportError`] so the caller (a [`FallbackTransport`](crate::FallbackTransport))
//! can fall back to the relay. It does NOT authenticate the peer or inspect the
//! envelope: a frame that decodes to a well-formed [`Envelope`] is queued, and a
//! frame that does not is dropped, but *whether that envelope opens as the pinned
//! peer* is decided later, by [`Envelope::open`](sigil_proto::Envelope::open) at
//! the approver/phone call site, never here.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use sigil_proto::envelope::Envelope;
use sigil_proto::{Direction, Transport, TransportError};

use crate::wire;

/// Hard ceiling on a single direct-link frame's payload. An honest envelope is a
/// few KiB (the relay caps a stored envelope at 16 KiB, see
/// `relay/shared/protocol.ts`); 64 KiB is generous headroom over that while
/// still refusing a hostile peer that declares a huge length to force an
/// unbounded read. A frame past this cap is a protocol violation and closes the
/// link (fail closed), rather than being skipped.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Errors specific to establishing or driving a direct TCP link. Round-trip
/// transport faults surface through the [`Transport`] seam as
/// [`TransportError`]; this type covers link *setup*.
#[derive(thiserror::Error, Debug)]
pub enum DirectError {
    /// Binding, connecting, or configuring the socket failed.
    #[error("direct link io: {0}")]
    Io(#[from] std::io::Error),
    /// No socket address resolved from the supplied endpoint string.
    #[error("no socket address resolved for {0:?}")]
    NoAddr(String),
}

/// The frame direction byte. Chosen to match the [`Direction`] roles without
/// leaking the enum's representation onto the wire.
const DIR_TO_PHONE: u8 = 0;
const DIR_TO_DAEMON: u8 = 1;

fn dir_to_byte(dir: Direction) -> u8 {
    match dir {
        Direction::ToPhone => DIR_TO_PHONE,
        Direction::ToDaemon => DIR_TO_DAEMON,
    }
}

fn byte_to_dir(b: u8) -> Option<Direction> {
    match b {
        DIR_TO_PHONE => Some(Direction::ToPhone),
        DIR_TO_DAEMON => Some(Direction::ToDaemon),
        _ => None,
    }
}

/// The queues plus the closed flag, shared between the reader thread and every
/// [`recv`](DirectLink::recv) caller.
#[derive(Default)]
struct Shared {
    queues: Mutex<HashMap<Direction, VecDeque<Envelope>>>,
    /// Notified on every enqueue and on close; `recv` re-checks its queue and
    /// the closed flag on each wake.
    signal: Condvar,
    /// Set once the link is torn down (peer EOF, io error, or a protocol
    /// violation such as an over-cap frame). Latched: never cleared.
    closed: AtomicBool,
    /// A clone of the connection used ONLY to force a socket shutdown on close.
    /// Because the read half lives on its own `try_clone` in the reader thread,
    /// simply dropping the writer would not close the fd (the clone keeps it
    /// open) and the peer would never see EOF; an explicit `shutdown(Both)`
    /// forces it, which both unblocks our own reader and propagates EOF to the
    /// peer so both ends fail over together.
    shutdown: Mutex<Option<TcpStream>>,
}

impl Shared {
    fn close(&self) {
        // Latch closed first so any wake sees the flag.
        self.closed.store(true, Ordering::Release);
        if let Ok(mut s) = self.shutdown.lock() {
            if let Some(stream) = s.take() {
                // Idempotent enough: a second shutdown just errors and is ignored.
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        // Wake every parked reader so it observes the flag and returns instead
        // of blocking to its full timeout.
        let _guard = self.queues.lock().expect("direct link queues poisoned");
        self.signal.notify_all();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// A [`Transport`] over one live duplex TCP connection to the paired peer.
///
/// Cheap to clone in spirit via `Arc`: [`from_stream`](DirectLink::from_stream)
/// hands back an `Arc<DirectLink>` so the daemon can share one link between the
/// approver's deposit path and the owner loop's `recv`, matching how the relay
/// transport is shared.
pub struct DirectLink {
    shared: Arc<Shared>,
    /// The write half of the TCP connection, behind a mutex so concurrent
    /// `send`s from different threads frame atomically.
    writer: Mutex<TcpStream>,
    /// Kept so the reader thread is joined on drop rather than detached.
    reader: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl DirectLink {
    /// Wrap an established TCP `stream`, spawning the reader thread. The stream
    /// must be a connected, duplex connection to the paired peer; this call does
    /// not connect or verify anything.
    pub fn from_stream(stream: TcpStream) -> Result<Arc<Self>, DirectError> {
        // A read timeout would spuriously tear the link down on an idle-but-live
        // connection, so the read half blocks indefinitely; the reader thread
        // exits only on real EOF/error or when the writer half is dropped.
        stream.set_nodelay(true).ok();
        let read_half = stream.try_clone()?;
        let shutdown_half = stream.try_clone()?;
        let shared = Arc::new(Shared::default());
        *shared
            .shutdown
            .lock()
            .expect("direct link shutdown poisoned") = Some(shutdown_half);
        let shared_reader = shared.clone();
        let handle = std::thread::Builder::new()
            .name("sigil-direct-reader".into())
            .spawn(move || read_loop(read_half, &shared_reader))?;
        Ok(Arc::new(Self {
            shared,
            writer: Mutex::new(stream),
            reader: Mutex::new(Some(handle)),
        }))
    }

    /// Dial `endpoint` (`host:port`, rung 2 / a discovered rung-1 address) and
    /// wrap the connection. Does not verify the peer -- see
    /// [`discovery::verify_link`](crate::discovery::verify_link).
    pub fn connect(endpoint: &str) -> Result<Arc<Self>, DirectError> {
        let addr = endpoint
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| DirectError::NoAddr(endpoint.to_string()))?;
        let stream = TcpStream::connect(addr)?;
        Self::from_stream(stream)
    }

    /// Dial with a connect timeout, so a black-holed address fails fast to the
    /// relay instead of hanging the caller.
    pub fn connect_timeout(endpoint: &str, timeout: Duration) -> Result<Arc<Self>, DirectError> {
        let addr = endpoint
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| DirectError::NoAddr(endpoint.to_string()))?;
        let stream = TcpStream::connect_timeout(&addr, timeout)?;
        Self::from_stream(stream)
    }

    /// True once the underlying connection has been torn down. A closed link
    /// makes every [`recv`](Transport::recv) and [`send`](Transport::send) fail,
    /// which is the signal a [`FallbackTransport`](crate::FallbackTransport) uses
    /// to retire the primary and revert to the relay.
    pub fn is_closed(&self) -> bool {
        self.shared.is_closed()
    }

    /// Non-blocking depth of one direction's queue, for tests and diagnostics.
    pub fn depth(&self, dir: Direction) -> usize {
        self.shared
            .queues
            .lock()
            .expect("direct link queues poisoned")
            .get(&dir)
            .map(VecDeque::len)
            .unwrap_or(0)
    }

    fn write_frame(&self, dir: Direction, env: &Envelope) -> Result<(), TransportError> {
        if self.shared.is_closed() {
            return Err(TransportError::Closed);
        }
        let payload = wire::envelope_to_wire(env)
            .map_err(|e| TransportError::Backend(format!("serializing envelope: {e}")))?;
        let bytes = payload.as_bytes();
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(TransportError::Backend(format!(
                "envelope frame {} exceeds {MAX_FRAME_BYTES} bytes",
                bytes.len()
            )));
        }
        let mut header = [0u8; 5];
        header[0] = dir_to_byte(dir);
        header[1..5].copy_from_slice(&(bytes.len() as u32).to_be_bytes());

        let mut w = self.writer.lock().map_err(|_| TransportError::Closed)?;
        // A write error means the link is gone: latch closed so the reader and
        // any parked recv also give up, then report it so the caller falls back.
        let res = w.write_all(&header).and_then(|()| w.write_all(bytes));
        if let Err(e) = res {
            drop(w);
            self.shared.close();
            return Err(TransportError::Backend(format!("writing frame: {e}")));
        }
        Ok(())
    }
}

impl Transport for DirectLink {
    fn send(
        &self,
        _mailbox: [u8; 32],
        dir: Direction,
        env: &Envelope,
    ) -> Result<(), TransportError> {
        self.write_frame(dir, env)
    }

    // `deposit_to_phone` uses the trait default (a plain ToPhone `send`): a
    // direct link has no relay to hand a `PushHint` to, so the hint is correctly
    // ignored. The phone is already awake on the live connection.

    fn recv(
        &self,
        _mailbox: [u8; 32],
        dir: Direction,
        timeout: Duration,
    ) -> Result<Option<Envelope>, TransportError> {
        let deadline = Instant::now() + timeout;
        let mut queues = self
            .shared
            .queues
            .lock()
            .map_err(|_| TransportError::Closed)?;
        loop {
            if let Some(env) = queues.get_mut(&dir).and_then(VecDeque::pop_front) {
                return Ok(Some(env));
            }
            // Closed with nothing buffered: fail so the selector reverts to the
            // relay. Checked after draining the queue so a frame that arrived
            // just before the close is still delivered.
            if self.shared.is_closed() {
                return Err(TransportError::Closed);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let (guard, res) = self
                .shared
                .signal
                .wait_timeout(queues, deadline - now)
                .map_err(|_| TransportError::Closed)?;
            queues = guard;
            if res.timed_out() {
                if let Some(env) = queues.get_mut(&dir).and_then(VecDeque::pop_front) {
                    return Ok(Some(env));
                }
                if self.shared.is_closed() {
                    return Err(TransportError::Closed);
                }
                return Ok(None);
            }
        }
    }
}

impl Drop for DirectLink {
    fn drop(&mut self) {
        // Dropping the writer half shuts the connection, which unblocks the
        // reader's blocking read so its thread exits; join it so we do not leak.
        self.shared.close();
        if let Ok(mut guard) = self.reader.lock() {
            if let Some(handle) = guard.take() {
                // The reader may still be parked in a blocking read on the clone
                // of the stream; dropping `self.writer` (after this Drop returns)
                // closes it. To avoid a join deadlock we detach rather than block
                // here: the OS closes the fd, the read returns, the thread ends.
                drop(handle);
            }
        }
    }
}

/// The reader thread body: pull framed envelopes off `stream` and demux them
/// into the shared queues until EOF, an io error, or a protocol violation.
fn read_loop(mut stream: TcpStream, shared: &Arc<Shared>) {
    loop {
        let mut header = [0u8; 5];
        if let Err(_e) = stream.read_exact(&mut header) {
            break; // EOF or io error: the link is gone.
        }
        let dir = match byte_to_dir(header[0]) {
            Some(d) => d,
            // An unknown direction byte means the framing is desynchronised or
            // the peer is hostile: closing is the only safe move.
            None => break,
        };
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if len > MAX_FRAME_BYTES {
            // Over-cap length: refuse to allocate it. Fail closed.
            break;
        }
        let mut payload = vec![0u8; len];
        if stream.read_exact(&mut payload).is_err() {
            break; // Truncated frame: the link is gone.
        }
        let text = match std::str::from_utf8(&payload) {
            Ok(t) => t,
            // Non-UTF8 within a valid length: drop this frame but keep the link;
            // framing is still synchronised (we consumed exactly `len` bytes).
            Err(_) => continue,
        };
        match wire::wire_to_envelope(text) {
            Ok(env) => {
                let mut queues = match shared.queues.lock() {
                    Ok(q) => q,
                    Err(_) => break,
                };
                queues.entry(dir).or_default().push_back(env);
                drop(queues);
                shared.signal.notify_all();
            }
            // An undecodable-but-length-valid frame is dropped, matching the
            // relay client's tolerance; the link stays up.
            Err(_) => continue,
        }
    }
    shared.close();
}

/// The rung-2 daemon side: an owned host:port the daemon binds and the phone
/// dials. [`accept`](DirectListener::accept) blocks for the next dial and hands
/// back an unverified [`DirectLink`]; the caller must run
/// [`verify_link`](crate::discovery::verify_link) before trusting it as a
/// primary.
pub struct DirectListener {
    listener: TcpListener,
}

impl DirectListener {
    /// Bind `endpoint` (`host:port`, e.g. `0.0.0.0:8787` or `[::]:8787`).
    pub fn bind(endpoint: &str) -> Result<Self, DirectError> {
        let addr = endpoint
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| DirectError::NoAddr(endpoint.to_string()))?;
        let listener = TcpListener::bind(addr)?;
        Ok(Self { listener })
    }

    /// The bound local address (useful when binding an ephemeral `:0` port).
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, DirectError> {
        Ok(self.listener.local_addr()?)
    }

    /// Block for the next dial and wrap it as a [`DirectLink`]. The returned link
    /// is UNVERIFIED: a same-LAN host can dial too, so promotion to a trusted
    /// primary must gate on [`verify_link`](crate::discovery::verify_link).
    pub fn accept(&self) -> Result<Arc<DirectLink>, DirectError> {
        let (stream, _peer) = self.listener.accept()?;
        DirectLink::from_stream(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_proto::identity::DeviceIdentity;

    /// Seal a throwaway envelope on `mailbox`. Its bytes are what a direct link
    /// carries; the tests here only assert the pipe round-trips them intact and
    /// never assert anything about trust (that is the envelope layer's job).
    fn sealed(mailbox: [u8; 32], counter: u64) -> Envelope {
        let sender = DeviceIdentity::generate();
        let recipient = DeviceIdentity::generate();
        Envelope::seal(
            &"payload".to_string(),
            mailbox,
            counter,
            &sender.signing,
            &recipient.peer_identity(),
        )
        .expect("seal")
    }

    /// A connected daemon/phone pair of links over loopback.
    fn connected_pair() -> (Arc<DirectLink>, Arc<DirectLink>) {
        let listener = DirectListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let dialer =
            std::thread::spawn(move || DirectLink::connect(&addr.to_string()).expect("connect"));
        let server = listener.accept().expect("accept");
        let client = dialer.join().expect("dialer thread");
        (server, client)
    }

    #[test]
    fn a_frame_written_one_side_arrives_intact_on_the_other() {
        let (server, client) = connected_pair();
        let mbx = [5u8; 32];
        let env = sealed(mbx, 1);
        // Daemon (server) deposits ToPhone; phone (client) receives ToPhone.
        server
            .send(mbx, Direction::ToPhone, &env)
            .expect("server send");
        let got = client
            .recv(mbx, Direction::ToPhone, Duration::from_secs(2))
            .expect("recv ok")
            .expect("an envelope");
        assert_eq!(got.request_id, env.request_id);
    }

    #[test]
    fn directions_are_independent_over_one_link() {
        let (server, client) = connected_pair();
        let mbx = [6u8; 32];
        let to_daemon = sealed(mbx, 1);
        // Phone (client) sends ToDaemon; nothing ToPhone.
        client
            .send(mbx, Direction::ToDaemon, &to_daemon)
            .expect("client send");
        assert!(server
            .recv(mbx, Direction::ToPhone, Duration::from_millis(50))
            .expect("recv ok")
            .is_none());
        assert!(server
            .recv(mbx, Direction::ToDaemon, Duration::from_secs(2))
            .expect("recv ok")
            .is_some());
    }

    #[test]
    fn recv_wakes_on_a_late_frame() {
        let (server, client) = connected_pair();
        let mbx = [7u8; 32];
        let waiter = std::thread::spawn(move || {
            server
                .recv(mbx, Direction::ToDaemon, Duration::from_secs(2))
                .expect("recv ok")
        });
        std::thread::sleep(Duration::from_millis(30));
        client
            .send(mbx, Direction::ToDaemon, &sealed(mbx, 1))
            .expect("client send");
        assert!(waiter.join().expect("waiter").is_some());
    }

    #[test]
    fn a_dropped_peer_makes_recv_fail_so_the_caller_can_fall_back() {
        let (server, client) = connected_pair();
        let mbx = [8u8; 32];
        drop(client); // peer closes the connection
                      // The reader observes EOF and latches closed; recv then errors rather
                      // than blocking to its full timeout or returning a false empty.
        let res = server.recv(mbx, Direction::ToDaemon, Duration::from_secs(2));
        assert!(
            matches!(res, Err(TransportError::Closed)),
            "a closed link must fail recv, got {res:?}"
        );
        assert!(server.is_closed());
    }

    #[test]
    fn a_send_after_the_peer_drops_fails() {
        let (server, client) = connected_pair();
        let mbx = [9u8; 32];
        drop(client);
        // Give the reader a moment to observe EOF and latch closed.
        std::thread::sleep(Duration::from_millis(50));
        let res = server.send(mbx, Direction::ToPhone, &sealed(mbx, 1));
        assert!(res.is_err(), "send on a dead link must fail, got {res:?}");
    }

    #[test]
    fn buffered_frames_survive_a_close_and_are_delivered_before_the_error() {
        let (server, client) = connected_pair();
        let mbx = [10u8; 32];
        let env = sealed(mbx, 1);
        client
            .send(mbx, Direction::ToDaemon, &env)
            .expect("client send");
        // Let the frame land in the server's queue, then drop the peer.
        std::thread::sleep(Duration::from_millis(50));
        drop(client);
        std::thread::sleep(Duration::from_millis(50));
        // The buffered frame comes out first...
        let first = server
            .recv(mbx, Direction::ToDaemon, Duration::from_millis(200))
            .expect("recv ok");
        assert!(first.is_some(), "the buffered frame must survive the close");
        // ...and only then does the closed link surface as an error.
        let second = server.recv(mbx, Direction::ToDaemon, Duration::from_millis(200));
        assert!(matches!(second, Err(TransportError::Closed)));
    }
}
