//! Shared HTTP plumbing for the v4 stateless relay.
//!
//! The relay is a per-mailbox ephemeral buffer with two direction slots and no
//! disk: a party POSTs an opaque payload to a slot, the peer GETs (drains) it.
//! The daemon, the phone, and the pairing rendezvous are all thin wrappers over
//! this one client. The relay treats every `env` as opaque bytes; the only
//! non-opaque field is the optional [`PushHint`], which the relay reads to ring a
//! content-free doorbell and then forgets.
//!
//! Blocking, like the phone side always was: each party does one round trip at a
//! time, so a synchronous client needs no runtime.

use std::io::Read as _;
use std::time::Duration;

use serde::Deserialize;

use latch_proto::{PushHint, TransportError};

use crate::mailbox_hex;

/// Per-request HTTP timeout. A slot GET now long-polls: an empty slot holds
/// the request open server-side for up to the relay's ~25s hold before
/// returning empty, rather than replying immediately. This must clear that
/// hold with slack, or the client would time out (and error) requests the
/// relay was about to legitimately answer empty; 35s gives 10s of margin.
const HTTP_TIMEOUT: Duration = Duration::from_secs(35);

/// Ceiling on a drained slot's response body. An honest relay bounds a
/// mailbox to `MAX_QUEUE` (32) envelopes of at most `MAX_ENVELOPE_BYTES`
/// (16 KiB) each (see `relay/shared/protocol.ts`), so a legitimate drain is a
/// few hundred KiB at most; 2 MiB is generous headroom over that. A buggy or
/// hostile relay ignoring its own limits must not be able to force unbounded
/// client-side allocation just because we asked it to drain a mailbox.
const MAX_DRAIN_BYTES: u64 = 2 * 1024 * 1024;

/// A mailbox's two direction slots. `daemon -> phone` is `to-phone`;
/// `phone -> daemon` is `to-daemon`.
#[derive(Clone, Copy)]
pub(crate) enum Slot {
    ToPhone,
    ToDaemon,
}

impl Slot {
    fn path(self) -> &'static str {
        match self {
            Slot::ToPhone => "to-phone",
            Slot::ToDaemon => "to-daemon",
        }
    }
}

/// A slot GET response: `{"envelopes":[...]}` drained on read.
#[derive(Deserialize)]
struct Drained {
    envelopes: Vec<String>,
}

/// A blocking client for one mailbox on the v4 relay.
pub(crate) struct HttpMailbox {
    base: String,
    mailbox_hex: String,
    client: reqwest::blocking::Client,
}

impl HttpMailbox {
    pub(crate) fn new(base: &str, mailbox: [u8; 32]) -> Result<Self, TransportError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| TransportError::Backend(format!("building http client: {e}")))?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            mailbox_hex: mailbox_hex(&mailbox),
            client,
        })
    }

    fn slot_url(&self, slot: Slot) -> String {
        format!("{}/mailbox/{}/{}", self.base, self.mailbox_hex, slot.path())
    }

    /// POST one opaque payload to a slot as `{"env":...,"pushToken"?,"platform"?}`.
    /// The hint is only ever present on a `to-phone` deposit; the relay rings the
    /// doorbell with it and forgets the token.
    pub(crate) fn deposit(
        &self,
        slot: Slot,
        env_wire: &str,
        hint: Option<&PushHint>,
    ) -> Result<(), TransportError> {
        let body = match hint {
            Some(h) => serde_json::json!({
                "env": env_wire,
                "pushToken": h.token,
                "platform": h.platform,
            }),
            None => serde_json::json!({ "env": env_wire }),
        }
        .to_string();
        let resp = self
            .client
            .post(self.slot_url(slot))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .map_err(|e| TransportError::Backend(format!("POST {}: {e}", slot.path())))?;
        if !resp.status().is_success() {
            return Err(TransportError::Backend(format!(
                "POST {}: status {}",
                slot.path(),
                resp.status()
            )));
        }
        Ok(())
    }

    /// GET and drain every opaque payload currently buffered for a slot
    /// (drain-on-read: the relay removes what it returns). The body is read
    /// through a hard cap ([`MAX_DRAIN_BYTES`]) rather than via `resp.text()`,
    /// so a relay that ignores its own queue/size limits (buggy, or hostile)
    /// cannot force this client to buffer an unbounded response.
    pub(crate) fn drain(&self, slot: Slot) -> Result<Vec<String>, TransportError> {
        let resp = self
            .client
            .get(self.slot_url(slot))
            .send()
            .map_err(|e| TransportError::Backend(format!("GET {}: {e}", slot.path())))?;
        if !resp.status().is_success() {
            return Err(TransportError::Backend(format!(
                "GET {}: status {}",
                slot.path(),
                resp.status()
            )));
        }
        let mut body = Vec::new();
        resp.take(MAX_DRAIN_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|e| TransportError::Backend(format!("reading {} body: {e}", slot.path())))?;
        if body.len() as u64 > MAX_DRAIN_BYTES {
            return Err(TransportError::Backend(format!(
                "{} body exceeded {MAX_DRAIN_BYTES} bytes; refusing to buffer it",
                slot.path()
            )));
        }
        let parsed: Drained = serde_json::from_slice(&body)
            .map_err(|e| TransportError::Backend(format!("parsing {} body: {e}", slot.path())))?;
        Ok(parsed.envelopes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// A raw-socket fake relay that answers one `to-daemon` GET with a body
    /// bigger than [`MAX_DRAIN_BYTES`]. Hand-rolled HTTP/1.1 framing (no
    /// mocking crate in the tree), `Connection: close` so the client need not
    /// pipeline a second request.
    fn spawn_oversized_relay(body_len: usize) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake relay");
        let addr = listener.local_addr().expect("local_addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf); // discard the request line/headers
            let resp_head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(resp_head.as_bytes());
            let _ = stream.write_all(&vec![b' '; body_len]);
        });
        (format!("http://{addr}"), handle)
    }

    #[test]
    fn drain_refuses_a_body_past_the_cap_instead_of_buffering_it() {
        let (base, server) = spawn_oversized_relay(MAX_DRAIN_BYTES as usize + 1024);
        let mailbox = HttpMailbox::new(&base, [9u8; 32]).expect("build mailbox client");
        let err = mailbox
            .drain(Slot::ToDaemon)
            .expect_err("an oversized body must be refused, not buffered");
        assert!(
            matches!(err, TransportError::Backend(ref m) if m.contains("exceeded")),
            "expected the size-cap error, got: {err:?}"
        );
        server.join().expect("fake relay thread");
    }
}
