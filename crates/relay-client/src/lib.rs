//! Network [`Transport`] implementations for the Latch blind relay.
//!
//! The in-process [`LocalRelay`](latch_proto::LocalRelay) proves the approval
//! loop headlessly; these two impls carry the same opaque [`Envelope`]s over the
//! real relay's wire (`relay/README.md`, `relay/shared/protocol.ts`). The relay
//! is never the security layer: both impls move ciphertext only, exactly as
//! `LocalRelay` does, and every guarantee still rests on the envelope.
//!
//! The relay has two asymmetric faces, so this crate has two impls, each mapping
//! the [`Direction`] pair onto exactly the queue that role owns:
//!
//! | impl | role | `send` | `recv` | relay route |
//! |------|------|--------|--------|-------------|
//! | [`DaemonRelay`] | daemon | [`Direction::ToPhone`] | [`Direction::ToDaemon`] | outbound WebSocket `attach` (`{"t":"send"}` / `deliver` frames) |
//! | [`PhoneRelay`]  | phone  | [`Direction::ToDaemon`] | [`Direction::ToPhone`] | HTTPS `POST /submit` / `GET /pending` |
//!
//! A call on the direction a role does not own is a programming error and
//! returns [`TransportError::Backend`] rather than silently doing nothing (which
//! could mask a mis-wired approver). The daemon dials **out** over WebSocket, so
//! no inbound port is needed on the Mac; the phone polls over HTTPS.

mod daemon_ws;
mod phone_http;

pub use daemon_ws::DaemonRelay;
pub use phone_http::PhoneRelay;

use latch_proto::envelope::Envelope;

/// Lowercase hex of the 32-byte mailbox id, the relay's URL path segment.
pub fn mailbox_hex(mailbox: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in mailbox {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Build the daemon's outbound WebSocket attach URL from an `http(s)://host`
/// relay base. `http` -> `ws`, `https` -> `wss`; any other scheme is passed
/// through unchanged (already a `ws(s)://` base).
pub(crate) fn attach_url(base: &str, mailbox_hex: &str) -> String {
    let base = base.trim_end_matches('/');
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_string()
    };
    format!("{ws_base}/mailbox/{mailbox_hex}/attach")
}

/// The opaque wire form of an envelope: the exact bytes the relay stores and
/// forwards, and the two clients' only (de)serialization boundary. The relay
/// treats this as an opaque UTF-8 string and never parses it.
pub(crate) mod wire {
    use super::Envelope;

    /// Serialize an envelope to the opaque relay string (its `serde_json` form).
    pub fn envelope_to_wire(env: &Envelope) -> Result<String, serde_json::Error> {
        serde_json::to_string(env)
    }

    /// Parse an opaque relay string back into an envelope.
    pub fn wire_to_envelope(s: &str) -> Result<Envelope, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// A daemon -> relay `send` control frame carrying the opaque envelope in
    /// `env`. `serde_json` escapes the nested string; the relay parses only this
    /// outer wrapper (`parseSend` in `shared/protocol.ts`).
    pub fn send_frame(env_wire: &str) -> String {
        serde_json::json!({ "t": "send", "env": env_wire }).to_string()
    }

    /// If `msg` is a relay -> daemon `deliver` frame, return its opaque `env`
    /// string; otherwise `None` (an `ack`, `err`, keepalive, or garbage). Mirrors
    /// `FRAME.deliver` / `parseSend` on the relay side.
    pub fn parse_deliver(msg: &str) -> Option<String> {
        let v: serde_json::Value = serde_json::from_str(msg).ok()?;
        if v.get("t")?.as_str()? != "deliver" {
            return None;
        }
        v.get("env")?.as_str().map(str::to_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_url_maps_scheme_to_ws() {
        assert_eq!(
            attach_url("https://relay.example", "ab"),
            "wss://relay.example/mailbox/ab/attach"
        );
        assert_eq!(
            attach_url("http://127.0.0.1:8787/", "cd"),
            "ws://127.0.0.1:8787/mailbox/cd/attach"
        );
        assert_eq!(
            attach_url("ws://host:1/", "ef"),
            "ws://host:1/mailbox/ef/attach"
        );
    }

    #[test]
    fn deliver_frame_round_trips_through_send_wrapper() {
        // A daemon send-frame and a relay deliver-frame both carry the same
        // opaque `env` string; parse_deliver recovers it, and non-deliver frames
        // are ignored.
        let env_wire = r#"{"opaque":"bytes","n":1}"#;
        let frame = wire::send_frame(env_wire);
        // Re-tag as a deliver frame the way the relay would echo it onward.
        let delivered = frame.replace("\"t\":\"send\"", "\"t\":\"deliver\"");
        assert_eq!(wire::parse_deliver(&delivered).as_deref(), Some(env_wire));
        assert_eq!(wire::parse_deliver(&frame), None); // send, not deliver
        assert_eq!(wire::parse_deliver(r#"{"t":"ack","depth":1}"#), None);
        assert_eq!(wire::parse_deliver("not json"), None);
    }

    #[test]
    fn mailbox_hex_is_64_lowercase_hex() {
        let mut m = [0u8; 32];
        m[0] = 0xab;
        m[31] = 0x0f;
        let h = mailbox_hex(&m);
        assert_eq!(h.len(), 64);
        assert!(h.starts_with("ab"));
        assert!(h.ends_with("0f"));
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
