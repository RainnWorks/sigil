//! Network [`Transport`] implementations for the Sigil blind relay.
//!
//! The in-process [`LocalRelay`](sigil_proto::LocalRelay) proves the approval
//! loop headlessly; these two impls carry the same opaque [`Envelope`]s over the
//! real relay's wire (`relay/README.md`, `relay/shared/protocol.ts`). The relay
//! is never the security layer: both impls move ciphertext only, exactly as
//! `LocalRelay` does, and every guarantee still rests on the envelope.
//!
//! The relay has two asymmetric faces, so this crate has two typed [`Transport`]
//! impls, each mapping the [`Direction`](sigil_proto::Direction) pair onto the
//! slot that role owns on the v4 relay:
//!
//! | impl | role | `send` | `recv` | relay route |
//! |------|------|--------|--------|-------------|
//! | [`DaemonRelay`] | daemon | `ToPhone` | `ToDaemon` | `POST /mailbox/{id}/to-phone` / `GET .../to-daemon` |
//! | [`PhoneRelay`]  | phone  | `ToDaemon` | `ToPhone` | `POST /mailbox/{id}/to-daemon` / `GET .../to-phone` |
//!
//! A call on the direction a role does not own is a programming error and
//! returns [`TransportError::Backend`] rather than silently doing nothing (which
//! could mask a mis-wired approver). Both faces are plain HTTP: the relay is a
//! per-mailbox ephemeral in-memory buffer with two direction slots, drained on
//! read, and holds no push token (the daemon forwards it per deposit).

mod daemon_http;
mod http;
mod phone_http;
mod rendezvous;

pub use daemon_http::DaemonRelay;
pub use phone_http::PhoneRelay;
pub use rendezvous::Rendezvous;

use sigil_proto::envelope::Envelope;

/// Lowercase hex of the 32-byte mailbox id, the relay's URL path segment.
pub fn mailbox_hex(mailbox: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in mailbox {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The opaque wire form of an envelope: the exact bytes the relay buffers and
/// forwards inside a slot's `env` field, and the clients' only (de)serialization
/// boundary. The relay treats this as an opaque string and never parses it.
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
