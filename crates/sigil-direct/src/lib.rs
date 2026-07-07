//! Direct transports for Sigil's transport ladder rungs 1 and 2.
//!
//! Today every daemon<->phone approval rides the blind relay (rung 3). When the
//! two can reach each other directly -- same LAN via Bonjour/mDNS (rung 1), or a
//! user-owned endpoint / dynamic-DNS host (rung 2) -- this crate carries the SAME
//! sealed [`Envelope`](sigil_proto::Envelope)s over a direct duplex TCP link and
//! lets the daemon skip the relay. The relay stays the always-available fallback.
//!
//! # The one safety rule this crate lives by
//!
//! **A direct transport is a pipe, never a trust boundary.** The security layer
//! is, and remains, the envelope: crypto_box-sealed to the pinned recipient,
//! Ed25519-signed by the pinned sender, single-use request id, per-pairing
//! monotonic counter, timestamp window. Nothing in this crate authenticates a
//! peer, decrypts a byte, or grants anything. A rogue host on the LAN can open a
//! TCP connection and inject frames, but every frame is still gated by
//! [`Envelope::open`](sigil_proto::Envelope::open) at the same
//! `RemoteApprover`/phone call site that gates a relay-delivered envelope. An
//! imposter cannot produce an envelope that opens as the pinned peer, so the
//! worst it can do over a direct link is send bytes that get dropped. It cannot
//! forge a request, forge or replay a response, or read anything.
//!
//! This is why the mDNS record ([`discovery`]) is treated as untrusted: it only
//! narrows which host to *dial*. Whether that host is really the paired phone is
//! decided by the envelope handshake ([`discovery::verify_link`]), not by
//! anything the network advertised.
//!
//! # The pieces
//!
//! * [`DirectLink`] -- a [`Transport`](sigil_proto::Transport) over one duplex TCP
//!   connection. It frames the exact opaque envelope wire the relay uses, so the
//!   daemon's `RemoteApprover` and the phone are byte-for-byte indifferent to
//!   which rung answered.
//! * [`DirectListener`] -- the rung-2 daemon side: bind an owned host:port, accept
//!   the phone's dial, hand back a [`DirectLink`].
//! * [`FallbackTransport`] -- the selector: prefer a *verified* direct link when
//!   one is live, fall back to the relay cleanly otherwise, and -- crucially --
//!   present exactly the relay's behaviour, byte-identical, whenever no direct
//!   link is up. This is where downgrade-safety is enforced (see its docs).
//! * [`discovery`] -- the mDNS service/record shape, the advertise/browse seam,
//!   and the envelope-based [`verify_link`](discovery::verify_link) gate that
//!   promotes a freshly dialled socket to a trusted primary only after it proves
//!   it is the pinned peer.

mod fallback;
mod tcp;

pub mod discovery;

pub use fallback::{DepositPolicy, FallbackTransport};
pub use tcp::{DirectError, DirectLink, DirectListener, MAX_FRAME_BYTES};

use sigil_proto::envelope::Envelope;

/// The opaque wire form of an envelope on a direct link: the *same*
/// `serde_json` bytes the blind relay buffers (see
/// `sigil_relay_client::wire`). Sharing the exact encoding is what makes a
/// direct link a drop-in for the relay -- neither the daemon's approver nor the
/// phone can tell which rung carried a given envelope.
pub(crate) mod wire {
    use super::Envelope;

    /// Serialize an envelope to the opaque direct-link string.
    pub fn envelope_to_wire(env: &Envelope) -> Result<String, serde_json::Error> {
        serde_json::to_string(env)
    }

    /// Parse an opaque direct-link string back into an envelope.
    pub fn wire_to_envelope(s: &str) -> Result<Envelope, serde_json::Error> {
        serde_json::from_str(s)
    }
}
