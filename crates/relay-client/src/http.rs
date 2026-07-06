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

use std::time::Duration;

use serde::Deserialize;

use latch_proto::{PushHint, TransportError};

use crate::mailbox_hex;

/// Per-request HTTP timeout. A slot GET returns immediately with whatever is
/// buffered (not a long-poll), so this only bounds a stalled connection.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// (drain-on-read: the relay removes what it returns).
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
        let body = resp
            .text()
            .map_err(|e| TransportError::Backend(format!("reading {} body: {e}", slot.path())))?;
        let parsed: Drained = serde_json::from_str(&body)
            .map_err(|e| TransportError::Backend(format!("parsing {} body: {e}", slot.path())))?;
        Ok(parsed.envelopes)
    }
}
