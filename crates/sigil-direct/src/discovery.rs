//! The rung-1 discovery seam and the envelope-based verification gate.
//!
//! On a LAN the daemon advertises itself over mDNS/Bonjour and the phone browses
//! for it. That advertisement is **untrusted**: any host can publish a matching
//! record, so discovery may only ever decide *which address to dial*, never
//! *who is on the other end*. Who is on the other end is settled by
//! [`verify_link`], which reads one [`Envelope`] off the freshly dialled link and
//! demands it open as the pinned paired peer. Only then may the caller install
//! the link as a [`FallbackTransport`](crate::FallbackTransport) primary.
//!
//! This module deliberately holds no identity or crypto types: the hash behind a
//! record's [`hint`](ServiceRecord::hint) and the `open` behind
//! [`verify_link`]'s predicate both live in `sigil` / `sigil-proto`, where the
//! pinned keys are. Here we define only the wire-shape of a record, the
//! advertise/browse trait a concrete Bonjour backend fills, and the promotion
//! gate. The concrete `mdns-sd` backend is specified in
//! `docs/design/direct-transport.md`; it is a thin adapter over this trait and is
//! not landed here because it cannot be exercised without a live multicast
//! network.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use sigil_proto::envelope::Envelope;
use sigil_proto::{Direction, Transport, TransportError};

use crate::tcp::DirectLink;

/// The DNS-SD service type the daemon advertises and the phone browses for.
pub const SERVICE_TYPE: &str = "_sigil._tcp";

/// An advertised (or discovered) direct endpoint.
///
/// The [`hint`](ServiceRecord::hint) is the only correlation field, and it must
/// be a NON-secret discriminator the paired phone can recompute from the pinned
/// daemon key (the design uses a salted, truncated hash of the daemon public
/// identity). It exists solely so the phone dials the right host among several on
/// the LAN; it grants nothing and is never trusted. In particular it is NOT the
/// mailbox id -- broadcasting that would advertise the pairing's routing address
/// on the LAN.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRecord {
    /// The host to dial (an IP literal or a resolvable name).
    pub host: String,
    /// The TCP port the daemon's [`DirectListener`](crate::DirectListener) bound.
    pub port: u16,
    /// A non-secret discriminator the phone recomputes and matches. Empty means
    /// "no hint": the phone must verify by dialling (correct but slower).
    #[serde(default)]
    pub hint: String,
}

impl ServiceRecord {
    /// The `host:port` string a [`DirectLink::connect`](crate::DirectLink::connect)
    /// consumes.
    pub fn endpoint(&self) -> String {
        // Bracket an IPv6 literal so `host:port` parses.
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Whether this record's hint matches `want`. An empty `want` matches
    /// anything (the phone was given no hint and will verify by dialling); a
    /// non-empty `want` must match exactly.
    pub fn hint_matches(&self, want: &str) -> bool {
        want.is_empty() || self.hint == want
    }
}

/// A live advertisement handle. Dropping it withdraws the service.
pub trait Advertisement: Send + Sync {}

/// The mDNS advertise/browse seam. A concrete Bonjour backend implements this;
/// [`InMemoryDiscovery`] implements it for tests and headless runs.
pub trait Discovery: Send + Sync {
    /// Publish `record` on the LAN under [`SERVICE_TYPE`]. The returned handle
    /// keeps the advertisement alive until dropped.
    fn advertise(&self, record: ServiceRecord) -> Result<Box<dyn Advertisement>, DiscoveryError>;

    /// Browse for [`SERVICE_TYPE`] records for up to `timeout`, returning every
    /// record seen. Records matching no known hint are still returned; filtering
    /// is the caller's job via [`ServiceRecord::hint_matches`].
    fn browse(&self, timeout: Duration) -> Result<Vec<ServiceRecord>, DiscoveryError>;
}

#[derive(thiserror::Error, Debug)]
pub enum DiscoveryError {
    /// The backend failed to publish or browse.
    #[error("discovery backend: {0}")]
    Backend(String),
}

/// Errors from promoting a dialled link to a verified primary.
#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    /// No envelope arrived on the link within the verification window.
    #[error("verification timed out with no envelope")]
    Timeout,
    /// The link failed before an envelope could be read.
    #[error("link failed during verification: {0}")]
    Link(#[from] TransportError),
    /// An envelope arrived but did not open as the pinned peer: the host at the
    /// other end is not the paired phone. Fail closed; do not install it.
    #[error("peer is not the pinned paired identity")]
    NotPinnedPeer,
}

/// Prove a freshly dialled/accepted [`DirectLink`] is the pinned paired peer
/// before it is trusted as a primary.
///
/// This is the whole security of rung 1: it reads exactly one [`Envelope`] off
/// `link` in `dir` and hands it to `opens_as_pinned_peer`, which the caller
/// wires to the SAME `Envelope::open` against the pinned peer key and daemon
/// agreement key it already uses for relay-delivered envelopes (including the
/// replay guard). A host that dialled in but does not hold the phone's key
/// cannot produce an envelope that opens, so it fails here and is never
/// installed. The network advertisement is never consulted.
///
/// Returns the verifying envelope on success so the caller can process it as the
/// first real message rather than discarding a legitimate one.
pub fn verify_link(
    link: &DirectLink,
    dir: Direction,
    timeout: Duration,
    mut opens_as_pinned_peer: impl FnMut(&Envelope) -> bool,
) -> Result<Envelope, VerifyError> {
    match link.recv([0u8; 32], dir, timeout)? {
        Some(env) => {
            if opens_as_pinned_peer(&env) {
                Ok(env)
            } else {
                Err(VerifyError::NotPinnedPeer)
            }
        }
        None => Err(VerifyError::Timeout),
    }
}

/// A process-local [`Discovery`] backend for tests and headless loops: an
/// in-memory registry shared by clones. No network, no multicast.
#[derive(Clone, Default)]
pub struct InMemoryDiscovery {
    records: Arc<Mutex<HashMap<String, ServiceRecord>>>,
}

impl InMemoryDiscovery {
    pub fn new() -> Self {
        Self::default()
    }
}

struct InMemoryAd {
    key: String,
    records: Arc<Mutex<HashMap<String, ServiceRecord>>>,
}
impl Advertisement for InMemoryAd {}
impl Drop for InMemoryAd {
    fn drop(&mut self) {
        if let Ok(mut r) = self.records.lock() {
            r.remove(&self.key);
        }
    }
}

impl Discovery for InMemoryDiscovery {
    fn advertise(&self, record: ServiceRecord) -> Result<Box<dyn Advertisement>, DiscoveryError> {
        let key = record.endpoint();
        self.records
            .lock()
            .map_err(|_| DiscoveryError::Backend("registry poisoned".into()))?
            .insert(key.clone(), record);
        Ok(Box::new(InMemoryAd {
            key,
            records: self.records.clone(),
        }))
    }

    fn browse(&self, _timeout: Duration) -> Result<Vec<ServiceRecord>, DiscoveryError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| DiscoveryError::Backend("registry poisoned".into()))?
            .values()
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::DirectListener;
    use sigil_proto::identity::DeviceIdentity;

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

    fn connected_pair() -> (Arc<DirectLink>, Arc<DirectLink>) {
        let listener = DirectListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let dialer =
            std::thread::spawn(move || DirectLink::connect(&addr.to_string()).expect("connect"));
        let server = listener.accept().expect("accept");
        let client = dialer.join().expect("dialer");
        (server, client)
    }

    #[test]
    fn endpoint_brackets_an_ipv6_literal() {
        let r = ServiceRecord {
            host: "fe80::1".into(),
            port: 8787,
            hint: String::new(),
        };
        assert_eq!(r.endpoint(), "[fe80::1]:8787");
        let r4 = ServiceRecord {
            host: "192.168.1.9".into(),
            port: 8787,
            hint: "abc".into(),
        };
        assert_eq!(r4.endpoint(), "192.168.1.9:8787");
    }

    #[test]
    fn hint_matches_is_exact_but_empty_is_a_wildcard() {
        let r = ServiceRecord {
            host: "h".into(),
            port: 1,
            hint: "deadbeef".into(),
        };
        assert!(r.hint_matches("deadbeef"));
        assert!(r.hint_matches("")); // no hint given: match and verify by dialling
        assert!(!r.hint_matches("beefdead"));
    }

    #[test]
    fn in_memory_discovery_round_trips_and_withdraws_on_drop() {
        let disc = InMemoryDiscovery::new();
        let rec = ServiceRecord {
            host: "127.0.0.1".into(),
            port: 8787,
            hint: "h".into(),
        };
        let ad = disc.advertise(rec.clone()).expect("advertise");
        let seen = disc.browse(Duration::from_millis(1)).expect("browse");
        assert_eq!(seen, vec![rec]);
        drop(ad);
        assert!(disc
            .browse(Duration::from_millis(1))
            .expect("browse")
            .is_empty());
    }

    #[test]
    fn verify_link_accepts_an_envelope_the_predicate_approves() {
        let (server, client) = connected_pair();
        let mbx = [1u8; 32];
        let env = sealed(mbx);
        let want = env.request_id;
        client.send(mbx, Direction::ToDaemon, &env).expect("send");
        // The predicate stands in for `Envelope::open` against the pinned peer.
        let verified = verify_link(&server, Direction::ToDaemon, Duration::from_secs(1), |e| {
            e.request_id == want
        })
        .expect("verification must pass");
        assert_eq!(verified.request_id, want);
    }

    #[test]
    fn verify_link_rejects_an_envelope_the_predicate_denies() {
        // An imposter dials in and sends an envelope that does NOT open as the
        // pinned peer; verification must fail closed so it is never installed.
        let (server, client) = connected_pair();
        let mbx = [2u8; 32];
        client
            .send(mbx, Direction::ToDaemon, &sealed(mbx))
            .expect("send");
        let res = verify_link(&server, Direction::ToDaemon, Duration::from_secs(1), |_| {
            false
        });
        assert!(matches!(res, Err(VerifyError::NotPinnedPeer)));
    }

    #[test]
    fn verify_link_times_out_when_nothing_arrives() {
        let (server, _client) = connected_pair();
        let res = verify_link(
            &server,
            Direction::ToDaemon,
            Duration::from_millis(50),
            |_| true,
        );
        assert!(matches!(res, Err(VerifyError::Timeout)));
    }
}
