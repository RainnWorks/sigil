//! Pure, runtime-agnostic relay logic. No I/O, no platform APIs.
//!
//! This is the Rust port of `relay/shared/protocol.ts`. It makes every wire
//! decision the server layer then executes, so the native relay speaks a
//! byte-identical protocol to the TS Cloudflare Worker and Bun variants:
//! identical routes, status codes, and JSON bodies. If a wire decision is not
//! made here, it is a bug.
//!
//! The relay never inspects an envelope. Every payload is an opaque `String`
//! that flows in one side and out the other unchanged; nothing here parses it,
//! hashes it, or reads a field of it. Routing is by the mailbox id in the URL,
//! which the daemon and phone both derive from their pinned keys (proto
//! `mailbox_id`); we only pattern-check its shape.
//!
//! The one thing the relay does add to a delivery is [`Origin`]: the network
//! address it observed the deposit arriving from. See that type for the threat
//! framing; it is a display-only hint and never an enforcement input.
//!
//! Long-poll semantics (see the async `long_poll` in `server.rs`) preserve the
//! v5.2 OFFER-THEN-DRAIN wake exactly: a GET on an empty slot registers a
//! [`Waiter`] and holds; a deposit OFFERS the still-queued blobs to the NEWEST
//! waiter and only drains the buffer once that waiter reports it ACCEPTED the
//! offer (was live). A settled/dead waiter rejects the offer, leaving the items
//! queued with their original `exp` (no TTL reset, no reorder) for the next GET.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Envelope time-to-live, ms. Short: this only has to outlive the gap between a
/// deposit and the other side's next poll, not a real offline window. Ordered
/// relay TTL >= proto REPLAY_WINDOW_MS (150_000) > the approval timeout
/// (120_000), so the relay never expires a queued envelope before the replay
/// window would still accept it. 180_000 leaves 30s of headroom.
pub const TTL_MS: u64 = 180_000;
/// Bounded FIFO depth per direction. Overflow is rejected, never silently dropped.
pub const MAX_QUEUE: usize = 32;
/// Envelopes are tiny (a sealed DEK or a small request). Larger is abuse.
pub const MAX_ENVELOPE_BYTES: usize = 16_384;
/// Coarse slack over [`MAX_ENVELOPE_BYTES`] for the JSON wrapper (a push token
/// and platform tag, both tiny). Only a pre-read guard against an oversized
/// body; the authoritative per-envelope cap is [`too_big`] on `env` itself.
pub const MAX_BODY_BYTES: usize = MAX_ENVELOPE_BYTES + 4_096;
/// How long a long-poll GET holds an empty slot open before returning empty.
/// Clients read with a comfortably longer timeout than this.
pub const LONG_POLL_MS: u64 = 25_000;
/// Upper bound on coexisting long-poll waiters per slot. Normally 1; climbs only
/// when a client's polls genuinely overlap (a reconnect after a disconnect whose
/// signal never fired). At the cap a new GET drops the OLDEST waiter (stalest,
/// likeliest orphaned) rather than resolving a live one early. This is the
/// explicit memory bound; the rate limiter is only a coarse backstop.
pub const MAX_WAITERS: usize = 8;
/// Global cap on the number of distinct live mailboxes the process will hold at
/// once. A mailbox id is a 256-bit capability, so a shape-valid id costs nothing
/// to mint; without this bound an unauthenticated flood of distinct ids grows
/// the map (and its held connections) until the 180s sweep reclaims them. At the
/// cap the relay refuses to CREATE a new mailbox (503) but never touches ones
/// already established, so real pairings keep working while a flood fails closed.
/// Generous enough that normal use never reaches it; a wide public deploy should
/// also sit behind a reverse proxy with its own connection/rate limits.
pub const MAX_MAILBOXES: usize = 100_000;
/// Per-mailbox ordinary deposits/drains allowed per [`RATE_WINDOW_MS`]. Held
/// only in the mailbox's in-memory record; never persisted. Non-load-bearing.
pub const RATE_MAX: u32 = 60;
pub const RATE_WINDOW_MS: u64 = 60_000;
/// A separate, tighter cap on pushes/knocks specifically, so a leaked push token
/// can't turn a mailbox into a doorbell-spam amplifier. Residual: per-mailbox,
/// not per-token.
pub const PUSH_MAX: u32 = 5;
pub const PUSH_WINDOW_MS: u64 = 60_000;

/// Milliseconds since the unix epoch, the clock all TTL/rate math uses.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A mailbox id is the lowercase hex of the 32-byte proto `mailbox_id`.
pub fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Envelopes are ASCII/UTF-8 JSON, so byte length is a sound ceiling.
pub fn too_big(blob: &str) -> bool {
    blob.len() > MAX_ENVELOPE_BYTES
}

/// Relay-ASSERTED provenance for one buffered to-phone envelope: the network
/// address the relay observed the deposit arriving from, and when it arrived.
///
/// Why this grants the relay no new power: a TCP server unavoidably sees the
/// peer address of every connection. Surfacing it to the phone tells the relay
/// nothing it did not already have; it only moves a fact the relay already
/// holds into the hands of the human who is about to approve something. The
/// envelope stays sealed and opaque either way, and nothing here is derived
/// from its bytes.
///
/// Why it is a hint and NOTHING else: the relay is the adversary in this
/// system's threat model. A hostile relay can forge this field, strip it, or
/// replay an old one, and no client can tell. So it must never be verified
/// against, compared for equality as a gate, or made an enforcement boundary
/// anywhere in the daemon, the phone, or a rule. Its entire value is as a soft
/// tell for a human reading an approval sheet: an approval that claims to come
/// from their own Mac but arrives from an unfamiliar network is worth a second
/// look, which is exactly the signal a stolen keystore file would trip.
///
/// It is not persisted. It lives in the [`Item`] it belongs to, for that item's
/// short TTL, in memory only, and dies with it. It is never logged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Origin {
    /// The address, rendered from a parsed [`IpAddr`], so this field is always a
    /// well-formed IP literal and never attacker-chosen free text reaching a UI.
    pub ip: String,
    /// When the deposit was observed, ms since the unix epoch.
    pub at_ms: u64,
}

impl Origin {
    pub fn new(ip: IpAddr, at_ms: u64) -> Self {
        Self {
            ip: ip.to_string(),
            at_ms,
        }
    }
}

/// Resolve the address to attribute a deposit to, given the socket peer we
/// actually observed, the `X-Forwarded-For` header if any, and how many trusted
/// proxies stand between this process and the real client.
///
/// `trusted_hops` counts the proxies in front of the relay, the nearest one
/// first: it is `0` for a directly exposed relay, `1` behind one reverse proxy,
/// and `2` for the `deploy/gcp/` layout (Caddy on loopback, Cloudflare in front
/// of Caddy). At `0` the header is not read at all and the socket peer is the
/// answer, which is the only self-evidently unforgeable option.
///
/// Above `0` we append the socket peer to the header's list, making the full
/// observed chain `[client, ...proxies, peer]`, and index `trusted_hops` places
/// left of its right-hand end. Each element to the RIGHT of the one we pick was
/// written by a hop we trust, so a client that prepends fake entries only pads
/// the left of the list and pushes its own real address into our slot; the
/// spoof does not move the answer. If the chain is shorter than `trusted_hops`
/// claims, or the element does not parse as an IP, we return `None` (unknown)
/// rather than reach further left into client-supplied text.
///
/// The misconfiguration is the danger, and it is worse than having no feature at
/// all: set `trusted_hops` HIGHER than the number of proxies genuinely in front
/// of the relay and the index lands inside the part of the header the client
/// wrote, at which point the phone is shown an attacker-chosen address wearing
/// the relay's authority. Set it to the real hop count or leave it at `0`.
pub fn client_ip(forwarded_for: Option<&str>, peer: IpAddr, trusted_hops: usize) -> Option<IpAddr> {
    if trusted_hops == 0 {
        return Some(peer);
    }
    let peer_text = peer.to_string();
    let mut chain: Vec<&str> = forwarded_for
        .map(|h| h.split(',').collect())
        .unwrap_or_default();
    chain.push(&peer_text);
    let idx = chain.len().checked_sub(trusted_hops + 1)?;
    parse_ip_entry(chain[idx])
}

/// Parse one forwarded-chain element into an address, tolerating the `host:port`
/// and `[v6]:port` forms proxies sometimes emit. Anything else is `None`: an
/// unparsable element is reported as unknown, never passed through as text.
fn parse_ip_entry(raw: &str) -> Option<IpAddr> {
    let s = raw.trim();
    let s = if let Some(rest) = s.strip_prefix('[') {
        rest.split(']').next()?
    } else if s.matches(':').count() == 1 {
        s.split(':').next()?
    } else {
        s
    };
    s.parse::<IpAddr>().ok()
}

/// One buffered opaque payload, its expiry (ms since epoch), and the relay's
/// own note of where it came from (see [`Origin`]; `None` on the to-daemon
/// direction, which never records one, and whenever the address is unknown).
#[derive(Clone)]
pub struct Item {
    pub blob: String,
    pub exp: u64,
    pub origin: Option<Origin>,
}

/// One drained item on its way out to a client: the opaque envelope exactly as
/// deposited, plus whatever provenance the relay recorded for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub env: String,
    pub origin: Option<Origin>,
}

/// A pending long-poll GET's resolver, called at most once with whatever was
/// offered to it. Returns whether it ACCEPTED the offer: `true` if this call is
/// the one that settles the waiter, `false` if the waiter was already settled
/// (timed out, aborted, or resolved) and dropped the offer. [`wake`] relies on
/// this: it only drains the buffer once a waiter reports it accepted, so an
/// offer a stale waiter rejects is never removed from the queue.
pub struct Waiter {
    pub id: u64,
    call: WaiterFn,
}

/// The offer callback a [`Waiter`] wraps (see [`Waiter`] for the accept/reject
/// contract). Aliased so the `dyn FnMut` type stays readable at every use site.
pub type WaiterFn = Box<dyn FnMut(&[Delivery]) -> bool + Send>;

impl Waiter {
    pub fn new(id: u64, call: WaiterFn) -> Self {
        Self { id, call }
    }
    /// Offer these deliveries to the waiter; see the type docs for the return value.
    pub fn offer(&mut self, items: &[Delivery]) -> bool {
        (self.call)(items)
    }
}

/// The complete in-memory state of one mailbox. No disk, ever.
pub struct Mailbox {
    /// daemon -> phone; drained by GET .../to-phone.
    pub to_phone: Vec<Item>,
    /// phone -> daemon; drained by GET .../to-daemon.
    pub to_daemon: Vec<Item>,
    /// GETs on .../to-phone currently long-polling an empty to_phone.
    pub to_phone_waiters: Vec<Waiter>,
    /// GETs on .../to-daemon currently long-polling an empty to_daemon.
    pub to_daemon_waiters: Vec<Waiter>,
    pub rate_count: u32,
    pub rate_start: u64,
    pub push_count: u32,
    pub push_start: u64,
}

impl Mailbox {
    pub fn new() -> Self {
        Self {
            to_phone: Vec::new(),
            to_daemon: Vec::new(),
            to_phone_waiters: Vec::new(),
            to_daemon_waiters: Vec::new(),
            rate_count: 0,
            rate_start: 0,
            push_count: 0,
            push_start: 0,
        }
    }

    /// Is this mailbox empty AND unwatched, hence safe for the sweep to drop?
    pub fn idle(&self) -> bool {
        self.to_phone.is_empty()
            && self.to_daemon.is_empty()
            && self.to_phone_waiters.is_empty()
            && self.to_daemon_waiters.is_empty()
    }
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Which direction slot a request addresses.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    ToPhone,
    ToDaemon,
}

impl Slot {
    /// Borrow this slot's (queue, waiters) pair out of a mailbox.
    pub fn parts<'a>(&self, m: &'a mut Mailbox) -> (&'a mut Vec<Item>, &'a mut Vec<Waiter>) {
        match self {
            Slot::ToPhone => (&mut m.to_phone, &mut m.to_phone_waiters),
            Slot::ToDaemon => (&mut m.to_daemon, &mut m.to_daemon_waiters),
        }
    }
}

/// Replace a list's contents in place with only its unexpired items.
pub fn retain_live(list: &mut Vec<Item>, now: u64) {
    list.retain(|i| i.exp > now);
}

/// Evict expired items from both directions (used by the periodic sweep).
pub fn evict_expired(m: &mut Mailbox, now: u64) {
    retain_live(&mut m.to_phone, now);
    retain_live(&mut m.to_daemon, now);
}

/// Fixed-window limiter over ordinary deposits/drains. Non-load-bearing
/// anti-abuse; clients verify everything themselves.
pub fn rate_ok(m: &mut Mailbox, now: u64) -> bool {
    if now.saturating_sub(m.rate_start) >= RATE_WINDOW_MS {
        m.rate_start = now;
        m.rate_count = 0;
    }
    m.rate_count += 1;
    m.rate_count <= RATE_MAX
}

/// A separate, tighter fixed-window limiter gating only the push/knock proxy.
pub fn push_ok(m: &mut Mailbox, now: u64) -> bool {
    if now.saturating_sub(m.push_start) >= PUSH_WINDOW_MS {
        m.push_start = now;
        m.push_count = 0;
    }
    m.push_count += 1;
    m.push_count <= PUSH_MAX
}

/// Result of an enqueue; the code mirrors the HTTP status the server returns.
#[derive(Debug, PartialEq, Eq)]
pub enum EnqueueResult {
    Ok,
    /// 413: the envelope is over [`MAX_ENVELOPE_BYTES`].
    TooLarge,
    /// 507: the queue is at [`MAX_QUEUE`].
    QueueFull,
}

/// Evict expired, reject oversized (413) or a full queue (507), else append.
/// `origin` is the relay's own note of where this deposit came from; it shares
/// the item's lifetime exactly and is dropped with it.
pub fn enqueue(
    list: &mut Vec<Item>,
    blob: String,
    origin: Option<Origin>,
    now: u64,
) -> EnqueueResult {
    if too_big(&blob) {
        return EnqueueResult::TooLarge;
    }
    retain_live(list, now);
    if list.len() >= MAX_QUEUE {
        return EnqueueResult::QueueFull;
    }
    list.push(Item {
        blob,
        exp: now + TTL_MS,
        origin,
    });
    EnqueueResult::Ok
}

/// Return every unexpired item and empty the queue (drain-on-read).
pub fn drain(list: &mut Vec<Item>, now: u64) -> Vec<Delivery> {
    let out: Vec<Delivery> = list
        .iter()
        .filter(|i| i.exp > now)
        .map(|i| Delivery {
            env: i.blob.clone(),
            origin: i.origin.clone(),
        })
        .collect();
    list.clear();
    out
}

/// Wake the NEWEST pending long-poll waiter for a slot, handing it everything
/// now queued. Call right after a successful [`enqueue`] on the same list. A
/// no-op if nothing is waiting: the item sits in the queue for the next GET.
///
/// Offer-then-drain, not drain-then-offer: we OFFER the still-queued blobs to a
/// waiter and only empty the buffer once that waiter reports it ACCEPTED. A
/// waiter that rejects (already settled) leaves every item exactly where it was
/// (same `exp`, no reorder); we try the next-newest, then leave the items
/// queued for the next GET if none accept. Newest, not oldest: the only reason a
/// slot holds more than one waiter is a client whose earlier poll's connection
/// died and then reconnected; the reconnect is the newest and the live one.
pub fn wake(list: &mut Vec<Item>, waiters: &mut Vec<Waiter>, now: u64) {
    retain_live(list, now);
    if list.is_empty() {
        return; // nothing to hand off (defensive; enqueue precedes wake)
    }
    while let Some(mut waiter) = waiters.pop() {
        let offered: Vec<Delivery> = list
            .iter()
            .map(|i| Delivery {
                env: i.blob.clone(),
                origin: i.origin.clone(),
            })
            .collect();
        if waiter.offer(&offered) {
            list.clear(); // accepted by a live waiter: now, and only now, drain
            return;
        }
        // rejected (already settled): items untouched, try the next-newest.
    }
}

// ---- Response bodies, as typed structs so serde emits byte-exact field order
// matching relay/shared/protocol.ts's RESP.* (no BTreeMap re-ordering). ----

#[derive(Serialize)]
pub struct HealthBody {
    pub ok: bool,
    pub service: &'static str,
}

#[derive(Serialize)]
pub struct OkBody {
    pub ok: bool,
}

/// The drain response. `envelopes` is unchanged from v5.2 and stays the whole
/// contract for any client that does not care about provenance: a bare array of
/// the opaque envelope strings, byte-identical to what was deposited.
///
/// `origins` is an ADDITIVE, optional sibling, index-aligned with `envelopes`:
/// `origins[i]` is the [`Origin`] of `envelopes[i]`, or `null` where the relay
/// has none. The whole field is omitted when no delivered item has one, which
/// is always the case for the to-daemon direction (the daemon has no use for
/// the phone's address, so none is ever recorded). A parallel array rather than
/// wrapping each envelope in an object: every deployed client parses
/// `envelopes: string[]`, and a display-only hint must not be able to break a
/// client that has never heard of it.
#[derive(Serialize)]
pub struct EnvelopesBody {
    pub envelopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origins: Option<Vec<Option<Origin>>>,
}

#[derive(Serialize)]
pub struct ErrBody<'a> {
    pub ok: bool,
    pub error: &'a str,
}

pub fn health_body() -> HealthBody {
    HealthBody {
        ok: true,
        service: "sigil-relay",
    }
}

pub fn deposited_body() -> OkBody {
    OkBody { ok: true }
}

pub fn envelopes_body(list: Vec<Delivery>) -> EnvelopesBody {
    let origins: Vec<Option<Origin>> = list.iter().map(|d| d.origin.clone()).collect();
    EnvelopesBody {
        envelopes: list.into_iter().map(|d| d.env).collect(),
        origins: origins.iter().any(Option::is_some).then_some(origins),
    }
}

pub fn err_body(error: &str) -> ErrBody<'_> {
    ErrBody { ok: false, error }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(blob: &str) -> Item {
        Item {
            blob: blob.into(),
            exp: now_ms() + 10_000,
            origin: None,
        }
    }

    /// The envelope strings out of a drain or an offer, for the many assertions
    /// that only care about which blobs moved.
    fn envs(items: &[Delivery]) -> Vec<String> {
        items.iter().map(|d| d.env.clone()).collect()
    }

    // A silent-orphan waiter models a connection that is gone but whose abort
    // never fired: it stays registered, is NOT settled, so it still reports it
    // ACCEPTED (returns true), and whatever it is handed goes into the void.
    fn silent_orphan(sink: std::sync::Arc<std::sync::Mutex<Vec<Vec<String>>>>, id: u64) -> Waiter {
        Waiter::new(
            id,
            Box::new(move |items| {
                sink.lock().unwrap().push(envs(items));
                true
            }),
        )
    }

    // A settled-dead waiter models a connection whose abort/timeout fired: if
    // wake reaches it, it must REJECT the offer so the item is preserved.
    fn settled_dead(id: u64) -> Waiter {
        Waiter::new(id, Box::new(|_| false))
    }

    #[test]
    fn valid_id_is_64_lowercase_hex() {
        assert!(valid_id(&"a".repeat(64)));
        assert!(valid_id(&"0123456789abcdef".repeat(4)));
        assert!(!valid_id(&"A".repeat(64))); // uppercase rejected
        assert!(!valid_id(&"a".repeat(63)));
        assert!(!valid_id(&"g".repeat(64)));
        assert!(!valid_id("not-hex"));
    }

    #[test]
    fn enqueue_rejects_oversized_and_full() {
        let now = now_ms();
        let mut list = Vec::new();
        assert_eq!(
            enqueue(&mut list, "x".repeat(MAX_ENVELOPE_BYTES + 1), None, now),
            EnqueueResult::TooLarge
        );
        for i in 0..MAX_QUEUE {
            assert_eq!(
                enqueue(&mut list, format!("e{i}"), None, now),
                EnqueueResult::Ok
            );
        }
        assert_eq!(
            enqueue(&mut list, "overflow".into(), None, now),
            EnqueueResult::QueueFull
        );
    }

    #[test]
    fn drain_returns_live_and_empties() {
        let now = now_ms();
        let mut list = vec![item("a"), item("b")];
        assert_eq!(envs(&drain(&mut list, now)), vec!["a", "b"]);
        assert!(list.is_empty());
    }

    #[test]
    fn expired_items_are_not_drained() {
        let now = now_ms();
        let mut list = vec![Item {
            blob: "stale".into(),
            exp: now.saturating_sub(1),
            origin: None,
        }];
        assert!(drain(&mut list, now).is_empty());
    }

    #[test]
    fn rate_limiter_trips_past_the_window_max() {
        let now = now_ms();
        let mut m = Mailbox::new();
        for _ in 0..RATE_MAX {
            assert!(rate_ok(&mut m, now));
        }
        assert!(!rate_ok(&mut m, now)); // RATE_MAX + 1
    }

    #[test]
    fn push_limiter_is_tighter_than_the_rate_limiter() {
        let now = now_ms();
        let mut m = Mailbox::new();
        for _ in 0..PUSH_MAX {
            assert!(push_ok(&mut m, now));
        }
        assert!(!push_ok(&mut m, now));
    }

    #[test]
    fn wake_with_no_waiters_leaves_the_item_queued() {
        let now = now_ms();
        let mut list = vec![item("unread")];
        let mut waiters: Vec<Waiter> = Vec::new();
        wake(&mut list, &mut waiters, now);
        assert_eq!(
            list.iter().map(|i| i.blob.clone()).collect::<Vec<_>>(),
            vec!["unread"]
        );
    }

    // Port of longpoll-adversarial.test.ts: the undetectable orphan-gap residual.
    #[test]
    fn residual_newest_silently_dead_accepts_older_live_deposit_lost() {
        let now = now_ms();
        let mut list = Vec::new();
        let mut waiters: Vec<Waiter> = Vec::new();
        let voided = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let live_got = std::sync::Arc::new(std::sync::Mutex::new(None::<Vec<String>>));

        // Older, LIVE waiter.
        let lg = live_got.clone();
        waiters.push(Waiter::new(
            1,
            Box::new(move |items| {
                *lg.lock().unwrap() = Some(envs(items));
                true
            }),
        ));
        // Newer, SILENTLY DEAD waiter (accepts because not settled).
        waiters.push(silent_orphan(voided.clone(), 2));

        list.push(item("approval-response"));
        wake(&mut list, &mut waiters, now);

        // The deposit went to the silent-dead newest and is gone.
        assert_eq!(
            *voided.lock().unwrap(),
            vec![vec!["approval-response".to_string()]]
        );
        assert!(live_got.lock().unwrap().is_none());
        assert!(list.is_empty()); // drained, not requeued: genuinely lost
    }

    // Port: offer-then-drain saves the observable disconnect.
    #[test]
    fn hardened_newest_settled_dead_rejects_older_live_gets_it() {
        let now = now_ms();
        let mut list = Vec::new();
        let mut waiters: Vec<Waiter> = Vec::new();
        let live_got = std::sync::Arc::new(std::sync::Mutex::new(None::<Vec<String>>));

        let lg = live_got.clone();
        waiters.push(Waiter::new(
            1,
            Box::new(move |items| {
                *lg.lock().unwrap() = Some(envs(items));
                true
            }),
        )); // older, LIVE
        waiters.push(settled_dead(2)); // newer, SETTLED-dead (rejects)

        list.push(item("approval-response"));
        wake(&mut list, &mut waiters, now);

        assert_eq!(
            *live_got.lock().unwrap(),
            Some(vec!["approval-response".to_string()])
        );
        assert!(list.is_empty());
        assert!(waiters.is_empty());
    }

    // Port: a lone settled-dead waiter never swallows the item.
    #[test]
    fn hardened_lone_settled_dead_preserves_item_for_next_get() {
        let now = now_ms();
        let mut list = vec![item("to-daemon-response")];
        let mut waiters: Vec<Waiter> = vec![settled_dead(1)];
        wake(&mut list, &mut waiters, now);
        assert_eq!(
            list.iter().map(|i| i.blob.clone()).collect::<Vec<_>>(),
            vec!["to-daemon-response"]
        );
        assert!(waiters.is_empty()); // the rejecting waiter was consumed
                                     // A later real drain gets it.
        assert_eq!(envs(&drain(&mut list, now)), vec!["to-daemon-response"]);
    }

    // Port: single-flight clients always have the live waiter newest.
    #[test]
    fn newest_wins_delivers_to_the_live_reconnect() {
        let now = now_ms();
        let mut list = Vec::new();
        let mut waiters: Vec<Waiter> = Vec::new();
        let orphan_void = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let reconnect_got = std::sync::Arc::new(std::sync::Mutex::new(None::<Vec<String>>));

        waiters.push(silent_orphan(orphan_void.clone(), 1)); // older = dead orphan
        let rg = reconnect_got.clone();
        waiters.push(Waiter::new(
            2,
            Box::new(move |items| {
                *rg.lock().unwrap() = Some(envs(items));
                true
            }),
        )); // newer = live

        list.push(item("approval-response"));
        wake(&mut list, &mut waiters, now);

        assert_eq!(
            *reconnect_got.lock().unwrap(),
            Some(vec!["approval-response".to_string()])
        );
        assert!(orphan_void.lock().unwrap().is_empty()); // orphan never touched
    }

    #[test]
    fn response_bodies_match_the_ts_wire_bytes() {
        assert_eq!(
            serde_json::to_string(&health_body()).unwrap(),
            r#"{"ok":true,"service":"sigil-relay"}"#
        );
        assert_eq!(
            serde_json::to_string(&deposited_body()).unwrap(),
            r#"{"ok":true}"#
        );
        // With no origin recorded the drain body is byte-identical to v5.2:
        // the `origins` key does not appear at all.
        assert_eq!(
            serde_json::to_string(&envelopes_body(vec![delivery("a", None)])).unwrap(),
            r#"{"envelopes":["a"]}"#
        );
        assert_eq!(
            serde_json::to_string(&err_body("rate_limited")).unwrap(),
            r#"{"ok":false,"error":"rate_limited"}"#
        );
    }

    // ---- origin stamping ----

    fn delivery(env: &str, origin: Option<Origin>) -> Delivery {
        Delivery {
            env: env.into(),
            origin,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test ip literal")
    }

    #[test]
    fn origins_ride_alongside_the_envelopes_index_aligned() {
        let body = envelopes_body(vec![
            delivery(
                "first",
                Some(Origin::new(ip("203.0.113.7"), 1_700_000_000_000)),
            ),
            delivery("second", None),
        ]);
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"envelopes":["first","second"],"origins":[{"ip":"203.0.113.7","at_ms":1700000000000},null]}"#
        );
    }

    #[test]
    fn an_origin_is_dropped_with_the_item_it_belongs_to() {
        let now = now_ms();
        let mut list = vec![Item {
            blob: "stale".into(),
            exp: now.saturating_sub(1),
            origin: Some(Origin::new(ip("203.0.113.7"), now)),
        }];
        // Expiry takes the envelope and its origin together; nothing is retained.
        assert!(drain(&mut list, now).is_empty());
        retain_live(&mut list, now);
        assert!(list.is_empty());
    }

    #[test]
    fn an_origin_survives_the_offer_then_drain_handoff() {
        let now = now_ms();
        let origin = Origin::new(ip("198.51.100.4"), now);
        let mut list = Vec::new();
        assert_eq!(
            enqueue(&mut list, "sealed".into(), Some(origin.clone()), now),
            EnqueueResult::Ok
        );
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None::<Vec<Delivery>>));
        let s = seen.clone();
        let mut waiters = vec![Waiter::new(
            1,
            Box::new(move |items: &[Delivery]| {
                *s.lock().unwrap() = Some(items.to_vec());
                true
            }),
        )];
        wake(&mut list, &mut waiters, now);
        assert_eq!(
            *seen.lock().unwrap(),
            Some(vec![delivery("sealed", Some(origin))])
        );
    }

    #[test]
    fn with_no_trusted_proxies_only_the_socket_peer_counts() {
        // The header is not read at all, so a client that invents one gains
        // nothing: what the phone sees is the address we actually observed.
        assert_eq!(
            client_ip(Some("1.2.3.4"), ip("198.51.100.9"), 0),
            Some(ip("198.51.100.9"))
        );
        assert_eq!(
            client_ip(None, ip("198.51.100.9"), 0),
            Some(ip("198.51.100.9"))
        );
    }

    #[test]
    fn one_trusted_proxy_reads_the_address_that_proxy_recorded() {
        // Caddy on loopback, nothing in front of it.
        assert_eq!(
            client_ip(Some("203.0.113.7"), ip("127.0.0.1"), 1),
            Some(ip("203.0.113.7"))
        );
    }

    #[test]
    fn the_gcp_two_hop_chain_resolves_to_the_real_client() {
        // deploy/gcp: client -> Cloudflare -> Caddy(loopback) -> relay. The
        // header holds [client, cloudflare-edge]; the peer is Caddy.
        assert_eq!(
            client_ip(Some("203.0.113.7, 172.68.1.1"), ip("127.0.0.1"), 2),
            Some(ip("203.0.113.7"))
        );
    }

    #[test]
    fn a_client_prepended_header_cannot_move_the_answer() {
        // The client claims to be 1.2.3.4; Cloudflare appends its real address
        // and Caddy appends Cloudflare's, so the forged entry is pushed left of
        // the slot we index and the real address is still what we report.
        assert_eq!(
            client_ip(
                Some("1.2.3.4, 198.51.100.9, 172.68.1.1"),
                ip("127.0.0.1"),
                2
            ),
            Some(ip("198.51.100.9"))
        );
    }

    #[test]
    fn a_chain_shorter_than_the_configured_trust_is_unknown_not_guessed() {
        // Someone reached the relay directly, or a proxy dropped the header.
        // Reaching further left would mean trusting client text, so: unknown.
        assert_eq!(client_ip(None, ip("198.51.100.9"), 2), None);
        assert_eq!(client_ip(Some("1.2.3.4"), ip("127.0.0.1"), 2), None);
    }

    #[test]
    fn forwarded_entries_are_parsed_as_addresses_or_dropped() {
        assert_eq!(
            client_ip(Some("  203.0.113.7:51000  "), ip("127.0.0.1"), 1),
            Some(ip("203.0.113.7"))
        );
        assert_eq!(
            client_ip(Some("[2001:db8::1]:443"), ip("127.0.0.1"), 1),
            Some(ip("2001:db8::1"))
        );
        assert_eq!(
            client_ip(Some("2001:db8::1"), ip("127.0.0.1"), 1),
            Some(ip("2001:db8::1"))
        );
        // Not an address: reported as unknown, never passed through as text.
        assert_eq!(client_ip(Some("unknown"), ip("127.0.0.1"), 1), None);
        assert_eq!(
            client_ip(Some("<script>alert(1)</script>"), ip("127.0.0.1"), 1),
            None
        );
    }
}
