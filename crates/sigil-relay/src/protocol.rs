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
//! Long-poll semantics (see the async `long_poll` in `server.rs`) preserve the
//! v5.2 OFFER-THEN-DRAIN wake exactly: a GET on an empty slot registers a
//! [`Waiter`] and holds; a deposit OFFERS the still-queued blobs to the NEWEST
//! waiter and only drains the buffer once that waiter reports it ACCEPTED the
//! offer (was live). A settled/dead waiter rejects the offer, leaving the items
//! queued with their original `exp` (no TTL reset, no reorder) for the next GET.

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

/// One buffered opaque payload plus its expiry (ms since epoch).
#[derive(Clone)]
pub struct Item {
    pub blob: String,
    pub exp: u64,
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
pub type WaiterFn = Box<dyn FnMut(&[String]) -> bool + Send>;

impl Waiter {
    pub fn new(id: u64, call: WaiterFn) -> Self {
        Self { id, call }
    }
    /// Offer these blobs to the waiter; see the type docs for the return value.
    pub fn offer(&mut self, blobs: &[String]) -> bool {
        (self.call)(blobs)
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
pub fn enqueue(list: &mut Vec<Item>, blob: String, now: u64) -> EnqueueResult {
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
    });
    EnqueueResult::Ok
}

/// Return every unexpired blob and empty the queue (drain-on-read).
pub fn drain(list: &mut Vec<Item>, now: u64) -> Vec<String> {
    let out: Vec<String> = list
        .iter()
        .filter(|i| i.exp > now)
        .map(|i| i.blob.clone())
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
        let blobs: Vec<String> = list.iter().map(|i| i.blob.clone()).collect();
        if waiter.offer(&blobs) {
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

#[derive(Serialize)]
pub struct EnvelopesBody {
    pub envelopes: Vec<String>,
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

pub fn envelopes_body(list: Vec<String>) -> EnvelopesBody {
    EnvelopesBody { envelopes: list }
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
        }
    }

    // A silent-orphan waiter models a connection that is gone but whose abort
    // never fired: it stays registered, is NOT settled, so it still reports it
    // ACCEPTED (returns true), and whatever it is handed goes into the void.
    fn silent_orphan(sink: std::sync::Arc<std::sync::Mutex<Vec<Vec<String>>>>, id: u64) -> Waiter {
        Waiter::new(
            id,
            Box::new(move |blobs| {
                sink.lock().unwrap().push(blobs.to_vec());
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
            enqueue(&mut list, "x".repeat(MAX_ENVELOPE_BYTES + 1), now),
            EnqueueResult::TooLarge
        );
        for i in 0..MAX_QUEUE {
            assert_eq!(enqueue(&mut list, format!("e{i}"), now), EnqueueResult::Ok);
        }
        assert_eq!(
            enqueue(&mut list, "overflow".into(), now),
            EnqueueResult::QueueFull
        );
    }

    #[test]
    fn drain_returns_live_and_empties() {
        let now = now_ms();
        let mut list = vec![item("a"), item("b")];
        assert_eq!(drain(&mut list, now), vec!["a", "b"]);
        assert!(list.is_empty());
    }

    #[test]
    fn expired_items_are_not_drained() {
        let now = now_ms();
        let mut list = vec![Item {
            blob: "stale".into(),
            exp: now.saturating_sub(1),
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
            Box::new(move |blobs| {
                *lg.lock().unwrap() = Some(blobs.to_vec());
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
            Box::new(move |blobs| {
                *lg.lock().unwrap() = Some(blobs.to_vec());
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
        assert_eq!(drain(&mut list, now), vec!["to-daemon-response"]);
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
            Box::new(move |blobs| {
                *rg.lock().unwrap() = Some(blobs.to_vec());
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
        assert_eq!(
            serde_json::to_string(&envelopes_body(vec!["a".into()])).unwrap(),
            r#"{"envelopes":["a"]}"#
        );
        assert_eq!(
            serde_json::to_string(&err_body("rate_limited")).unwrap(),
            r#"{"ok":false,"error":"rate_limited"}"#
        );
    }
}
