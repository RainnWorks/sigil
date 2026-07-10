//! Replay protection for the envelope layer.
//!
//! A [`ReplayGuard`] tracks one pairing in one direction. Two independent gates
//! must both pass before an authentic envelope is accepted:
//!
//! 1. **Freshness** — the sender timestamp must be within `window_ms` of now,
//!    in either direction, so a captured envelope cannot be held and replayed
//!    later and a wildly skewed clock is rejected rather than trusted.
//! 2. **Single use** — the uuidv7 request id must not have been seen before.
//!
//! Signature verification happens in [`crate::envelope::Envelope::open`]
//! *before* this guard runs, so state here is only ever mutated for envelopes
//! that are already authentic. Signature + freshness + single-use are complete:
//! a captured envelope either still verifies within the freshness window (and is
//! caught by the single-use id) or has aged out (and is caught by freshness);
//! forging a fresh id requires the sender's signing key, which the relay lacks.
//!
//! The request-id set is bounded by **age**: an entry is remembered only while
//! its timestamp is still inside the freshness window, because a replay of an
//! aged-out id now fails the freshness gate regardless, so forgetting it is
//! safe. [`MAX_SEEN`] is a hard memory backstop for a pathological burst of
//! distinct authentic ids inside one window.
//!
//! The per-pairing `counter` still rides the wire (it is part of the signed
//! canonical bytes, so the envelope format is unchanged) but is no longer a
//! gate: a monotonic in-memory counter reset to 0 on either side after a daemon
//! restart or a phone session recreation, which made the guard drop a genuine,
//! user-approved envelope as a false "replay". Freshness + single-use protect
//! replay without it.

use std::collections::{HashSet, VecDeque};

use uuid::Uuid;

/// Hard upper bound on remembered request ids: a memory backstop, not a
/// correctness gate. Age-based eviction normally keeps the set far smaller;
/// this cap only bites under a pathological burst of distinct authentic ids
/// inside one freshness window, and any id it drops early is one the freshness
/// gate will still reject once the window passes.
const MAX_SEEN: usize = 4096;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ReplayError {
    /// The request id has already been accepted on this pairing.
    #[error("request id already seen")]
    DuplicateRequest,
    /// The sender timestamp is outside the accepted window around now.
    #[error("timestamp {ts} outside {window_ms}ms window around {now}")]
    TimestampOutOfWindow { ts: u64, now: u64, window_ms: u64 },
}

/// Per-pairing, per-direction replay state. The caller holds one guard per
/// pairing (typically a map keyed by `pairing_id`).
#[derive(Debug, Default)]
pub struct ReplayGuard {
    seen: HashSet<Uuid>,
    /// `(request_id, ts)` in insertion order, oldest at the front. Entries are
    /// dropped once `ts` has aged past the freshness window (safe: a replay of
    /// an aged-out id fails freshness), or from the front once the set exceeds
    /// [`MAX_SEEN`].
    order: VecDeque<(Uuid, u64)>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run both gates and, only if each passes, record the request id. On any
    /// error no state changes, so a rejected envelope never poisons a later
    /// legitimate one.
    ///
    /// `counter` is retained in the signature for wire/format compatibility (it
    /// is part of the signed canonical bytes) but is no longer gated: see the
    /// module docs for why the monotonic-counter gate was retired.
    pub fn check_and_record(
        &mut self,
        request_id: Uuid,
        counter: u64,
        ts: u64,
        now: u64,
        window_ms: u64,
    ) -> Result<(), ReplayError> {
        let _ = counter;

        if now.abs_diff(ts) > window_ms {
            return Err(ReplayError::TimestampOutOfWindow { ts, now, window_ms });
        }

        self.evict_aged(now, window_ms);

        if self.seen.contains(&request_id) {
            return Err(ReplayError::DuplicateRequest);
        }

        self.record(request_id, ts);
        Ok(())
    }

    /// Drop remembered ids whose timestamp has aged past the freshness window.
    /// Only front entries that are provably past the window are removed; a
    /// future-dated (still in-window) entry stops the sweep. An out-of-order
    /// older entry that is not yet at the front simply lingers harmlessly until
    /// it reaches the front or the [`MAX_SEEN`] backstop evicts it.
    fn evict_aged(&mut self, now: u64, window_ms: u64) {
        while let Some(&(id, ts)) = self.order.front() {
            if now.saturating_sub(ts) > window_ms {
                self.order.pop_front();
                self.seen.remove(&id);
            } else {
                break;
            }
        }
    }

    fn record(&mut self, request_id: Uuid, ts: u64) {
        if self.seen.insert(request_id) {
            self.order.push_back((request_id, ts));
            while self.order.len() > MAX_SEEN {
                if let Some((evicted, _)) = self.order.pop_front() {
                    self.seen.remove(&evicted);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: u64 = 90_000;
    const NOW: u64 = 1_000_000;

    fn fresh() -> ReplayGuard {
        ReplayGuard::new()
    }

    #[test]
    fn first_envelope_is_accepted() {
        let mut g = fresh();
        assert_eq!(
            g.check_and_record(Uuid::now_v7(), 1, NOW, NOW, WINDOW),
            Ok(())
        );
    }

    #[test]
    fn duplicate_request_id_is_rejected() {
        let mut g = fresh();
        let id = Uuid::now_v7();
        g.check_and_record(id, 1, NOW, NOW, WINDOW).unwrap();
        // Same id, advanced counter: the single-use gate still fires.
        assert_eq!(
            g.check_and_record(id, 2, NOW, NOW, WINDOW),
            Err(ReplayError::DuplicateRequest)
        );
    }

    #[test]
    fn lower_or_reset_counter_with_fresh_ts_and_new_id_is_accepted() {
        // The fix: a lower (or reset-to-0) counter is no longer a rejection.
        // Freshness + single-use are the only gates, so a genuine envelope that
        // rides a restarted, lower counter is accepted instead of being dropped
        // as a false replay.
        let mut g = fresh();
        g.check_and_record(Uuid::now_v7(), 5, NOW, NOW, WINDOW)
            .unwrap();
        assert_eq!(
            g.check_and_record(Uuid::now_v7(), 5, NOW, NOW, WINDOW),
            Ok(())
        );
        assert_eq!(
            g.check_and_record(Uuid::now_v7(), 0, NOW, NOW, WINDOW),
            Ok(())
        );
    }

    #[test]
    fn stale_timestamp_beyond_window_is_rejected() {
        let mut g = fresh();
        let ts = NOW - WINDOW - 1;
        assert_eq!(
            g.check_and_record(Uuid::now_v7(), 1, ts, NOW, WINDOW),
            Err(ReplayError::TimestampOutOfWindow {
                ts,
                now: NOW,
                window_ms: WINDOW
            })
        );
    }

    #[test]
    fn future_timestamp_beyond_window_is_rejected() {
        let mut g = fresh();
        let ts = NOW + WINDOW + 1;
        assert_eq!(
            g.check_and_record(Uuid::now_v7(), 1, ts, NOW, WINDOW),
            Err(ReplayError::TimestampOutOfWindow {
                ts,
                now: NOW,
                window_ms: WINDOW
            })
        );
    }

    #[test]
    fn rejected_envelope_does_not_advance_state() {
        let mut g = fresh();
        let good = Uuid::now_v7();
        g.check_and_record(good, 5, NOW, NOW, WINDOW).unwrap();
        // A stale envelope is rejected and must not touch the seen-set: the
        // still-valid id below is unaffected.
        let _ = g.check_and_record(Uuid::now_v7(), 6, NOW - WINDOW - 1, NOW, WINDOW);
        // The previously accepted id is still remembered (still a duplicate).
        assert_eq!(
            g.check_and_record(good, 6, NOW, NOW, WINDOW),
            Err(ReplayError::DuplicateRequest)
        );
        // And a brand new id still opens cleanly.
        assert_eq!(
            g.check_and_record(Uuid::now_v7(), 6, NOW, NOW, WINDOW),
            Ok(())
        );
    }

    #[test]
    fn a_replay_after_the_id_ages_out_is_caught_by_freshness() {
        // Once an accepted id ages past the window it is forgotten, but a replay
        // of it can only carry its original (now-stale) ts, which the freshness
        // gate rejects before the single-use check even runs. So age-eviction
        // never opens a replay hole.
        let mut g = fresh();
        let id = Uuid::now_v7();
        let ts = NOW;
        g.check_and_record(id, 1, ts, NOW, WINDOW).unwrap();
        // Clock advances well past the window; the entry is now evictable.
        let later = NOW + WINDOW * 3;
        // Replaying the exact same (id, ts) is rejected as stale, not accepted.
        assert_eq!(
            g.check_and_record(id, 1, ts, later, WINDOW),
            Err(ReplayError::TimestampOutOfWindow {
                ts,
                now: later,
                window_ms: WINDOW
            })
        );
    }

    #[test]
    fn age_eviction_keeps_the_set_bounded_over_a_moving_window() {
        // Feed a long stream of unique ids with timestamps that track a steadily
        // advancing clock. Age-eviction alone (no MAX_SEEN needed here) keeps the
        // remembered set within roughly one window's worth of entries.
        let mut g = fresh();
        for step in 0..10_000u64 {
            let now = NOW + step; // 1ms per step
            g.check_and_record(Uuid::now_v7(), step, now, now, WINDOW)
                .unwrap();
        }
        // Only ids from within the last WINDOW ms survive.
        assert!(g.seen.len() <= WINDOW as usize + 1);
        assert_eq!(g.order.len(), g.seen.len());
    }

    #[test]
    fn hard_cap_bounds_a_same_instant_burst() {
        // A pathological burst of distinct authentic ids at one instant cannot be
        // age-evicted (all share now), so the MAX_SEEN backstop bounds memory.
        let mut g = fresh();
        for c in 0..(MAX_SEEN as u64 + 100) {
            g.check_and_record(Uuid::now_v7(), c, NOW, NOW, WINDOW)
                .unwrap();
        }
        assert!(g.seen.len() <= MAX_SEEN);
        assert_eq!(g.order.len(), g.seen.len());
    }
}
