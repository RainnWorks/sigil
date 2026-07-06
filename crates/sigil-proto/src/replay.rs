//! Replay protection for the envelope layer.
//!
//! A [`ReplayGuard`] tracks one pairing in one direction. Three independent
//! gates must all pass before an authentic envelope is accepted:
//!
//! 1. **Freshness** — the sender timestamp must be within `window_ms` of now,
//!    in either direction, so a captured envelope cannot be held and replayed
//!    later and a wildly skewed clock is rejected rather than trusted.
//! 2. **Single use** — the uuidv7 request id must not have been seen before.
//! 3. **Monotonic counter** — the per-pairing counter must strictly advance.
//!
//! The counter is the durable guarantee: it rejects any envelope whose counter
//! does not exceed the last accepted one, so an evicted-from-memory request id
//! can never be replayed. The request-id set is bounded defence in depth that
//! also names an exact-duplicate delivery precisely. Signature verification
//! happens in [`crate::envelope::Envelope::open`] *before* this guard runs, so
//! state here is only ever mutated for envelopes that are already authentic.

use std::collections::{HashSet, VecDeque};

use uuid::Uuid;

/// Upper bound on remembered request ids. Old ids fall out of the set once it
/// is full; the monotonic counter keeps their replay impossible after that.
const MAX_SEEN: usize = 4096;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ReplayError {
    /// The request id has already been accepted on this pairing.
    #[error("request id already seen")]
    DuplicateRequest,
    /// The counter did not strictly advance past the last accepted value.
    #[error("counter regression: got {got}, last accepted {last}")]
    CounterRegression { got: u64, last: u64 },
    /// The sender timestamp is outside the accepted window around now.
    #[error("timestamp {ts} outside {window_ms}ms window around {now}")]
    TimestampOutOfWindow { ts: u64, now: u64, window_ms: u64 },
}

/// Per-pairing, per-direction replay state. The caller holds one guard per
/// pairing (typically a map keyed by `pairing_id`).
#[derive(Debug, Default)]
pub struct ReplayGuard {
    last_counter: Option<u64>,
    seen: HashSet<Uuid>,
    order: VecDeque<Uuid>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all three gates and, only if every one passes, record the request id
    /// and advance the counter. On any error no state changes, so a rejected
    /// envelope never poisons a later legitimate one.
    pub fn check_and_record(
        &mut self,
        request_id: Uuid,
        counter: u64,
        ts: u64,
        now: u64,
        window_ms: u64,
    ) -> Result<(), ReplayError> {
        if now.abs_diff(ts) > window_ms {
            return Err(ReplayError::TimestampOutOfWindow { ts, now, window_ms });
        }

        if self.seen.contains(&request_id) {
            return Err(ReplayError::DuplicateRequest);
        }

        if let Some(last) = self.last_counter {
            if counter <= last {
                return Err(ReplayError::CounterRegression { got: counter, last });
            }
        }

        self.record(request_id, counter);
        Ok(())
    }

    fn record(&mut self, request_id: Uuid, counter: u64) {
        if self.seen.insert(request_id) {
            self.order.push_back(request_id);
            if self.order.len() > MAX_SEEN {
                if let Some(evicted) = self.order.pop_front() {
                    self.seen.remove(&evicted);
                }
            }
        }
        self.last_counter = Some(counter);
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
    fn counter_must_strictly_advance() {
        let mut g = fresh();
        g.check_and_record(Uuid::now_v7(), 5, NOW, NOW, WINDOW)
            .unwrap();
        assert_eq!(
            g.check_and_record(Uuid::now_v7(), 5, NOW, NOW, WINDOW),
            Err(ReplayError::CounterRegression { got: 5, last: 5 })
        );
        assert_eq!(
            g.check_and_record(Uuid::now_v7(), 3, NOW, NOW, WINDOW),
            Err(ReplayError::CounterRegression { got: 3, last: 5 })
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
        g.check_and_record(Uuid::now_v7(), 5, NOW, NOW, WINDOW)
            .unwrap();
        // A stale envelope is rejected and must not touch the counter.
        let _ = g.check_and_record(Uuid::now_v7(), 6, NOW - WINDOW - 1, NOW, WINDOW);
        // Counter 6 is still valid afterwards.
        assert_eq!(
            g.check_and_record(Uuid::now_v7(), 6, NOW, NOW, WINDOW),
            Ok(())
        );
    }

    #[test]
    fn eviction_keeps_memory_bounded() {
        let mut g = fresh();
        for c in 1..=(MAX_SEEN as u64 + 100) {
            g.check_and_record(Uuid::now_v7(), c, NOW, NOW, WINDOW)
                .unwrap();
        }
        assert!(g.seen.len() <= MAX_SEEN);
        assert_eq!(g.order.len(), g.seen.len());
    }
}
