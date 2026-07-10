/**
 * Replay protection, mirroring crates/sigil-proto/src/replay.rs. One guard tracks one
 * pairing in one direction. Two gates must both pass before an authentic
 * envelope is accepted: freshness (timestamp within the window) and single use
 * (unseen request id). On any failure no state changes, so a rejected envelope
 * never poisons a later legitimate one. Signature verification runs before this
 * guard, so state is only ever mutated for already-authentic envelopes.
 *
 * The per-pairing counter still rides the wire (it is part of the signed
 * canonical bytes, so the envelope format is unchanged) but is no longer a gate:
 * a monotonic in-memory counter reset to 0 on either side after a daemon restart
 * or a phone session recreation, which made a counter gate drop a genuine,
 * user-approved envelope as a false replay. Signature + freshness + single-use
 * are complete without it.
 *
 * The request-id set is bounded by AGE: an id is remembered only while its
 * timestamp is still inside the freshness window, because a replay of an
 * aged-out id fails freshness regardless, so forgetting it is safe. MAX_SEEN is
 * a hard memory backstop for a pathological burst of distinct authentic ids
 * inside one window.
 */

/** Maximum allowed clock skew, milliseconds. Matches proto REPLAY_WINDOW_MS. */
export const REPLAY_WINDOW_MS = 90_000;

/**
 * Hard upper bound on remembered request ids: a memory backstop, not a
 * correctness gate. Age-based eviction normally keeps the set far smaller.
 */
const MAX_SEEN = 4096;

export type ReplayError =
  | { kind: "duplicateRequest" }
  | { kind: "timestampOutOfWindow"; ts: number; now: number; windowMs: number };

export class ReplayRejected extends Error {
  constructor(readonly detail: ReplayError) {
    super(ReplayRejected.describe(detail));
    this.name = "ReplayRejected";
  }
  static describe(d: ReplayError): string {
    switch (d.kind) {
      case "duplicateRequest":
        return "request id already seen";
      case "timestampOutOfWindow":
        return `timestamp ${d.ts} outside ${d.windowMs}ms window around ${d.now}`;
    }
  }
}

export class ReplayGuard {
  private readonly seen = new Set<string>();
  /** `{ id, ts }` in insertion order, oldest first; see record/evictAged. */
  private readonly order: Array<{ id: string; ts: number }> = [];

  /**
   * Run both gates and, only if each passes, record the request id. Throws
   * `ReplayRejected` otherwise, mutating nothing.
   *
   * `counter` is retained in the signature for wire/format compatibility (it is
   * part of the signed canonical bytes) but is no longer gated: see the module
   * docs for why the monotonic-counter gate was retired.
   */
  checkAndRecord(
    requestId: string,
    counter: number,
    ts: number,
    now: number,
    windowMs: number = REPLAY_WINDOW_MS,
  ): void {
    void counter;
    if (Math.abs(now - ts) > windowMs) {
      throw new ReplayRejected({ kind: "timestampOutOfWindow", ts, now, windowMs });
    }
    this.evictAged(now, windowMs);
    if (this.seen.has(requestId)) {
      throw new ReplayRejected({ kind: "duplicateRequest" });
    }
    this.record(requestId, ts);
  }

  /**
   * Drop remembered ids whose timestamp has aged past the freshness window.
   * Only front entries provably past the window are removed; a future-dated
   * (still in-window) entry stops the sweep. An out-of-order older entry not yet
   * at the front lingers harmlessly until it reaches the front or MAX_SEEN.
   */
  private evictAged(now: number, windowMs: number): void {
    while (this.order.length > 0) {
      const front = this.order[0]!;
      if (now - front.ts > windowMs) {
        this.order.shift();
        this.seen.delete(front.id);
      } else {
        break;
      }
    }
  }

  private record(requestId: string, ts: number): void {
    if (!this.seen.has(requestId)) {
      this.seen.add(requestId);
      this.order.push({ id: requestId, ts });
      while (this.order.length > MAX_SEEN) {
        const evicted = this.order.shift();
        if (evicted !== undefined) this.seen.delete(evicted.id);
      }
    }
  }
}
