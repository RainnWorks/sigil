/**
 * Replay protection, mirroring crates/proto/src/replay.rs. One guard tracks one
 * pairing in one direction. Three gates must all pass before an authentic
 * envelope is accepted: freshness (timestamp within the window), single use
 * (unseen request id), and a strictly-advancing per-pairing counter. On any
 * failure no state changes, so a rejected envelope never poisons a later
 * legitimate one. Signature verification runs before this guard, so state is
 * only ever mutated for already-authentic envelopes.
 */

/** Maximum allowed clock skew, milliseconds. Matches proto REPLAY_WINDOW_MS. */
export const REPLAY_WINDOW_MS = 90_000;

/** Bound on remembered request ids; the counter keeps replay impossible after eviction. */
const MAX_SEEN = 4096;

export type ReplayError =
  | { kind: "duplicateRequest" }
  | { kind: "counterRegression"; got: number; last: number }
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
      case "counterRegression":
        return `counter regression: got ${d.got}, last accepted ${d.last}`;
      case "timestampOutOfWindow":
        return `timestamp ${d.ts} outside ${d.windowMs}ms window around ${d.now}`;
    }
  }
}

export class ReplayGuard {
  private lastCounter: number | null = null;
  private readonly seen = new Set<string>();
  private readonly order: string[] = [];

  /**
   * Run all three gates and, only if every one passes, record the request id
   * and advance the counter. Throws `ReplayRejected` otherwise, mutating nothing.
   */
  checkAndRecord(
    requestId: string,
    counter: number,
    ts: number,
    now: number,
    windowMs: number = REPLAY_WINDOW_MS,
  ): void {
    if (Math.abs(now - ts) > windowMs) {
      throw new ReplayRejected({ kind: "timestampOutOfWindow", ts, now, windowMs });
    }
    if (this.seen.has(requestId)) {
      throw new ReplayRejected({ kind: "duplicateRequest" });
    }
    if (this.lastCounter !== null && counter <= this.lastCounter) {
      throw new ReplayRejected({
        kind: "counterRegression",
        got: counter,
        last: this.lastCounter,
      });
    }
    this.record(requestId, counter);
  }

  private record(requestId: string, counter: number): void {
    if (!this.seen.has(requestId)) {
      this.seen.add(requestId);
      this.order.push(requestId);
      if (this.order.length > MAX_SEEN) {
        const evicted = this.order.shift();
        if (evicted !== undefined) this.seen.delete(evicted);
      }
    }
    this.lastCounter = counter;
  }
}
