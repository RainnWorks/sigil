/**
 * The real phone-side {@link Transport}: sealed envelopes over the blind
 * relay's v4 HTTP contract (`relay-http.ts`), mirroring crates/relay-client.
 * There is no persistent connection: the phone drains
 * `GET /mailbox/{id}/to-phone` on demand and posts to
 * `POST /mailbox/{id}/to-daemon` to send. Push sending is the relay's job now
 * (it holds the publisher's APNs cert); this phone only ever registers its
 * token with the daemon (`src/lib/push.ts`), unaffected by this transport.
 *
 * The APNs push doorbell is the primary wake: a push receipt or tap calls
 * {@link PhoneRelay.wake}, which drains `to-phone` once. While the app is
 * foregrounded, a ~30s backstop (AppState-gated, re-armed on every foreground
 * transition) catches anything a missed push would have delivered. No idle
 * connection, no tight polling loop.
 */
import { AppState, type AppStateStatus } from "react-native";

import {
  type Envelope,
  envelopeFromWire,
  envelopeToWire,
  type EnvelopeWire,
} from "@/src/protocol";
import { type ConnectionRung } from "@/src/domain/types";
import { RelayMailbox } from "./relay-http";
import { type Transport, type TransportStatus } from "./transport";

/**
 * Foreground backstop cadence: how often to drain `to-phone` in case a push
 * was missed. Push is the primary wake, so this is a safety net, not the
 * latency budget.
 */
const BACKSTOP_INTERVAL_MS = 30_000;

export interface PhoneRelayConfig {
  /** Relay base URL (http(s) or ws(s); normalized internally). */
  base: string;
  /** The steady-state routing mailbox: `mailboxId(phonePub, daemonPub)`. */
  mailbox: Uint8Array;
  /** Machine label for the status readout (display only). */
  machine?: string;
}

type EnvelopeListener = (e: Envelope) => void;

export class PhoneRelay implements Transport {
  private readonly mailbox: RelayMailbox;
  private readonly listeners = new Set<EnvelopeListener>();
  private running = false;
  private connected = false;
  private lastSeenAt = 0;
  private backstopTimer: ReturnType<typeof setInterval> | null = null;
  private appStateSub: { remove: () => void } | null = null;

  constructor(private readonly cfg: PhoneRelayConfig) {
    this.mailbox = new RelayMailbox(cfg.base, cfg.mailbox);
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    this.backstopTimer = setInterval(() => void this.wake(), BACKSTOP_INTERVAL_MS);
    this.appStateSub = AppState.addEventListener("change", (state: AppStateStatus) => {
      if (state === "active") void this.wake();
    });
  }

  stop(): void {
    this.running = false;
    this.listeners.clear();
    if (this.backstopTimer) clearInterval(this.backstopTimer);
    this.backstopTimer = null;
    this.appStateSub?.remove();
    this.appStateSub = null;
  }

  status(): TransportStatus {
    return {
      rung: "relay" as ConnectionRung,
      connected: this.connected,
      machine: this.cfg.machine ?? "",
      lastSeenAt: this.lastSeenAt,
    };
  }

  onEnvelope(cb: EnvelopeListener): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  /**
   * Drain `to-phone` right now. Used by the push doorbell (receipt or tap)
   * and the foreground backstop; a no-op before `start()` or after `stop()`.
   */
  async wake(): Promise<void> {
    if (!this.running) return;
    try {
      await this.drainOnce();
    } catch {
      // A transient relay error just means the next backstop tick (or the
      // next push) tries again.
      this.connected = false;
    }
  }

  /** Seal-agnostic: POST the envelope's opaque JSON toward the daemon. */
  async send(e: Envelope): Promise<void> {
    await this.mailbox.send(JSON.stringify(envelopeToWire(e)));
  }

  /** Drain `to-phone`, decode, and fan out. One malformed entry is dropped, not fatal. */
  private async drainOnce(): Promise<void> {
    const batch = await this.mailbox.drain();
    this.connected = true;
    if (batch.length > 0) this.lastSeenAt = Date.now();
    for (const s of batch) {
      let env: Envelope;
      try {
        env = envelopeFromWire(JSON.parse(s) as EnvelopeWire);
      } catch {
        // An undecodable entry is dropped; fail closed on that one.
        continue;
      }
      for (const l of this.listeners) l(env);
    }
  }
}
