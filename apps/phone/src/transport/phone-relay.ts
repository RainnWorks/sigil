/**
 * The real phone-side {@link Transport}: sealed envelopes over the blind
 * relay's v4 HTTP contract (`relay-http.ts`), mirroring crates/sigil-relay-client.
 * There is no persistent connection: the phone drains
 * `GET /mailbox/{id}/to-phone` on demand and posts to
 * `POST /mailbox/{id}/to-daemon` to send. Push sending is the relay's job now
 * (it holds the publisher's APNs cert); this phone only ever registers its
 * token with the daemon (`src/lib/push.ts`), unaffected by this transport.
 *
 * The APNs push doorbell is the primary wake: a push receipt or tap calls
 * {@link PhoneRelay.wake}, which drains `to-phone` once. The ~30s backstop is
 * strictly foreground-only (armed on becoming active, disarmed on backgrounding)
 * so backgrounded steady state is APNs wakeups ONLY, never a poll. No idle
 * connection, no tight polling loop.
 *
 * `to-phone` is now a long-poll (`relay-http.ts`): an empty mailbox holds the
 * GET open server-side for ~25s before returning, so one `wake()` call can
 * itself take that long. `wake()` collapses concurrent callers (push, tap,
 * backstop tick, foreground transition) onto the same in-flight drain rather
 * than firing overlapping GETs.
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
  /**
   * Called with each drain result: true when the relay answered, false when a
   * drain failed. Transport liveness only, for the UI's link dot; it says
   * nothing about the Mac on the far side.
   */
  onStatus?: (connected: boolean) => void;
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
  private inFlight: Promise<void> | null = null;

  constructor(private readonly cfg: PhoneRelayConfig) {
    this.mailbox = new RelayMailbox(cfg.base, cfg.mailbox);
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    this.appStateSub = AppState.addEventListener("change", (state: AppStateStatus) => {
      if (state === "active") {
        void this.wake();
        this.armBackstop();
      } else {
        // Backgrounded: no poll at all. APNs is the only wake until we resume.
        this.disarmBackstop();
      }
    });
    // Arm now iff we start foregrounded; a background start stays poll-free.
    if (AppState.currentState === "active") this.armBackstop();
  }

  stop(): void {
    this.running = false;
    this.listeners.clear();
    this.disarmBackstop();
    this.appStateSub?.remove();
    this.appStateSub = null;
  }

  /** Start the foreground backstop tick if it is not already running. */
  private armBackstop(): void {
    if (this.backstopTimer) return;
    this.backstopTimer = setInterval(() => void this.wake(), BACKSTOP_INTERVAL_MS);
  }

  /** Stop the backstop tick (backgrounding or teardown). */
  private disarmBackstop(): void {
    if (this.backstopTimer) clearInterval(this.backstopTimer);
    this.backstopTimer = null;
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
   * Since one drain can now itself hold for ~25-30s (the relay's long-poll),
   * a wake that arrives while another is already in flight just joins it
   * instead of firing a second overlapping GET.
   */
  async wake(): Promise<void> {
    if (!this.running) return;
    if (this.inFlight) return this.inFlight;
    const attempt = (async () => {
      try {
        await this.drainOnce();
      } catch {
        // A transient relay error just means the next backstop tick (or the
        // next push) tries again.
        this.connected = false;
        this.cfg.onStatus?.(false);
      }
    })();
    this.inFlight = attempt;
    try {
      await attempt;
    } finally {
      if (this.inFlight === attempt) this.inFlight = null;
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
    this.cfg.onStatus?.(true);
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
