/**
 * The real phone-side {@link Transport}: sealed envelopes over the blind relay's
 * HTTPS contract, mirroring crates/relay-client/src/phone_http.rs.
 *
 * The phone has no inbound connection; it polls. A background loop drains
 * `GET /pending` (drain-on-read: the relay removes what it returns), decodes each
 * opaque string into an {@link Envelope}, and hands it to the subscribers.
 * `send` POSTs the envelope's JSON to `POST /submit`. The security layer is the
 * envelope, never the transport: this moves ciphertext only, exactly as the mock
 * does, so the same {@link LatchSession} rides either one unchanged.
 *
 * The APNs push doorbell (`src/lib/push.ts`) is the primary wake now; this loop
 * is a 30s backstop for whenever push is denied, delayed, or absent. A tapped
 * notification calls {@link PhoneRelay.pollNow} to drain immediately instead of
 * waiting out the backstop interval.
 */
import {
  type Envelope,
  envelopeFromWire,
  envelopeToWire,
  type EnvelopeWire,
} from "@/src/protocol";
import { type ConnectionRung } from "@/src/domain/types";
import { RelayMailbox, sleep } from "./relay-http";
import { type Transport, type TransportStatus } from "./transport";

/**
 * Delay between empty `/pending` polls. Push is the primary wake, so this is a
 * backstop cadence, not the latency budget: 30s trades a little worst-case
 * delay (when push is unavailable) for a lot less request volume.
 */
const POLL_INTERVAL_MS = 30_000;

export interface PhoneRelayConfig {
  /** Relay base URL (http(s) or ws(s); normalized internally). */
  base: string;
  /** The steady-state routing mailbox: `mailboxId(phonePub, daemonPub)`. */
  mailbox: Uint8Array;
  /** Machine label for the status readout (display only). */
  machine?: string;
  /** Override the empty-poll delay (tests use a short one). */
  pollIntervalMs?: number;
}

type EnvelopeListener = (e: Envelope) => void;

export class PhoneRelay implements Transport {
  private readonly mailbox: RelayMailbox;
  private readonly listeners = new Set<EnvelopeListener>();
  private readonly pollIntervalMs: number;
  private running = false;
  private loop: Promise<void> | null = null;
  private lastSeenAt = 0;
  private connected = false;

  constructor(private readonly cfg: PhoneRelayConfig) {
    this.mailbox = new RelayMailbox(cfg.base, cfg.mailbox);
    this.pollIntervalMs = cfg.pollIntervalMs ?? POLL_INTERVAL_MS;
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    this.loop = this.pollLoop();
  }

  stop(): void {
    this.running = false;
    this.listeners.clear();
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

  /** Seal-agnostic: POST the envelope's opaque JSON toward the daemon. */
  async send(e: Envelope): Promise<void> {
    const wire = JSON.stringify(envelopeToWire(e));
    await this.mailbox.submit(wire);
  }

  /**
   * Force one drain right now, outside the backstop cadence. Used to react to a
   * tapped push notification without waiting up to `pollIntervalMs`. A no-op
   * before `start()` or after `stop()`.
   */
  async pollNow(): Promise<void> {
    if (!this.running) return;
    try {
      await this.drainOnce();
    } catch {
      // Same fail-closed handling as the loop: a transient error just means
      // the next backstop tick (or the next tap) tries again.
      this.connected = false;
    }
  }

  /** Drain `/pending`, decode, and fan out. One malformed entry is dropped, not fatal. */
  private async drainOnce(): Promise<void> {
    const batch = await this.mailbox.pending();
    this.connected = true;
    if (batch.length > 0) this.lastSeenAt = Date.now();
    for (const s of batch) {
      let env: Envelope;
      try {
        env = envelopeFromWire(JSON.parse(s) as EnvelopeWire);
      } catch {
        // An undecodable pending entry is dropped; fail closed on that one.
        continue;
      }
      for (const l of this.listeners) l(env);
    }
  }

  private async pollLoop(): Promise<void> {
    while (this.running) {
      try {
        await this.drainOnce();
      } catch {
        // A transient relay error must not kill the loop; the daemon retries.
        this.connected = false;
      }
      if (!this.running) break;
      await sleep(this.pollIntervalMs);
    }
  }
}
