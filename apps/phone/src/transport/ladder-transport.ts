/**
 * LadderTransport: the phone-side selector that mirrors the daemon's
 * `sigil_direct::FallbackTransport`. It composes the always-available blind
 * relay ({@link PhoneRelay}) with an OPTIONAL direct rung (LAN Bonjour, rung 1;
 * or an owned endpoint, rung 2) and prefers the direct rung when it is
 * connected, falling back to the relay cleanly otherwise.
 *
 * The transport is never the security layer: every request the phone receives on
 * EITHER rung is the same sealed, signed {@link Envelope} that the session
 * controller opens against the pinned daemon key with its replay guard, so a
 * rogue host that answers a LAN discovery cannot forge a request, and a duplicate
 * that arrives on both rungs is deduped by that same guard. This selector only
 * chooses the pipe.
 *
 * Downgrade-safety mirrors the daemon side exactly:
 *  - With no direct rung installed (the default), this IS the relay: `send`,
 *    `onEnvelope`, and `status` all delegate straight through, unchanged.
 *  - Inbound requests are delivered from BOTH rungs at once, so a request the
 *    daemon deposited on the relay is never missed just because a direct rung is
 *    present; the controller's replay guard drops the redundant copy.
 *  - A direct `send` that throws (link dropped) falls back to the relay so an
 *    approval in flight is completed, never lost.
 *
 * The concrete direct rung itself -- a raw-TCP {@link Transport} carrying the
 * framed envelope wire -- needs a native socket module and is specified in
 * `docs/design/direct-transport.md`; this selector works against any `Transport`
 * that fills that contract and is fully exercised today with in-memory doubles.
 */
import { type Envelope } from "@/src/protocol";
import { type Transport, type TransportStatus } from "./transport";

export interface LadderConfig {
  /** The always-available blind relay. Required; the floor of the ladder. */
  relay: Transport;
  /**
   * The direct rung (LAN/endpoint), when one is configured/available. `null`
   * (the default) makes the ladder behave exactly like the relay alone.
   */
  direct?: Transport | null;
  /**
   * Also send the phone's response over the relay as insurance, even when the
   * direct rung accepted it. Off by default (the point of a direct rung is to
   * skip the relay); turn on only when the direct link's liveness is not
   * otherwise monitored. Harmless when on: a redundant relay copy the daemon
   * already answered simply expires unread.
   */
  mirrorSend?: boolean;
}

type EnvelopeListener = (e: Envelope) => void;

export class LadderTransport implements Transport {
  private readonly relay: Transport;
  private direct: Transport | null;
  private readonly mirrorSend: boolean;
  private readonly listeners = new Set<EnvelopeListener>();
  /** Unsubscribe handles for the fan-in from the underlying rungs. */
  private unsubs: Array<() => void> = [];
  private running = false;

  constructor(cfg: LadderConfig) {
    this.relay = cfg.relay;
    this.direct = cfg.direct ?? null;
    this.mirrorSend = cfg.mirrorSend ?? false;
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    // Listen on BOTH rungs so a request on either reaches the sheet; the
    // controller's replay guard dedupes a request that arrives on both.
    this.unsubs.push(this.relay.onEnvelope((e) => this.fanOut(e)));
    if (this.direct) this.unsubs.push(this.direct.onEnvelope((e) => this.fanOut(e)));
    await this.relay.start();
    if (this.direct) await this.direct.start();
  }

  stop(): void {
    this.running = false;
    for (const u of this.unsubs) u();
    this.unsubs = [];
    this.listeners.clear();
    this.relay.stop();
    this.direct?.stop();
  }

  /**
   * Attach or replace the direct rung at runtime (e.g. after Bonjour discovery
   * resolves a daemon on the LAN). Passing `null` retires the direct rung and
   * reverts to relay-only. Only takes effect on the next {@link start}.
   */
  setDirect(direct: Transport | null): void {
    this.direct = direct;
  }

  status(): TransportStatus {
    // Report the direct rung when it is genuinely connected; otherwise the
    // relay's status is the truth of the ladder.
    if (this.direct) {
      const d = this.direct.status();
      if (d.connected) return d;
    }
    return this.relay.status();
  }

  onEnvelope(cb: EnvelopeListener): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  async send(e: Envelope): Promise<void> {
    if (this.direct && this.direct.status().connected) {
      try {
        await this.direct.send(e);
        if (this.mirrorSend) {
          // Best-effort insurance; a relay error is not fatal here.
          try {
            await this.relay.send(e);
          } catch {
            /* the direct send already carried the response */
          }
        }
        return;
      } catch {
        // The direct link failed mid-send: fall back to the relay so the
        // response is not lost with the connection.
      }
    }
    await this.relay.send(e);
  }

  private fanOut(e: Envelope): void {
    for (const l of this.listeners) l(e);
  }
}
