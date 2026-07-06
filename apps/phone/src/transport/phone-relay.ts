/**
 * The real phone-side {@link Transport}: the v3 stateless relay's live
 * `/attach` rendezvous (see `relay-attach.ts`), mirroring
 * relay/shared/protocol.ts and the daemon's crates/relay-client. There is no
 * buffered mailbox any more: the relay only bridges two live sockets, so this
 * phone is never persistently connected. It attaches to check for or send
 * something, and disconnects once idle.
 *
 * The APNs push doorbell (`src/lib/push.ts`) is the primary wake: a push
 * receipt or tap calls {@link PhoneRelay.wake}, which attaches so the daemon's
 * `deliver` can land. While the app is foregrounded, a ~30s backstop
 * (`BACKSTOP_INTERVAL_MS`) plus one attach on every foreground transition
 * catches anything a missed push would have delivered. No idle socket, no
 * polling loop: every attach closes itself after `IDLE_CLOSE_MS` of no
 * traffic.
 */
import { AppState, type AppStateStatus } from "react-native";

import {
  type Envelope,
  envelopeFromWire,
  envelopeToWire,
  type EnvelopeWire,
} from "@/src/protocol";
import { type ConnectionRung } from "@/src/domain/types";
import { AttachSocket, attachUrlForMailbox } from "./relay-attach";
import { type Transport, type TransportStatus } from "./transport";

/** An attach with no traffic for this long closes itself. */
const IDLE_CLOSE_MS = 5_000;
/**
 * Foreground backstop cadence: how often to re-attach in case a push was
 * missed. Push is the primary wake, so this is a safety net, not the latency
 * budget.
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
  private readonly url: string;
  private socket: AttachSocket | null = null;
  private readonly listeners = new Set<EnvelopeListener>();
  private running = false;
  private connected = false;
  private lastSeenAt = 0;
  private idleTimer: ReturnType<typeof setTimeout> | null = null;
  private backstopTimer: ReturnType<typeof setInterval> | null = null;
  private appStateSub: { remove: () => void } | null = null;

  constructor(private readonly cfg: PhoneRelayConfig) {
    this.url = attachUrlForMailbox(cfg.base, cfg.mailbox);
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
    this.closeNow();
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
   * Attach (if not already) so anything the daemon is trying to deliver right
   * now lands. Used by the push doorbell (receipt or tap) and the foreground
   * backstop; a no-op before `start()` or after `stop()`.
   */
  async wake(): Promise<void> {
    if (!this.running) return;
    try {
      await this.ensureAttached();
    } catch {
      this.connected = false;
    }
  }

  /** Seal-agnostic: send the envelope's opaque JSON over a live attach. */
  async send(e: Envelope): Promise<void> {
    const socket = await this.ensureAttached();
    await socket.send(JSON.stringify(envelopeToWire(e)));
    this.touch();
  }

  private async ensureAttached(): Promise<AttachSocket> {
    if (!this.socket) {
      const socket = new AttachSocket(this.url);
      socket.on((e) => {
        if (e.kind === "open") {
          this.connected = true;
        } else if (e.kind === "deliver") {
          this.lastSeenAt = Date.now();
          this.touch();
          let env: Envelope;
          try {
            env = envelopeFromWire(JSON.parse(e.env) as EnvelopeWire);
          } catch {
            return; // one malformed delivery is dropped, not fatal
          }
          for (const l of this.listeners) l(env);
        } else if (e.kind === "close") {
          this.connected = false;
          if (this.socket === socket) this.socket = null;
        }
        // "peer" transitions (the daemon attaching/detaching) are informational
        // only; nothing here reacts to them.
      });
      this.socket = socket;
    }
    await this.socket.open();
    this.touch();
    return this.socket;
  }

  /**
   * Reset the idle-close timer: an attach with no traffic for
   * `IDLE_CLOSE_MS` closes itself, so nothing stays attached at rest.
   */
  private touch(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => this.closeNow(), IDLE_CLOSE_MS);
  }

  private closeNow(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = null;
    this.socket?.close();
    this.socket = null;
    this.connected = false;
  }
}
