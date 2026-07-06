/**
 * The v3 stateless relay's live rendezvous: one WebSocket at
 * `/attach/{mailbox_id_hex}`, mirroring relay/shared/protocol.ts's FRAME
 * shapes byte-for-byte (and crates/relay-client's `wire` module on the daemon
 * side). The relay holds nothing at rest: a mailbox is at most two live
 * sockets, and a `send` from one is forwarded to the other live, or answered
 * `nopeer` if it isn't there yet. There is no positive ack for a delivered
 * send, only the negative `nopeer` / `err`.
 *
 * "Mailbox" is just a routing key here, not a distinct wire: the steady-state
 * approval mailbox ({@link PhoneRelay}) and the pairing ceremony's bootstrap
 * rendezvous mailbox (`src/session/pairing-flow.ts`) both attach through
 * {@link AttachSocket} to this same endpoint, keyed by different ids.
 */
import { toHex } from "@/src/protocol";
import { normalizeRelayBase } from "./relay-http";

/** Build the `ws(s)://.../attach/{hex}` URL from an `http(s)`/`ws(s)` relay base. */
export function attachUrl(base: string, mailboxHex: string): string {
  const httpBase = normalizeRelayBase(base);
  const wsBase = httpBase.startsWith("https://")
    ? "wss://" + httpBase.slice("https://".length)
    : httpBase.startsWith("http://")
      ? "ws://" + httpBase.slice("http://".length)
      : httpBase; // already ws(s)://
  return `${wsBase}/attach/${mailboxHex}`;
}

export function attachUrlForMailbox(base: string, mailbox: Uint8Array): string {
  return attachUrl(base, toHex(mailbox));
}

type ParsedFrame =
  | { t: "deliver"; env: string }
  | { t: "nopeer" }
  | { t: "peer"; state: "attached" | "detached" }
  | { t: "pong" }
  | { t: "err"; code: number };

function parseFrame(raw: string): ParsedFrame | null {
  let o: unknown;
  try {
    o = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!o || typeof o !== "object") return null;
  const rec = o as Record<string, unknown>;
  switch (rec.t) {
    case "deliver":
      return typeof rec.env === "string" ? { t: "deliver", env: rec.env } : null;
    case "nopeer":
      return { t: "nopeer" };
    case "peer":
      return rec.state === "attached" || rec.state === "detached"
        ? { t: "peer", state: rec.state }
        : null;
    case "pong":
      return { t: "pong" };
    case "err":
      return typeof rec.code === "number" ? { t: "err", code: rec.code } : null;
    default:
      return null;
  }
}

/** How many times `send` retries a `nopeer` before giving up. */
const MAX_SEND_ATTEMPTS = 5;
/** Delay between `nopeer` retries. */
const SEND_RETRY_MS = 700;
/** How long `send` waits for a `nopeer`/`err` before treating the send as delivered. */
const ACK_WINDOW_MS = 1200;

export type AttachEvent =
  | { kind: "open" }
  | { kind: "deliver"; env: string }
  | { kind: "peer"; state: "attached" | "detached" }
  | { kind: "close" };

/**
 * One raw `/attach` connection. This wraps connect/close and frame
 * parsing only; callers decide when to open, when to close, and how long to
 * stay attached - the transient, "no idle socket" policy lives in the caller
 * (see {@link PhoneRelay} for the steady-state policy, `pairing-flow.ts` for
 * the pairing ceremony's single bounded-lifetime attach).
 */
export class AttachSocket {
  private ws: WebSocket | null = null;
  private opening: Promise<void> | null = null;
  private readonly listeners = new Set<(e: AttachEvent) => void>();
  private pendingSend: { resolve: () => void; reject: (e: Error) => void; env: string; attempt: number } | null =
    null;

  constructor(private readonly url: string) {}

  on(cb: (e: AttachEvent) => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  get isOpen(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  /** Open the connection (idempotent): resolves once it is ready to send. */
  async open(): Promise<void> {
    if (this.isOpen) return;
    if (this.opening) return this.opening;
    this.opening = new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(this.url);
      let settled = false;
      ws.onopen = () => {
        settled = true;
        this.ws = ws;
        this.emit({ kind: "open" });
        resolve();
      };
      ws.onmessage = (e) => this.handleMessage(String(e.data));
      ws.onerror = () => {
        if (!settled) {
          settled = true;
          reject(new Error("attach socket failed to open"));
        }
      };
      ws.onclose = () => {
        this.ws = null;
        this.opening = null;
        this.pendingSend?.reject(new Error("attach socket closed"));
        this.pendingSend = null;
        this.emit({ kind: "close" });
        if (!settled) {
          settled = true;
          reject(new Error("attach socket closed before opening"));
        }
      };
    });
    return this.opening;
  }

  close(): void {
    this.ws?.close(1000, "done");
    this.ws = null;
    this.opening = null;
  }

  /**
   * Send one opaque payload, retrying briefly on `nopeer` (the other party
   * isn't attached yet - see the class doc). The v3 wire has no positive ack,
   * so this resolves optimistically if neither `nopeer` nor `err` arrives
   * within a short window, and rejects on a relay-side `err` or on exhausting
   * the `nopeer` retries.
   */
  async send(env: string): Promise<void> {
    await this.open();
    const ws = this.ws;
    if (!ws) throw new Error("attach socket not open");
    return new Promise<void>((resolve, reject) => {
      this.pendingSend = { resolve, reject, env, attempt: 0 };
      ws.send(JSON.stringify({ t: "send", env }));
      setTimeout(() => {
        if (this.pendingSend?.resolve === resolve) {
          this.pendingSend = null;
          resolve();
        }
      }, ACK_WINDOW_MS);
    });
  }

  /**
   * Wait for the next `deliver` frame, or `null` on timeout. Used by the
   * pairing ceremony's one-shot wait for the daemon's sealed DEK (message 3);
   * the steady-state {@link PhoneRelay} instead reacts to every `deliver` via
   * `on()`, since it may see several over one attach.
   */
  async waitForDeliver(timeoutMs: number): Promise<string | null> {
    await this.open();
    return new Promise<string | null>((resolve) => {
      const timer = setTimeout(() => {
        unsub();
        resolve(null);
      }, timeoutMs);
      const unsub = this.on((e) => {
        if (e.kind === "deliver") {
          clearTimeout(timer);
          unsub();
          resolve(e.env);
        }
      });
    });
  }

  private emit(e: AttachEvent): void {
    for (const l of this.listeners) l(e);
  }

  private handleMessage(raw: string): void {
    const frame = parseFrame(raw);
    if (!frame) return;
    if (frame.t === "deliver") {
      this.emit({ kind: "deliver", env: frame.env });
      return;
    }
    if (frame.t === "peer") {
      this.emit({ kind: "peer", state: frame.state });
      return;
    }
    if (frame.t === "nopeer") {
      const p = this.pendingSend;
      if (!p) return;
      if (p.attempt >= MAX_SEND_ATTEMPTS) {
        this.pendingSend = null;
        p.reject(new Error("no peer attached"));
        return;
      }
      p.attempt += 1;
      setTimeout(() => {
        if (this.pendingSend === p && this.ws) {
          this.ws.send(JSON.stringify({ t: "send", env: p.env }));
        }
      }, SEND_RETRY_MS);
      return;
    }
    if (frame.t === "err") {
      const p = this.pendingSend;
      this.pendingSend = null;
      p?.reject(new Error(`relay rejected send: ${frame.code}`));
    }
    // "pong" needs no reaction; nothing sends "ping" from this side yet.
  }
}
