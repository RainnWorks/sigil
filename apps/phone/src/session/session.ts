/**
 * The session glue between transport and store. It owns the phone's identity and
 * the pinned daemon identity, opens every inbound envelope into an
 * ApprovalRequest (verifying signature, replay, and decryption via the protocol
 * layer), and seals outbound ApprovalResponses. The request-read path and the
 * approval path stay separate: displaying metadata needs only the open above;
 * authorizing release needs the Face ID gate before `respond` is ever called.
 */
import {
  agreementSecretKey,
  type ApprovalRequest,
  type ApprovalResponse,
  classifyToPhone,
  type Decision,
  type DeliveryReceiptMessage,
  type DeviceIdentity,
  type Envelope,
  type LeaseListReplyMessage,
  type LeaseRevokeReplyMessage,
  type PeerIdentity,
  type Sodium,
  open,
  ReplayGuard,
  seal,
  signingSecretKey,
} from "@/src/protocol";
import { store } from "@/src/state/store";
import { type RelayOrigin } from "@/src/domain/types";
import { type Transport } from "@/src/transport/transport";

export interface SessionConfig {
  sodium: Sodium;
  phone: DeviceIdentity;
  daemonPub: PeerIdentity;
  pairingId: Uint8Array;
  transport: Transport;
  /**
   * Where a verified answer to a lease-control question goes. Handed in rather
   * than written straight to the store, because the caller (the session
   * controller) is what asked the question and owns the reply timers that decide
   * when silence becomes "cannot confirm". Absent => lease replies are dropped,
   * which is the correct behavior for a session nobody is asking through.
   */
  onLeaseReply?: (reply: LeaseControlReply) => void;
}

/** A verified lease-control answer, already demuxed and shape-checked. */
export type LeaseControlReply =
  | { kind: "leaseList"; reply: LeaseListReplyMessage }
  | { kind: "leaseRevoke"; reply: LeaseRevokeReplyMessage };

export class SigilSession {
  private readonly inboundGuard = new ReplayGuard();
  // Seed the outbound counter from the wall clock, not 0. A new SigilSession is
  // created on every arm / foreground / reconnect, and the daemon's replay guard
  // rejects any counter <= the highest it has already seen this run, so a
  // reset-to-0 counter made the daemon drop our approval responses as stale
  // replays (the command hangs, "approved but never unlocks"). The clock is a
  // monotonic source shared with the daemon's own seed (crates/sigil/src/
  // remote.rs), so a fresh session always resumes above the daemon's last-seen,
  // with no persisted state. Mirror of the daemon-side fix.
  private outboundCounter = Date.now();
  private unsubscribe: (() => void) | null = null;

  constructor(private readonly cfg: SessionConfig) {}

  async start(): Promise<void> {
    await this.cfg.transport.start();
    this.unsubscribe = this.cfg.transport.onEnvelope((e, relayOrigin) =>
      this.handleInbound(e, relayOrigin),
    );
  }

  stop(): void {
    this.unsubscribe?.();
    this.unsubscribe = null;
    this.cfg.transport.stop();
  }

  /**
   * `relayOrigin` is the carrier's unverified claim about where this envelope was
   * deposited from. It plays no part in opening, verifying, or demuxing below:
   * the crypto decides everything, and the hint is only handed to the store for
   * the sheet to show. A forged or missing one changes nothing here.
   */
  private handleInbound(envelope: Envelope, relayOrigin?: RelayOrigin): void {
    let payload: unknown;
    try {
      // Open once to a raw payload; the crypto (signature, replay, decryption) is
      // verified by `open` regardless of which ToPhone shape this turns out to be.
      // Both an ApprovalRequest and a ResolutionBroadcast ride the same sealed,
      // signed, single-use envelope on the daemon->phone counter, so a hostile
      // relay can neither forge nor replay either.
      payload = open<unknown>(this.cfg.sodium, envelope, {
        sender: this.cfg.daemonPub,
        recipientAgreementSecret: agreementSecretKey(this.cfg.sodium, this.cfg.phone),
        guard: this.inboundGuard,
      });
    } catch {
      // A push only wakes the app; an envelope that fails to verify is dropped
      // silently. Fail closed.
      return;
    }
    // Demux by the `type` tag, mirroring the daemon's ToDaemon demux.
    const msg = classifyToPhone(payload);
    if (!msg) return; // malformed: drop it (fail closed)
    if (msg.kind === "leaseList" || msg.kind === "leaseRevoke") {
      // An answer to a lease-control question. It rides the same sealed, signed,
      // single-use envelope as everything else on this counter, so a hostile relay
      // can neither forge one (to claim a window closed, or that none are open) nor
      // replay an old one. It releases nothing and gates nothing: it is a report,
      // and suppressing it can only ever leave the phone saying it does not know.
      this.cfg.onLeaseReply?.(msg);
      return;
    }
    if (msg.kind === "resolution") {
      // #36: another paired device resolved this ring-all request (or it expired /
      // was withdrawn). Dismiss our copy. Zero-knowledge: we learn only that it is
      // over, never who resolved it or how. Never a decision, never a release, and
      // never acknowledged with a delivery receipt.
      store.dismissResolved(msg.resolution.requestId, msg.resolution.status);
      return;
    }
    const request = msg.request;
    store.receive(request, relayOrigin);
    // Task #41: acknowledge receipt so the daemon can advance the requester's
    // UI Sent -> Delivered. Best-effort and non-blocking: a failed ack leaves
    // the daemon to fall back to "couldn't confirm"; it never gates display or
    // the decision path.
    void this.sendDelivered(request.requestId);
  }

  /**
   * Seal and send a {@link DeliveryReceiptMessage} for a just-opened request.
   * Fails soft: a lost ack only costs the requester the "Delivered" reflection
   * (the daemon shows "couldn't confirm"), never the approval itself.
   */
  private async sendDelivered(requestId: string): Promise<void> {
    try {
      await this.sealAndSend<DeliveryReceiptMessage>({ type: "delivered", requestId });
    } catch (e) {
      console.warn(`[receipt] delivery ack failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  /**
   * Seal and send a decision. The caller MUST have passed the Face ID gate for
   * an approval before invoking this; there is no unguarded approve path. The
   * optional `partial` is the phone's threshold `Z_F`, produced by the Secure
   * Enclave key-agreement; a plain gate approve carries none.
   */
  async respond(
    request: ApprovalRequest,
    decision: Decision,
    extras: Pick<ApprovalResponse, "partial" | "lease" | "block"> = {},
  ): Promise<void> {
    const response: ApprovalResponse = {
      requestId: request.requestId,
      decision,
      decidedAt: Date.now(),
      ...extras,
    };
    await this.sealAndSend(response);
  }

  /**
   * Seal and send an arbitrary tagged payload toward the daemon outside the
   * request/response flow (e.g. {@link PushRegisterMessage}). Shares the
   * outbound counter and pairing id with `respond`, so both ride the same
   * per-direction replay sequence.
   *
   * Returns the ENVELOPE's single-use uuidv7 request id. For a payload the
   * daemon answers, that id is the correlation handle: the daemon echoes it as
   * `inReplyTo`, and the caller matches the reply against the request it issued.
   * That application-layer match is load-bearing rather than decorative, because
   * the envelope guard's single-use id set lives in RAM and is empty again after
   * any restart (see `LeaseRevokeReplyMessage.inReplyTo`).
   */
  async sendToDaemon<T>(payload: T): Promise<string> {
    return this.sealAndSend(payload);
  }

  /** Seals, sends, and returns the envelope's single-use request id. */
  private async sealAndSend<T>(payload: T): Promise<string> {
    const envelope = seal(this.cfg.sodium, payload, {
      pairingId: this.cfg.pairingId,
      counter: ++this.outboundCounter,
      senderSigningSecret: signingSecretKey(this.cfg.sodium, this.cfg.phone),
      recipient: this.cfg.daemonPub,
    });
    await this.cfg.transport.send(envelope);
    return envelope.requestId;
  }
}
