/**
 * The session glue between transport and store. It owns the phone's identity and
 * the pinned daemon identity, opens every inbound envelope into an
 * ApprovalRequest (verifying signature, replay, and decryption via the protocol
 * layer), and seals outbound ApprovalResponses. The request-read path and the
 * approval path stay separate: displaying metadata needs only the open above;
 * authorizing release needs the Face ID gate before `respond` is ever called.
 */
import {
  type ApprovalRequest,
  type ApprovalResponse,
  type Decision,
  type DeviceIdentity,
  type Envelope,
  type PeerIdentity,
  type Sodium,
  open,
  ReplayGuard,
  seal,
  signingSecretKey,
} from "@/src/protocol";
import { store } from "@/src/state/store";
import { type Transport } from "@/src/transport/transport";

export interface SessionConfig {
  sodium: Sodium;
  phone: DeviceIdentity;
  daemonPub: PeerIdentity;
  pairingId: Uint8Array;
  transport: Transport;
}

export class LatchSession {
  private readonly inboundGuard = new ReplayGuard();
  private outboundCounter = 0;
  private unsubscribe: (() => void) | null = null;

  constructor(private readonly cfg: SessionConfig) {}

  async start(): Promise<void> {
    await this.cfg.transport.start();
    this.unsubscribe = this.cfg.transport.onEnvelope((e) => this.handleInbound(e));
  }

  stop(): void {
    this.unsubscribe?.();
    this.unsubscribe = null;
    this.cfg.transport.stop();
  }

  private handleInbound(envelope: Envelope): void {
    let request: ApprovalRequest;
    try {
      request = open<ApprovalRequest>(this.cfg.sodium, envelope, {
        sender: this.cfg.daemonPub,
        recipientAgreementSecret: this.cfg.phone.agreementSecret,
        guard: this.inboundGuard,
      });
    } catch {
      // A push only wakes the app; an envelope that fails to verify is dropped
      // silently. Fail closed.
      return;
    }
    store.receive(request);
  }

  /**
   * Seal and send a decision. The caller MUST have passed the Face ID gate for
   * an approval before invoking this; there is no unguarded approve path.
   * `wrappedDek` would be produced by the enclave re-wrap on device.
   */
  async respond(
    request: ApprovalRequest,
    decision: Decision,
    extras: Pick<ApprovalResponse, "wrappedDek" | "lease" | "block"> = {},
  ): Promise<void> {
    const response: ApprovalResponse = {
      requestId: request.requestId,
      decision,
      decidedAt: Date.now(),
      ...extras,
    };
    const envelope = seal(this.cfg.sodium, response, {
      pairingId: this.cfg.pairingId,
      counter: ++this.outboundCounter,
      senderSigningSecret: signingSecretKey(this.cfg.sodium, this.cfg.phone),
      recipient: this.cfg.daemonPub,
    });
    await this.cfg.transport.send(envelope);
  }
}
