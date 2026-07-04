/**
 * A mock transport that plays the daemon's part locally, through the real crypto
 * path. It seals canned ApprovalRequests to the phone and, when the phone sends
 * a sealed response back, opens and verifies it exactly as the daemon would.
 * This makes the approval sheet fully exercisable in a dev build and proves the
 * remote loop end to end without a relay.
 *
 * Requires a resolved libsodium binding (react-native-libsodium on device); if
 * crypto is unavailable, seed the store directly instead (see demo.ts).
 */
import {
  type ApprovalRequest,
  type DeviceIdentity,
  type Envelope,
  type PeerIdentity,
  type Sodium,
  open,
  peerIdentity,
  ReplayGuard,
  seal,
  signingSecretKey,
} from "@/src/protocol";
import { type ApprovalResponse } from "@/src/protocol";
import { type Transport, type TransportStatus } from "./transport";

export interface MockTransportConfig {
  sodium: Sodium;
  /** The mock daemon's identity (seals requests, opens responses). */
  daemon: DeviceIdentity;
  /** The phone's pinned public identity (recipient of requests). */
  phonePub: PeerIdentity;
  /** Shared routing mailbox id. */
  pairingId: Uint8Array;
}

type EnvelopeListener = (e: Envelope) => void;

export class MockTransport implements Transport {
  private readonly listeners = new Set<EnvelopeListener>();
  private outboundCounter = 0;
  private inboundGuard = new ReplayGuard();
  private started = false;
  private readonly daemonPub: PeerIdentity;

  constructor(private readonly cfg: MockTransportConfig) {
    this.daemonPub = peerIdentity(cfg.sodium, cfg.daemon);
  }

  async start(): Promise<void> {
    this.started = true;
  }

  stop(): void {
    this.started = false;
    this.listeners.clear();
  }

  status(): TransportStatus {
    return {
      rung: "lan",
      connected: this.started,
      machine: "studio.local",
      lastSeenAt: Date.now(),
    };
  }

  onEnvelope(cb: EnvelopeListener): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  /** The phone's sealed response. Opened and verified as the daemon would. */
  async send(e: Envelope): Promise<void> {
    const response = open<ApprovalResponse>(this.cfg.sodium, e, {
      sender: this.cfg.phonePub,
      recipientAgreementSecret: this.cfg.daemon.agreementSecret,
      guard: this.inboundGuard,
    });
    // In the real daemon this unwraps the DEK and spawns op; here we just prove
    // the response was authentic and well-formed.
    // eslint-disable-next-line no-console
    console.log(`[mock daemon] response ${response.decision} for ${response.requestId}`);
  }

  /** Seal a canned request and deliver it to the phone (the daemon's job). */
  emitRequest(request: ApprovalRequest): void {
    if (!this.started) return;
    const envelope = seal(this.cfg.sodium, request, {
      pairingId: this.cfg.pairingId,
      counter: ++this.outboundCounter,
      senderSigningSecret: signingSecretKey(this.cfg.sodium, this.cfg.daemon),
      recipient: this.cfg.phonePub,
    });
    for (const l of this.listeners) l(envelope);
  }
}
