/**
 * The transport seam. Transport carries sealed envelopes and nothing else; it is
 * never the security layer (the envelope is). The real implementation walks the
 * ladder (LAN Bonjour, owned endpoint, blind relay) and the daemon accepts any
 * rung identically. Today only the mock impl exists; the relay lands later.
 *
 * STUBBED FOR LATER: the real LAN/endpoint/relay transports. This interface is
 * the contract they fill.
 */
import { type Envelope } from "@/src/protocol";
import { type ConnectionRung } from "@/src/domain/types";

export interface TransportStatus {
  rung: ConnectionRung;
  connected: boolean;
  machine: string;
  lastSeenAt: number;
}

export interface Transport {
  start(): Promise<void>;
  stop(): void;
  status(): TransportStatus;
  /** Subscribe to inbound sealed envelopes (requests from the daemon). */
  onEnvelope(cb: (e: Envelope) => void): () => void;
  /** Send a sealed envelope (our response) toward the daemon. */
  send(e: Envelope): Promise<void>;
}
