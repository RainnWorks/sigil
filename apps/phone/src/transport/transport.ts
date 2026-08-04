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
import { type ConnectionRung, type RelayOrigin } from "@/src/domain/types";

export interface TransportStatus {
  rung: ConnectionRung;
  connected: boolean;
  machine: string;
  lastSeenAt: number;
}

/**
 * An inbound sealed envelope, plus the transport's own unverified note about
 * where it came from.
 *
 * The two arguments are separate on purpose, and the second is optional so a
 * rung that has no such note (LAN/direct: no relay in the path) and a listener
 * that does not care both stay correct. `relayOrigin` is NEVER part of the envelope:
 * the envelope is signed and sealed by the daemon, this is hearsay from the
 * carrier, and the type system should keep anyone from confusing the two.
 */
export type EnvelopeListener = (e: Envelope, relayOrigin?: RelayOrigin) => void;

export interface Transport {
  start(): Promise<void>;
  stop(): void;
  status(): TransportStatus;
  /** Subscribe to inbound sealed envelopes (requests from the daemon). */
  onEnvelope(cb: EnvelopeListener): () => void;
  /** Send a sealed envelope (our response) toward the daemon. */
  send(e: Envelope): Promise<void>;
}
