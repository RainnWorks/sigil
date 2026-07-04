/**
 * The pairing QR payload, mirroring crates/proto/src/pairing.rs. The Mac renders
 * this into a QR; the phone scans it, pins `daemon`, and opens a channel. The
 * JSON shape matches the Rust `serde_json` form (byte arrays as number arrays,
 * the one-time secret as a 32-number array) and is base64url-encoded without
 * padding, so a QR from a real daemon parses here unchanged.
 */
import { fromBase64Url, toBase64Url } from "./bytes";
import { type PeerIdentity } from "./identity";

export interface PairingPayload {
  /** The daemon's pinned public identity. */
  daemon: PeerIdentity;
  /** Ordered endpoints to try: lan://, https://ddns, relay mailbox, etc. */
  endpoints: string[];
  /** One-time pairing secret, consumed on first contact. 32 bytes. */
  secret: Uint8Array;
  /** Daemon wall clock at mint, unix ms; a stale QR is rejected. */
  createdAt: number;
}

interface PairingJson {
  daemon: { verifying: number[]; agreement: number[] };
  endpoints: string[];
  secret: number[];
  created_at: number;
}

export function pairingToQrString(p: PairingPayload): string {
  const json: PairingJson = {
    daemon: {
      verifying: Array.from(p.daemon.verifying),
      agreement: Array.from(p.daemon.agreement),
    },
    endpoints: p.endpoints,
    secret: Array.from(p.secret),
    created_at: p.createdAt,
  };
  return toBase64Url(new TextEncoder().encode(JSON.stringify(json)));
}

export class PairingParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PairingParseError";
  }
}

export function pairingFromQrString(s: string): PairingPayload {
  let json: PairingJson;
  try {
    json = JSON.parse(new TextDecoder().decode(fromBase64Url(s))) as PairingJson;
  } catch {
    throw new PairingParseError("pairing payload is not valid base64url JSON");
  }
  if (
    !json.daemon ||
    !Array.isArray(json.daemon.verifying) ||
    json.daemon.verifying.length !== 32 ||
    !Array.isArray(json.daemon.agreement) ||
    json.daemon.agreement.length !== 32 ||
    !Array.isArray(json.secret) ||
    json.secret.length !== 32
  ) {
    throw new PairingParseError("pairing payload has malformed key material");
  }
  return {
    daemon: {
      verifying: Uint8Array.from(json.daemon.verifying),
      agreement: Uint8Array.from(json.daemon.agreement),
    },
    endpoints: Array.isArray(json.endpoints) ? json.endpoints : [],
    secret: Uint8Array.from(json.secret),
    createdAt: json.created_at,
  };
}
