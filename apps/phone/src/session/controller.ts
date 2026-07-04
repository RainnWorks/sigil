/**
 * The live session controller: the single place the app arms the real transport
 * and dispatches decisions over it. It ties together the keystore (the stored
 * pairing), the {@link PhoneRelay} transport, and the {@link LatchSession} crypto.
 *
 * Two tiers, kept apart exactly as the keystore stores them:
 *   - Arming is a read-path action: it loads the passcode-tier identity, starts
 *     polling, and opens/displays inbound requests. No biometric.
 *   - Approving is a release-path action: {@link liveApprove} reads the DEK behind
 *     Face ID (the `requireAuthentication` keystore item) and only then seals the
 *     response carrying `wrappedDek`. The biometric IS the key release; there is
 *     no path that seals an approve without it. Deny seals nothing sensitive and
 *     needs no biometric.
 *
 * When no pairing is stored (dev / demo) nothing is armed and the UI falls back
 * to its local-only store path with the mock transport.
 */
import {
  type ApprovalRequest,
  loadSodium,
  type Sodium,
  toBase64,
} from "@/src/protocol";
import { PhoneRelay } from "@/src/transport/phone-relay";
import { LatchSession } from "./session";
import { loadDek, loadPairing } from "./keystore";

interface Live {
  session: LatchSession;
  transport: PhoneRelay;
}

let live: Live | null = null;

export function isArmed(): boolean {
  return live !== null;
}

/**
 * Arm the real relay session from the stored pairing. Idempotent. Returns whether
 * a session is now running (false when this phone is unpaired, so the caller uses
 * the local/demo path). Any failure fails closed to no session.
 */
export async function armLiveSession(): Promise<boolean> {
  if (live) return true;
  const pairing = await loadPairing();
  if (!pairing) return false;
  let sodium: Sodium;
  try {
    sodium = await loadSodium();
  } catch {
    return false;
  }
  const transport = new PhoneRelay({
    base: pairing.relayBase,
    mailbox: pairing.mailbox,
  });
  const session = new LatchSession({
    sodium,
    phone: pairing.phone,
    daemonPub: pairing.daemonPub,
    pairingId: pairing.mailbox,
    transport,
  });
  await session.start();
  live = { session, transport };
  return true;
}

/** Tear the live session down (unpair, lockdown, or app teardown). */
export function disarmLiveSession(): void {
  live?.session.stop();
  live = null;
}

export type ApproveOutcome = "sent" | "refused" | "no-session" | "error";

/**
 * Approve `request` over the live transport. Reads the DEK behind Face ID and,
 * only if the gate passes, seals an `ApprovalResponse` carrying `wrappedDek`
 * (standard-base64 of the raw 32-byte DEK, confidential inside the envelope seal)
 * and sends it toward the daemon. Returns "refused" if the biometric did not
 * pass (nothing is sent), "no-session" when unarmed, "error" on transport failure.
 */
export async function liveApprove(request: ApprovalRequest): Promise<ApproveOutcome> {
  if (!live) return "no-session";
  const dek = await loadDek("Approve secret release");
  if (!dek) return "refused";
  try {
    await live.session.respond(request, "approved", { wrappedDek: toBase64(dek) });
    return "sent";
  } catch {
    return "error";
  } finally {
    dek.fill(0);
  }
}

export type DenyOutcome = "sent" | "no-session" | "error";

/**
 * Deny `request` over the live transport. Carries no DEK, so a denial can never
 * release a secret, and needs no biometric (deny is always frictionless).
 */
export async function liveDeny(request: ApprovalRequest): Promise<DenyOutcome> {
  if (!live) return "no-session";
  try {
    await live.session.respond(request, "denied");
    return "sent";
  } catch {
    return "error";
  }
}
