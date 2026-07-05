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
  fingerprintWords,
  fromBase64,
  loadSodium,
  peerIdentity,
  shapeEcdh,
  type Sodium,
  toBase64,
} from "@/src/protocol";
import { computePartial, isSecureEnclaveAvailable } from "@/modules/latch-se";
import { store } from "@/src/state/store";
import { PhoneRelay } from "@/src/transport/phone-relay";
import { LatchSession } from "./session";
import { clearPairing, loadDek, loadPairing, type StoredPairing } from "./keystore";

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
  // Reflect the real pairing into the store so the UI shows paired (not demo) and
  // stops routing into the pairing flow. This is the single point both boot-time
  // hydration and a just-completed ceremony pass through.
  store.reflectPairing({
    ownFingerprint: ownFingerprint(sodium, pairing),
    machine: relayHost(pairing.relayBase),
    seenAt: pairing.pairedAt,
  });
  return true;
}

/** This phone's own public-key fingerprint words, for the pairing/device UI. */
function ownFingerprint(sodium: Sodium, pairing: StoredPairing): string {
  const pub = peerIdentity(sodium, pairing.phone);
  return fingerprintWords(sodium, pub, pub).join(" ");
}

/** Host label for the connection line, derived from the relay base URL. */
function relayHost(relayBase: string): string {
  return relayBase.replace(/^https?:\/\//, "").replace(/\/.*$/, "") || "relay";
}

/** Tear the live session down (lockdown or app teardown). Keeps the stored pairing. */
export function disarmLiveSession(): void {
  live?.session.stop();
  live = null;
}

/**
 * Reset the pairing entirely: tear down the live session, erase the stored
 * identity + DEK from the keystore, and return the store to the unpaired empty
 * state so the app routes back into the pairing flow. Used by "Reset pairing".
 */
export async function unpair(): Promise<void> {
  disarmLiveSession();
  await clearPairing();
  store.clearPairingState();
}

export type ApproveOutcome = "sent" | "refused" | "mismatch" | "no-session" | "error";

/**
 * Approve `request` over the live transport. Reads the DEK behind Face ID and,
 * only if the gate passes, seals an `ApprovalResponse` carrying `wrappedDek`
 * (standard-base64 of the raw 32-byte DEK, confidential inside the envelope seal)
 * and sends it toward the daemon. Returns "refused" if the biometric did not
 * pass (nothing is sent), "no-session" when unarmed, "error" on transport failure.
 */
export async function liveApprove(request: ApprovalRequest): Promise<ApproveOutcome> {
  if (!live) return "no-session";
  // v2 accounts carry a threshold challenge: the release factor is the Secure
  // Enclave key-agreement (Z_F), not a stored DEK. Selected by the presence of
  // the challenge, never by a wire flag; a v2 approve never emits a DEK.
  if (request.threshold) return liveApproveThreshold(request);

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

/**
 * The v2 approve: derive the phone's partial `Z_F = x(f·E)` in the Secure Enclave
 * and seal it as a `ThresholdPartial` (never a DEK). The enclave key-agreement is
 * itself the Face ID gate, so there is no separate biometric and no unguarded
 * path. R5: the biometric prompt's reason names the account being unlocked
 * (`threshold.label`), binding the human's consent to the account the challenge
 * claims. Fails closed to "refused" on a denied/failed biometric or an off-curve
 * `E`, and "error" if this device has no Secure Enclave (a v2 account cannot be
 * approved without it).
 */
async function liveApproveThreshold(request: ApprovalRequest): Promise<ApproveOutcome> {
  if (!live) return "no-session";
  const ch = request.threshold;
  if (!ch) return "error";
  if (!isSecureEnclaveAvailable()) return "error";

  // R5: bind consent to the account shown. The sheet displays `ch.label` as the
  // account being unlocked; refuse (fail closed, before the SE op) if that
  // account shares nothing with the secret refs in the readout, so a mis-issued
  // challenge cannot show the human account A while cryptographically unlocking
  // account B.
  if (!consentConsistent(ch.label, ch.accountId, request.secrets)) return "mismatch";

  let zfB64: string;
  try {
    const sodium = await loadSodium();
    // The enclave key-agreement is the Face ID gate; the reason names the account
    // (R5). It returns the RAW 32-byte X-coordinate; the ECDH-output shaping
    // (raw-x identity vs x963-sha256) is applied here in the vector-locked TS
    // combiner core, byte-exact with the Mac's threshold.rs, so the phone never
    // depends on CryptoKit's KDF parameters (NV-7).
    const rawXB64 = await computePartial(ch.seKeyId, ch.ephemeralPub, `Approve ${ch.label}`);
    const zf = shapeEcdh(sodium, fromBase64(rawXB64), ch.ecdhAlgo, fromBase64(ch.ephemeralPub));
    zfB64 = toBase64(zf);
  } catch {
    // Denied/failed Face ID, an off-curve E (R2), or a missing key: no partial.
    return "refused";
  }
  try {
    await live.session.respond(request, "approved", {
      partial: { accountId: ch.accountId, zf: zfB64 },
    });
    return "sent";
  } catch {
    return "error";
  }
}

/**
 * R5 consent cross-check: does the account named in the challenge agree with the
 * secret refs shown in the readout? A residual-#7 Mac attacker can only decouple
 * "what the human sees" from "what gets unlocked" if the account label and the
 * displayed secrets can drift apart, so we refuse when the challenge's account
 * shares no meaningful token with any secret ref. Consistent (or nothing to
 * cross-check, i.e. no secrets) => true.
 */
function consentConsistent(
  label: string,
  accountId: string,
  secrets: ApprovalRequest["secrets"],
): boolean {
  if (secrets.length === 0) return true;
  const account = new Set([...tokens(label), ...tokens(accountId)]);
  if (account.size === 0) return false;
  for (const ref of secrets) {
    for (const t of [ref.label, ref.provider, ...ref.segments].flatMap(tokens)) {
      if (account.has(t)) return true;
    }
  }
  return false;
}

/** Lowercase word tokens (>=3 chars) for the fuzzy consent cross-check. */
function tokens(s: string): string[] {
  return s
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length >= 3);
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
