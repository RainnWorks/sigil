/**
 * The biometric gate. Approving REQUIRES a fresh biometric and nothing else will
 * do: no device passcode, on any gate, ever (see {@link BIOMETRIC_ONLY}, which
 * carries the reasoning and the accepted cost). Deny requires nothing and never
 * calls in here.
 *
 * What this gate IS depends on the path, and the difference matters:
 *
 *   - A PLAIN GATE approve has this check as its ONLY authorization. Nothing
 *     cryptographic is unlocked; passing here is what authorizes the decision.
 *     Every `op` rule on this user's machine is a plain gate, so this is the
 *     primary path, not an edge case.
 *   - A THRESHOLD approve does not rely on this at all. There the Secure Enclave
 *     key-agreement is its own gate, enforced by the key's access control rather
 *     than by any flag passed here.
 *
 * NEEDS VERIFICATION, and it is the second half of security review R8-F1. The
 * enclave key is created with `[.privateKeyUsage, .biometryCurrentSet]`
 * (modules/sigil-se/ios/SigilSeModule.swift), and by Apple's documentation that
 * combination admits biometry only and not the passcode. That has never been
 * exercised on hardware here, so it is what the source says rather than
 * something observed: until someone confirms it on a device, no string, comment
 * or document may claim the threshold path is passcode-proof. Do not delete this
 * note because the code above it looks correct; the code looking correct is
 * exactly what it is recording.
 */
import * as LocalAuthentication from "expo-local-authentication";

import { BIOMETRIC_ONLY } from "./biometric-policy";

export type GateResult =
  | { ok: true }
  | { ok: false; reason: "unavailable" | "cancelled" | "failed" };

/**
 * Prompt for biometry before an approve registers. Returns whether it passed.
 *
 * `prompt` is per-caller on purpose and the callers deliberately differ: a human
 * trained to clear an identical prompt for a harmless read is being conditioned
 * to clear the one that releases a secret. The POLICY, by contrast, is fixed and
 * takes no argument, so no caller can weaken it.
 *
 * Fails closed on everything that is not a pass. A biometric lockout arrives as
 * `"failed"` alongside an ordinary mismatch, which is correct: they differ in how
 * the human recovers, never in whether the gate opened.
 */
export async function faceGate(prompt = "Approve secret release"): Promise<GateResult> {
  const hasHardware = await LocalAuthentication.hasHardwareAsync();
  const enrolled = await LocalAuthentication.isEnrolledAsync();
  if (!hasHardware || !enrolled) return { ok: false, reason: "unavailable" };

  const res = await LocalAuthentication.authenticateAsync({
    promptMessage: prompt,
    ...BIOMETRIC_ONLY,
  });

  if (res.success) return { ok: true };
  const cancelled =
    "error" in res && (res.error === "user_cancel" || res.error === "system_cancel");
  return { ok: false, reason: cancelled ? "cancelled" : "failed" };
}
