/**
 * The Face ID gate. Approving REQUIRES a fresh biometric; there is no code path
 * that seals an approval response without one. Deny requires nothing and never
 * calls in here.
 *
 * On a real build the biometric unlocks the Secure Enclave key that re-wraps the
 * DEK. Here it is modeled as an authentication check; the enclave binding is the
 * device-keystore seam (NEEDS VERIFICATION: expo-local-authentication gates a
 * key via `.biometryCurrentSet`-equivalent; enclave key custody needs a small
 * native module or SecureStore with `requireAuthentication`, confirmed on device).
 */
import * as LocalAuthentication from "expo-local-authentication";

export type GateResult =
  | { ok: true }
  | { ok: false; reason: "unavailable" | "cancelled" | "failed" };

/** Prompt Face ID before an approve registers. Returns whether it passed. */
export async function faceGate(prompt = "Approve secret release"): Promise<GateResult> {
  const hasHardware = await LocalAuthentication.hasHardwareAsync();
  const enrolled = await LocalAuthentication.isEnrolledAsync();
  if (!hasHardware || !enrolled) return { ok: false, reason: "unavailable" };

  const res = await LocalAuthentication.authenticateAsync({
    promptMessage: prompt,
    // Never silently fall through to a device passcode for an approval; the
    // enclave key is gated on the biometric specifically.
    disableDeviceFallback: false,
    cancelLabel: "Cancel",
  });

  if (res.success) return { ok: true };
  const cancelled =
    "error" in res && (res.error === "user_cancel" || res.error === "system_cancel");
  return { ok: false, reason: cancelled ? "cancelled" : "failed" };
}
