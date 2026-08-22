/**
 * The authentication policy every gate in this app uses, in a module of its own
 * so it can be asserted headlessly (`biometric.ts` imports a native module and
 * cannot be loaded outside a device build).
 *
 * There is exactly ONE policy and it takes no parameters, deliberately. A
 * per-call option would be a footgun pointed at the approve path: the weak
 * variant would exist, and the strong one would be one forgotten argument away.
 * Making the two impossible to diverge is worth more than the flexibility.
 */

/**
 * Biometry only. No device passcode, on any gate, ever.
 *
 * **`disableDeviceFallback: true` is the security property, and its polarity is
 * the trap.** `false` does not mean "no fallback"; it is the value that ENABLES
 * iOS's "Use Passcode" button after failed biometry, and it is the library's
 * default. This module shipped with `false` under a comment claiming the
 * opposite, which meant anyone holding the phone and its passcode could approve
 * a gated command having never passed biometry (security review R8-F1).
 *
 * That is invariant #4, "approve requires hardware-gated biometrics", and it
 * broke on the path that matters most rather than an edge case: a plain gate
 * approve has the biometric gate as its ONLY authorization, and every `op` rule
 * on this user's machine is a plain gate. The threshold path was unaffected,
 * since there the Secure Enclave key-agreement is its own gate and this flag
 * never reaches it.
 *
 * **The cost, which is real and is accepted.** With no passcode fallback,
 * repeated biometric failure locks biometry out at the OS level and there is no
 * in-app recovery: approvals stop until the human unlocks the device by other
 * means. A lockout surfaces as a plain failure, which is correct, because every
 * way of not passing biometry has to mean the same thing. That is the fail-closed
 * direction and it is the one this product is supposed to fail in. Devices with
 * no biometric hardware, or none enrolled, are rejected before this policy is
 * ever reached, so they are unaffected by it.
 *
 * **It applies to the lease list too**, not only to release. Listing is
 * disclosure rather than release, so a weaker gate there is arguable, and the
 * argument fails: the only thing gating the list still buys is denying an
 * enumeration of live auto-approve windows to someone holding an unlocked phone
 * who cannot pass biometry, and someone who unlocked the phone plausibly knows
 * its passcode. A passcode fallback would hand back the exact capability the
 * gate exists to deny.
 */
export const BIOMETRIC_ONLY = {
  /** True = no "Use Passcode" fallback. See this module's note on the polarity. */
  disableDeviceFallback: true,
  cancelLabel: "Cancel",
} as const;
