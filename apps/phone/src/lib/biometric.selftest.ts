/**
 * A guard on the one flag that decides whether invariant #4 holds.
 *
 * This exists because the failure it pins already happened once and was invisible
 * for as long as it took a reviewer to read the line: `disableDeviceFallback`
 * shipped as `false` under a comment saying the app never falls through to a
 * passcode. The polarity is the trap. `false` is not "no fallback"; it is the
 * library default and it ENABLES iOS's "Use Passcode" button after failed
 * biometry. On the plain gate approve path, which is every `op` rule on this
 * user's machine, that check is the only authorization there is, so the phone was
 * approving gated commands for anyone holding it and knowing its passcode.
 *
 * A comment could not catch that, because the wrong comment was already there.
 *
 * `biometric.ts` itself imports a native module and cannot be loaded outside a
 * device build, which is why the policy lives in its own dependency-free module
 * and this asserts on the value rather than grepping the source.
 *
 * Run: `bun run src/lib/biometric.selftest.ts`.
 */
import { BIOMETRIC_ONLY } from "./biometric-policy";

let failures = 0;
function eq<T>(a: T, b: T, label: string): void {
  if (a === b) {
    console.log(`  ok    ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label} (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`);
  }
}

function main(): void {
  console.log("biometric policy (invariant #4: approve requires hardware-gated biometrics)");
  {
    // The assertion. `true` means no device passcode fallback. If this ever reads
    // false again, the plain gate approve path accepts a passcode as an approval.
    eq(
      BIOMETRIC_ONLY.disableDeviceFallback,
      true,
      "device passcode fallback is disabled on every gate",
    );

    // One policy, no parameters: there must be no weak variant to reach for. If
    // a later change makes the policy a function or adds an options argument,
    // this fails and the change gets to justify itself.
    eq(typeof BIOMETRIC_ONLY, "object", "the policy is a fixed value, not a builder");
    eq(
      Object.keys(BIOMETRIC_ONLY).sort().join(","),
      "cancelLabel,disableDeviceFallback",
      "the policy carries no other knobs",
    );
  }

  console.log(
    failures === 0 ? "\nbiometric self-test: all green" : `\nbiometric self-test: ${failures} FAILED`,
  );
  if (failures > 0) process.exit(1);
}

main();
