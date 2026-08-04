/**
 * Unit checks for {@link commandWord}, the argv[0] derivation behind the
 * leasable sheet's coverage caption. The caption names a command to the human,
 * so a wrong or empty word is a copy bug on the one screen that authorizes a
 * release: pin the degenerate argv shapes here rather than on device.
 *
 * House style matches src/protocol/self-test.ts and the transport selftests: a
 * plain `bun run` script with an `ok()` harness (no `bun:test`, so tsc stays
 * clean and no new dep). Run: `bun run src/lib/format.selftest.ts`.
 */
import { commandWord, durationWindow } from "./format";

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
  console.log("commandWord");
  // A plain word: the common shim case, passed through untouched.
  eq(commandWord(["op", "read", "op://Engineering/.env/graphql-api"]), "op", "plain word");
  eq(commandWord(["ssh", "git@github.com"]), "ssh", "plain word, ssh");
  // An absolute path: only the binary is shown, never the install location.
  eq(commandWord(["/usr/local/bin/op", "read"]), "op", "absolute path");
  eq(commandWord(["/opt/homebrew/bin/gcloud"]), "gcloud", "absolute path, no args");
  eq(commandWord(["./scripts/deploy"]), "deploy", "relative path");
  // Trailing slash: the last non-empty segment, never an empty word.
  eq(commandWord(["op/"]), "op", "trailing slash");
  eq(commandWord(["/usr/local/bin/op/"]), "op", "absolute path, trailing slash");
  // Blank / absent argv: null, so the caller drops the word instead of naming
  // a command that is not there.
  eq(commandWord([]), null, "empty argv");
  eq(commandWord([""]), null, "empty argv[0]");
  eq(commandWord(["   "]), null, "whitespace argv[0]");
  eq(commandWord(["/"]), null, "bare slash");
  eq(commandWord(["///"]), null, "slashes only");
  // Surrounding whitespace is trimmed; inner spacing is left alone (it is the
  // word as invoked, and the caption is display only).
  eq(commandWord(["  op  ", "read"]), "op", "trimmed");

  console.log("durationWindow (the primary capsule's window)");
  eq(durationWindow(45), "45 seconds", "sub-minute");
  eq(durationWindow(1), "1 second", "singular second");
  eq(durationWindow(900), "15 minutes", "quarter hour");
  eq(durationWindow(3600), "1 hour", "singular hour");

  console.log(failures === 0 ? "\nformat self-test: all green" : `\nformat self-test: ${failures} FAILED`);
  if (failures > 0) process.exit(1);
}

main();
