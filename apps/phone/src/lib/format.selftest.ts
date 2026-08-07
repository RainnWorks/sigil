/**
 * Unit checks for the words the leasable approval sheet puts in front of the
 * human: {@link coverageLabel} (the daemon's description of how wide the window
 * is) and {@link commandWord} (the actor the deny control offers to block). Both
 * are copy on the one screen that authorizes a release, so the degenerate shapes
 * are pinned here rather than on device.
 *
 * House style matches src/protocol/self-test.ts and the transport selftests: a
 * plain `bun run` script with an `ok()` harness (no `bun:test`, so tsc stays
 * clean and no new dep). Run: `bun run src/lib/format.selftest.ts`.
 */
import { COVERS_MAX_CHARS } from "../protocol/requests";
import { commandWord, coverageLabel, durationWindow } from "./format";

let failures = 0;
function eq<T>(a: T, b: T, label: string): void {
  if (a === b) {
    console.log(`  ok    ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label} (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`);
  }
}

/**
 * A test label safe to print. JSON.stringify escapes control characters but not
 * U+202E, so echoing a bidi vector verbatim would reorder the runner's own
 * output: the same trick the vector plays on the approval sheet.
 */
function visible(s: string): string {
  return JSON.stringify(s).replace(/[\p{Cf}\p{Mn}]/gu, (c) =>
    `\\u${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}`,
  );
}

function main(): void {
  console.log("coverageLabel (the leasable caption's breadth clause)");
  // The nine shapes the daemon actually renders, passed through untouched: the
  // phone states the rule in the daemon's words and adds none of its own.
  for (const shape of [
    "op",
    "op read",
    'op with --account "rowmhq.1password.eu"',
    "op with --vault",
    'op containing "prod"',
    'op read with --vault, containing "prod"',
    "any command with the subcommand read",
    "op read with 5 match conditions",
    "op matching a pattern",
  ]) {
    eq(coverageLabel(shape), shape, `verbatim: ${shape}`);
  }
  // Nothing to state: the caller shows no coverage clause rather than inventing
  // one. `undefined` is an older daemon; "" is the omitted-when-empty case.
  eq(coverageLabel(undefined), null, "absent");
  eq(coverageLabel(""), null, "empty");
  eq(coverageLabel("   "), null, "whitespace only");
  // The daemon guarantees collapsed, control-free, bounded text. These pin what
  // happens if that guarantee is ever violated: a clipped caption, never a
  // broken sheet and never a caption that escapes its line.
  eq(coverageLabel("  op\n\tread   with\r\n--vault  "), "op read with --vault", "flattened");
  eq(coverageLabel("op\u2028read"), "op read", "line separator flattened");
  const long = "x".repeat(200);
  const clipped = coverageLabel(long);
  eq(clipped === null ? -1 : Array.from(clipped).length, COVERS_MAX_CHARS, "over-long is clipped");
  eq(clipped?.endsWith("…"), true, "clip ends in a single ellipsis");
  // Code points, not UTF-16 units: an accented or emoji-width label clips at the
  // same place the daemon would have clipped it.
  const wide = "é".repeat(200);
  eq(
    Array.from(coverageLabel(wide) ?? "").length,
    COVERS_MAX_CHARS,
    "over-long is clipped by code point",
  );
  eq(coverageLabel("x".repeat(COVERS_MAX_CHARS)), "x".repeat(COVERS_MAX_CHARS), "exactly at bound");

  // Security review R4-F4. The label shares one line with the sentence that
  // states how wide the window is, so a character that reorders or hides glyphs
  // inside the label attacks the human's only defence. Both vectors are the
  // reviewer's, and both defeated the old sanitizer: neither is a control
  // character, and both fit well inside COVERS_MAX_CHARS, so neither the
  // control-character strip nor the length bound touched them.
  const RLO = "\u202E"; // RIGHT-TO-LEFT OVERRIDE: reverses everything after it
  const ZWSP = "\u200B"; // ZERO WIDTH SPACE: splits a word invisibly
  const ACUTE = "\u0301"; // COMBINING ACUTE ACCENT: piles up over the glyph
  eq(
    coverageLabel(`op with --account "${RLO}terces-on${ZWSP}"`),
    'op with --account "terces-on"',
    "bidi override and zero width space removed, reading order restored",
  );
  // Removed, not merely clipped: 40 marks is 47 code points, comfortably under
  // the bound, so a length check alone would have rendered every one of them.
  eq(coverageLabel(`op read${ACUTE.repeat(40)}`), "op read", "combining pile removed, not clipped");
  // Deleted rather than spaced. These are not separators, so spacing them would
  // split one word into two instead of putting it back together.
  eq(coverageLabel(`o${ZWSP}p read`), "op read", "zero width space does not split a word");
  eq(coverageLabel("op\u00ADread"), "opread", "soft hyphen removed");
  // The whole bidi family, not just the one vector: overrides, embeddings, the
  // pop, and the invisible marks.
  eq(
    coverageLabel(`op\u202A\u202B\u202C\u202D${RLO}\u200E\u200F read`),
    "op read",
    "every bidi control removed",
  );
  // The property that actually matters is about the RENDERED line, not the label
  // alone: no format character or combining mark may survive anywhere in the
  // sentence the human reads. Asserted as a property so it cannot drift into a
  // second copy of the sheet's wording (approval-sheet.tsx owns that string).
  const caption = (label: string): string =>
    `Covers ${label}: every command and secret that rule matches, from anywhere on this Mac.`;
  for (const vector of [
    `op with --account "${RLO}terces-on${ZWSP}"`,
    `op read${ACUTE.repeat(40)}`,
    `${RLO}op read`,
  ]) {
    const rendered = caption(coverageLabel(vector) ?? "");
    eq(
      /[\p{Cf}\p{Mn}]/u.test(rendered),
      false,
      `rendered caption cannot be reordered or buried: ${visible(vector)}`,
    );
  }

  console.log("commandWord (the deny control's actor)");
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
