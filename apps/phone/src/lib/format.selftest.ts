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
import {
  commandWord,
  coverageLabel,
  durationWindow,
  LABEL_ELLIPSIS,
  LABEL_REJECTED,
} from "./format";

/** The rejection marker, under the short name the assertions read with. */
const MARK = LABEL_REJECTED;

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
  // Code points, not UTF-16 units. The ellipsis is the one non-ASCII character
  // the allowlist admits, so it is what proves the cut is counted and made in
  // characters (an accented label can no longer reach the bound at all).
  eq(
    Array.from(coverageLabel(LABEL_ELLIPSIS.repeat(200)) ?? "").length,
    COVERS_MAX_CHARS,
    "over-long is clipped by code point",
  );
  // A trailing space is trimmed before the mark, so a clip never reads "abc …".
  const spaced = coverageLabel("x".repeat(COVERS_MAX_CHARS - 2) + " " + "y".repeat(20));
  eq(spaced, "x".repeat(COVERS_MAX_CHARS - 2) + LABEL_ELLIPSIS, "clip trims the trailing space");
  eq(coverageLabel("x".repeat(COVERS_MAX_CHARS)), "x".repeat(COVERS_MAX_CHARS), "exactly at bound");

  // Security review R4-F4 and its follow-up. The label shares one line with the
  // sentence stating how wide the window is, so a character that reorders or
  // hides glyphs inside the label attacks the human's only defence.
  //
  // The filter is an ALLOWLIST mirroring the daemon's `sanitize_label`, not a
  // Cc/Cf/Mn blocklist: a blocklist passed characters that are neither control
  // nor mark and still render as nothing, and it failed open on whatever a
  // future Unicode revision adds. Every case below is asserted against the
  // marker, so a silent deletion would fail just as loudly as a pass-through.
  const RLO = "\u202E"; // RIGHT-TO-LEFT OVERRIDE: reverses everything after it
  const ZWSP = "\u200B"; // ZERO WIDTH SPACE: splits a word invisibly
  const ACUTE = "\u0301"; // COMBINING ACUTE ACCENT (Mn): piles up over the glyph
  const ENCLOSING = "\u20DD"; // COMBINING ENCLOSING CIRCLE (Me): a blocklist on Mn misses it
  const FILLER = "\u3164"; // HANGUL FILLER: a LETTER that renders as nothing
  const BRAILLE = "\u2800"; // BRAILLE PATTERN BLANK: a SYMBOL that renders as nothing
  const TAG = "\u{E0041}"; // U+E0041, the tag block used to smuggle whole sentences

  // The reviewer's two original vectors.
  eq(
    coverageLabel(`op with --account "${RLO}terces-on${ZWSP}"`),
    `op with --account "${MARK}terces-on${MARK}"`,
    "bidi override and zero width space marked, reading order restored",
  );
  // Marked, not merely clipped: 40 marks is 47 code points, comfortably under
  // the bound, so a length check alone would have rendered every one of them.
  eq(coverageLabel(`op read${ACUTE.repeat(40)}`), `op read${MARK}`, "combining pile marked, not clipped");

  // What the Cc/Cf/Mn blocklist let through. None of these is a control
  // character or a combining mark, and all three render as nothing.
  eq(coverageLabel(`op${FILLER}read`), `op${MARK}read`, "hangul filler marked (a letter that renders as nothing)");
  eq(coverageLabel(`op${BRAILLE}read`), `op${MARK}read`, "braille blank marked (a symbol that renders as nothing)");
  eq(coverageLabel(`op read${ENCLOSING}`), `op read${MARK}`, "enclosing mark marked (Me, not Mn)");
  eq(coverageLabel(`op${TAG}read`), `op${MARK}read`, "tag block marked (astral, one code point)");

  // Marked rather than deleted. The human is told something was there and would
  // not render, instead of being shown a word that silently closed up.
  eq(coverageLabel(`o${ZWSP}p read`), `o${MARK}p read`, "zero width space is marked, not deleted");
  eq(coverageLabel("op\u00ADread"), `op${MARK}read`, "soft hyphen marked");

  // A run collapses to one marker, so a rejected pile cannot spend the bound
  // either: forty markers would deform the line as badly as the input did.
  eq(
    coverageLabel(`op\u202A\u202B\u202C\u202D${RLO}\u200E\u200F read`),
    `op${MARK} read`,
    "a run of bidi controls collapses to one marker",
  );
  eq(coverageLabel(RLO.repeat(500)), MARK, "a rejected pile costs one character, not the bound");

  // The accepted cost, pinned so it cannot regress silently: a legitimately
  // non-ASCII rule token does not survive. `sigil-config list` is the surface
  // that echoes a rule verbatim; this one states breadth.
  eq(coverageLabel("op with --vault Équipe"), `op with --vault ${MARK}quipe`, "non-ASCII rule token marked");

  // Idempotency. The daemon runs first and is authoritative, so re-filtering its
  // output must be a no-op: a marker it already emitted is re-emitted as itself
  // and never marked again, and an ordinary label is untouched.
  eq(coverageLabel(`op ${MARK} read`), `op ${MARK} read`, "an emitted marker is not re-marked");
  // The daemon's own marks are permitted content, not a run to collapse, so a
  // second pass preserves them exactly as it received them.
  eq(coverageLabel(`a${MARK}${MARK}b`), `a${MARK}${MARK}b`, "adjacent emitted markers are preserved");
  eq(
    coverageLabel(`op read${LABEL_ELLIPSIS}`),
    `op read${LABEL_ELLIPSIS}`,
    "an emitted ellipsis is not re-marked",
  );
  // The daemon pins this exact vector (request.rs). Mirrored here so the two
  // implementations are known to agree on a mixed rejected run, not just assumed
  // to: the braille blank and both tag characters are one run, so one marker.
  eq(
    coverageLabel("op\u{3164}read\u{2800}\u{E0041}\u{E0042}"),
    `op${MARK}read${MARK}`,
    "daemon vector: filler, braille blank and tag block",
  );
  eq(coverageLabel("op?read"), "op?read", "a literal '?' is ordinary ASCII, not a marker");
  // A lone surrogate is the one input class the daemon cannot hold (Rust strings
  // are well-formed), so it cannot be covered by comparing the two against the
  // same corpus. It has to be marked here rather than reach the sheet.
  eq(coverageLabel("op\uD800read"), `op${MARK}read`, "lone high surrogate marked");
  eq(coverageLabel("op\uDFFFread"), `op${MARK}read`, "lone low surrogate marked");
  for (const vector of [
    `op with --account "${RLO}terces-on${ZWSP}"`,
    `op read${ACUTE.repeat(40)}`,
    `op${FILLER}read${BRAILLE}${TAG}`,
    "op with --vault \"Shared Eng\"",
    "x".repeat(200),
  ]) {
    const once = coverageLabel(vector) ?? "";
    eq(coverageLabel(once), once, `idempotent: ${visible(vector)}`);
  }

  // The property that actually matters is about the RENDERED line, not the label
  // alone: nothing outside the permitted set may survive anywhere in the sentence
  // the human reads. Asserted as a property so it cannot drift into a second copy
  // of the sheet's wording (approval-sheet.tsx owns that string).
  const caption = (label: string): string =>
    `Covers ${label}: every command and secret that rule matches, from anywhere on this Mac.`;
  for (const vector of [
    `op with --account "${RLO}terces-on${ZWSP}"`,
    `op read${ACUTE.repeat(40)}`,
    `${RLO}op read`,
    `op${FILLER}${BRAILLE}${ENCLOSING}${TAG}read`,
  ]) {
    const rendered = caption(coverageLabel(vector) ?? "");
    const stray = Array.from(rendered).filter(
      (c) => !/[\x21-\x7E]/.test(c) && c !== " " && c !== LABEL_ELLIPSIS && c !== MARK,
    );
    eq(stray.length, 0, `rendered caption holds the allowlist: ${visible(vector)}`);
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
