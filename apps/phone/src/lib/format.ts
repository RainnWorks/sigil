/**
 * Formatting for the content voice: relative time, mono clocks, and the
 * secret-reference readout the well needs. Everything here works off a
 * SecretRef's display-only `segments` / `label`; it never parses the opaque
 * `reference`, which only the owning provider understands.
 */
import { COVERS_MAX_CHARS, type SecretRef, type SshChallenge } from "@/src/protocol";

/** "just now", "12s ago", "4m ago", "2d ago": the brief's terse register. */
export function relativeTime(fromMs: number, nowMs: number = Date.now()): string {
  const s = Math.max(0, Math.round((nowMs - fromMs) / 1000));
  if (s < 3) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  return `${d}d ago`;
}

/** A remaining duration as m:ss for the gauge center and numeric countdown. */
export function clock(msRemaining: number): string {
  const total = Math.max(0, Math.ceil(msRemaining / 1000));
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

export interface RefSegment {
  text: string;
  /** the item name is the brightest segment. */
  emphasis: "bright" | "normal" | "sep";
}

/**
 * Segment a SecretRef for the well: its `segments`, most-general first, joined
 * by dim separators, with the item (the segment equal to `label`) brightest. If
 * no segment matches the label, the last (the most specific, meaningful
 * segment) is brightened instead.
 */
export function segmentSecretRef(ref: SecretRef): RefSegment[] {
  const out: RefSegment[] = [];
  ref.segments.forEach((seg, i) => {
    if (i > 0) out.push({ text: " / ", emphasis: "sep" });
    out.push({ text: seg, emphasis: seg === ref.label ? "bright" : "normal" });
  });
  const last = out[out.length - 1];
  if (last && !ref.segments.includes(ref.label)) {
    last.emphasis = "bright";
  }
  return out;
}

/**
 * A one-line label for a secret ref, e.g. "Engineering/.env › graphql-api":
 * the leading segments joined by "/", then the most-specific segment after "›".
 * Falls back to the label when there are no segments.
 */
export function secretRefLabel(ref: SecretRef): string {
  const leaf = ref.segments[ref.segments.length - 1];
  if (leaf === undefined) return ref.label;
  const head = ref.segments.slice(0, -1).join("/");
  return head ? `${head} › ${leaf}` : leaf;
}

/**
 * A lease-window duration in words for the approve-with-a-window control, e.g.
 * "45 seconds", "15 minutes", "1 hour". Rounds to the coarsest natural unit;
 * display only.
 */
export function durationWindow(totalSecs: number): string {
  const s = Math.max(0, Math.round(totalSecs));
  if (s < 60) return `${s} second${s === 1 ? "" : "s"}`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} minute${m === 1 ? "" : "s"}`;
  const h = Math.round(m / 60);
  return `${h} hour${h === 1 ? "" : "s"}`;
}

/**
 * The one non-ASCII character the allowlist admits, because it is what a clipped
 * label ends in. Mirrors `LABEL_ELLIPSIS` in crates/sigil-proto.
 */
export const LABEL_ELLIPSIS = "…";

/**
 * What one run of rejected characters becomes, mirroring `LABEL_REJECTED` in
 * crates/sigil-proto.
 *
 * U+FFFD rather than "?", because the marker has to be unforgeable: "?" is
 * itself printable ASCII, so a rule written to contain one renders the same
 * glyph in the same position as a rejection, and the reader cannot tell "a
 * character was removed here" from "the rule really does contain a question
 * mark". U+FFFD cannot survive the filter as content, so that ambiguity does not
 * arise.
 *
 * It IS permitted, together with the ellipsis, and that is what makes the filter
 * exactly idempotent rather than idempotent by luck. Neither mark can be forged
 * into a label from outside, so permitting them lets nothing new through.
 */
export const LABEL_REJECTED = "�";

/**
 * Rust's `char::is_control` is general category Cc, and `char::is_whitespace` is
 * the Unicode White_Space property. Matched exactly, and NOT with JS `\s`: `\s`
 * also matches U+FEFF, which White_Space excludes, so it would turn a zero-width
 * no-break space into a word separator here and a rejection marker on the
 * daemon. The two surfaces must not disagree.
 */
const LABEL_SEPARATOR = /[\p{Cc}\p{White_Space}]/u;

/** Rust's `char::is_ascii_graphic`: U+0021..=U+007E. Space is not graphic; it
 *  reaches the output through the separator branch instead. */
const LABEL_GRAPHIC = /[\x21-\x7E]/;

/**
 * The daemon's `sanitize_label`, character for character (crates/sigil-proto,
 * `request.rs`). Permitted: printable ASCII, runs of whitespace collapsed to one
 * space, and exactly the two non-ASCII marks the daemon itself emits, the
 * ellipsis and the rejection marker. Everything else becomes one
 * {@link LABEL_REJECTED} per run. Then the result is clipped to `maxChars`,
 * elision mark included.
 *
 * **An allowlist, deliberately, not a list of known-bad characters** (security
 * review R4-F4 and its follow-up). The blocklist this replaces filtered Cc, Cf
 * and Mn, which still passed characters that are neither control nor mark and
 * render as nothing: U+3164 HANGUL FILLER is a letter, U+2800 BRAILLE PATTERN
 * BLANK is a symbol, enclosing marks are Me, and a future Unicode revision can
 * add more. Unknown input is rejected rather than passed, which is the direction
 * a consent surface has to fail in.
 */
function sanitizeLabel(raw: string, maxChars: number): string {
  if (maxChars === 0) return "";
  let out = "";
  let pendingSpace = false;
  let prevRejected = false;
  // `for...of` walks code points, so one unit here is one `char` on the daemon
  // side. A lone surrogate (which Rust cannot hold) is simply not permitted.
  for (const ch of raw) {
    if (LABEL_SEPARATOR.test(ch)) {
      pendingSpace = out.length > 0;
      continue;
    }
    // The daemon's own two marks are permitted so a second pass over an
    // already-filtered label is a no-op (see the idempotence note above).
    const permitted =
      LABEL_GRAPHIC.test(ch) || ch === LABEL_ELLIPSIS || ch === LABEL_REJECTED;
    // A run of rejected characters collapses to one marker, the same way a run
    // of whitespace collapses to one space: forty combining marks are one piece
    // of information, and forty markers would deform the line by themselves.
    if (!permitted && prevRejected && !pendingSpace) continue;
    if (pendingSpace) {
      out += " ";
      pendingSpace = false;
    }
    out += permitted ? ch : LABEL_REJECTED;
    prevRejected = !permitted;
  }
  const chars = Array.from(out);
  if (chars.length <= maxChars) return out;
  // Trailing space trimmed before the mark, so a clip never reads "abc …".
  return `${chars.slice(0, maxChars - 1).join("").trimEnd()}${LABEL_ELLIPSIS}`;
}

/**
 * The daemon's lease coverage label, made safe to lay out: `op read`,
 * `op with --account "rowmhq.1password.eu"`, `any command with the subcommand
 * read`. Returns null when there is nothing to show, and the caller then shows
 * NO coverage clause rather than inventing one.
 *
 * This is hygiene, not interpretation. The label is display only: it is never
 * parsed, nothing branches on its contents, and the words in it are the daemon's
 * (rendered from the user's own rule), not the phone's.
 *
 * Why the phone repeats work the daemon already did: the label and the sentence
 * stating how wide the window is share one line, so anything that reorders or
 * hides glyphs inside the label attacks the human's only defence. The daemon
 * runs first and is authoritative; this pass is a no-op on anything it produced
 * and exists for the case where that guarantee failed, which is exactly the case
 * where failing open on unfamiliar Unicode would bite. Same rule on both sides,
 * so the two surfaces cannot render the same input differently.
 *
 * The cost, stated plainly: a legitimately non-ASCII rule token (a vault named
 * `Ingenierie` with an acute accent) renders with a marker in place of the
 * accented character. That is accepted. This string is a statement of BREADTH on
 * a consent surface, not a faithful echo of config; `sigil-config list` shows the
 * rule verbatim, and it is the only place that claims to.
 */
export function coverageLabel(covers: string | undefined): string | null {
  if (!covers) return null;
  const label = sanitizeLabel(covers, COVERS_MAX_CHARS);
  return label === "" ? null : label;
}

/**
 * The bare command word from an intercepted argv: "op" from
 * ["/usr/local/bin/op", "read", ...]. Display only, and provider-blind: this is
 * whatever binary the shim intercepted, never a provider or account name. It is
 * argv[0] and may differ from the process chain's leaf, which the daemon resolves
 * separately. Returns null for an empty or blank argv so callers phrase
 * generically instead of naming a command that isn't there.
 *
 * It names the ACTOR on the deny control ("Deny and block op for 1h"), which is
 * its only remaining caller. It no longer describes lease breadth: the sheet's
 * coverage caption states {@link coverageLabel}, the daemon's rendering of the
 * user's rule, because argv[0] never knew how wide the rule was.
 */
export function commandWord(command: string[]): string | null {
  const argv0 = command[0]?.trim();
  if (!argv0) return null;
  // Last non-empty path segment, so a trailing slash cannot yield an empty word.
  const base = argv0.split("/").filter((seg) => seg.length > 0).pop();
  return base ?? null;
}

/** Render a resolved process chain as "zsh -> claude -> op read". */
export function processChain(chain: string[]): string {
  return chain.join(" → ");
}

/**
 * A one-line label for an SSH request, e.g. "github-deploy → github.com".
 * Keyed on the structured host binding (F8), never by parsing `host`: a named
 * or fingerprint binding shows the host string (a known-hosts name or the host
 * key's SHA256 fingerprint), and an unbound one says plainly that the
 * destination is unverified rather than echoing the daemon's marker string.
 */
export function sshLabel(ssh: SshChallenge): string {
  const dest =
    ssh.binding === "named" || ssh.binding === "fingerprint"
      ? ssh.host
      : "destination unverified";
  return `${ssh.keyLabel} → ${dest}`;
}
