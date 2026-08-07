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
 * The daemon's lease coverage label, made safe to lay out: `op read`,
 * `op with --account "rowmhq.1password.eu"`, `any command with the subcommand
 * read`. Returns null when there is nothing to show, and the caller then shows
 * NO coverage clause rather than inventing one.
 *
 * This is hygiene, not interpretation. The label is display only: it is never
 * parsed, nothing branches on its contents, and the words in it are the daemon's
 * (rendered from the user's own rule), not the phone's. The daemon sanitizes to
 * these same categories at its own choke point; this repeats the work so a
 * violated guarantee costs a clipped caption instead of a misread one.
 *
 * Why it strips more than control characters (security review R4-F4): the label
 * and the sentence stating how wide the window is share one line, so anything
 * that reorders or hides glyphs inside the label reorders the human's only
 * defence. A rule value carrying U+202E RIGHT-TO-LEFT OVERRIDE flips the text
 * after it, and a pile of combining marks buries it; 40 of those fit inside the
 * length bound, so the bound alone stops neither. That a config author could
 * write a wide rule anyway is not the point: the designed path has an agent
 * adding rules on the human's behalf, and reading this caption correctly is what
 * the human is left with.
 */
export function coverageLabel(covers: string | undefined): string | null {
  if (!covers) return null;
  const flat = covers
    // Format characters (Cf: the bidi overrides and embeddings, zero-width
    // space/joiner, soft hyphen) and non-spacing combining marks (Mn) are
    // DELETED, not spaced, because they are not separators: spacing them would
    // split "o<ZWSP>p" into two words rather than restoring "op". Accepted cost:
    // a decomposed "e" + U+0301 loses its accent, while a precomposed "é"
    // (U+00E9, not Mn) is untouched. On a consent surface an unambiguous
    // rendering is worth more than a faithful one.
    .replace(/[\p{Cf}\p{Mn}]/gu, "")
    // Control characters (including newlines and the line/paragraph separators)
    // ARE separators, so they become spaces; then runs of whitespace collapse
    // and a caption is one line either way.
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!flat) return null;
  // Count code points, not UTF-16 units, so an over-long label is clipped at the
  // same place the daemon would have clipped it.
  const chars = Array.from(flat);
  if (chars.length <= COVERS_MAX_CHARS) return flat;
  return `${chars.slice(0, COVERS_MAX_CHARS - 1).join("")}…`;
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
