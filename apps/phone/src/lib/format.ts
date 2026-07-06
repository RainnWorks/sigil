/**
 * Formatting for the content voice: relative time, mono clocks, and the
 * secret-reference readout the well needs. Everything here works off a
 * SecretRef's display-only `segments` / `label`; it never parses the opaque
 * `reference`, which only the owning provider understands.
 */
import { type SecretRef } from "@/src/protocol";

/** "just now", "12s ago", "4m ago", "2d ago" — the brief's terse register. */
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
 * no segment matches the label, the last — the most specific, meaningful
 * segment — is brightened instead.
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

/** Render a resolved process chain as "zsh -> claude -> op read". */
export function processChain(chain: string[]): string {
  return chain.join(" → ");
}
