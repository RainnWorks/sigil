/**
 * Formatting for the content voice: relative time, mono clocks, and the op://
 * reference segmentation the readout well needs.
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
 * Segment an op:// reference for the well: leading "op://", then account / vault
 * / item / field with dim separators, the item name brightest.
 */
export function segmentSecretRef(ref: SecretRef): RefSegment[] {
  const sep: RefSegment = { text: " / ", emphasis: "sep" };
  return [
    { text: "op://", emphasis: "sep" },
    { text: ref.account, emphasis: "normal" },
    sep,
    { text: ref.vault, emphasis: "normal" },
    sep,
    { text: ref.item, emphasis: "bright" },
    sep,
    { text: ref.field, emphasis: "normal" },
  ];
}

/** Render a resolved process chain as "zsh -> claude -> op read". */
export function processChain(chain: string[]): string {
  return chain.join(" → ");
}
