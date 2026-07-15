/**
 * Sigil design tokens, converted from the brief's oklch source of truth to
 * sRGB hex (D65). These are plain strings on purpose: they are safe to hand to
 * Reanimated worklets, unlike PlatformColor / the expo-router Color API, which
 * must never cross into animated styles.
 *
 * Identity budget is deliberately small: one cobalt accent, three semantic
 * state colors (brass = pending, sea green = approved, rust = denied), plus
 * neutrals. Dark-first; approvals happen on the couch.
 *
 * When the brief's oklch values change, regenerate with scratchpad/oklch.mjs.
 */

export type Scheme = "light" | "dark";

export interface Palette {
  /** Screen ground. */
  bg: string;
  /** Cards, grouped rows. */
  surface: string;
  /** The recessed readout well behind the op:// reference. */
  well: string;
  /** Primary text. */
  label: string;
  /** Secondary text: provenance values, captions. */
  muted: string;
  /** Tertiary text: separators in the reference, disabled. */
  faint: string;
  /** Hairline separators. */
  line: string;
  /** Brand accent. Tint only, never a state. */
  cobalt: string;
  /** Text/glyph that sits on a cobalt fill. */
  cobaltInk: string;
  /** Pending. The timeout gauge. */
  brass: string;
  /** Approved. */
  ok: string;
  /** Denied. Never an alarm color; the calm safe default. */
  deny: string;
}

const light: Palette = {
  bg: "#ffffff",
  surface: "#f3f6f8",
  well: "#e9edf0",
  label: "#181f25",
  muted: "#5d646b",
  faint: "#81878c",
  line: "#d5dade",
  cobalt: "#0b5d7c",
  cobaltInk: "#f8fafc",
  brass: "#ae7b28",
  ok: "#1c7456",
  deny: "#a83634",
};

const dark: Palette = {
  bg: "#0b1116",
  surface: "#141a20",
  well: "#1a2128",
  label: "#ecf1f4",
  muted: "#98a0a5",
  faint: "#747b81",
  line: "#272f35",
  cobalt: "#3ea4d3",
  cobaltInk: "#060e15",
  brass: "#d6a453",
  ok: "#51b48d",
  deny: "#db6c66",
};

export const palettes: Record<Scheme, Palette> = { light, dark };

/** Non-hook accessor, for Reanimated worklets and module scope. Accepts the
 * broader `ColorSchemeName` ("light" | "dark" | "unspecified" | null). */
export function paletteFor(scheme: string | null | undefined): Palette {
  return scheme === "dark" ? dark : light;
}

/** Typography. SF Pro for voice, SF Mono for anything technical. */
export const type = {
  sans: undefined, // system default = SF Pro on iOS, honors Dynamic Type
  mono: "ui-monospace",
} as const;

/** Spacing scale, points. */
export const space = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 24,
  xxl: 32,
} as const;

export const radius = {
  well: 14,
  card: 16,
  control: 12,
  capsule: 999,
} as const;
