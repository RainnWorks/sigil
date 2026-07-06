/**
 * Theme access. `useTheme` re-resolves on light/dark flips; `Semantic` maps the
 * fixed state vocabulary (Pending/Approved/Denied/Expired/Locked down) onto the
 * three brand state colors so screens never reach for a raw hex.
 */
import { useColorScheme } from "react-native";

import { type Palette, paletteFor, type Scheme } from "./tokens";

export function useTheme(): Palette {
  const scheme = useColorScheme();
  return paletteFor(scheme);
}

export function useScheme(): Scheme {
  return useColorScheme() === "dark" ? "dark" : "light";
}

/** The product's fixed decision vocabulary. */
export type DecisionState =
  | "armed"
  | "pending"
  | "approved"
  | "denied"
  | "expired"
  | "superseded"
  | "lockedDown";

export function stateColor(p: Palette, state: DecisionState): string {
  switch (state) {
    case "armed":
      return p.cobalt;
    case "pending":
      return p.brass;
    case "approved":
      return p.ok;
    case "denied":
    case "lockedDown":
      return p.deny;
    case "expired":
    case "superseded":
      return p.faint;
  }
}

/** Human label for a state. Fixed strings, brief's voice. */
export function stateLabel(state: DecisionState): string {
  switch (state) {
    case "armed":
      return "Armed";
    case "pending":
      return "Pending";
    case "approved":
      return "Approved";
    case "denied":
      return "Denied";
    case "expired":
      return "Expired";
    case "superseded":
      return "Superseded";
    case "lockedDown":
      return "Locked down";
  }
}
