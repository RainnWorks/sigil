/**
 * The one place SF Symbols enter the app, so the binding is swappable. Uses
 * expo-symbols SymbolView (the API the reference docs document).
 *
 * NEEDS VERIFICATION: SKILL.md's library preferences favor expo-image with an
 * `sf:` source over expo-symbols. Both render SF Symbols natively; if the house
 * rule is enforced, reimplement this single component against expo-image and
 * nothing else changes.
 */
import { SymbolView, type SymbolViewProps } from "expo-symbols";

export interface SfProps {
  name: SymbolViewProps["name"];
  color?: string;
  size?: number;
  weight?: SymbolViewProps["weight"];
}

export function Sf({ name, color, size = 20, weight = "regular" }: SfProps) {
  return (
    <SymbolView
      name={name}
      tintColor={color}
      weight={weight}
      resizeMode="scaleAspectFit"
      style={{ width: size, height: size }}
    />
  );
}
