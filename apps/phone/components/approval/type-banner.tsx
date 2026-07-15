/**
 * The type banner: an SF Symbol plus the request kind in letter-spaced mono.
 * `kind` is a display hint only — it selects the icon and caption here, never
 * how the daemon fulfills the request.
 */
import { type SymbolViewProps } from "expo-symbols";
import { View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono } from "@/components/ui/text";
import { useTheme } from "@/theme/colors";
import { type RequestKind } from "@/src/protocol";

const BANNER: Record<RequestKind, { icon: SymbolViewProps["name"]; caption: string }> = {
  secret_read: { icon: "key.fill", caption: "READ SECRET" },
  ssh_signature: { icon: "signature", caption: "SSH SIGNATURE" },
  resume: { icon: "play.fill", caption: "RESUME" },
};

export function TypeBanner({ kind }: { kind: RequestKind }) {
  const p = useTheme();
  const banner = BANNER[kind];
  return (
    <View style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
      <Sf name={banner.icon} color={p.cobalt} size={16} weight="semibold" />
      <Mono size={12} weight="semibold" tone="muted" style={{ letterSpacing: 2.4 }}>
        {banner.caption}
      </Mono>
    </View>
  );
}
