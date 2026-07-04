/**
 * The type banner: an SF Symbol plus the request kind in letter-spaced mono.
 * Two kinds only: READ SECRET and SSH SIGNATURE.
 */
import { View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono } from "@/components/ui/text";
import { useTheme } from "@/theme/colors";
import { type RequestKind } from "@/src/protocol";

export function TypeBanner({ kind }: { kind: RequestKind }) {
  const p = useTheme();
  const isRead = kind === "read_secret";
  return (
    <View style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
      <Sf name={isRead ? "key.fill" : "signature"} color={p.cobalt} size={16} weight="semibold" />
      <Mono size={12} weight="semibold" tone="muted" style={{ letterSpacing: 2.4 }}>
        {isRead ? "READ SECRET" : "SSH SIGNATURE"}
      </Mono>
    </View>
  );
}
