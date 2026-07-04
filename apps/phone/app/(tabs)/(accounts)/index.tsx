import { ScrollView, View } from "react-native";

import { Mono, Sans } from "@/components/ui/text";
import { Card, Hairline } from "@/components/ui/primitives";
import { useTheme } from "@/theme/colors";
import { space } from "@/theme/tokens";
import { relativeTime } from "@/src/lib/format";
import { type Account, type TokenHealth } from "@/src/domain/types";
import { useAppState } from "@/src/state/store";

/**
 * Token health per 1Password account. The phone shows health and metadata; token
 * lifecycle (add, rotate, remove) lives on the Mac configurator and CLI.
 */
export default function AccountsScreen() {
  const s = useAppState();
  return (
    <ScrollView
      contentInsetAdjustmentBehavior="automatic"
      contentContainerStyle={{ padding: space.lg, paddingBottom: 48 }}
    >
      <Card>
        {s.accounts.map((a, i) => (
          <View key={a.id}>
            {i > 0 ? <Hairline inset={space.lg} /> : null}
            <Row account={a} />
          </View>
        ))}
      </Card>
      <Sans size={13} tone="faint" style={{ marginTop: space.md, marginHorizontal: space.xs }}>
        Add, rotate, or remove tokens on the Mac. The phone never holds a token.
      </Sans>
    </ScrollView>
  );
}

function healthColor(health: TokenHealth, p: ReturnType<typeof useTheme>): string {
  return health === "healthy" ? p.ok : health === "rotate" ? p.brass : p.deny;
}

function healthLabel(a: Account): string {
  if (a.health === "healthy") return "token healthy";
  return a.detail ?? (a.health === "rotate" ? "rotate soon" : "expiring");
}

function Row({ account }: { account: Account }) {
  const p = useTheme();
  const color = healthColor(account.health, p);
  return (
    <View style={{ padding: space.lg, gap: 6 }}>
      <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center" }}>
        <Sans size={16} weight="semibold">
          {account.label}
        </Sans>
        <View style={{ flexDirection: "row", alignItems: "center", gap: 6 }}>
          <View style={{ width: 7, height: 7, borderRadius: 99, backgroundColor: color }} />
          <Mono size={12} style={{ color }}>
            {healthLabel(account)}
          </Mono>
        </View>
      </View>
      <Mono size={12} tone="muted">
        {account.vaults} vault{account.vaults === 1 ? "" : "s"} · used {relativeTime(account.lastUsedAt)}
      </Mono>
    </View>
  );
}
