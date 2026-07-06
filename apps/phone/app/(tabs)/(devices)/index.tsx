import { Link } from "expo-router";
import { Pressable, ScrollView, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono, Sans } from "@/components/ui/text";
import { Card, Hairline, SectionHeader } from "@/components/ui/primitives";
import { stateColor, useTheme } from "@/theme/colors";
import { space } from "@/theme/tokens";
import { relativeTime } from "@/src/lib/format";
import { useAppState } from "@/src/state/store";

/**
 * The Macs this phone approves for. Provider-agnostic by construction: the phone
 * is a blind approver, so it knows nothing about what any Mac stores or which
 * tool asks. It shows only the pairing itself: which machine, whether the link is
 * live, and this phone's own fingerprint. Multi-device pairing grows here.
 */
export default function DevicesScreen() {
  const p = useTheme();
  const s = useAppState();
  const online = s.paired && s.connection.rung !== "none";

  return (
    <ScrollView
      contentInsetAdjustmentBehavior="automatic"
      contentContainerStyle={{ padding: space.lg, gap: space.xl, paddingBottom: 48 }}
    >
      <View>
        <SectionHeader>Approving for</SectionHeader>
        <Card>
          {s.paired ? (
            <View style={{ padding: space.lg, gap: 6 }}>
              <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center" }}>
                <Sans size={16} weight="semibold">
                  {s.connection.machine || "paired Mac"}
                </Sans>
                <View style={{ flexDirection: "row", alignItems: "center", gap: 6 }}>
                  <View
                    style={{
                      width: 7,
                      height: 7,
                      borderRadius: 99,
                      backgroundColor: online ? stateColor(p, "armed") : p.faint,
                    }}
                  />
                  <Mono size={12} style={{ color: online ? stateColor(p, "armed") : p.faint }}>
                    {online ? "connected" : "no link"}
                  </Mono>
                </View>
              </View>
              <Mono size={12} tone="muted">
                {online
                  ? `${s.connection.rung} · seen ${relativeTime(s.connection.lastSeenAt)}`
                  : "waiting for the daemon"}
              </Mono>
            </View>
          ) : (
            <View style={{ padding: space.lg }}>
              <Sans tone="muted">Not paired with any Mac yet.</Sans>
            </View>
          )}
          <Hairline inset={space.lg} />
          <Link href="/pairing" asChild>
            <Pressable
              style={{ flexDirection: "row", alignItems: "center", gap: space.md, padding: space.lg }}
            >
              <Sf name="plus.circle" color={p.cobalt} size={18} />
              <Sans size={16} style={{ flex: 1, color: p.cobalt }}>
                Pair another device
              </Sans>
              <Sf name="chevron.right" color={p.faint} size={14} />
            </Pressable>
          </Link>
        </Card>
        <Sans size={13} tone="faint" style={{ marginTop: space.md, marginHorizontal: space.xs }}>
          Pairing is set up from the Mac. Each Mac shows a QR code you scan here.
        </Sans>
      </View>

      <View>
        <SectionHeader>This phone</SectionHeader>
        <Card>
          <View style={{ padding: space.lg, gap: 4 }}>
            <Sans size={13} tone="muted">
              Public key fingerprint
            </Sans>
            <Mono size={14} selectable>
              {s.ownFingerprint ?? "not paired"}
            </Mono>
          </View>
        </Card>
      </View>
    </ScrollView>
  );
}
