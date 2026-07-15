import { Link } from "expo-router";
import { Pressable, ScrollView, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono, Sans } from "@/components/ui/text";
import { Card, Hairline, SectionHeader } from "@/components/ui/primitives";
import { stateColor, useTheme } from "@/theme/colors";
import { space } from "@/theme/tokens";
import { relativeTime } from "@/src/lib/format";
import { pairedMacName, useAppState } from "@/src/state/store";

/**
 * The Macs this phone approves for. Provider-agnostic by construction: the phone
 * is a blind approver, so it knows nothing about what any Mac stores or which
 * tool asks. It shows only the pairing itself: which Mac, when it was pinned,
 * and this phone's own fingerprint. The transport is a quiet dot; the relay is
 * plumbing and is never named here. Multi-device pairing grows here.
 */
export default function DevicesScreen() {
  const p = useTheme();
  const s = useAppState();
  const linked = s.paired && s.connection.rung !== "none";

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
                <View style={{ flexDirection: "row", alignItems: "center", gap: 8, flexShrink: 1 }}>
                  <Sf name="laptopcomputer" color={p.muted} size={18} />
                  <Sans size={16} weight="semibold" numberOfLines={1} style={{ flexShrink: 1 }}>
                    {pairedMacName(s) ?? "Your Mac"}
                  </Sans>
                </View>
                <View style={{ flexDirection: "row", alignItems: "center", gap: 6 }}>
                  <View
                    style={{
                      width: 7,
                      height: 7,
                      borderRadius: 99,
                      backgroundColor: linked ? stateColor(p, "armed") : p.faint,
                    }}
                  />
                  <Mono size={12} style={{ color: linked ? stateColor(p, "armed") : p.faint }}>
                    {linked ? "link" : "no link"}
                  </Mono>
                </View>
              </View>
              <Mono size={12} tone="muted">
                paired {relativeTime(s.pairedAt)}
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
          Pairing is set up from the Mac. Each Mac shows a QR code you scan here. Requests travel
          sealed between the two paired devices; whatever carries them can neither read nor forge
          them.
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
