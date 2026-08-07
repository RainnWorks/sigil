import { useRouter } from "expo-router";
import { Pressable, ScrollView, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono, Sans } from "@/components/ui/text";
import { Card, Hairline, SectionHeader, StatePill } from "@/components/ui/primitives";
import { stateColor, stateLabel, useTheme } from "@/theme/colors";
import { space } from "@/theme/tokens";
import { relativeTime, secretRefLabel, sshLabel } from "@/src/lib/format";
import { type PendingRequest } from "@/src/domain/types";
import { pairedMacName, useAppState } from "@/src/state/store";

export default function HomeScreen() {
  const p = useTheme();
  const router = useRouter();
  const s = useAppState();

  const live = s.pending.filter((r) => r.state === "fresh" || r.state === "expiring");
  const last = s.history[0];
  const mac = pairedMacName(s) ?? "your Mac";
  const linked = s.paired && s.connection.rung !== "none";

  return (
    <ScrollView
      contentInsetAdjustmentBehavior="automatic"
      contentContainerStyle={{ padding: space.lg, gap: space.xl, paddingBottom: 48 }}
    >
      {/* status: this phone's own state. The transport is a quiet dot at the
          margin, never a named party and never the headline. */}
      <View
        style={{ flexDirection: "row", alignItems: "center", justifyContent: "space-between" }}
      >
        <StatePill state={s.arm} label={stateLabel(s.arm)} />
        {s.paired ? (
          <View style={{ flexDirection: "row", alignItems: "center", gap: 6 }}>
            <View
              style={{
                width: 7,
                height: 7,
                borderRadius: 99,
                backgroundColor: linked ? stateColor(p, "armed") : p.faint,
              }}
            />
            <Mono size={12} tone="faint">
              {linked ? "link" : "no link"}
            </Mono>
          </View>
        ) : null}
      </View>

      {/* pending */}
      {live.length > 0 ? (
        <View>
          <SectionHeader>Pending</SectionHeader>
          <Card>
            {live.map((r, i) => (
              <View key={r.request.requestId}>
                {i > 0 ? <Hairline inset={space.lg} /> : null}
                <PendingRow pending={r} onPress={() => router.push("/approval")} />
              </View>
            ))}
          </Card>
        </View>
      ) : (
        <Card style={{ padding: space.lg }}>
          <Sans tone="muted">
            Nothing pending. When {mac} asks for an approval, you decide here.
          </Sans>
        </Card>
      )}

      {/* last decision */}
      {last ? (
        <View>
          <SectionHeader>Last decision</SectionHeader>
          <Card style={{ padding: space.lg, gap: 6 }}>
            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center" }}>
              <StatePill
                state={last.decision === "approved" ? "approved" : last.decision === "denied" ? "denied" : "expired"}
                label={stateLabel(
                  last.decision === "approved" ? "approved" : last.decision === "denied" ? "denied" : "expired",
                )}
              />
              <Mono size={12} tone="faint">
                {relativeTime(last.at)}
              </Mono>
            </View>
            <Mono size={14} style={{ marginTop: 4 }}>
              {last.label}
            </Mono>
            <Mono size={12} tone="muted">
              {last.process} · {last.cwd}
            </Mono>
          </Card>
        </View>
      ) : null}
    </ScrollView>
  );
}

function PendingRow({ pending, onPress }: { pending: PendingRequest; onPress: () => void }) {
  const p = useTheme();
  const r = pending.request;
  const label =
    r.secrets.length > 0
      ? r.secrets.map(secretRefLabel).join(", ")
      : r.ssh
        ? sshLabel(r.ssh)
        : r.command.join(" ") || r.provenance.machine;
  return (
    <Pressable
      onPress={onPress}
      style={{ flexDirection: "row", alignItems: "center", gap: space.md, padding: space.lg }}
    >
      <View style={{ width: 8, height: 8, borderRadius: 99, backgroundColor: p.brass }} />
      <View style={{ flex: 1 }}>
        <Mono size={15} weight="medium">
          {label}
        </Mono>
        <Mono size={12} tone="muted">
          {r.provenance.machine} · {r.provenance.processChain[r.provenance.processChain.length - 1]}
        </Mono>
      </View>
      <Sf name="chevron.right" color={p.faint} size={14} />
    </Pressable>
  );
}
