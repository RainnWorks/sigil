import { Link, useRouter } from "expo-router";
import { Pressable, ScrollView, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono, Sans } from "@/components/ui/text";
import { Card, Hairline, SectionHeader, StatePill } from "@/components/ui/primitives";
import { stateLabel, useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import { relativeTime, requestSource, secretRefLabel } from "@/src/lib/format";
import { type PendingRequest } from "@/src/domain/types";
import { useAppState } from "@/src/state/store";

export default function HomeScreen() {
  const p = useTheme();
  const router = useRouter();
  const s = useAppState();

  const live = s.pending.filter((r) => r.state === "fresh" || r.state === "expiring");
  const last = s.history[0];
  const armLabelState =
    s.arm === "lockedDown" ? "lockedDown" : s.arm === "armed" ? "armed" : "expired";

  return (
    <ScrollView
      contentInsetAdjustmentBehavior="automatic"
      contentContainerStyle={{ padding: space.lg, gap: space.xl, paddingBottom: 48 }}
    >
      {/* status line */}
      <View style={{ gap: space.md }}>
        <View style={{ flexDirection: "row", alignItems: "center", gap: space.md }}>
          <StatePill state={armLabelState} label={stateLabel(armLabelState)} />
          {s.connection.rung !== "none" ? (
            <Mono size={13} tone="muted">
              {s.connection.machine} connected
            </Mono>
          ) : (
            <Mono size={13} tone="deny">
              phone unreachable
            </Mono>
          )}
        </View>
        <Mono size={13} tone="faint">
          {s.accounts.length} account{s.accounts.length === 1 ? "" : "s"} ·{" "}
          {s.connection.rung === "none" ? "no link" : `${s.connection.rung} · seen ${relativeTime(s.connection.lastSeenAt)}`}
        </Mono>
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
          <Sans tone="muted">Nothing pending. You will be asked when a secret is requested.</Sans>
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

      {/* lockdown */}
      <Link href="/lockdown" asChild>
        <Pressable
          style={{
            flexDirection: "row",
            alignItems: "center",
            justifyContent: "center",
            gap: 8,
            height: 52,
            borderRadius: radius.control,
            borderCurve: "continuous",
            borderWidth: 1,
            borderColor: s.arm === "lockedDown" ? p.deny : p.line,
            backgroundColor: s.arm === "lockedDown" ? p.deny + "1a" : "transparent",
          }}
        >
          <Sf name={s.arm === "lockedDown" ? "lock.fill" : "lock"} color={p.deny} size={18} />
          <Sans size={16} weight="medium" style={{ color: p.deny }}>
            {s.arm === "lockedDown" ? "Locked down · tap to release" : "Lock down"}
          </Sans>
        </Pressable>
      </Link>
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
        ? `${r.ssh.keyLabel} → ${r.ssh.host}`
        : requestSource(r);
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
          {requestSource(r)} · {r.provenance.processChain[r.provenance.processChain.length - 1]}
        </Mono>
      </View>
      <Sf name="chevron.right" color={p.faint} size={14} />
    </Pressable>
  );
}
