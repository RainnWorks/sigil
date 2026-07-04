import { Link } from "expo-router";
import { Pressable, ScrollView, Switch, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono, Sans } from "@/components/ui/text";
import { Card, Hairline, SectionHeader } from "@/components/ui/primitives";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import { useCountdown } from "@/src/lib/use-countdown";
import { type Lease } from "@/src/domain/types";
import { store, useAppState } from "@/src/state/store";

/**
 * Leases (view + revoke), approval and notification preferences, default
 * timeout, and the device/pairing entry.
 */
export default function SettingsScreen() {
  const p = useTheme();
  const s = useAppState();

  return (
    <ScrollView
      contentInsetAdjustmentBehavior="automatic"
      contentContainerStyle={{ padding: space.lg, gap: space.xl, paddingBottom: 48 }}
    >
      {/* leases */}
      <View>
        <SectionHeader>Active leases</SectionHeader>
        <Card>
          {s.leases.length === 0 ? (
            <View style={{ padding: space.lg }}>
              <Sans tone="muted">No active leases.</Sans>
            </View>
          ) : (
            s.leases.map((l, i) => (
              <View key={l.id}>
                {i > 0 ? <Hairline inset={space.lg} /> : null}
                <LeaseRow lease={l} />
              </View>
            ))
          )}
        </Card>
      </View>

      {/* approvals */}
      <View>
        <SectionHeader>Approvals</SectionHeader>
        <Card>
          <ToggleRow
            label="Require Face ID before approve"
            note="Always enforced; the enclave will not release the key without it."
            value={s.settings.faceIdBeforeApprove}
            disabled
            onChange={(v) => store.setSetting("faceIdBeforeApprove", v)}
          />
          <Hairline inset={space.lg} />
          <ToggleRow
            label="Reduce motion"
            note="Collapses the timeout gauge to a numeric countdown."
            value={s.settings.reduceMotion}
            onChange={(v) => store.setSetting("reduceMotion", v)}
          />
        </Card>
      </View>

      {/* timeout */}
      <View>
        <SectionHeader>Default timeout</SectionHeader>
        <Card style={{ padding: space.lg, gap: space.md }}>
          <Segmented
            options={[60, 90, 120]}
            value={s.settings.defaultTimeoutSec}
            onChange={(v) => store.setSetting("defaultTimeoutSec", v)}
            render={(v) => `${v}s`}
          />
          <Sans size={13} tone="faint">
            How long a request waits before it expires and fails closed.
          </Sans>
        </Card>
      </View>

      {/* notifications */}
      <View>
        <SectionHeader>Notifications</SectionHeader>
        <Card>
          <ToggleRow
            label="Approval doorbell"
            note="A content-free push wakes the app; the request is fetched on-device."
            value={s.settings.notificationsEnabled}
            onChange={(v) => store.setSetting("notificationsEnabled", v)}
          />
        </Card>
      </View>

      {/* device */}
      <View>
        <SectionHeader>This device</SectionHeader>
        <Card>
          <View style={{ padding: space.lg, gap: 4 }}>
            <Sans size={13} tone="muted">
              Public key fingerprint
            </Sans>
            <Mono size={14} selectable>
              {s.ownFingerprint ?? "not paired"}
            </Mono>
          </View>
          <Hairline inset={space.lg} />
          <Link href="/pairing" asChild>
            <Pressable
              style={{ flexDirection: "row", alignItems: "center", gap: space.md, padding: space.lg }}
            >
              <Sf name="qrcode" color={p.cobalt} size={18} />
              <Sans size={16} style={{ flex: 1, color: p.cobalt }}>
                Re-pair or add a device
              </Sans>
              <Sf name="chevron.right" color={p.faint} size={14} />
            </Pressable>
          </Link>
        </Card>
      </View>
    </ScrollView>
  );
}

function LeaseRow({ lease }: { lease: Lease }) {
  const p = useTheme();
  const { remainingMs } = useCountdown(lease.expiresAt, lease.expiresAt - lease.grantedAt);
  const mins = Math.max(0, Math.round(remainingMs / 60000));
  return (
    <View style={{ flexDirection: "row", alignItems: "center", gap: space.md, padding: space.lg }}>
      <View style={{ flex: 1 }}>
        <Mono size={14} weight="medium">
          {lease.caller}
        </Mono>
        <Mono size={12} tone="muted">
          {lease.scope} · {mins}m left
        </Mono>
      </View>
      <Pressable
        onPress={() => store.revokeLease(lease.id)}
        hitSlop={8}
        style={{
          paddingHorizontal: 14,
          paddingVertical: 7,
          borderRadius: radius.capsule,
          borderWidth: 1,
          borderColor: p.deny + "80",
        }}
      >
        <Sans size={13} weight="medium" style={{ color: p.deny }}>
          Revoke
        </Sans>
      </Pressable>
    </View>
  );
}

function ToggleRow({
  label,
  note,
  value,
  disabled,
  onChange,
}: {
  label: string;
  note?: string;
  value: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <View style={{ flexDirection: "row", alignItems: "center", gap: space.md, padding: space.lg }}>
      <View style={{ flex: 1, gap: 2 }}>
        <Sans size={16}>{label}</Sans>
        {note ? (
          <Sans size={12} tone="faint">
            {note}
          </Sans>
        ) : null}
      </View>
      <Switch value={value} onValueChange={onChange} disabled={disabled} />
    </View>
  );
}

function Segmented<T extends string | number>({
  options,
  value,
  onChange,
  render,
}: {
  options: T[];
  value: T;
  onChange: (v: T) => void;
  render: (v: T) => string;
}) {
  const p = useTheme();
  return (
    <View
      style={{
        flexDirection: "row",
        backgroundColor: p.well,
        borderRadius: radius.control,
        borderCurve: "continuous",
        padding: 3,
      }}
    >
      {options.map((o) => {
        const active = o === value;
        return (
          <Pressable
            key={String(o)}
            onPress={() => onChange(o)}
            style={{
              flex: 1,
              paddingVertical: 8,
              alignItems: "center",
              borderRadius: radius.control - 3,
              borderCurve: "continuous",
              backgroundColor: active ? p.surface : "transparent",
            }}
          >
            <Mono size={14} weight={active ? "semibold" : "regular"} tone={active ? "label" : "muted"}>
              {render(o)}
            </Mono>
          </Pressable>
        );
      })}
    </View>
  );
}
