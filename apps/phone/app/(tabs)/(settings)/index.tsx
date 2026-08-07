import { Link } from "expo-router";
import { Alert, Pressable, ScrollView, Switch, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono, Sans } from "@/components/ui/text";
import { Card, Hairline, SectionHeader } from "@/components/ui/primitives";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import { useCountdown } from "@/src/lib/use-countdown";
import { usePushDiag } from "@/src/lib/push";
import { unpair } from "@/src/session/controller";
import { type Lease } from "@/src/domain/types";
import { DEMO, store, useAppState } from "@/src/state/store";

/**
 * Leases (view + revoke), approval and notification preferences, default
 * timeout, and the device/pairing entry.
 */
export default function SettingsScreen() {
  const p = useTheme();
  const s = useAppState();
  const pushDiag = usePushDiag();

  function confirmReset(): void {
    Alert.alert(
      "Reset pairing?",
      "This erases the stored keys for this Mac. You will need to pair again from the Mac's QR code before any secret can be approved.",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Reset",
          style: "destructive",
          // unpair() clears the keystore + store; the root layout then routes
          // back into the pairing flow because `paired` flips to false.
          onPress: () => void unpair(),
        },
      ],
    );
  }

  return (
    <ScrollView
      contentInsetAdjustmentBehavior="automatic"
      contentContainerStyle={{ padding: space.lg, gap: space.xl, paddingBottom: 48 }}
    >
      {/* Leases: PREVIEW ONLY (security review F7). `AppState.leases` is written
          by the demo seed and by nothing else, and no envelope message carries a
          revoke, so this list cannot show a real window and cannot end one. It
          therefore renders no revoke control and never claims the list is empty:
          a phone that cannot see the Mac's leases saying "No active leases" is a
          false statement of fact, and a revoke that silently drops a local row is
          worse than no revoke at all. Revocation today is the Mac CLI, named
          below. Restore the rows and the control when the daemon-side messages
          land. */}
      <View>
        <SectionHeader badge="Planned">Active leases</SectionHeader>
        <Card>
          {DEMO && s.leases.length > 0 ? (
            <>
              {s.leases.map((l, i) => (
                <View key={l.id}>
                  {i > 0 ? <Hairline inset={space.lg} /> : null}
                  <LeaseRow lease={l} />
                </View>
              ))}
              <Hairline inset={space.lg} />
            </>
          ) : null}
          <View style={{ padding: space.lg, gap: space.sm }}>
            <Sans size={13} tone="muted">
              {DEMO && s.leases.length > 0
                ? "Sample rows only. This phone does not read or end the Mac's leases yet."
                : "This phone does not read or end the Mac's leases yet."}
            </Sans>
            <Sans size={13} tone="muted">
              To end a window now, revoke it in Sigil on the Mac, or run:
            </Sans>
            <Mono size={12} tone="faint">
              {"sigil lease revoke <prefix>"}
            </Mono>
          </View>
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
          {pushDiag.phase !== "idle" && pushDiag.message ? (
            <>
              <Hairline inset={space.lg} />
              <View style={{ flexDirection: "row", alignItems: "center", gap: space.md, padding: space.lg }}>
                <View
                  style={{
                    width: 7,
                    height: 7,
                    borderRadius: 99,
                    backgroundColor:
                      pushDiag.phase === "registered"
                        ? p.cobalt
                        : pushDiag.phase === "failed" || pushDiag.phase === "blocked"
                          ? p.brass
                          : p.faint,
                  }}
                />
                <Sans size={13} tone="muted" style={{ flex: 1 }}>
                  {pushDiag.message}
                </Sans>
              </View>
            </>
          ) : null}
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
          {s.paired ? (
            <>
              <Hairline inset={space.lg} />
              <Pressable
                onPress={confirmReset}
                style={{ flexDirection: "row", alignItems: "center", gap: space.md, padding: space.lg }}
              >
                <Sf name="trash" color={p.deny} size={18} />
                <Sans size={16} style={{ flex: 1, color: p.deny }}>
                  Reset pairing
                </Sans>
                <Sf name="chevron.right" color={p.faint} size={14} />
              </Pressable>
            </>
          ) : null}
        </Card>
      </View>
    </ScrollView>
  );
}

function LeaseRow({ lease }: { lease: Lease }) {
  const { remainingMs } = useCountdown(lease.expiresAt, lease.expiresAt - lease.grantedAt);
  const mins = Math.max(0, Math.round(remainingMs / 60000));
  return (
    <View style={{ flexDirection: "row", alignItems: "center", gap: space.md, padding: space.lg }}>
      <View style={{ flex: 1 }}>
        <Mono size={14} weight="medium">
          {lease.caller}
        </Mono>
        {/* The scope is a RULE name, and one lease covers every command that
            rule matches for this caller until it expires. The row says so
            outright rather than letting a rule name read as a command line
            (the daemon's `sigil lease list` row states the same breadth). */}
        <Mono size={12} tone="muted">
          {lease.scope}, any matching command, {mins}m left
        </Mono>
      </View>
      {/* No revoke control here on purpose: nothing on this phone can end a
          daemon lease yet, and a button that quietly drops a local row would
          tell the human the window closed while the Mac keeps honoring it. */}
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
