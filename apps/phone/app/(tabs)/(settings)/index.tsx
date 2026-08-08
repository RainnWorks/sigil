import { Link, useFocusEffect } from "expo-router";
import { useCallback, useState } from "react";
import { Alert, Pressable, ScrollView, Switch, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono, Sans } from "@/components/ui/text";
import { Card, Hairline, SectionHeader } from "@/components/ui/primitives";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import { useCountdown } from "@/src/lib/use-countdown";
import { usePushDiag } from "@/src/lib/push";
import { refreshLeases, revokeLease, unpair } from "@/src/session/controller";
import {
  coverageSentence,
  leaseListStatus,
  liveLeases,
  remainingSentence,
  REVOKE_FALLBACK_CAVEAT,
  REVOKE_FALLBACK_LIST,
  REVOKE_FALLBACK_REVOKE,
  revokeNoteLine,
  revokeState,
  unconfirmedRevokeDetail,
  unconfirmedRevokeLine,
  unconfirmedRevokes,
} from "@/src/domain/leases";
import { type ActiveLease, type LeaseView, type PendingRevoke } from "@/src/domain/types";
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
      <LeaseSection view={s.leases} />

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

/**
 * The active-lease list: a snapshot of what the daemon says is open, and the
 * control that ends one. The rules this screen is built around, none negotiable:
 *
 *   - It never says "No active leases" without a fresh successful snapshot. The
 *     three no-list situations (never asked, cannot ask, asked and got none) read
 *     as three different sentences, because they are three different facts.
 *   - What it shows is a snapshot and it says so, stamped with the daemon's own
 *     time and visibly ageing, rather than sitting there implying it still
 *     describes the Mac.
 *   - A revoke never clears its row optimistically. The row stays, in flight,
 *     until a reply CORRELATED to that exact request arrives; if nothing comes
 *     back it becomes a standing warning that outlives this screen. Failing here
 *     means failing toward "the window may still be open", never toward a
 *     clean-looking list.
 *   - Asking costs a biometric, because a pulled list is a schedule of what will
 *     release without a tap. Revoking costs nothing, because it is a deny.
 *   - A row that runs out of time simply goes. That is not a revoke and is never
 *     reported as one.
 */
function LeaseSection({ view }: { view: LeaseView }) {
  const p = useTheme();
  const [now, setNow] = useState(() => Date.now());

  // One clock while the screen is up: it ages the snapshot wording and drops rows
  // whose window has run out. A lapsed row leaving is arithmetic on the daemon's
  // own number, never a claim that anything was revoked.
  //
  // There is deliberately NO polling. Asking passes a biometric, so the list is
  // an explicit one-shot pull rather than a live view, and on leaving the screen
  // the snapshot is thrown away: a held enumeration of live auto-approve windows
  // should not outlive the moment someone chose to look at it.
  useFocusEffect(
    useCallback(() => {
      setNow(Date.now());
      const tick = setInterval(() => {
        const t = Date.now();
        setNow(t);
        store.expireLeases(t);
      }, 1000);
      return () => {
        clearInterval(tick);
        store.clearLeaseSnapshot();
      };
    }, []),
  );

  const rows = liveLeases(view, now);
  const status = leaseListStatus(view, now);
  const warnings = unconfirmedRevokes(view);

  return (
    <View>
      <SectionHeader>Active leases</SectionHeader>
      <Card>
        {/* Standing warnings first, and above the rows on purpose: an unresolved
            revoke is the most important thing this screen can be saying, and it
            has to survive the snapshot that produced it being thrown away. */}
        {warnings.map((r, i) => (
          <View key={r.requestId}>
            {i > 0 ? <Hairline inset={space.lg} /> : null}
            <UnconfirmedRevoke revoke={r} now={now} />
          </View>
        ))}
        {warnings.length > 0 ? <Hairline inset={space.lg} /> : null}

        {rows.map((l, i) => (
          <View key={l.leaseId}>
            {i > 0 ? <Hairline inset={space.lg} /> : null}
            <LeaseRow lease={l} state={revokeState(view, l.leaseId)} />
          </View>
        ))}
        {rows.length > 0 ? <Hairline inset={space.lg} /> : null}

        <View style={{ padding: space.lg, gap: 4 }}>
          <Sans size={13} tone={status.authoritative ? "muted" : "label"}>
            {status.line}
          </Sans>
          {status.detail ? (
            <Sans size={12} tone="faint">
              {status.detail}
            </Sans>
          ) : null}
          {view.note && warnings.length === 0 ? (
            <Sans size={12} tone="muted" style={{ marginTop: 4 }}>
              {revokeNoteLine(view.note.outcome)}
            </Sans>
          ) : null}
          {DEMO && rows.length > 0 ? (
            <Sans size={12} tone="faint" style={{ marginTop: 4 }}>
              Sample rows from the demo build, not a real window.
            </Sans>
          ) : null}
        </View>

        <Hairline inset={space.lg} />
        <Pressable
          onPress={() => void refreshLeases()}
          disabled={view.asking}
          style={{ flexDirection: "row", alignItems: "center", gap: space.md, padding: space.lg }}
        >
          <Sf
            name={view.askedAt > 0 ? "arrow.clockwise" : "faceid"}
            color={view.asking ? p.faint : p.cobalt}
            size={16}
          />
          <Sans size={16} style={{ flex: 1, color: view.asking ? p.faint : p.cobalt }}>
            {view.asking ? "Checking" : view.askedAt > 0 ? "Check again" : "Show active leases"}
          </Sans>
        </Pressable>
      </Card>
    </View>
  );
}

/**
 * A revoke that went out and was never answered. It names what it was about, when
 * it was sent, and the Mac-side steps that settle it for certain.
 *
 * The Mac command is a LITERAL placeholder, not an id printed from here:
 * `sigil lease revoke` is prefix matched, so an id that arrived truncated would
 * revoke everything while reporting success. The human reads the real one off
 * `sigil lease list` on the Mac, where it cannot have been mangled in transit.
 */
function UnconfirmedRevoke({ revoke, now }: { revoke: PendingRevoke; now: number }) {
  const p = useTheme();
  return (
    <View style={{ padding: space.lg, gap: 4 }}>
      <View style={{ flexDirection: "row", alignItems: "center", gap: space.sm }}>
        <Sf name="exclamationmark.triangle" color={p.brass} size={15} />
        <Sans size={14} style={{ flex: 1, color: p.brass }}>
          {unconfirmedRevokeLine(revoke)}
        </Sans>
      </View>
      <Sans size={12} tone="faint">
        {unconfirmedRevokeDetail(revoke, now)}
      </Sans>
      <Mono size={12} tone="faint" selectable>
        {REVOKE_FALLBACK_LIST}
      </Mono>
      <Sans size={12} tone="faint">
        then end the window it shows:
      </Sans>
      <Mono size={12} tone="faint" selectable>
        {REVOKE_FALLBACK_REVOKE}
      </Mono>
      <Sans size={12} tone="faint">
        {REVOKE_FALLBACK_CAVEAT}
      </Sans>
    </View>
  );
}

function LeaseRow({
  lease,
  state,
}: {
  lease: ActiveLease;
  state: "idle" | "sending" | "unconfirmed";
}) {
  const p = useTheme();
  const { remainingMs } = useCountdown(lease.expiresAt, lease.windowMs);
  return (
    <View style={{ padding: space.lg, gap: 4 }}>
      <View style={{ flexDirection: "row", alignItems: "center", gap: space.md }}>
        <Mono size={14} weight="medium" style={{ flex: 1 }}>
          {lease.scope ?? "unnamed rule"}
        </Mono>
        {/* No confirmation step and no biometric, deliberately. Revoking can only
            narrow what the Mac will serve, so it is the safe direction, and the
            deny control set the precedent that refusing is never made heavier
            than allowing. An accidental revoke costs one extra approval; a
            confirmation sheet costs time at exactly the moment someone wants a
            window shut. */}
        <Pressable
          onPress={() => void revokeLease(lease.leaseId, lease.scope)}
          disabled={state !== "idle"}
        >
          <Sans size={15} style={{ color: state === "idle" ? p.deny : p.faint }}>
            {state === "idle" ? "Revoke" : "Revoking"}
          </Sans>
        </Pressable>
      </View>
      {/* The scope is a RULE name, and one window covers every command that rule
          matches for the caller that opened it. The row says so outright rather
          than letting a rule name read as a command line, and states the breadth
          in the daemon's own words (the same string the approval sheet's caption
          consented to). */}
      <Sans size={12} tone="muted">
        {coverageSentence(lease)}
      </Sans>
      <Mono size={12} tone="faint">
        {remainingSentence(lease, remainingMs)}
      </Mono>
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
