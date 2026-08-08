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
  lapsedRevokeLine,
  leaseListStatus,
  liveLeases,
  partitionRevokes,
  remainingSentence,
  REVOKE_FALLBACK_CAVEAT,
  REVOKE_FALLBACK_LIST,
  REVOKE_FALLBACK_REVOKE,
  revokeNoteLine,
  type RevokeState,
  revokeState,
  unconfirmedRevokeDetail,
  unconfirmedRevokeLine,
} from "@/src/domain/leases";
import {
  type ActiveLease,
  type HistoryEntry,
  type LeaseView,
  type PendingRevoke,
} from "@/src/domain/types";
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
      <LeaseSection view={s.leases} history={s.history} />

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
function LeaseSection({ view, history }: { view: LeaseView; history: HistoryEntry[] }) {
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
  // Standing warnings sit above everything; lapsed ones sink below the rows,
  // because they carry no action and would otherwise push live windows down the
  // screen and suppress the confirmed-revoke note behind stale news.
  const { standing, lapsed } = partitionRevokes(view, history, now);

  return (
    <View>
      <SectionHeader>Active leases</SectionHeader>
      <Card>
        {/* Above the rows on purpose: an unresolved revoke is the most important
            thing this screen can be saying, and it has to survive the snapshot
            that produced it being thrown away. */}
        {standing.map((r, i) => (
          <View key={r.leaseId}>
            {i > 0 ? <Hairline inset={space.lg} /> : null}
            <StandingRevoke revoke={r} now={now} />
          </View>
        ))}
        {/* The Mac steps are hoisted below the last warning rather than repeated
            inside each one: two warnings meant two identical command blocks, and
            a command repeated is a command skimmed. */}
        {standing.length > 0 ? <MacFallback /> : null}
        {standing.length > 0 ? <Hairline inset={space.lg} /> : null}

        {rows.map((l, i) => (
          <View key={l.leaseId}>
            {i > 0 ? <Hairline inset={space.lg} /> : null}
            <LeaseRow lease={l} state={revokeState(view, l.leaseId)} />
          </View>
        ))}
        {rows.length > 0 ? <Hairline inset={space.lg} /> : null}

        {lapsed.map((r) => (
          <View key={r.leaseId}>
            <LapsedRevoke revoke={r} />
            <Hairline inset={space.lg} />
          </View>
        ))}

        <View style={{ padding: space.lg, gap: 4 }}>
          {/* THE TONE INVERSION IS DELIBERATE. DO NOT NORMALISE IT. The
              authoritative claim ("No active leases.") renders MUTED and the
              uncertain one ("cannot check right now", "as of 14:23:07") renders
              at full label weight, which is backwards from how these are usually
              styled and is exactly why it will look like a mistake to someone
              tidying tones later. It is what makes "none" and "cannot tell" read
              apart at a glance, before either sentence is actually read: good news
              recedes, doubt asserts itself. Weighting them the other way would
              make the phone's most confident-looking state the one where it knows
              least. */}
          <Sans size={13} tone={status.authoritative ? "muted" : "label"}>
            {status.line}
          </Sans>
          {status.detail ? (
            <Sans size={12} tone="faint">
              {status.detail}
            </Sans>
          ) : null}
          {view.note && standing.length === 0 ? (
            <Sans size={12} tone="muted" style={{ marginTop: 4 }}>
              {revokeNoteLine(view.note.outcome)}
            </Sans>
          ) : null}
          {DEMO ? (
            <Sans size={12} tone="faint" style={{ marginTop: 4 }}>
              Demo build: any rows or warnings here are samples, not real windows.
            </Sans>
          ) : null}
        </View>

        <Hairline inset={space.lg} />
        {/* The Face ID symbol stays in BOTH states. Disclosing the cost once and
            then hiding it means every later check is a surprise; the cost does
            not go away after the first ask, so neither should the sign of it.
            Disabled outright when no biometric is enrolled, since that is a dead
            end rather than something worth retrying. */}
        <Pressable
          onPress={() => void refreshLeases()}
          disabled={view.asking || view.noBiometric}
          style={({ pressed }) => ({
            flexDirection: "row",
            alignItems: "center",
            gap: space.md,
            padding: space.lg,
            opacity: pressed ? 0.6 : 1,
          })}
        >
          <Sf
            name="faceid"
            color={view.asking || view.noBiometric ? p.faint : p.cobalt}
            size={16}
          />
          <Sans
            size={16}
            style={{ flex: 1, color: view.asking || view.noBiometric ? p.faint : p.cobalt }}
          >
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
/**
 * A revoke that went out and was never answered: the most important thing this
 * section can say, so it reads at full label weight rather than in the faint tone
 * the rest of the supporting copy uses. Brass stays on the ICON, where a colour
 * signal is the point and the 3:1 non-text contrast threshold applies, instead of
 * on 14pt body text where it does not reach AA. Brass and not rust: an
 * unconfirmed revoke is pending, not denied.
 */
function StandingRevoke({ revoke, now }: { revoke: PendingRevoke; now: number }) {
  const p = useTheme();
  return (
    <View style={{ padding: space.lg, gap: 4 }}>
      <View style={{ flexDirection: "row", alignItems: "center", gap: space.sm }}>
        <Sf name="exclamationmark.triangle" color={p.brass} size={15} />
        <Sans size={14} weight="medium" tone="label" style={{ flex: 1 }}>
          {unconfirmedRevokeLine(revoke)}
        </Sans>
      </View>
      <Sans size={12} tone="muted">
        {unconfirmedRevokeDetail(revoke, now)}
      </Sans>
    </View>
  );
}

/**
 * The Mac-side steps, rendered once below the last standing warning rather than
 * inside each one. `sigil lease list` is selectable because it is meant to be
 * copied; the revoke line is NOT, because it ends in a literal `<prefix>`
 * placeholder and pasting that into zsh redirects to a file rather than running
 * anything.
 */
function MacFallback() {
  return (
    <View style={{ paddingHorizontal: space.lg, paddingBottom: space.lg, gap: 4 }}>
      <Mono size={12} tone="muted" selectable>
        {REVOKE_FALLBACK_LIST}
      </Mono>
      <Sans size={12} tone="muted">
        then end the window it shows:
      </Sans>
      <Mono size={12} tone="muted">
        {REVOKE_FALLBACK_REVOKE}
      </Mono>
      <Sans size={12} tone="muted">
        {REVOKE_FALLBACK_CAVEAT}
      </Sans>
    </View>
  );
}

/**
 * A warning whose window has since run out on its own. Demoted to the palette's
 * existing Expired vocabulary (clock on faint) and sunk below the live rows,
 * because there is no action left in it. It stays visible until the section is
 * left, so the resolution is something the reader watches happen rather than
 * something that silently stopped being true.
 */
function LapsedRevoke({ revoke }: { revoke: PendingRevoke }) {
  const p = useTheme();
  return (
    <View style={{ flexDirection: "row", alignItems: "center", gap: space.sm, padding: space.lg }}>
      <Sf name="clock" color={p.faint} size={15} />
      <Sans size={13} tone="muted" style={{ flex: 1 }}>
        {lapsedRevokeLine(revoke)}
      </Sans>
    </View>
  );
}

function LeaseRow({ lease, state }: { lease: ActiveLease; state: RevokeState }) {
  const p = useTheme();
  // 1Hz, not the gauge's 4Hz: remainingWindow is coarse above a minute, so three
  // of every four re-renders produced an identical string. The approval sheet's
  // countdown is a different problem with a different budget.
  const { remainingMs } = useCountdown(lease.expiresAt, lease.windowMs, 10_000, 1_000);
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
            window shut.

            That same argument is why an UNCONFIRMED revoke stays tappable. Dead
            here, the only way left to close the window was the Mac, which is
            refusing made heavier than approving on the one control that must not
            be. Only an attempt actually in flight disables it.

            hitSlop because the label alone is roughly 55x18pt against a 44pt
            minimum, and this is the last control that should be fiddly. */}
        <Pressable
          onPress={() => void revokeLease(lease.leaseId, lease.scope, lease.expiresAt)}
          disabled={state === "sending" || state === "retrying"}
          hitSlop={12}
          style={({ pressed }) => ({ opacity: pressed ? 0.6 : 1 })}
        >
          <Sans
            size={15}
            style={{ color: state === "sending" || state === "retrying" ? p.faint : p.deny }}
          >
            {state === "sending" || state === "retrying" ? "Revoking" : "Revoke"}
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
