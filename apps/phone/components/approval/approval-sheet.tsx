/**
 * The hero: the approval sheet body. Composes the account header + brass gauge,
 * type banner, readout well, provenance, the risk line, and the risk-scaled
 * approve control alongside the always-one-tap deny. Drives every state:
 * fresh, expiring, expired, approved, denied, superseded.
 *
 * The approval path and the read path are separate: rendering this needs only
 * the already-opened request; committing an approve runs the Face ID gate first
 * and there is no code path that commits without it (invariant: approve requires
 * a hardware-gated biometric, deny requires nothing).
 */
import { useState } from "react";
import { View } from "react-native";

import { Sans } from "@/components/ui/text";
import { Mono } from "@/components/ui/text";
import { useTheme } from "@/theme/colors";
import { space } from "@/theme/tokens";
import { faceGate } from "@/src/lib/biometric";
import { isArmed, liveApprove, liveDeny } from "@/src/session/controller";
import { hapticCommit } from "@/src/lib/haptics";
import { requestSource } from "@/src/lib/format";
import { type PendingRequest } from "@/src/domain/types";
import { store, useSelector } from "@/src/state/store";
import { ApproveControl } from "./approve-control";
import { DenyControl } from "./deny-control";
import { ProvenanceRows } from "./provenance-rows";
import { SecretReadout, SshReadout } from "./readout-well";
import { TimeoutGauge } from "./timeout-gauge";
import { TypeBanner } from "./type-banner";

const riskDot = (risk: PendingRequest["request"]["risk"], p: ReturnType<typeof useTheme>) =>
  risk === "critical" ? p.deny : risk === "elevated" ? p.brass : p.cobalt;

export function ApprovalSheet({
  pending,
  onDone,
}: {
  pending: PendingRequest;
  onDone: () => void;
}) {
  const p = useTheme();
  const reduceMotion = useSelector((s) => s.settings.reduceMotion);
  const [busy, setBusy] = useState(false);
  const [gateNote, setGateNote] = useState<string | null>(null);

  const { request, state } = pending;
  const terminal = state === "approved" || state === "denied" || state === "expired" || state === "superseded";
  const process = request.provenance.processChain[request.provenance.processChain.length - 1] ?? "process";

  async function handleApprove(): Promise<void> {
    setBusy(true);
    setGateNote(null);
    // The biometric is mandatory and non-negotiable; the settings toggle never
    // removes it. When a live pairing is armed, reading the DEK from the
    // biometric-tier keystore IS that gate (it seals the wrappedDek back to the
    // daemon over the relay); when unpaired (dev/demo), faceGate stands in.
    if (isArmed()) {
      const outcome = await liveApprove(request);
      if (outcome !== "sent") {
        setBusy(false);
        setGateNote(
          outcome === "refused"
            ? "Face ID did not pass. Nothing was approved."
            : outcome === "mismatch"
              ? "This request's account does not match the secret shown. Nothing was approved."
              : "Could not reach your Mac. Nothing was approved.",
        );
        return;
      }
    } else {
      const gate = await faceGate("Approve secret release");
      if (!gate.ok) {
        setBusy(false);
        setGateNote(
          gate.reason === "cancelled" ? null : "Face ID did not pass. Nothing was approved.",
        );
        return;
      }
    }
    await hapticCommit("approved");
    store.decide(request.requestId, "approved");
    onDone();
  }

  async function handleDeny(): Promise<void> {
    await hapticCommit("denied");
    if (isArmed()) await liveDeny(request);
    store.decide(request.requestId, "denied");
    onDone();
  }

  async function handleDenyAndBlock(): Promise<void> {
    await hapticCommit("denied");
    if (isArmed()) await liveDeny(request);
    store.decide(request.requestId, "denied", `blocked ${process} 1h`);
    onDone();
  }

  return (
    <View style={{ flex: 1 }}>
      <View style={{ flex: 1, paddingHorizontal: space.xl, gap: space.lg }}>
        {/* account header + gauge */}
        <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center" }}>
          <Mono size={14} tone="muted">
            {requestSource(request)}
          </Mono>
          <TimeoutGauge
            expiresAt={request.expiresAt}
            timeoutMs={request.timeoutMs}
            reduceMotion={reduceMotion}
            frozen={terminal}
          />
        </View>

        <TypeBanner kind={request.kind} />

        {/* R5: name the account this approval unlocks, so consent is bound to the
            account the threshold challenge claims, cross-checkable against the
            readout below. The Face ID prompt repeats this label. */}
        {request.threshold ? (
          <View style={{ flexDirection: "row", alignItems: "baseline", gap: 8 }}>
            <Mono size={12} tone="faint">
              unlocks account
            </Mono>
            <Mono size={14} weight="semibold">
              {request.threshold.label}
            </Mono>
          </View>
        ) : null}

        {request.secrets.length > 0 ? (
          <SecretReadout secrets={request.secrets} />
        ) : request.ssh ? (
          <SshReadout ssh={request.ssh} />
        ) : null}

        <ProvenanceRows provenance={request.provenance} now={Date.now()} />

        {pending.coalesced > 0 ? (
          <Mono size={12} tone="faint">
            {pending.coalesced + 1} identical requests waiting on this decision
          </Mono>
        ) : null}
      </View>

      {/* footer: controls or terminal status */}
      <View style={{ paddingHorizontal: space.xl, paddingTop: space.md, gap: space.md }}>
        {terminal ? (
          <TerminalStatus state={state} onDone={onDone} />
        ) : (
          <>
            {request.reason ? (
              <View style={{ flexDirection: "row", gap: 8, alignItems: "center" }}>
                <View
                  style={{ width: 7, height: 7, borderRadius: 99, backgroundColor: riskDot(request.risk, p) }}
                />
                <Sans size={14} tone="muted" style={{ flexShrink: 1 }}>
                  {request.reason}
                </Sans>
              </View>
            ) : null}
            <ApproveControl risk={request.risk} busy={busy} onApprove={handleApprove} />
            {gateNote ? (
              <Sans size={13} tone="deny" style={{ textAlign: "center" }}>
                {gateNote}
              </Sans>
            ) : null}
            <DenyControl
              process={process}
              disabled={busy}
              onDeny={handleDeny}
              onDenyAndBlock={handleDenyAndBlock}
            />
          </>
        )}
      </View>
    </View>
  );
}

function TerminalStatus({
  state,
  onDone,
}: {
  state: "approved" | "denied" | "expired" | "superseded";
  onDone: () => void;
}) {
  const p = useTheme();
  const copy: Record<typeof state, { text: string; tone: "ok" | "deny" | "faint" }> = {
    approved: { text: "Approved. Secret delivered.", tone: "ok" },
    denied: { text: "Denied. No secret was delivered.", tone: "deny" },
    expired: { text: "Request expired. No secret was delivered.", tone: "faint" },
    superseded: { text: "Superseded by a newer request.", tone: "faint" },
  };
  const c = copy[state];
  return (
    <View style={{ gap: space.md, paddingBottom: space.sm }}>
      <Sans size={16} weight="medium" tone={c.tone} style={{ textAlign: "center" }}>
        {c.text}
      </Sans>
      <Sans
        size={16}
        weight="semibold"
        onPress={onDone}
        style={{ textAlign: "center", color: p.cobalt, paddingVertical: 8 }}
      >
        Done
      </Sans>
    </View>
  );
}
