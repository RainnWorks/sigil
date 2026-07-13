/**
 * The hero: the approval sheet body. Composes the origin header + brass gauge,
 * type banner, readout well, provenance, the reason line, and the
 * always-one-tap approve control alongside the always-one-tap deny.
 *
 * Zero-knowledge approver: this sheet renders only the opaque, Mac-provided
 * DISPLAY fields (caller / command / reason / a display-only `kind` hint, plus
 * the readout the daemon composed). It never interprets provider or account
 * semantics, and it never reasons about what happens on the Mac after a decision
 * leaves the phone. Approving dispatches the decision and shows, at most, that it
 * was sent; it makes no claim that the Mac unlocked or delivered anything.
 *
 * The approval path and the read path are separate: rendering this needs only
 * the already-opened request; committing an approve runs the Face ID gate first
 * and there is no code path that commits without it (invariant: approve requires
 * a hardware-gated biometric, deny requires nothing).
 */
import { useEffect, useState } from "react";
import { View } from "react-native";

import { Sans } from "@/components/ui/text";
import { Mono } from "@/components/ui/text";
import { useTheme } from "@/theme/colors";
import { space } from "@/theme/tokens";
import { faceGate } from "@/src/lib/biometric";
import { isArmed, liveApprove, liveDeny } from "@/src/session/controller";
import { hapticCommit } from "@/src/lib/haptics";
import { durationWindow } from "@/src/lib/format";
import { type Decision } from "@/src/protocol";
import { type PendingRequest } from "@/src/domain/types";
import { store, useSelector } from "@/src/state/store";
import { ApproveControl } from "./approve-control";
import { DenyControl } from "./deny-control";
import { ProvenanceRows } from "./provenance-rows";
import { SecretReadout, SshReadout } from "./readout-well";
import { TimeoutGauge } from "./timeout-gauge";
import { TypeBanner } from "./type-banner";

/** A fixed slot for the gate/status note so the controls below never shift. */
const STATUS_SLOT_HEIGHT = 34;

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
  // The human's just-made decision, held locally so we can show a brief neutral
  // acknowledgement before auto-dismissing. We defer writing it to the store
  // (which removes the request from the active queue) until that moment, so the
  // sheet stays stable during the acknowledgement instead of flashing empty.
  const [committed, setCommitted] = useState<{ decision: Decision; note?: string } | null>(null);

  const { request, state } = pending;
  // A leasable request lets the human approve once OR keep the grant approved
  // for a window up to maxSecs. Run-once requests (no policy) show approve-once
  // only. Purely the daemon's offer; the phone reads the duration and nothing
  // provider-shaped.
  const lease = request.leasePolicy?.kind === "leasable" ? request.leasePolicy : null;
  const terminal = state === "approved" || state === "denied" || state === "expired" || state === "superseded";
  const process = request.provenance.processChain[request.provenance.processChain.length - 1] ?? "process";
  const origin = request.provenance.machine || process;

  useEffect(() => {
    if (!committed) return;
    // Record the decision, then either advance or dismiss. Approve lingers a
    // touch longer so the acknowledgement reads; deny is quicker (it must never
    // feel heavier).
    const delay = committed.decision === "approved" ? 950 : 650;
    const t = setTimeout(() => {
      store.decide(request.requestId, committed.decision, committed.note);
      // If another request is still waiting, leave the sheet open: the route
      // re-selects the next pending one and remounts this component (keyed by
      // request id), so "decide one, the next is right there". Only dismiss when
      // the queue is empty.
      const more = store
        .getState()
        .pending.some((pp) => pp.state === "fresh" || pp.state === "expiring");
      if (!more) onDone();
    }, delay);
    return () => clearTimeout(t);
  }, [committed, request.requestId, onDone]);

  async function handleApprove(leaseWindow?: { ttlMs: number }): Promise<void> {
    setBusy(true);
    setGateNote(null);
    // The biometric is mandatory and non-negotiable; the settings toggle never
    // removes it. When a live pairing is armed, the Face ID gate (the enclave
    // key-agreement for a threshold secret, or the bare gate for a plain gate) IS
    // that gate and seals the response back to the daemon over the relay; when
    // unpaired (dev/demo), faceGate stands in. A non-"sent" live outcome only
    // tells us the decision did not leave this phone; it never carries knowledge
    // of the Mac's state.
    if (isArmed()) {
      const outcome = await liveApprove(request, leaseWindow ? { lease: leaseWindow } : {});
      if (outcome !== "sent") {
        setBusy(false);
        setGateNote(
          outcome === "refused"
            ? "Face ID did not pass. Nothing was approved."
            : // Neutral about cause (a local seal error or an unreachable relay are
              // indistinguishable here and both fail closed); never a claim about
              // the Mac, and never mislabeling a pre-network fault as a send.
              "That didn't go through. Nothing was approved.",
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
    setCommitted({ decision: "approved" });
  }

  async function handleDeny(): Promise<void> {
    await hapticCommit("denied");
    if (isArmed()) await liveDeny(request);
    setCommitted({ decision: "denied" });
  }

  async function handleDenyAndBlock(): Promise<void> {
    await hapticCommit("denied");
    if (isArmed()) await liveDeny(request);
    setCommitted({ decision: "denied", note: `blocked ${process} 1h` });
  }

  return (
    <View style={{ flex: 1 }}>
      <View style={{ flex: 1, paddingHorizontal: space.xl, gap: space.lg }}>
        {/* origin header + gauge */}
        <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center" }}>
          <Mono size={14} tone="muted">
            {origin}
          </Mono>
          <TimeoutGauge
            expiresAt={request.expiresAt}
            timeoutMs={request.timeoutMs}
            reduceMotion={reduceMotion}
            frozen={terminal || committed !== null}
          />
        </View>

        <TypeBanner kind={request.kind} />

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

      {/* footer: controls, the just-sent acknowledgement, or a terminal status */}
      <View style={{ paddingHorizontal: space.xl, paddingTop: space.md, gap: space.md }}>
        {committed ? (
          <DecisionSent decision={committed.decision} />
        ) : terminal ? (
          <TerminalStatus state={state} onDone={onDone} />
        ) : (
          <>
            {request.reason ? (
              <View style={{ flexDirection: "row", gap: 8, alignItems: "center" }}>
                <View
                  style={{ width: 7, height: 7, borderRadius: 99, backgroundColor: p.cobalt }}
                />
                <Sans size={14} tone="muted" style={{ flexShrink: 1 }}>
                  {request.reason}
                </Sans>
              </View>
            ) : null}
            {lease ? (
              <View style={{ gap: space.sm }}>
                <ApproveControl label="Approve once" busy={busy} onApprove={() => void handleApprove()} />
                <ApproveControl
                  variant="secondary"
                  label={`Keep approved for ${durationWindow(lease.maxSecs)}`}
                  busy={busy}
                  onApprove={() => void handleApprove({ ttlMs: lease.maxSecs * 1000 })}
                />
              </View>
            ) : (
              <ApproveControl label="Approve" busy={busy} onApprove={() => void handleApprove()} />
            )}
            {/* Fixed-height status slot: the gate note appears here without ever
                nudging the deny control below it. */}
            <View style={{ height: STATUS_SLOT_HEIGHT, justifyContent: "center" }}>
              {gateNote ? (
                <Sans size={13} tone="deny" style={{ textAlign: "center" }}>
                  {gateNote}
                </Sans>
              ) : null}
            </View>
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

/**
 * The neutral acknowledgement shown for a beat after a decision is dispatched.
 * It reports only that the decision was sent from the phone; it makes no claim
 * about what the Mac did, because the phone does not and must not know.
 */
function DecisionSent({ decision }: { decision: Decision }) {
  const copy =
    decision === "approved"
      ? { text: "Approved. Sent.", tone: "ok" as const }
      : { text: "Denied.", tone: "deny" as const };
  return (
    <View style={{ paddingVertical: space.lg }}>
      <Sans size={16} weight="medium" tone={copy.tone} style={{ textAlign: "center" }}>
        {copy.text}
      </Sans>
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
  // Phone-local facts only, with no claim about the Mac's outcome: the phone
  // sent a decision (or the request timed out / was superseded) and is done.
  const copy: Record<typeof state, { text: string; tone: "ok" | "deny" | "faint" }> = {
    approved: { text: "Approved. Sent.", tone: "ok" },
    denied: { text: "Denied.", tone: "deny" },
    expired: { text: "Request expired.", tone: "faint" },
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
