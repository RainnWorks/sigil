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

import { Sf } from "@/components/ui/sf";
import { Sans } from "@/components/ui/text";
import { Mono } from "@/components/ui/text";
import { useTheme } from "@/theme/colors";
import { space } from "@/theme/tokens";
import { faceGate } from "@/src/lib/biometric";
import { isArmed, liveApprove, liveDeny } from "@/src/session/controller";
import { hapticCommit } from "@/src/lib/haptics";
import { commandWord, coverageLabel, durationWindow } from "@/src/lib/format";
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
  // Which approve is in flight, if any. Not a bare boolean: the two capsules
  // authorize different things (one invocation vs a window), so the frozen state
  // has to say which one the human tapped instead of putting "Approving…" on
  // both. Null while nothing is committing.
  const [inFlight, setInFlight] = useState<"once" | "window" | null>(null);
  const busy = inFlight !== null;
  const [gateNote, setGateNote] = useState<string | null>(null);
  // The human's just-made decision, held locally so we can show a brief neutral
  // acknowledgement before auto-dismissing. We defer writing it to the store
  // (which removes the request from the active queue) until that moment, so the
  // sheet stays stable during the acknowledgement instead of flashing empty.
  // `windowSecs` is set only on an approve that opened a window, so the
  // acknowledgement can name the window the human actually granted.
  const [committed, setCommitted] = useState<{
    decision: Decision;
    note?: string;
    windowSecs?: number;
  } | null>(null);

  const { request, state } = pending;
  // A leasable request lets the human keep the grant approved for a window up to
  // maxSecs (the primary offer) OR approve this one invocation only. Run-once
  // requests (no policy) show approve-only. Purely the daemon's offer; the phone
  // reads the duration and nothing provider-shaped.
  //
  // The window is BROADER than a re-run of this exact argv, on three axes, and
  // the caption below has to carry all three or the consent is not informed
  // (security review F1/F2):
  //   1. other commands the rule matches, not just this argv. The daemon now
  //      states this axis exactly, in `leasePolicy.covers`: a label it renders
  //      from the user's own rule ("op read", "op with --vault", "any command
  //      with the subcommand read"). The phone used to guess it from argv[0],
  //      which could only ever name the command that happened to trip the rule,
  //      never the rule. Display only: rendered, never parsed, never branched on;
  //   2. other SECRETS the rule matches, not just the reference in the readout
  //      well above. This is the axis the human is actually reading, so it is
  //      named explicitly and never left implied. The noun is "secrets", the
  //      phone's own word (see the type banner and SecretRef); "items" is a
  //      provider's noun and this app stays provider-blind;
  //   3. no process, session, or terminal binding. The daemon's grant key binds
  //      the CODE IDENTITY of the ancestor chain and deliberately excludes pids,
  //      so a second agent session in another terminal and another project has
  //      the same chain and rides the same window. "from anywhere on this Mac"
  //      is the honest phrasing; never claim "from this process".
  // Axis 3 makes the caption slightly BROADER than the grant (which also wants a
  // matching caller code identity). That is deliberate: on a consent surface an
  // over-broad claim is safe and an under-broad one is not.
  const lease = request.leasePolicy?.kind === "leasable" ? request.leasePolicy : null;
  const covers = coverageLabel(lease?.covers);
  const terminal = state === "approved" || state === "denied" || state === "expired" || state === "superseded";
  // The actor named on the deny control ("Deny and block op for 1h") and in the
  // block note. It comes from argv[0], NOT from the process chain: the sheet
  // never renders request.command, and the daemon resolves the chain separately,
  // so the two can differ (a chain leaf may carry a subcommand). Null when argv
  // is empty, in which case the deny control falls back to the chain leaf. It
  // deliberately does NOT describe the lease window any more; that is the
  // daemon's `covers` label above.
  const cmd = commandWord(request.command);
  const chainLeaf = request.provenance.processChain[request.provenance.processChain.length - 1] ?? "process";
  const actor = cmd ?? chainLeaf;
  const origin = request.provenance.machine || chainLeaf;

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
    setInFlight(leaseWindow ? "window" : "once");
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
        setInFlight(null);
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
        setInFlight(null);
        setGateNote(
          gate.reason === "cancelled" ? null : "Face ID did not pass. Nothing was approved.",
        );
        return;
      }
    }
    await hapticCommit("approved");
    setCommitted({
      decision: "approved",
      windowSecs: leaseWindow ? Math.round(leaseWindow.ttlMs / 1000) : undefined,
    });
  }

  async function handleDeny(): Promise<void> {
    await hapticCommit("denied");
    if (isArmed()) await liveDeny(request);
    setCommitted({ decision: "denied" });
  }

  async function handleDenyAndBlock(): Promise<void> {
    await hapticCommit("denied");
    if (isArmed()) await liveDeny(request);
    setCommitted({ decision: "denied", note: `blocked ${actor} 1h` });
  }

  return (
    <View style={{ flex: 1 }}>
      <View style={{ flex: 1, paddingHorizontal: space.xl, gap: space.lg }}>
        {/* the asking machine + gauge: the party first, the clock second */}
        <View
          style={{
            flexDirection: "row",
            justifyContent: "space-between",
            alignItems: "center",
            gap: space.md,
          }}
        >
          <View style={{ flexDirection: "row", alignItems: "center", gap: 8, flexShrink: 1 }}>
            <Sf name="laptopcomputer" color={p.muted} size={16} />
            <Mono size={15} weight="medium" numberOfLines={1} style={{ flexShrink: 1 }}>
              {origin}
            </Mono>
          </View>
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

        {/* `pending.relayOrigin` is the relay's unverified claim, kept off the
            signed request object and passed separately so it can never be
            mistaken for daemon-vouched provenance. */}
        <ProvenanceRows
          provenance={request.provenance}
          now={Date.now()}
          {...(pending.relayOrigin ? { relayOrigin: pending.relayOrigin } : {})}
        />

        {pending.coalesced > 0 ? (
          <Mono size={12} tone="faint">
            {pending.coalesced + 1} identical requests waiting on this decision
          </Mono>
        ) : null}
      </View>

      {/* footer: controls, the just-sent acknowledgement, or a terminal status */}
      <View style={{ paddingHorizontal: space.xl, paddingTop: space.md, gap: space.md }}>
        {committed ? (
          <DecisionSent decision={committed.decision} windowSecs={committed.windowSecs} />
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
              <View style={{ gap: space.md }}>
                {/* The caption belongs to the capsule above it, so it sits inside
                    that group (space.sm) and the secondary sits a step away. */}
                <View style={{ gap: space.sm }}>
                  <ApproveControl
                    label={`Keep approved for ${durationWindow(lease.maxSecs)}`}
                    busy={busy}
                    committing={inFlight === "window"}
                    onApprove={() => void handleApprove({ ttlMs: lease.maxSecs * 1000 })}
                  />
                  {/* The breadth of the window, in the daemon's words. "that
                      rule" is load-bearing: it gives the pronoun an antecedent
                      the label itself cannot be, and it stops the label reading
                      as the thing that does the matching. Several of the real
                      shapes are phrases rather than single words (`op with
                      --account "rowmhq.1password.eu"`, `any command with the
                      subcommand read`), so the label carries a weight bump to
                      mark where the rule's description ends; it does NOT carry a
                      tone bump, because on a consent surface the brightest text
                      must not be the half that makes the grant sound contained.
                      "every command and secret" and "from anywhere on this Mac"
                      are the dangerous halves and they read at caption tone.
                      When the daemon sent no label (one that predates the
                      field), the sentence still states both remaining axes and
                      simply cannot name the rule. It never guesses one. */}
                  <Sans size={13} tone="muted">
                    {covers ? (
                      <>
                        Covers{" "}
                        {/* tone is restated, not omitted: Sans defaults to
                            tone="label" and always writes a color, so leaving
                            it off would brighten the label rather than inherit
                            the caption's muted. */}
                        <Sans size={13} weight="medium" tone="muted">
                          {covers}
                        </Sans>
                        : every command and secret that rule matches, from anywhere on this Mac.
                      </>
                    ) : (
                      "Covers every command and secret this rule matches, from anywhere on this Mac."
                    )}
                  </Sans>
                </View>
                <ApproveControl
                  variant="secondary"
                  label="Approve once"
                  busy={busy}
                  committing={inFlight === "once"}
                  onApprove={() => void handleApprove()}
                />
              </View>
            ) : (
              <ApproveControl
                label="Approve"
                busy={busy}
                committing={inFlight === "once"}
                onApprove={() => void handleApprove()}
              />
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
              process={actor}
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
 * about what the Mac did, because the phone does not and must not know. Naming
 * the window on the lease path is likewise a phone-local fact: it is the window
 * this phone chose and sent, not a claim that the Mac honored it.
 */
function DecisionSent({ decision, windowSecs }: { decision: Decision; windowSecs?: number }) {
  const copy =
    decision === "approved"
      ? {
          text:
            windowSecs === undefined
              ? "Approved. Sent."
              : `Approved for ${durationWindow(windowSecs)}. Sent.`,
          tone: "ok" as const,
        }
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
