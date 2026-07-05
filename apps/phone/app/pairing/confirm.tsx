import { useEffect, useState } from "react";
import { useRouter } from "expo-router";
import { Pressable, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono, Sans } from "@/components/ui/text";
import { Card } from "@/components/ui/primitives";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import {
  awaitDekDelivery,
  currentCeremony,
  resetCeremony,
  submitPairingResponse,
} from "@/src/session/pairing-flow";
import { armLiveSession } from "@/src/session/controller";

type Phase = "handshaking" | "confirm" | "delivering" | "error";

/**
 * The fingerprint confirmation and the live rendezvous. On mount the phone sends
 * its authenticated PairingResponse to the daemon (message 1) over the relay;
 * both devices then show the same six words derived from the two pinned
 * identities. "They match" waits for the daemon's sealed DEK (message 3), stores
 * it, and completes. "Don't match" aborts, because a mismatch is the signature of
 * a man-in-the-middle on the QR channel.
 */
export default function ConfirmScreen() {
  const p = useTheme();
  const router = useRouter();
  const [phase, setPhase] = useState<Phase>("handshaking");
  const [words, setWords] = useState<string[]>([]);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    let alive = true;
    (async () => {
      const c = currentCeremony();
      if (!c?.confirmWords) {
        if (alive) {
          setError("Pairing lost its place. Start again from the Mac's QR code.");
          setPhase("error");
        }
        return;
      }
      if (alive) setWords(c.confirmWords);
      try {
        // Message 1: prove possession of the one-time secret and let the daemon
        // pin this phone, so its screen can show the matching words.
        await submitPairingResponse();
        if (alive) setPhase("confirm");
      } catch (e) {
        if (alive) {
          setError(e instanceof Error ? e.message : "Could not reach the Mac over the relay.");
          setPhase("error");
        }
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  async function onMatch(): Promise<void> {
    setPhase("delivering");
    try {
      // Message 3: the daemon seals the DEK once its human confirms too.
      await awaitDekDelivery();
      // Reflect the freshly persisted pairing into the store (paired: true, armed)
      // so the root layout keeps us on the tabs instead of bouncing back into the
      // pairing stack. Without this the flag only flips on the next cold boot.
      await armLiveSession();
      router.replace({ pathname: "/pairing/done", params: { ok: "1" } });
    } catch (e) {
      setError(e instanceof Error ? e.message : "The Mac did not deliver the key.");
      setPhase("error");
    }
  }

  function onMismatch(): void {
    resetCeremony();
    router.replace({ pathname: "/pairing/done", params: { ok: "0" } });
  }

  if (phase === "error") {
    return (
      <View style={{ flex: 1, padding: space.xl, justifyContent: "center", gap: space.md }}>
        <Sans size={18} weight="semibold" tone="deny">
          Pairing did not complete
        </Sans>
        <Sans tone="muted">{error}</Sans>
      </View>
    );
  }

  return (
    <View style={{ flex: 1, padding: space.xl, gap: space.xl, justifyContent: "center" }}>
      <View style={{ alignItems: "center", gap: space.sm }}>
        {phase === "handshaking" || phase === "delivering" ? (
          <Sf name="dot.radiowaves.left.and.right" color={p.cobalt} size={36} />
        ) : (
          <Sf name="checkmark.shield" color={p.cobalt} size={36} />
        )}
        <Sans size={20} weight="semibold" style={{ textAlign: "center" }}>
          {phase === "handshaking"
            ? "Handshaking…"
            : phase === "delivering"
              ? "Delivering the key…"
              : "Do both screens match?"}
        </Sans>
        <Sans size={15} tone="muted" style={{ textAlign: "center", maxWidth: 320 }}>
          Confirm both devices show these six words.
        </Sans>
      </View>

      <Card style={{ padding: space.xl, alignItems: "center" }}>
        <Mono size={20} weight="semibold" selectable style={{ lineHeight: 32, textAlign: "center" }}>
          {words.join(" · ")}
        </Mono>
      </Card>

      {phase === "confirm" ? (
        <View style={{ gap: space.md }}>
          <Pressable
            onPress={onMatch}
            style={{
              height: 52,
              borderRadius: radius.capsule,
              backgroundColor: p.cobalt,
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Sans size={17} weight="semibold" style={{ color: p.cobaltInk }}>
              They match
            </Sans>
          </Pressable>
          <Pressable
            onPress={onMismatch}
            style={{
              height: 48,
              borderRadius: radius.capsule,
              borderWidth: 1,
              borderColor: p.deny + "a6",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Sans size={16} weight="medium" style={{ color: p.deny }}>
              Don&apos;t match
            </Sans>
          </Pressable>
        </View>
      ) : null}
    </View>
  );
}
