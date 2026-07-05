import { useEffect, useState } from "react";
import { useRouter } from "expo-router";
import { Pressable, ScrollView, View } from "react-native";

import { Sf } from "@/components/ui/sf";
import { Mono, Sans } from "@/components/ui/text";
import { Card } from "@/components/ui/primitives";
import { useTheme } from "@/theme/colors";
import { radius, space } from "@/theme/tokens";
import { faceGate } from "@/src/lib/biometric";
import { beginCeremony, currentCeremony } from "@/src/session/pairing-flow";

type Step = "generating" | "ready" | "sealing" | "sealed" | "error";

/**
 * The key-generation ceremony: mint Ed25519 + X25519 on-device, then create the
 * SE-gated wrapping key behind a Face ID confirmation, with a plain-language
 * explanation and this phone's own public-key fingerprint.
 */
export default function KeysScreen() {
  const p = useTheme();
  const router = useRouter();
  const [step, setStep] = useState<Step>("generating");
  const [words, setWords] = useState<string[]>([]);
  const [errMsg, setErrMsg] = useState<string>("");

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const c = currentCeremony() ?? (await beginCeremony());
        if (!alive) return;
        setWords(c.ownWords);
        setStep("ready");
      } catch (err) {
        if (alive) {
          setErrMsg(err instanceof Error ? err.message : String(err));
          setStep("error");
        }
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  async function sealWrappingKey(): Promise<void> {
    setStep("sealing");
    const gate = await faceGate("Create the key that holds your unwrap key");
    if (!gate.ok) {
      setStep("ready");
      return;
    }
    setStep("sealed");
  }

  return (
    <ScrollView contentContainerStyle={{ padding: space.xl, gap: space.xl }}>
      <View style={{ gap: space.md }}>
        <Sf name="key.horizontal.fill" color={p.cobalt} size={40} />
        <Sans size={22} weight="semibold">
          This phone is the key
        </Sans>
        <Sans size={16} tone="muted" style={{ lineHeight: 24 }}>
          Latch just generated a signing key and an agreement key inside this phone&apos;s secure
          hardware. The private halves never leave it. Your Mac holds only ciphertext; approving is
          the missing half of the cryptography, not a permission flag.
        </Sans>
      </View>

      <View style={{ gap: space.sm }}>
        <Sans size={13} tone="faint">
          This phone&apos;s fingerprint
        </Sans>
        <Card style={{ padding: space.lg }}>
          {step === "generating" ? (
            <Mono tone="muted">generating…</Mono>
          ) : step === "error" ? (
            <Mono tone="deny" selectable style={{ lineHeight: 22 }}>
              {errMsg || "could not generate keys on this device"}
            </Mono>
          ) : (
            <Mono size={16} selectable style={{ lineHeight: 24 }}>
              {words.join(" · ")}
            </Mono>
          )}
        </Card>
      </View>

      {step === "sealed" ? (
        <View style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
          <Sf name="checkmark.seal.fill" color={p.ok} size={20} />
          <Sans size={15} style={{ color: p.ok }}>
            Wrapping key created and sealed to the Secure Enclave.
          </Sans>
        </View>
      ) : null}

      <View style={{ gap: space.sm }}>
        <Pressable
          disabled={step === "generating" || step === "error"}
          onPress={step === "sealed" ? () => router.push("/pairing/scan") : sealWrappingKey}
          style={{
            height: 52,
            borderRadius: radius.capsule,
            backgroundColor: p.cobalt,
            alignItems: "center",
            justifyContent: "center",
            opacity: step === "generating" || step === "error" ? 0.5 : 1,
          }}
        >
          <Sans size={17} weight="semibold" style={{ color: p.cobaltInk }}>
            {step === "sealing" ? "Confirming…" : step === "sealed" ? "Scan the Mac" : "Create wrapping key (Face ID)"}
          </Sans>
        </Pressable>
      </View>
    </ScrollView>
  );
}
