# Latch approver (apps/phone)

The phone is the product's second factor: it holds the device identity keys and
the DEK wrap, and it never sees a service-account token or a secret value. One
Expo codebase, iOS-first, rendering native UI (SwiftUI primitives and iOS 26
glass via `expo-glass-effect`); Android (Compose) follows in v2 behind the same
seams.

## Run

```sh
bun install
bun run proto:selftest     # crypto loop, no simulator needed
bun run typecheck          # tsc --strict
bunx expo export -p ios    # verify the Metro bundle compiles
```

Native modules (`react-native-libsodium`, `expo-glass-effect`, `expo-camera`,
`expo-local-authentication`) are NOT in Expo Go, so on-device runs need a
development build:

```sh
bunx expo run:ios          # or: eas build --profile development
```

A dev seed (see `app/_layout.tsx`) populates canned pending requests so the
approval sheet and every state are reachable without a daemon.

## Layout

```
app/                       expo-router routes
  _layout.tsx              root Stack + providers + modal surfaces
  (tabs)/                  Home · History · Accounts · Settings (native tabs)
  approval.tsx             the hero: approval sheet (form sheet w/ detents)
  lockdown.tsx             hold-to-seal
  pairing/                 priming → keys → scan → confirm → done
components/
  approval/                gauge, type banner, readout well, provenance,
                           approve control (tap/slide/hold), deny control
  ui/                      Sans/Mono text, SF symbol wrapper, primitives
theme/                     tokens (oklch→hex) and semantic color access
src/
  protocol/                crypto layer — byte-matches crates/proto
  transport/               transport interface + mock (proves the loop)
  session/                 session glue + pairing ceremony state
  state/                   observable store (useSyncExternalStore) + demo data
  lib/                     biometric gate, haptics, countdown, formatting
  domain/                  app-facing types
```

## Protocol layer and the shared test-vector contract

`src/protocol` mirrors `crates/proto` field-for-field: `identity`, `envelope`
(seal/open, canonical bytes), `replay`, `fingerprint` (six words + mailbox id,
sharing the 256-word list in `words.ts`), and `pairing` (QR payload). The one
libsodium seam is `sodium.ts`; on device it is `react-native-libsodium`, in Node
tests it is `libsodium-wrappers` (injected via `sodium-node.ts`).

`ApprovalRequest` / `ApprovalResponse` in `requests.ts` are the payloads carried
*inside* an envelope. `crates/proto` has not landed these yet; this is the
phone's proposed shape and must be reconciled when the Rust type lands (one file,
one diff).

**What rust-core needs to export** (`src/protocol/vectors.contract.ts` has the
full JSON schema and where to drop the file): known-answer vectors for
`canonicalBytes`, `fingerprint` (words + mailbox), `pairingQr`, `open` (an
envelope the daemon sealed + expected plaintext or error), and `replay` (a
guard state machine). `bun run proto:vectors` replays them through this TS
implementation; it is a no-op until the file exists, then a hard CI gate.

## NEEDS VERIFICATION

- **Expo SDK / @expo/ui pins**: pinned to SDK 57 (RN 0.86); reconcile against the
  installed SDK with `bunx expo install --fix`. `@expo/ui/swift-ui` primitives
  are installed but this build uses expo-router native tabs + native controls
  and has not yet swapped list/stack internals to `@expo/ui` host views.
- **libsodium binding**: `react-native-libsodium@1.7` mirrors the
  `libsodium-wrappers` API used here; confirm on device that `crypto_box_easy`,
  `crypto_sign_detached`, `crypto_sign_seed_keypair`, `crypto_generichash`, and
  `crypto_scalarmult_base` behave identically (the shared vectors will prove it).
- **SF Symbols**: `components/ui/sf.tsx` uses `expo-symbols`; SKILL.md prefers
  `expo-image` `sf:` sources. Both render natively; swap the one component if the
  house rule is enforced.
- **Secure Enclave key custody**: `biometric.ts` models the Face ID gate via
  `expo-local-authentication`; binding the wrapping key to the enclave with
  `.biometryCurrentSet` semantics needs a small native module or
  `expo-secure-store` with `requireAuthentication`, confirmed on device.
- **Entitlements**: camera and Face ID usage strings are set in `app.json`;
  `remote-notification` background mode is declared for the doorbell.

## Stubbed for later

- **Real transport** (LAN Bonjour, owned endpoint, blind relay): only the mock
  exists; `src/transport/transport.ts` is the interface the real rungs fill.
- **Real push**: the notification-service-extension fetch down the ladder and
  APNs registration are not wired; priming and permission ask are.
- **SQLite history mirror**: history is in-memory demo data; `expo-sqlite` is
  installed for the local audit mirror (names and metadata, never values).
