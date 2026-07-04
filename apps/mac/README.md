# Latch — Mac configurator + menubar

Native SwiftUI. A single configurator window (source-list sidebar + detail) and
a `MenuBarExtra` pulse. Agent app (no Dock icon); the menubar is always present,
the window opens on demand. A thin skin over the daemon: everything here the
`latch` CLI can do headless.

See `RESEARCH.md` for the pinned toolchain/API versions and the Liquid Glass /
Secure Enclave / MenuBarExtra decisions.

## Build

```sh
cd apps/mac
xcodegen generate                       # regenerate Latch.xcodeproj from project.yml
xcodebuild -project Latch.xcodeproj -scheme Latch -configuration Debug \
  -destination 'platform=macOS' build CODE_SIGNING_ALLOWED=NO
```

Requires Xcode 26+ / macOS 26 SDK (verified against Xcode 26.3, Swift 6.2.4).
Warnings are errors; a green build has no Swift warnings.

## Run with fixtures (no daemon needed)

```sh
LATCH_MOCK=1 open Build/.../Latch.app
```

`LATCH_MOCK=1` swaps in `MockDaemonClient` + `MockApprover`, so every screen and
state renders and the approve/deny/lockdown/pair flows are demoable end to end
without a running daemon. SwiftUI previews use the mock directly (each view has a
`#Preview` per state).

## Structure

```
Latch/
  App/            LatchApp (Window + MenuBarExtra + Settings scenes), Info.plist, entitlements
  Design/         Palette (oklch->sRGB), Typography (SF Pro/SF Mono), Glass, MenubarGlyph (4 shape states)
  Model/          Domain types, DaemonClient protocol, Mock + CLI impls, AppModel (observable store)
  Security/       LocalApprovalService protocol, SecureEnclaveApprover (real), MockApprover
  Views/          RootWindow + 6 tabs (Status/Accounts/Pairing/Leases/History/Settings), MenubarContent, components
Tools/
  se-selftest.swift   on-device Secure Enclave round-trip (the NEEDS VERIFICATION command)
```

## The two seams (mirroring the phone app's mock transport)

- **`DaemonClient`** (`Model/DaemonClient.swift`) — the app drives the `latch`
  binary. `CLIDaemonClient` is coded against a `latch <cmd> --json` contract that
  rust-core needs to add (the CLI currently emits styled human text only). The
  exact commands and JSON shapes are documented at the top of
  `Model/CLIDaemonClient.swift`. Until they land, run on the mock.
- **`LocalApprovalService`** (`Security/LocalApproval.swift`) — Touch ID + Secure
  Enclave, isolated like the Rust `keystore_macos` seam.
  `SecureEnclaveApprover` is written against the confirmed API but is marked
  **NEEDS VERIFICATION** (the Enclave can't be exercised off real hardware); run
  `Tools/se-selftest.swift` on an Apple-silicon Mac with an enrolled biometric to
  confirm, and reconcile the envelope format with rust-core's `wrap_dek_for`
  (P-256 ECIES vs X25519 — see RESEARCH.md).
