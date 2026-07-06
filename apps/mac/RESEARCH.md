# apps/mac research: pinned versions and APIs (July 2026)

The toolchain and APIs I target, verified locally and against current Apple docs.
Where an API depends on hardware I cannot exercise in this environment, it is
marked **NEEDS VERIFICATION** with the command that confirms it.

## Toolchain (verified locally)

| Thing | Version | How checked |
|---|---|---|
| macOS | 26.3 "Tahoe" (build 25D125) | `sw_vers` |
| Xcode | 26.3 (17C529) | `xcodebuild -version` |
| Swift | 6.2.4 (swiftlang 6.2.4.1.4) | `swift --version` |
| macOS SDK | 26.2 | `xcrun --sdk macosx --show-sdk-version` |
| xcodegen | present at /opt/homebrew/bin | `which xcodegen` |

Deployment target: **macOS 26.0**. Language mode: **Swift 6** (strict concurrency).
The app is single-user, personal-tool scale, so a macOS 26 floor is fine; no
back-deployment fallbacks are carried. This is a deliberate simplification the
brief's "personal tool, never a fleet product" framing licenses.

## What changed since early 2026

Nothing load-bearing moved. Liquid Glass (introduced WWDC 2025, shipped in the
26 line) is now the settled default rather than a beta; the SwiftUI surface below
is GA in the 26.2 SDK. The one thing worth stating plainly: the `Glass` type has
**no `.prominent` value** (a common early-beta misconception). Prominence is
expressed by tint opacity, or by `.buttonStyle(.glassProminent)` for buttons.

## Liquid Glass (native SwiftUI, confirmed real in the 26.2 SDK)

- `.glassEffect(_ glass: Glass = .regular, in shape: some Shape = .rect, isEnabled: Bool = true)`
- `Glass` statics: `.regular`, `.clear`, `.identity`. Modifiers: `.tint(Color)`,
  `.interactive()` (only on genuinely interactive views).
- `GlassEffectContainer(spacing:)` groups nearby glass so they share one sampling
  region (glass cannot sample other glass). The container `spacing` should match
  the layout spacing.
- Button styles `.glass` and `.glassProminent`.
- HIG rule I follow: glass is for the **navigation/control layer floating over
  content**, not for content itself. So: sidebar, menubar popover chrome, the
  approve/deny capsules, fix-it buttons, toolbar get glass; tables and readout
  wells stay on plain grouped-background surfaces. This keeps it a System
  Settings sibling, not a glass novelty.
- Reduced-transparency: the system already degrades `glassEffect` toward opaque
  materials under Accessibility > Reduce Transparency, so no manual fallback is
  needed on a macOS-26 floor.

## MenuBarExtra (confirmed)

- `MenuBarExtra(_:systemImage:) { ... }.menuBarExtraStyle(.window)` gives a
  popover panel that hosts arbitrary SwiftUI (needed for the pending-request list
  + Touch ID buttons). `.menu` style is too limited for our dropdown.
- Icon: the four states differ by **shape**, not color, so they survive the
  monochrome template rendering the menu bar applies. I render them as SF Symbols
  chosen for silhouette (dotted / filled / filled+badge / slashed) rather than
  color, exactly as the brief's table requires. Rendered via `Label(_:image:)`
  with a custom template image so the shape is what carries state.
- The app is an **agent app** (`LSUIElement = true`): no Dock icon, menubar-first.
  The configurator window is opened on demand via `openWindow` /
  `NSApplication.activate`. A Settings scene provides Cmd+, .

## LocalAuthentication + Secure Enclave (the Touch ID / Mac-envelope seam)

Confirmed current API shape (Security.framework + LocalAuthentication):

- Secure Enclave key: `SecKeyCreateRandomKey` with attributes
  `kSecAttrTokenID: kSecAttrTokenIDSecureEnclave`,
  `kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom`, `kSecAttrKeySizeInBits: 256`.
  Only EC P-256 lives in the Enclave.
- Access control: `SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &err)`.
  `.biometryCurrentSet` invalidates the key if the enrolled biometric set
  changes (matches the Rust seam's `.biometryCurrentSet` intent). This is the
  gate: the private key is unusable without a live Touch ID.
- Touch ID prompt: pass an `LAContext` as `kSecUseAuthenticationContext` to the
  decrypt call; the Enclave demands the biometric before it will operate. Set
  `context.localizedReason` / the operation prompt to the approval line.
- Envelope math: the Mac's DEK envelope is **ECIES over the SE P-256 key**
  (`SecKeyCreateEncryptedData` / `SecKeyCreateDecryptedData` with
  `.eciesEncryptionCofactorVariableIVX963SHA256AESGCM`). Approving locally =
  the SE decrypts the wrapped DEK after a live biometric. There is no code path
  that yields the DEK without the Enclave and a biometric.

### Cross-seam contract flag (NEEDS VERIFICATION with rust-core)

The pairing doc's `wrap_dek_for` "second recipient" is described as an **X25519
crypto_box** wrap. **The Secure Enclave cannot do X25519** — it only holds P-256
and performs P-256 ECDH / ECIES. So the Mac envelope the daemon produces for
local approvals must be **P-256 ECIES to an SE public key the Mac hands the
daemon at "Enable Mac approvals" time**, not an X25519 box. This is a genuine
contract question between `apps/mac` and `crates/`:

> **NEEDS VERIFICATION:** the exact wire format of the Mac local-approval
> envelope. `apps/mac` produces a P-256 SE public key; `crates` must wrap the DEK
> to it with P-256 ECIES (`eciesEncryptionCofactorVariableIVX963SHA256AESGCM`),
> and `open_dek`/local-approval path must accept that format. I have coded the
> Swift SE seam to (a) export an ANSI X9.63 SE public key and (b) decrypt a
> P-256 ECIES envelope. If rust-core's `wrap_dek_for` is X25519-only, one side
> must change; the SE cannot be the one that moves.

Confirming commands (must run on real Apple-silicon hardware with an enrolled
biometric, not this build box, not a VM, not the Simulator):

```sh
# SE keygen + biometric-gated decrypt exercised by the app's Security self-test:
#   Latch.app > menubar > (debug) "Run SE self-test"   [DEBUG builds only]
# or headless:
swift apps/mac/Tools/se-selftest.swift     # prints the P-256 pubkey + round-trips ECIES
```

## QR rendering

Native CoreImage `CIFilter.qrCodeGenerator()` upscaled with a nearest-neighbour
transform; no third-party QR dependency. The pairing payload base64 is fed in as
UTF-8. Single-frame scan-fidelity for long endpoint lists remains a phone-side
**NEEDS VERIFICATION** (already noted in `docs/design/pairing.md`).

## Live countdowns

Lease TTL and gauge depletion use `TimelineView(.periodic(from:by:))` /
`.animation`-free redraws so the countdown is a real clock, and collapse to a
numeric readout under Reduce Motion (per the brief's motion rule).

## Dependencies

**Zero third-party.** SwiftUI, AppKit (only where SwiftUI has no equivalent:
`NSApplication.activate`, template menubar image), Security, LocalAuthentication,
CoreImage, CryptoKit. No SPM packages.
