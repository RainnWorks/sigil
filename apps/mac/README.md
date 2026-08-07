# Sigil — Mac configurator + menubar

Native SwiftUI. A single configurator window (source-list sidebar + detail) and
a `MenuBarExtra` pulse. Agent app (no Dock icon); the menubar is always present,
the window opens on demand. A thin skin over the daemon: everything here the
`sigil` CLI can do headless.

See `RESEARCH.md` for the pinned toolchain/API versions and the Liquid Glass /
Secure Enclave / MenuBarExtra decisions.

## Build

```sh
cd apps/mac
xcodegen generate                       # regenerate Sigil.xcodeproj from project.yml
xcodebuild -project Sigil.xcodeproj -scheme Sigil -configuration Debug \
  -destination 'platform=macOS' build CODE_SIGNING_ALLOWED=NO
```

Requires Xcode 26+ / macOS 26 SDK (verified against Xcode 26.3, Swift 6.2.4).
Warnings are errors; a green build has no Swift warnings.

## Run with fixtures (no daemon needed)

```sh
SIGIL_MOCK=1 open Build/.../Sigil.app
```

`SIGIL_MOCK=1` swaps in `MockDaemonClient` + `MockApprover`, so every screen and
state renders and the approve/deny/lockdown/pair flows are demoable end to end
without a running daemon. SwiftUI previews use the mock directly (each view has a
`#Preview` per state).

## Structure

```
Sigil/
  App/            SigilApp (Window + MenuBarExtra + Settings scenes), Info.plist, entitlements
  Design/         Palette (oklch->sRGB), Typography (SF Pro/SF Mono), Glass, MenubarGlyph (4 shape states)
  Model/          Domain types, DaemonClient protocol, Mock + CLI impls, AppModel (observable store)
  Security/       LocalApprovalService protocol, SecureEnclaveApprover (real), MockApprover
  Views/          RootWindow + 6 tabs (Status/Accounts/Pairing/Leases/History/Settings), MenubarContent, components
Tools/
  se-selftest.swift   on-device Secure Enclave round-trip (the NEEDS VERIFICATION command)
```

## The two seams (mirroring the phone app's mock transport)

- **`DaemonClient`** (`Model/DaemonClient.swift`) — the app drives the `sigil`
  binary. `CLIDaemonClient` is coded against a `sigil <cmd> --json` contract that
  rust-core needs to add (the CLI currently emits styled human text only). The
  exact commands and JSON shapes are documented at the top of
  `Model/CLIDaemonClient.swift`. Until they land, run on the mock.
- **`KeystoreWrapKey`** (`Model/KeystoreWrapKey.swift`) — the only Keychain and
  Secure Enclave access in the app, isolated like the Rust `keystore_macos` seam.
  Everything above it sees a two-method protocol.

## Keystore wrapping (the app's Secure Enclave half)

The daemon is portable and unsigned, so it can hold no Enclave key; the signed
app can. The app encrypts `~/.sigil/keystore.json` to a Secure Enclave P-256 key
(tag `works.rainn.sigil.keystore-wrap`, `.privateKeyUsage` only, so unwrapping is
silent) and hands the material to the running daemon over the control socket. On
disk the file becomes `{"v":2,"pub_digest":...,"se_pub":...,"ciphertext":...}`,
useless off this Mac.

Three flows, all in `Model/KeystoreCoordinator.swift`: adopt (v1 -> v2), provision
(on every connection, since the daemon takes material once per lifetime), and
de-adopt. De-adoption is the one path gated on Touch ID, because it is the one
path that lowers protection; it also destroys the wrapping key, and that absence
is the record that the unwrap was sanctioned. A plaintext file next to a
surviving wrapping key is a downgrade and is alarmed as one.

A write-back ("commit") flow is deferred, not missing: the production daemon
never writes the keystore, since every mutation is CLI-side and those are refused
up front while the store is wrapped. `KeystoreWrapper.wrap` already takes
arbitrary material, so switching one on later is a stream case and a fetch verb.

Material never rides inside JSON. Provisioning is a JSON header line naming a
length followed by exactly that many raw bytes on the same connection, so key
material never lands in a `String` that is never cleared.

**Release signing is part of this contract**, not a checklist item (see the
`Release` config in `project.yml`): hardened runtime, library validation, and no
injected `get-task-allow`. The Enclave key is bound to the app's code signature,
so anything that lets other code run inside this process makes the wrap
decorative.

See the design brief's "The keystore at rest" section for what this does and does
not protect: it removes at-rest exfiltration (backups, disk images, synced home
folders), not runtime access.

**Device-gated.** Compilation proves the API usage type-checks and the file
format round-trips; only a signed, installed `.app` proves the Enclave path. An
unsigned binary asking for a data-protection keychain item is killed by amfid
rather than merely refused, so this cannot be exercised from a CLI harness.
