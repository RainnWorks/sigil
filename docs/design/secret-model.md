# Secret model (agreed 2026-07-13): gate, do not broker

Sigil is a **phone-gated command interceptor** that can inject **its own** stored
secrets. It is NOT a credential broker for other tools.

## The model

1. **Gate.** Sigil intercepts a matched command and requires a phone approval,
   then runs it. This is the product. Most commands need nothing else.
2. **Inject own secrets (optional).** A rule may inject Sigil-stored secrets as
   env vars into the gated command (the `EnvFileProvider` / inline-env shape).
   These secrets are sealed at rest under **threshold** (see below).
3. **1Password (and any provider) = just call it, gated.** You do
   `SECRET=$(op read "op://...")` in your gated command; `op` is gated by Sigil
   and does its own auth. Sigil does NOT hold or inject op's service-account
   token. There is no "account" concept.

## What dies

- **`accounts` / `sigil account *`** — the stored op SA-token catalogue.
- **`OpProvider` credential injection** — injecting `OP_SERVICE_ACCOUNT_TOKEN`
  into a child is exactly the brokering we reject. `op` becomes a plain gated
  command (a normal gate rule), not a special provider.
- **The v1 DEK path entirely** — `Dek`, `secrets::{encrypt,decrypt}_token`, the
  keystore `ensure_dek`/`unwrap_dek`/`has_dek`, `se_ecies`, proto `Dek` /
  deliver_dek, the phone-side DEK, and local Touch-ID auto-approve.
- **Desktop Secure Enclave keystore** — see [[se-needs-app-bundle-signing]];
  threshold replaces it (see [[threshold-replaces-se]]).

## What stays

- **Gating** (rules, leases, lockdown, audit).
- **Own-secret injection** — reframed onto threshold instead of the DEK.
- **Keystore BLOB storage** (daemon identity key, the Mac share `m`) — legacy
  login-keychain generic passwords, no entitlement, works from the unsigned
  binary.
- **The Touch-ID pairing gate** (`verify_presence`) stays as a concept, but its
  current implementation mints a PERSISTENT DataProtection-keychain Secure
  Enclave key, which needs the `keychain-access-groups` entitlement the unsigned
  daemon does not have (proven: OSStatus -34018 / amfid SIGKILL). So on an
  unsigned daemon it breaks pairing. OPEN ITEM: move it to
  `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`
  (LocalAuthentication needs no keychain/entitlement) or a transient
  non-persistent SE key proven on hardware. Until then only the `SIGIL_DEV_KEYSTORE`
  dev path (no biometric, `m` in the clear) pairs. See
  [[verify-presence-persistent-se-key-breaks-unsigned]].
- **Threshold** as the single at-rest seal for everything Sigil owns: injected
  env secrets AND stored SSH keys. Ciphertext on disk, openable only with the
  phone's per-request partial. "No DEK to downgrade to."

## SSH agent = a set of per-host key sources, configured like the gates

An SSH host routes to a *way to get the key*:

- **Stored key** — Sigil holds the private key, threshold-sealed, opened per-sign
  with the phone. This is "store SSH creds for people without 1Password."
- **Key file** — a key already on disk.
- **Gated command** — e.g. `op read "op://.../private key"`, itself gated by
  Sigil. This is the 1Password case; **"1Password quick setup" is a recipe that
  fills in this command source**, not a distinct concept.
- **Secure Enclave** — deferred (needs app-bundle signing).

Honest constraint: an `ssh-agent` SIGN_REQUEST returns a *signature*, and no CLI
emits an SSH-auth signature from op. So a source "gets the key" (gated fetch or a
stored/file read) and **the daemon signs locally** — the key is in daemon RAM for
one signature for every source except SE. Inherent to the agent protocol.

For a headless op-source, op needs non-interactive auth; that credential (if
used) is **a secret injected into that gated `op read`**, via the same
env-injection mechanism — not a global account.

## Teardown order (each crypto phase gets an independent security review)

1. SSH: add the **stored-key (threshold)** source; reframe op-source as a gated
   command; keep file; SE deferred.
2. Migrate inline-`env` injection off the DEK onto threshold.
3. Move the SSH op-source and any provider fetch to the "gated command" shape;
   delete `OpProvider` credential injection; `op` becomes a plain gate.
4. Delete `accounts` / `sigil account *` and `AccountStore.accounts`.
5. Phone: delete the DEK path.
6. Delete the v1 DEK/SE surface in the daemon/proto (keep blob storage +
   verify_presence).
7. Mac app: drop account/DEK UI; SSH pane shows the reframed sources.

Riskiest single step: the SSH signer -> threshold move (it holds a real private
key briefly and gates every signature). It mirrors the provider threshold path
and must be reviewed as such.

See [[threshold-replaces-se]], [[se-needs-app-bundle-signing]],
[[latch-phone-is-provider-blind]], [[latch-binary-split-and-receipt]].
