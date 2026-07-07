# Security claims → enforcing code → proving test

This is the map a skeptical adopter reads. Every row is a claim Sigil makes,
the exact code that enforces it (`file::symbol`), and the test that proves it.
A claim with no test is marked **UNPROVEN** in bold; a claim proven only for a
seam that is not yet wired into the shipping daemon is marked **PARTIAL** with
the gap named.

Paths are relative to the repo root. Test names are the `#[test]` fn names;
run any with `cargo test <name>`.

**Authorship convention (review integrity).** The claim/code/test rows and the
residuals are maintained by whoever touches the surface. But a *verdict* — any
"reviewed and found sound" / "CONFIRMED SOUND" statement about whether a
construction is correct — is written **only by an independent security-reviewer
that did not author the code under review**, never by the implementer
(self-certification is not a verdict). A proving-test cell reading "reviewed by
inspection" is a narrower thing: a reviewer's note that a specific claim is
verified by manual inspection because it has no automated test (and it is flagged
**UNPROVEN** where inspection is the only evidence). It is not a soundness
verdict. Sweep at `747b3a4`: the only construction verdict in this document is
§14 (P-256 SE wrap), written by the reviewer, not the implementer.

Reviewed at commit `3d005aa` (the first end-to-end remote-approval loop).
Extended at commit `ee49ee3` (any-CLI generalization: provider registry, the
`env-file` direct-injection provider, the pluggable SSH signer, and the
CLI-only pairing persistence) — sections 11–13 and residuals 9–11 below.
Extended again at commit `747b3a4` (the P-256 Secure Enclave DEK wrap) — section
14 and residual 12; and the env-file invalid-UTF-8 residual was fixed (see §12).

---

## 1. Root of trust: pairing is MITM-safe

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The optical QR carries the daemon's real keys + a 256-bit one-time secret; the phone pins the daemon with certainty | `proto/src/pairing.rs::PairingPayload`, `PhonePairing::scan` | `pairing.rs::qr_roundtrip_preserves_payload` |
| A network attacker who swaps the phone's **full** identity on the return channel is rejected | `proto/src/pairing.rs::PairingResponse::verify` (tag over `pairing_transcript` binding `phone.verifying`+`phone.agreement`) | `pairing_mitm.rs::full_phone_identity_substitution_is_rejected` |
| Swapping only the phone **agreement** key is rejected | same | `pairing_mitm.rs::phone_agreement_key_substitution_alone_is_rejected` |
| Swapping only the phone **verifying** key is rejected | same | `pairing_mitm.rs::phone_verifying_key_substitution_alone_is_rejected` |
| A forged / stripped / bit-flipped confirmation tag is rejected | `pairing.rs::verify_confirmation_tag` (constant-time `Mac::verify_slice`) | `pairing_mitm.rs::forged_random_tag_is_rejected`, `stripped_zero_tag_is_rejected`, `single_bit_flip_in_tag_is_rejected` |
| An attacker without the QR secret cannot forge an acceptable response | `pairing.rs::derive_subkey` (MAC key = secret) | `pairing_mitm.rs::response_built_without_the_qr_secret_is_rejected` |
| Every transcript-bound field (daemon id, endpoints, created_at, phone id, nonce) actually breaks the tag when mutated | `pairing.rs::pairing_transcript` | `pairing_mitm.rs::transcript_binds_daemon_identity`, `transcript_binds_endpoints`, `transcript_binds_created_at`, `transcript_binds_phone_identity_and_nonce`, `nonce_tamper_is_rejected` |
| A response captured from pairing A is worthless against fresh pairing B | `pairing.rs::PairingResponse::verify` | `pairing_mitm.rs::a_captured_response_is_worthless_against_a_fresh_pairing` |
| A stale/expired QR is refused, expiry checked **before** the tag | `pairing.rs::DaemonPairing::receive_response`, `PhonePairing::scan` | `pairing_mitm.rs::expired_response_is_rejected_before_the_tag`, `phone_rejects_a_stale_qr_at_scan` |
| A flood of bad responses never burns the one-time secret | `pairing.rs::receive_response` (consumes only on valid tag) | `pairing_mitm.rs::a_flood_of_bad_responses_never_burns_the_secret` |
| The secret is one-time: a second valid response is refused (daemon and phone) | `receive_response` (`consumed`), `PhonePairing::respond` (`secret.take()`) | `pairing_mitm.rs::a_second_valid_response_is_refused_after_the_first`, `the_phone_emits_exactly_one_response` |
| SAS catches a **leaked-secret** MITM (attacker forged a valid tag with its own key): the six words diverge on the two screens | `pairing.rs::sas_words`, `fingerprint.rs::fingerprint_words`, `verify_sas` | `pairing_mitm.rs::sas_catches_a_leaked_secret_mitm`, `sas_words_diverge_whenever_the_pinned_pair_differs` |
| The pairing secret is CSPRNG, zeroized, and redacts its Debug | `pairing.rs::PairingSecret` (`ZeroizeOnDrop`, custom `Debug`) | `pairing.rs::debug_does_not_leak_secret` |

## 2. DEK handoff and the DEK-return path

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The DEK is delivered to the phone only after SAS confirmation | `pairing.rs::DaemonPairing::deliver_dek` (requires `Confirmed`) | `pairing_mitm.rs::dek_is_never_delivered_before_sas_confirmation`, `pairing.rs::dek_not_delivered_before_confirmation` |
| A DEK envelope forged by a relay key is rejected (wrong sender) | `proto/src/envelope.rs::Envelope::open` (Ed25519 over `canonical_bytes`) | `pairing_mitm.rs::dek_from_a_forged_sender_is_rejected` |
| A DEK sealed to the phone cannot be opened by any other recipient | `envelope.rs::Envelope::open` (crypto_box to pinned agreement key) | `pairing_mitm.rs::dek_to_the_wrong_recipient_cannot_be_opened` |
| A replayed DEK envelope is rejected | `envelope.rs` + `replay.rs::ReplayGuard` | `pairing_mitm.rs::a_replayed_dek_envelope_is_rejected` |
| On approve, the phone's `ApprovalResponse` carries the DEK sealed inside the Envelope; a relay/MITM can neither read nor replay it | `request.rs::ApprovalResponse::approve`, `remote.rs::RemoteApprover::round_trip` (open + `guard` + `request_id` correlation) | `daemon.rs::remote_softphone_approval_delivers_secret_over_the_socket`; envelope confidentiality by `hostile_relay.rs::relay_cannot_read_the_payload` |
| A deny response carries **no** DEK, so a denial can never release a secret | `request.rs::ApprovalResponse::deny`, `remote.rs` (approve without DEK fails closed) | `daemon.rs::remote_softphone_denial_fails_closed_with_no_secret`, `request.rs::approve_carries_the_dek_and_deny_never_does` |
| A malformed DEK base64 fails closed to `None`, never a partial key | `request.rs::ApprovalResponse::dek` | `request.rs::malformed_dek_base64_fails_closed_to_none` |
| The decoded DEK bytes do not linger in a non-zeroized heap buffer | `request.rs::ApprovalResponse::dek` (`Zeroizing` decode buffer) | *(hardening; covered by roundtrip `response_round_trips_through_json`)* |
| The daemon zeroizes the DEK immediately after decrypting the one token | `daemon.rs::fulfill` (`drop(dek)` after `decrypt_token`; `Dek` is `Zeroizing`) | **UNPROVEN** by direct observation (drop timing is not asserted); exercised end-to-end by `remote_softphone_approval_delivers_secret_over_the_socket` |

## 3. Daemon inert at rest

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Tokens are AES-256-GCM ciphertext at rest; no plaintext token on disk | `secrets.rs::encrypt_token`, `AccountStore::save` (0600 file / 0700 dir) | `secrets.rs::store_persists_ciphertext_only` |
| AES-256-GCM nonce is random per seal; identical plaintext yields different ciphertext (no nonce reuse) | `secrets.rs::encrypt_token` (`OsRng` 96-bit nonce) | `secrets.rs::nonce_is_unique_so_ciphertext_differs` |
| Wrong DEK or tampered ciphertext is rejected (authenticated) | `secrets.rs::decrypt_token` | `secrets.rs::wrong_dek_fails_to_decrypt`, `tampered_ciphertext_is_rejected`, `truncated_ciphertext_is_rejected` |
| In the remote configuration the daemon holds **no** DEK at rest; the key arrives per-approval from the phone | `daemon.rs::Core` (MemoryKeystore with no DEK), `remote.rs` | `daemon.rs::remote_softphone_approval_delivers_secret_over_the_socket` (keystore has no DEK) |
| The DEK is CSPRNG and zeroized | `secrets.rs::generate_dek` (`Zeroizing`), `pairing.rs::Dek` (`ZeroizeOnDrop`) | `secrets.rs::dek_is_random_each_call`, `pairing.rs::dek_debug_does_not_leak` |

## 4. Secrets bypass the daemon (invariant #2)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The `op` child's stdout/stderr are the caller's own fds; secret bytes never enter daemon memory | `daemon.rs::spawn_op` (`Stdio::from(fd)`), `local.rs::recv_with_fds` (SCM_RIGHTS) | `daemon.rs::dev_autoapprove_full_loop_delivers_secret_to_caller` (asserts secret reached the *caller* fd), `local.rs::op_fd_passing_and_reply_roundtrip_over_a_socketpair` |
| The provider seam injects a **credential** (SA token) into the child env, never fetches secret values into the daemon | `provider.rs` (describe/kind only), `daemon.rs::spawn_op` (`OP_SERVICE_ACCOUNT_TOKEN`) | `provider.rs::describe_extracts_op_references_only`; end-to-end `remote_softphone_approval_delivers_secret_over_the_socket` |
| The daemon never logs the token or secret output; only argv/cwd/pid | `daemon.rs::log_request`, `secrets.rs::probe_vaults` (suppresses token-bearing stderr) | **UNPROVEN** (no negative-logging assertion); reviewed by inspection |

## 5. Replay is impossible (post-pairing envelopes)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Single-use uuidv7 request id | `replay.rs::ReplayGuard::check_and_record` | `replay.rs::duplicate_request_id_is_rejected`, `hostile_relay.rs::replay_of_a_delivered_envelope_is_rejected` |
| Per-pairing monotonic counter must strictly advance | `replay.rs` | `replay.rs::counter_must_strictly_advance`, `hostile_relay.rs::a_genuinely_old_lower_counter_message_is_rejected`, `reordering_queued_envelopes_is_caught` |
| 90s freshness window; held-late and skewed envelopes rejected | `replay.rs`, `lib.rs::REPLAY_WINDOW_MS` | `replay.rs::stale_timestamp_beyond_window_is_rejected`, `future_timestamp_beyond_window_is_rejected`, `hostile_relay.rs::an_envelope_held_past_the_window_is_rejected` |
| Any field tamper breaks the Ed25519 signature | `envelope.rs::canonical_bytes`, `open` | `envelope.rs::any_field_tamper_breaks_the_signature`, `hostile_relay.rs::{bit_flipped_ciphertext,swapped_ciphertext_between_envelopes,forged_envelope_from_relay_key}_is_rejected` |
| A rejected envelope never poisons later state | `replay.rs::check_and_record` (record only on full pass) | `replay.rs::rejected_envelope_does_not_advance_state` |

## 6. Biometric gating is structural (invariant #5)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| A dev/in-memory keystore can never count as the biometric approving factor | `keystore.rs::Keystore::is_biometric` (default `false`), `approve.rs::LocalApprover::decide_local` (guard `is_biometric() && has_dek()`) | `keystore.rs::memory_keystore_is_not_a_biometric_factor`, `approve.rs::dev_autoapprove_grants_without_biometrics` (grant only via explicit dev switch) |
| Only the macOS Secure Enclave keystore reports biometric, and its unwrap refuses until verified on hardware | `keystore_macos.rs::MacKeystore::is_biometric` (`true`), `unwrap_dek` (`NeedsVerification`) | `keystore_macos.rs::se_paths_refuse_until_verified` |
| Deny / timeout always fails closed (never a grant) | `approve.rs::LocalApprover::decide_local` (timeout → `Deny`), `remote.rs::RemoteApprover::decide` (`unwrap_or Deny`) | `approve.rs::local_timeout_fails_closed`, `daemon.rs::denied_request_fails_closed_and_delivers_no_secret` |
| The Secure Enclave DEK unwrap fires Touch ID on real hardware | `keystore_macos.rs::unwrap_dek` | **UNPROVEN — PARTIAL**: FFI is documented but returns `NeedsVerification`; must be exercised on a Mac (see NEEDS-VERIFICATION block). Until then, the shipping local approver falls through to the control socket (see Residuals). |

## 7. Caller identity is daemon-verified (invariant #6)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Peer pid is read from the kernel, not the client | `lease.rs::peer_pid` (`LOCAL_PEERPID`/`SO_PEERCRED`) | **UNPROVEN — PARTIAL** on hardware (`NEEDS-VERIFICATION` in `lease.rs`); logic exercised via injected pid in daemon tests |
| Ancestry is walked kernel-side; the grant key binds code identity, never pids | `lease.rs::walk_ancestry`, `grant_key` (excludes pids) | `lease.rs::ancestry_walk_is_root_first_and_stops_at_init`, `grant_key_ignores_recycled_pids`, `grant_key_changes_with_root_scope_or_ancestry` |
| The ancestry walk terminates on cycles / bounded depth | `lease.rs::walk_ancestry` (`MAX_ANCESTRY_DEPTH`, `seen` set) | `lease.rs::ancestry_walk_terminates_on_a_cycle` |
| A phone-claimed grant key is ignored; the daemon derives and trusts its own | `daemon.rs::fulfill` (uses `gk`), `request.rs::InstallLease` (echo only), `softphone/lib.rs` (empty `grant_key`) | reviewed by inspection; exercised by `daemon.rs::lease_decision_covers_the_next_identical_request` |
| The ancestor "code identity" is a real code-signing measurement | `lease.rs::SysProcessTable::identity` | **UNPROVEN — PARTIAL**: interim BLAKE2b of the exe bytes; the design calls for the cdhash / Developer ID (NEEDS-VERIFICATION in `lease.rs`) |

## 8. Fail closed, leases bounded, lockdown (invariants #7, #8)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Every failure path denies (deny, timeout, dead phone, decrypt failure, lockdown) | `daemon.rs::fulfill` (`fail_closed` on each branch), `remote.rs::round_trip` (`?`/`None` → Deny) | `daemon.rs::denied_request_fails_closed_and_delivers_no_secret`, `remote_softphone_denial_fails_closed_with_no_secret`, `approve.rs::local_timeout_fails_closed` |
| Leases are RAM-only, triple-scoped (grant key + account + scope) | `lease.rs::LeaseStore`, `Lease` | `lease.rs::lease_grant_lookup_and_scope_isolation` |
| Leases expire on TTL and are purged (and zeroized) | `lease.rs::token_for`/`grant` (`retain(expires>now)`; token is `Zeroizing`) | `lease.rs::lease_expires_and_is_purged` |
| Lockdown clears (zeroizes) every lease and refuses new requests | `daemon.rs::handle_conn` (`Lockdown`), `lease.rs::LeaseStore::clear`, `fulfill` (lockdown check first) | `lease.rs::lockdown_clears_all_leases`, `daemon.rs::lockdown_refuses_new_requests` |
| Daemon restart / ctrl-c zeroizes leases | `daemon.rs::serve` (`core.leases.clear()` on ctrl-c) + RAM-only storage | **UNPROVEN** by test (process-exit path); RAM-only + `clear()` reviewed by inspection |
| A revoke drops matching leases | `lease.rs::LeaseStore::revoke` | `lease.rs::revoke_by_grant_prefix` |

## 9. The relay is powerless (invariant #3)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The relay never sees plaintext (opaque envelopes only) | `envelope.rs::Envelope`, `transport.rs` (carries opaque envelopes); the real network transport carries the same opaque `serde_json` envelope string (`relay-client/src/lib.rs::wire`, daemon-side WS `DaemonRelay`, phone-side HTTPS `PhoneRelay`) | `hostile_relay.rs::relay_cannot_read_the_payload`; end to end over the **real** Bun relay by `daemon.rs::remote_approval_over_the_real_relay_delivers_the_secret` |
| The relay cannot forge, tamper, replay, reorder, backdate, or drop-to-effect | `envelope.rs::open`, `replay.rs` (unchanged whichever transport carries the bytes) | the full `hostile_relay.rs` suite (14 attacks) |
| The mailbox id carries no identity and is order-independent | `fingerprint.rs::mailbox_id` | `fingerprint.rs::mailbox_is_order_independent`, `mailbox_differs_for_different_pairs`, `fingerprint_and_mailbox_are_domain_separated` |
| The relay has no key-distribution role (pairing is out-of-band QR) | `pairing.rs` (keys travel optically) | design invariant; the whole `pairing_mitm.rs` suite proves trust does not rest on any network party |

## 10. Pairing persistence stays inert at rest (the `sigil pair` at-rest format)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The persisted set is `{daemon private identity → keystore, phone PUBLIC identity, relay URL, SAS words}`; no DEK, no DEK envelope, no pairing secret is ever persisted | `pairing_store.rs::{save,PersistedPairing,NewPairing}` | `pairing_store.rs::config_file_is_0600_and_holds_no_dek` (asserts no `dek`/`secret`/`signing` substring), `daemon.rs::persisted_pairing_reloads_and_stays_inert_at_rest` (`has_dek()==false`) |
| The daemon private identity is sealed into the keystore blob seam (Keychain on macOS), never the plaintext file | `pairing_store.rs::save` (`store_blob(DAEMON_IDENTITY_LABEL, …)`), `keystore_macos.rs::MacKeystore::store_blob` | `pairing_store.rs::save_then_load_reconstructs_the_config_and_pins_the_phone` |
| The 64-byte identity serialization is `Zeroizing`, length-checked, and fails closed on a corrupt/truncated blob (no partial key) | `identity.rs::DeviceIdentity::{to_secret_bytes,from_secret_bytes}` (intermediates zeroized) | `identity.rs::secret_bytes_round_trip_preserves_the_public_identity`, `from_secret_bytes_rejects_a_wrong_length_blob` |
| The public config file is 0600 and holds no key material | `pairing_store.rs::save` (`set_permissions 0o600`) | `pairing_store.rs::config_file_is_0600_and_holds_no_dek` |
| An attacker with the whole disk cannot produce a secret: tokens are ciphertext under the DEK the daemon does not hold; the stolen state can only *ask* the phone, which requires a fresh hardware-gated approval | `pairing_store.rs` (no DEK persisted), `daemon.rs::fulfill` (DEK arrives per-approval), `remote.rs` | `daemon.rs::reloaded_pairing_serves_a_secret_over_the_real_relay` (reloaded identity serves a secret ONLY via the phone's sealed DEK, `has_dek()==false`) |
| A half-broken pairing (config present, keystore identity gone) surfaces loudly instead of silently failing | `pairing_store.rs::load` (`MissingIdentity`/`CorruptIdentity`), `daemon.rs::load_remote_pairing` (logs, treats as no-pairing → fails closed) | `pairing_store.rs::config_present_but_identity_missing_is_a_loud_error` |
| The bootstrap **rendezvous mailbox** is domain-separated and non-invertible: leaking it reveals nothing about the secret | `pairing.rs::rendezvous_mailbox` (`BLAKE2b(RENDEZVOUS_DOMAIN ‖ daemon.verifying ‖ daemon.agreement ‖ secret)`, distinct from `mailbox_id`/`fingerprint`/confirm-tag domains; secret is 256-bit CSPRNG so preimage-resistant) | reviewed by inspection (domain constants distinct; length-prefixed absorb is injective); **UNPROVEN** by a dedicated test — no negative test asserts domain separation of the rendezvous id |
| Pairing message 1 (`PairingResponse`) travels the relay as MAC-authenticated plaintext carrying only public data (phone pubkey, nonce, tag); substitution is rejected | `pairing.rs::PairingResponse::verify`, `relay-client/src/rendezvous_ws.rs` (moves opaque strings only, no envelope/key handling) | the full `pairing_mitm.rs` suite (message 1 is exactly what it attacks) |
| Persisting a pairing auto-selects the phone factor with no dev flag | `daemon.rs::{load_remote_pairing,build_gate}` (`Factor::Phone`) | `daemon.rs::build_gate_selects_the_phone_approver_from_a_persisted_config` |

## 11. The provider seam (any-CLI generalization, `ee49ee3`)

The daemon core became provider-agnostic: a command's config names a provider,
and the daemon dispatches the gated run to it. Two injection shapes ship, and
the security boundary between them is stated honestly, not blurred.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| An **unconfigured** command is refused, never run ungated; the caller gets the exact `sigil config add` hint | `daemon.rs::fulfill` (`commands.resolve` → `None` → `fail_closed`), `command.rs::CommandStore::resolve` (only `op` resolves by default) | `daemon.rs::unconfigured_command_is_refused_with_a_config_hint`, `command.rs::an_unconfigured_command_does_not_resolve` |
| A config entry naming an **unknown provider** fails closed, never runs | `daemon.rs::fulfill` (`providers.get` → `None` → `fail_closed`) | reviewed by inspection (the `unknown provider` branch); exercised structurally by `provider.rs::registry_dispatches_by_id_and_lists_defaults` |
| The env-file **source path comes only from the CLI-side config (0600), never from the caller's argv**, so a caller cannot redirect env-file at an arbitrary file (`/etc/shadow`, a co-worker's `.env`) | `daemon.rs::fulfill` (`source = cfg.source`, argv is never consulted for the source), `command.rs` (config is a CLI-only mutation surface) | reviewed by inspection; the config-store add/get/remove path is `command.rs::add_get_remove_round_trip_and_reject_duplicates` |
| A command that **shadows a reserved verb** fails toward the built-in verb (safe), never toward ungated execution; the escape hatch is `sigil run -- <cmd>` | `cli.rs::main` dispatch + `is_reserved_verb`, `shim.rs::dispatch` (the daemon's `fulfill` is the sole injection chokepoint) | `cli.rs::reserved_verbs_take_precedence_over_command_dispatch` |
| Argv is passed to the child as **separate argv entries, never a shell string** (no shell-injection surface); the real binary is resolved via PATH skipping the shim | `provider.rs::{OpProvider,EnvFileProvider}::run` (`Command::new(real).args(...)`), `paths::{find_real,find_real_op}` | `daemon.rs::env_file_command_runs_gated_and_injects_env`, `provider.rs::run_streams_op_child_output_to_the_caller_fd` |
| A **down daemon** makes the shim exec the bare tool with **no injected secret** (fail-safe: nothing is released); a protocol error while the daemon is **up** fails closed (exit 70), never runs ungated | `shim.rs::dispatch` (`Ok`→exit code; `forward` error→exit 70; only a *down* socket → `exec_real`), `shim.rs::exec_real` (no env injected) | reviewed by inspection (the module contract; no negative test asserts the exec fallback injects nothing) — **UNPROVEN** by a dedicated test |

## 12. The `env-file` direct-injection provider (invariant #2, honestly relaxed)

`env-file` is the reference provider that proves the seam is not op-shaped. It is
the **one** path where resolved secret VALUES (not a credential) transit daemon
RAM, and the doc is explicit about the exact residual that buys.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| `describe()` names the source **without reading it**, so no secret value enters daemon memory before the decision | `provider.rs::EnvFileProvider::describe` (uses `Path::file_name` only, never `read`) | reviewed by inspection; `provider.rs::env_file_parses_pairs_and_strips_quotes_and_comments` covers the parser that runs only at `run()` time |
| The file is read into a `Zeroizing` buffer and every value lands in a `Zeroizing` string; both are wiped when the map drops at end of `run()` | `provider.rs::{EnvFileProvider::run,parse_env_file}` (`Zeroizing::new(bytes)`, `Zeroizing<Vec<(String, Zeroizing<String>)>>`) | `provider.rs::env_file_provider_injects_the_vars_into_the_child` (values reach the child), parser by `env_file_parses_pairs_and_strips_quotes_and_comments` |
| **Leasing is disabled for env-file**: a lease would hold resolved values in RAM across a TTL, so a direct-injection provider is gated on **every** run — even when the decision grants a session lease | `daemon.rs::fulfill` (the lease short-circuit and the `grant` are both inside `if needs_account` / `if let Some(ciphertext)`, and `EnvFileProvider::needs_account()==false`) | `daemon.rs::env_file_lease_decision_grants_no_lease` (Lease decision → runs once, `leases.active()==0`), `env_file_command_runs_gated_and_injects_env` (`active()==0`) |
| `needs_account()==false` correctly gates that env-file **never** routes an account, unwraps the DEK, or touches leasing | `provider.rs::EnvFileProvider::needs_account`, `daemon.rs::fulfill` (all account/DEK/lease work guarded by `needs_account`) | `provider.rs::op_provider_needs_an_account_and_env_file_does_not`, `daemon.rs::env_file_command_runs_gated_and_injects_env` |
| No value is ever logged: every env-file error line names the **path / io error only** | `provider.rs::EnvFileProvider::run` (all `eprintln!` carry `run.source` or `command[0]`, never a value) | reviewed by inspection (no negative-logging assertion) — **UNPROVEN** by test |
| The parser cannot panic on hostile input, and an **invalid-UTF-8** file fails closed with no owned/un-zeroized `String` allocated (borrows with `str::from_utf8`, returns `None`; `split_once` guard; `len() >= 2` quote guard) | `provider.rs::{parse_env_file,EnvFileProvider::run}` | `provider.rs::{env_file_parses_pairs_and_strips_quotes_and_comments,env_file_with_invalid_utf8_is_rejected,env_file_run_fails_closed_on_invalid_utf8}` |

See **residual 9** for the two un-wiped copies this shape unavoidably leaves (the
`Command` env map and the child's `/proc/<pid>/environ`).

## 13. The pluggable SSH signer (invariant #5, per-signature custody)

The daemon holds `Vec<Box<dyn SshSigner>>`; after the phone gate it routes the
signature to the signer that owns the key. Two signers ship (`OpSshSigner`,
`FileSshSigner`); the gate is applied by the Core **before** `sign()` is called.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| **No signer can sign without the gate having passed**: `Core::approve_and_sign` runs `gate.decide` and returns `None` on any non-grant *before* calling `signer.sign` | `daemon.rs::Core::approve_and_sign` (`if !outcome.decision.is_grant() { return None }` precedes the `signer.sign` call); the `ssh_signers` field is private, so `sign()` has no other daemon caller | `daemon.rs::ssh_file_signer_denied_gate_yields_no_signature` (denied gate → `None`, signer never reached), `sshagent.rs::a_denied_sign_request_yields_failure_and_no_signature` |
| The **data-to-sign hash is bound into the approval**: the scope folds in `sha256(data)`, so the gate's grant-key coalescing can never let one challenge ride another's approval; only a byte-identical re-sign coalesces | `daemon.rs::{ssh_sign_scope,approve_and_sign}` (`scope = "ssh-sign {label} {sha256(data)}"`, `gk = grant_key(caller,"",scope)`) | `daemon.rs::different_ssh_challenges_do_not_share_a_grant_key` |
| The human approves the **hash of exactly the bytes signed**: the phone shows `sha256(data)`; the signer signs the same `data` verbatim | `sshagent.rs::sign` (`data` passed through), `daemon.rs::approve_and_sign` (`fingerprint = sha256_fingerprint(req.data)`, `signer.sign(req.id, req.data, ...)`) | `sshagent.rs::sign_request_produces_a_signature_that_verifies`, `fetch_and_sign_reads_the_key_and_signs_a_verifiable_signature` |
| **Every SSH signature is gated** (no lease short-circuit in v1): the sign path never consults `leases` | `daemon.rs::approve_and_sign` (no `token_for`/`grant` call anywhere in the path) | reviewed by inspection; contrasted with the leased op path in `fulfill` |
| A **wrong / missing / non-ed25519 / passphrase-encrypted key fails closed** to no signature (both signers) | `sshagent.rs::{FileSshSigner::sign` (`find(...)?`, `fs::read(...).ok()?`), `OpSshSigner::sign` (`credential?`), `sign_openssh_ed25519` (ed25519-only, `from_openssh(...).ok()?`)}` | `sshagent.rs::{fetch_and_sign_fails_closed_when_the_token_is_wrong,op_signer_fetches_and_signs_and_requires_a_credential (no-credential branch),sign_request_for_an_unknown_key_is_refused}` |
| Both signers hold key material in a `Zeroizing` buffer for the **one** signature and wipe it; the key never reaches the SSH client | `sshagent.rs::{op_read_openssh_key` (stdout→`Zeroizing`, stderr `null`), `FileSshSigner::sign` (`Zeroizing::new(fs::read)`), `sign_openssh_ed25519` (`ssh_key::PrivateKey` zeroizes on drop)}` | `sshagent.rs::{fetch_and_sign_reads_the_key_and_signs_a_verifiable_signature,file_signer_signs_from_a_local_key_and_needs_no_account}`, `daemon.rs::ssh_file_signer_signs_when_gated` |
| The `OpSshSigner` **whole-key-in-RAM-for-one-signature** residual is unchanged but isolated to that signer; `FileSshSigner` matches the same custody discipline | `sshagent.rs` module docs §"Custody (v1)", `OpSshSigner::sign` → `fetch_and_sign` | design residual (see `docs/design/ssh-agent.md` §4); exercised by the fetch/file sign tests above |
| The `session-bind` host is **advisory context, attacker-nameable, never a boundary**; the load-bearing fields are the key label + data hash | `sshagent.rs::derive_host` (doc + honest fingerprint fallback; the host signature is not verified) | `sshagent.rs::{unknown_host_key_falls_back_to_a_fingerprint_not_a_fake_name,no_session_bind_yields_an_honest_unbound_marker}` |
| The `ssh-keys.json` store holds **only public material + op coordinates**, never key bytes (inert like the account catalogue), and is 0600 | `sshagent.rs::{SshKeyEntry,SshFileEntry,SshKeyConfig::save}` (0700 dir / 0600 file) | `sshagent.rs::config_entry_resolves_to_a_served_identity` (only public fields), reviewed by inspection for perms |

**Key-file-swap residual (Low, same-UID):** `FileSshSigner` advertises the
public key resolved from `<path>.pub` at arm time but reads the private key at
sign time, and does not re-verify that the produced signature matches the
advertised public key. A same-UID attacker who swaps the private-key file
between arm and sign makes the agent emit a signature under a *different* key —
which the SSH client then rejects (it does not match the offered identity), so
this breaks the connection rather than forging anything. A same-UID file swap is
already outside Sigil's boundary. Not a distinct escalation; noted for
completeness.

## 14. The P-256 Secure Enclave DEK wrap (`747b3a4`)

The Mac local-approval factor unwraps the DEK *inside* the Secure Enclave under
Touch ID, and the SE holds only P-256 keys — so the Mac-SE wrap is a second,
independent envelope of the same DEK (the phone path is unchanged X25519). It
reproduces Apple's `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`
so `SecKeyCreateDecryptedData` opens it.

**Independent review verdict — CONFIRMED SOUND.** This verdict is written by the
security-reviewer, which did **not** author `se_ecies.rs` (implemented by
rust-core in `747b3a4`); per the review-integrity rule the implementer documents
behavior and residuals, and only the independent reviewer records a "reviewed"
verdict — this is not a self-certification. The adversarial pass covered the
construction against Apple's spec (the AES-128-not-256 and VariableIV gotchas),
on-curve point validation of both the recipient and ephemeral keys, per-wrap
IV/key freshness (no GCM nonce reuse), zeroization of every secret intermediate,
the SAS-Confirmed gate, and the AAD / envelope-binding question (see residual
12); no correctness issue was found and no code change to the construction was
needed. The only outstanding item is on-device interop
(`SecKeyCreateDecryptedData` opening a `wrap_dek_p256` blob), which is
**NEEDS-VERIFICATION** off-hardware and marked in the table below.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The construction matches Apple's ECIES exactly: ephemeral P-256 → cofactor ECDH (P-256 h=1) → ANSI-X9.63 KDF-SHA256 with sharedInfo = ephemeral X9.63 pubkey → **AES-128** key ‖ 16-byte **variable IV** → AES-128-GCM, empty AAD, 16-byte tag; wire `eph_pub(65) ‖ ct(32) ‖ tag(16) = 113` | `se_ecies.rs::{wrap_dek_p256,x963_kdf_sha256,split_key_iv,Aes128GcmVarIv}` | `se_ecies.rs::{wrap_unwrap_round_trips_the_dek,sealed_blob_has_the_apple_wire_length,x963_kdf_matches_a_known_answer}`; on-device interop is **UNPROVEN — NEEDS-VERIFICATION** (`apps/mac/Tools/se-selftest.swift`, blob must read 113) |
| The recipient and ephemeral public keys are **validated as on-curve X9.63 points** (identity/garbage refused); P-256 is prime-order so no small-subgroup surface | `se_ecies.rs::{wrap_dek_p256,unwrap_dek_p256}` (`PublicKey::from_sec1_bytes`) | `se_ecies.rs::{a_non_point_recipient_key_is_refused,a_tampered_ephemeral_key_is_rejected}` |
| Every wrap uses a **fresh ephemeral key** → fresh shared secret → fresh AES key **and** IV, so there is never a `(key, IV)` reuse across wraps (the GCM catastrophe) | `se_ecies.rs::wrap_dek_p256` (`EphemeralSecret::random` per call) | `se_ecies.rs::each_wrap_uses_a_fresh_ephemeral_key` |
| A wrong SE key or any tampered byte fails closed (GCM auth); no DEK leaks; a truncated blob is refused before any crypto | `se_ecies.rs::unwrap_dek_p256` | `se_ecies.rs::{wrong_se_key_cannot_unwrap,a_tampered_ciphertext_is_rejected,a_truncated_blob_is_rejected}` |
| Key material is zeroized: ephemeral secret (`EphemeralSecret` ZeroizeOnDrop), shared secret (`SharedSecret` zeroizes), KDF output + AES key + recovered DEK intermediate all `Zeroizing` | `se_ecies.rs::{x963_kdf_sha256,split_key_iv,unwrap_dek_p256}` | reviewed by inspection (the `Zeroizing` wrappers); `unwrap_dek_p256`'s recovered-key copy was wrapped in `Zeroizing` in this review |
| The wrap is gated on **SAS confirmation** (`Confirmed`/`DekDelivered`), same as the phone DEK delivery; it does not change pairing state | `pairing.rs::DaemonPairing::wrap_dek_for_se_p256` (state guard) | `pairing.rs` SE-wrap round-trip test (line ~1028) |
| **Empty AAD is correct, not a gap**: `SecKeyCreateDecryptedData` for this ECIES algorithm accepts no AAD, so AAD is fixed-empty on both sides; identity binding via AAD is impossible and unnecessary here (confidentiality = ECDH-to-SE-key, integrity = GCM tag, DEK↔token binding = the account store's own AES-256-GCM). Cross-device/cross-pairing replay fails closed | `se_ecies.rs` module docs §"Binding and sender authentication", `keystore_macos.rs`, `apps/mac/.../SecureEnclaveApprover.swift` (SE decrypt) | design analysis (see residual 12) |

**Wiring status:** `wrap_dek_for_se_p256` is built and unit-tested but **not yet
called by the shipping daemon/CLI**; the Mac `approve(wrappedDEK:)` path exists
and `AppModel` currently passes an empty placeholder. The at-rest storage and
delivery of the wrapped blob are the remaining integration, at which point
residual 12's local-only assumption must be re-checked.

## 15. The config rule engine + account routing (`b66404c`)

The per-command `CommandStore` became a generic if-this-then-that engine: an
ordered rule list (`Match` -> `Action`) plus named `Source`s. `parse_vault`
argv-sniffing is deleted; account routing is now the matched source's configured
`account` label, and `AccountStore::route` / `ThresholdAccountStore::{route,
route_exact}` match by **label OR vault**.

**Independent review verdict — CONFIRMED SOUND (two low-severity hardening
notes).** Written by the security-reviewer, which did **not** author `config.rs`
or the `fulfill` rewrite (rust-core, `b66404c`); per the review-integrity rule
this is not a self-certification. The adversarial pass covered: whether a crafted
argv/rule can route to the wrong account or the wrong threshold key; whether
removing the `op` hardwiring opens a fail-open path; and whether the deferred
`arg_regex` can be smuggled into an always-true match.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Account routing is **config-derived, never caller-argv-derived**: the hint is the matched source's `account` label; the caller's argv no longer influences which account unlocks (it only selects which of Tom's own rules matches, and every match still requires a fresh approval/lease). This is *stronger* than the old `--vault` sniff | `daemon.rs::fulfill` (`vault = action.account.clone()`; `parse_vault` deleted), `config.rs::Config::resolve` | `daemon.rs::v1_and_v2_accounts_coexist_and_each_takes_its_own_path`, `config::tests::resolve_first_match_wins_and_flattens_source` |
| The v2 threshold path selects **one** account atomically (`record.clone()`): the phone's partial `Z_F` is agreed against that record's `E` and combined with the SAME account's Mac share `m` and token ciphertext — no cross-account share splicing is reachable via label/vault confusion | `daemon.rs::fulfill` (`v2 = store.route_exact(...).map(\|a\| (label, a.record.clone()))`), `threshold.rs::route_exact` | `daemon.rs::remote_v2_threshold_approval_decrypts_via_two_party_combine`, `threshold::tests::each_account_gets_a_unique_ephemeral_and_routes`, `full_two_of_two_round_trip_{raw_x,x963}` |
| `route_exact` stays **exact** when v1 accounts coexist (v2 claims only a label/vault match, never the single-account fallback), so a migration store never lets v2 over-capture a v1 request | `daemon.rs::fulfill` (`route_exact(...).or_else(\|\| if v1_empty { route(...) } else { None })`) | `daemon.rs::v1_and_v2_accounts_coexist_and_each_takes_its_own_path` |
| An invocation that **no rule matches** is refused, never run ungated; removing `default_op`/`parse_vault` leaves **no** built-in rule for any command (a zero-config daemon refuses everything until configured) | `config.rs::Config::resolve` (`None`), `daemon.rs::fulfill` (`fail_closed`) | `daemon.rs::unconfigured_command_is_refused_with_a_config_hint`, `config::tests::empty_match_never_matches` |
| An **empty match** never matches (a malformed/partial rule fails closed, never gates every command) | `config.rs::Match::matches` (`is_empty() -> false`) | `config::tests::empty_match_never_matches`, `add_rule_rejects_unknown_source_and_empty_match` |
| The deferred **`arg_regex` cannot be smuggled into an always-true match**: `Match::matches` returns `false` whenever `arg_regex.is_some()`, independent of how the config was authored — so even a hand-edited/imported regex rule is a dead rule (fails closed), only ever *more* restrictive, never always-true | `config.rs::Match::matches` (`if self.arg_regex.is_some() { return false }`) | `config::tests::regex_condition_is_deferred_and_fails_closed` |
| Invariants #1/#2/#7 unchanged: the config only chooses provider/source/risk; token-ciphertext-at-rest, op-child-stdout->client-fd, and the fail-closed branches are the same code paths | `daemon.rs::fulfill` (unchanged token/provider handling), `config.rs` (routing only) | the full `daemon::tests` suite (inert-at-rest, denial-fails-closed) passes unchanged |

**Low-severity hardening note A (config-authoring ambiguity, not caller-exploitable).**
`route`/`route_exact` match `label == v OR vault.contains(v)` with `.find()`
returning the first hit. If one account's `label` collides with another
account's `vault` name, routing is order-dependent. The hint is config-derived
(Tom's own source label), so this is a misconfiguration foot-gun, not an attacker
primitive, and the mis-routed account still requires a fresh phone approval.
Recommend documenting that a source `account` label must be unambiguous across
the account/threshold stores.

**Low-severity hardening note B (fall-through on a dangling source).**
`Config::resolve` `continue`s past a rule whose `Match` holds but whose
`action.source` is unknown, trying the next rule rather than hard-refusing.
`add_rule`, `remove_source`, and `config import` all validate referential
integrity (`cli.rs::config_import` rejects an unknown source / empty match), so a
dangling source cannot arrive via the CLI or import; only a direct hand-edit of
the 0600 `config.json` (a same-UID write, already outside Sigil's boundary) can
reach it, and the worst effect is a *downgrade* to a later broader rule — still
gated, never ungated. Recommend a matched-rule-with-unknown-source hard
fail-closed (refuse the invocation) rather than fall through, so a misconfigured
specific rule can never silently resolve to a broader one. Informational.

## 16. The zero-knowledge phone reduction (`cdeebb7`, `ec59737`, `6e3d485`)

The phone dropped the R5 `consentConsistent` account<->secret cross-check, all
provider/account display surfaces, and all Mac-outcome reasoning, becoming a
pure provider-blind approve/deny approver that renders only the opaque
Mac-provided display fields.

**Independent review verdict — CONFIRMED SOUND.** Written by the
security-reviewer, which did **not** author the phone reduction (phone-approver);
not a self-certification. The adversarial pass covered: whether removing R5
creates a new display-spoof materially worse than the accepted residual #7;
whether the phone still learns only TRANSPORT status (never OUTCOME); and whether
the crypto is byte-identical.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Removing R5 creates **no** new attack worse than residual #7. A hostile relay gains nothing (the request rides the Ed25519-signed `Envelope` + replay guard; any tamper breaks the signature). A compromised Mac controls BOTH the displayed `secret_refs` AND the challenge `label`/`accountId`, so R5's fuzzy token-overlap was trivially self-satisfiable and never stopped the residual-#7 spoof; the "inconsistent request" R5 caught maps to no capable-adversary primitive | `envelope.rs::open`, `replay.rs::ReplayGuard`; phone `controller.ts::liveApproveThreshold` (no consent check, SE gate is the key release) | `proto/tests/hostile_relay.rs` (26 attacks) + `pairing_mitm.rs` pass unchanged; the phone gates the KEY not the display truth |
| The honest residual is correctly a **Mac-trust boundary, not a phone one**: a compromised Mac can spoof the display; the phone gates the SE key-agreement / DEK read behind Face ID, and the human declining an unexpected request is the backstop | `controller.ts::liveApprove{,Threshold}` (Face ID gate), residual #7 | reviewed by inspection; consistent with residual #7 |
| The phone learns only **TRANSPORT** status, never **OUTCOME**: `ApproveOutcome = sent \| refused \| no-session \| error`; "sent" means only that the response left the phone. All Mac-outcome copy ("Secret delivered" / "No secret was delivered" / "Could not reach your Mac") is removed for phone-local facts ("Approved. Sent." / "Denied." / "Request expired." / cause-neutral "That didn't go through.") | `controller.ts::liveApprove` (doc: "does not learn, and must not infer, whether the Mac then unlocked or delivered anything"), `approval-sheet.tsx::{DecisionSent,TerminalStatus}` | `bun run proto:selftest` green; grep confirms no approval-time outcome inference remains (only zero-knowledge doc-comments + legitimate pairing-msg-1 transport facts) |
| **Crypto byte-identical.** The only crypto-path edit is the Face ID `reason` string (`Approve ${label}` -> `"Approve request"`), which is a display-only `LAContext` prompt — the ECDH is `sharedSecretFromKeyAgreement(f, E)`, independent of `reason`. `requests.ts` is doc-comment only; wire fields unchanged; `ephemeralPub` is the sole crypto input, authenticated by the enclosing signed envelope; `accountId`/`seKeyId` travel in one signed challenge | phone `SigilSeModule.swift::computePartial` (reason feeds only the prompt), `controller.ts` (loadDek/computePartial/shapeEcdh/session.respond unchanged), `requests.ts` (doc only) | phone protocol **vectors 15/15**, `proto:selftest` all green (envelope, replay, forged-sender, wrong-recipient, tamper, fingerprint/mailbox, pairing tag/rendezvous vs rust); Rust `sigil-proto` 26 pass |

**Minor doc-drift (non-security, both changes).** A stale comment at
`apps/phone/modules/sigil-se/ios/SigilSeModule.swift:138` still reads "Bind the
Face-ID prompt to the account being unlocked (R5): the reason is the account
label" — the reason is now the generic "Approve request". Flagged to the
phone-approver to clean; not a vulnerability.

**R5 mapping in this doc:** no §/row mapped R5 to phone code (the sweep found
none), so no stale claim to retract here; the R5 protocol doc comment on
`requests.ts` was already rewritten in `ec59737`.

## 17. Caller-stdin splice to the tool child (`538fd70`)

The `Run` frame now carries three descriptors (stdin, stdout, stderr) over
SCM_RIGHTS instead of two; the daemon splices the caller's stdin straight to the
spawned tool child so interactive tools (`op inject`, prompts) read the caller's
terminal. The claim is that the daemon only *passes* the fd (never reads it), so
invariant #2 (no caller/secret bytes in daemon memory) holds for the input
direction too.

**Independent review verdict — CONFIRMED SOUND on the happy path (two
low-severity hardening notes).** Written by the security-reviewer, which did
**not** author the splice (config-cli, `538fd70`); not a self-certification. The
adversarial pass covered: whether the daemon ever reads/buffers/inspects stdin;
fd ownership/lifetime (leak, retained readable dup, cross-request confusion);
whether stdin perturbs the stdout/stderr splice; fail-closed on a missing fd; and
new hostile surface (weird fd, blocking-stdin stall).

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| The daemon **only passes** the stdin fd, never `read()`s / buffers / inspects it: its sole consumer is `cmd.stdin(Stdio::from(fd))`. No caller/secret byte enters daemon memory for the input direction (invariant #2 holds for input) | `provider.rs::{OpProvider,EnvFileProvider}::run` (`Stdio::from(run.stdin)`), `daemon.rs::{handle_conn,fulfill}` (threads the fd through, never reads it) | `daemon.rs::caller_stdin_is_spliced_to_the_tool_child` (bytes written to the caller-side pipe reach the child; the daemon reads nothing) |
| **fd ownership/lifetime is correct**: every received fd is wrapped in `OwnedFd` (closed exactly once on drop); the daemon never `dup`s, so it retains no readable copy; on every fail-closed early return the unused stdin/stdout `OwnedFd`s drop (close) rather than splice | `local.rs::recv_with_fds` (`OwnedFd::from_raw_fd`), `daemon.rs::fulfill` (owned params dropped on early return), `provider.rs::run` (`Stdio::from` moves ownership to the child spawn) | `local.rs::op_fd_passing_and_reply_roundtrip_over_a_socketpair`, `daemon.rs::full_loop_over_the_socket_with_local_control_approval` |
| **No cross-request / cross-client fd confusion**; ordering preserved: each connection is a separate `spawn_blocking` task with its own `recv_frame` -> its own `OwnedFd` set on its own stack; the shim sends `[stdin, stdout, stderr]` and the daemon reads `next()/next()/next()` in the same order (SCM_RIGHTS preserves array order) | `daemon.rs::serve` (per-conn `spawn_blocking`), `handle_conn` (positional `fds.next()`), `shim.rs::forward` (`[inp, out, err]`) | `daemon.rs::caller_stdin_is_spliced_to_the_tool_child`, `dev_autoapprove_full_loop_delivers_secret_to_caller` |
| **Fails closed on the input path**: there is no daemon-buffered-stdin fallback anywhere — the daemon never reads stdin, so a missing/failed fd cannot fall through to daemon-read input; the child simply gets `None` for that slot | `daemon.rs::fulfill`, `provider.rs::run` (no daemon read of stdin exists) | reviewed by inspection (grep: `run.stdin`'s only use is `Stdio::from`) |
| A **malicious client passing a weird fd** as stdin gains nothing: the daemon splices it to the child (same UID as the attacker) and never acts on the fd's identity, so it is no more than what the attacker could feed a tool it ran itself | `provider.rs::run` (passthrough only) | reviewed by inspection; same trust model as the pre-existing stdout/stderr passing |

**Low-severity hardening note A (missing-fd inherit — invariant-#2-adjacent,
defense-in-depth).** The daemon does not validate that a `Run` frame carries
exactly three descriptors, and a missing fd makes the child **inherit the
daemon's** corresponding stdio (`provider.rs::run`: `if let Some(fd) = run.stdout
{ cmd.stdout(Stdio::from(fd)) }` with no `else` -> std default is *inherit*). So a
non-conforming same-UID client that sends fewer than three fds (e.g. zero) makes
an approved `op` child write its **secret to the daemon's inherited stdout**
(under launchd, a same-UID-readable log) instead of to the caller — secret bytes
leaving the intended splice path. The `None`->inherit pattern pre-dates this
change for stdout/stderr, but the stdin splice makes the three-fd positional
contract load-bearing with still no validation, and a *short* count now also
**misassigns** slots (a two-fd `[stdout, stderr]` sender is read as `[stdin,
stdout]`, leaving `stderr = None` -> inherit and shifting stdout). Bounded:
requires a crafted non-standard frame from a same-UID client **and** a granted
approval or active lease, and a same-UID attacker can read the secret more
directly — no real escalation. Cheap to close and recommended for an airtight
invariant #2: (a) reject a `Run` frame whose fd count != 3 (fail closed), and
(b) default an absent child stdio to `Stdio::null()` rather than inherit, so the
daemon's own stdio can never become a sink for tool output.

**RESOLVED (`91aab46`).** Both closes landed and are verified sound: `handle_conn`
now refuses any `Run` frame whose descriptor count != 3 (`fds.len() != 3 -> Exit
{ code: 1 }`) **before** anything spawns, so a short/long count can never
misassign slots; and both providers default an absent stdio to `Stdio::null()`
(`run.stdin.map_or_else(Stdio::null, Stdio::from)`), so the daemon's own
same-UID-readable stdio can never sink a tool's secret output. Proven by
`daemon.rs::run_frame_with_wrong_fd_count_is_refused` (a 2-fd frame -> exit 1, no
output) with the happy-path splice unchanged (`caller_stdin_is_spliced_to_the_tool_child`).

**Low-severity hardening note B (caller-stdin stall — DoS, post-approval +
same-UID).** Splicing the caller's stdin lets a compromised caller pin a daemon
blocking-thread: pre-change the child inherited the daemon's stdin (effectively
`/dev/null` under launchd, so a stdin read hit EOF); post-change the child reads
the caller's fd, which the attacker can hold open without sending data, so a
stdin-reading tool (`op inject`) blocks and holds its `spawn_blocking` thread for
as long as the caller keeps the fd open. With an active lease (approval
short-circuited) an attacker could fire many such requests and exhaust the
bounded blocking pool. Bounded (post-approval, same-UID, DoS-only, no disclosure,
fails closed) and the same class as any long-running approved child, but now
caller-triggerable via input. Optional hardening: a spawn watchdog/timeout, or
record it as an accepted same-UID residual.

**Note:** commit `538fd70`'s `shim.rs` hunk references a `crate::proxy` module
(the recursion fuse) that is part of the concurrent proxy work and was untracked
at review time, so the crate did not build standalone at that commit; the stdin
tests above were exercised by supplying the `proxy` module into a detached
worktree. Flagged to the team so the proxy module lands committed and the tree
builds clean (not a defect in the splice itself). **Update:** the proxy module is
now committed (`f5448cf`) and the tree builds (`91aab46` also landed Finding A's
fix — the `Run` fd path is now airtight); see §18.

## 18. The auto-aliasing proxy (`f5448cf`, `65d75d2`)

`~/.sigil/bin` goes first on `PATH`; each intercepted command is a symlink there
at the `sigil` runtime binary. Running `op` resolves the symlink -> `sigil`
re-enters as `sigil op ...` -> gates on the phone -> execs the **real** `op`
(resolved with the proxy excluded). Management is `sigil-config proxy
add|remove|list|status|doctor|env`. Design: `docs/design/proxy-aliasing.md`.

**Independent review verdict — CONFIRMED SOUND (two low-severity notes, neither a
distinct exploit).** Written by the security-reviewer, which did **not** author
the proxy (proxy-shim / rust-core); not a self-certification. The proxy is a
PATH/resolution convenience layer that **correctly disclaims being a containment
boundary**; the adversarial pass confirmed it fails closed on every
resolution/recursion fault, never lets the caller-controlled depth counter touch
a security decision, and does not weaken caller identity (#6) or secret handling
(#2).

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| `find_real` cannot be steered to an **attacker binary** via symlinks: `canonicalize` resolves a symlink / symlink-chain / real-looking symlink-into-the-proxy-dir to the running `sigil` binary, and rule 1 (canonical == `own_binary`) excludes it **in any directory** | `paths.rs::find_real` (skip `canon == own`), `proxy.rs::alias_target` | `proxy::a_stray_alias_symlink_outside_the_proxy_dir_is_not_the_real_tool`, `drift_when_a_real_binary_precedes_the_alias_is_a_bypass`, `healthy_when_alias_is_first_and_points_at_current` |
| The **daemon-up** path is immune to **caller PATH poisoning**: the `Run` frame carries only `argv`/`cwd`/`proxy_depth`/fds — never the caller's `PATH`/env — so the daemon resolves the real binary in its **own** trusted (launchd-pinned) `PATH`; a caller cannot redirect what the daemon spawns or steer the injected SA token to an attacker binary. The daemon-**down** path uses the caller's `PATH` but injects **no** secret (transparent exec), so a poisoned `PATH` there just runs the caller's own binary with no token — identical to no-Sigil | `local.rs::Frame::Run` (no env field), `provider.rs::OpProvider::resolve` -> `paths::find_real` (daemon env), `shim.rs::exec_real` (no env injected) | reviewed by inspection; `daemon.rs` provider tests spawn from the daemon's own resolution |
| A **hard copy** of the `sigil` binary planted as `<cmd>` (not caught by canonical equality) **fails closed**: `find_real` returns it -> re-enter -> loop, bounded by the depth fuse to exit 70 (shim) / daemon refuse at `MAX_DEPTH`. No ungated run, no secret leak — a bounded self-DoS requiring same-UID to plant a copy of the binary | `shim.rs::dispatch` (`depth_exceeded` -> exit 70), `daemon.rs::fulfill` (`proxy_depth >= MAX_DEPTH` -> `fail_closed`) | `daemon.rs::proxy_depth_is_incremented_on_the_child_and_fuses_at_the_limit`, `proxy::depth_fuse_reads_and_increments` |
| **PATH-order bypass is documented as a residual, never claimed prevented.** A real `<cmd>` before the proxy routes an *unmodified* caller ungated; `doctor` reports it as an operator convenience, and a caller that *wants* to skip the gate always can (real binary is never moved). No code treats PATH order as a control | `proxy.rs::ProxyStatus::issue` ("a real {cmd} precedes the proxy on PATH (requests would be ungated)"), `docs/design/proxy-aliasing.md` §"not a containment boundary" | `proxy::drift_when_a_real_binary_precedes_the_alias_is_a_bypass` |
| The **recursion guard cannot be cleared to escape gating.** `proxy_depth` is used in exactly one decision — `fulfill`'s `>= MAX_DEPTH -> fail_closed` (deny, safe direction) — and is **never** consulted by the phone gate, account routing, caller-identity derivation, or lease keys. Setting `SIGIL_PROXY_DEPTH` high -> self-deny; setting it to 0 -> only prolongs a loop that exists solely if `find_real` is buggy (self-DoS), never a bypass; `saturating_add` prevents wrap | `daemon.rs::fulfill` (sole `proxy_depth` decision + `child_depth` env), `proxy.rs::{current_depth,depth_exceeded,next_depth_value}` | `daemon.rs::proxy_depth_is_incremented_on_the_child_and_fuses_at_the_limit`, `proxy::depth_fuse_reads_and_increments` |
| Caller identity (#6) is **not weakened**: the daemon derives identity from the kernel peer pid + ancestry walk, independent of anything the proxy supplies (argv/cwd/depth are decorative for identity) | `daemon.rs::handle_conn` (`peer = lease::peer_pid`), `lease.rs::walk_ancestry` | existing `lease.rs` ancestry/grant-key suite (unchanged) |
| Fail-closed (#7): a resolution failure execs nothing (`exit 127`); a protocol fault while the daemon is up is `exit 70`, never an ungated run; only a **down** daemon execs transparently (by design, injecting no secret) | `shim.rs::{exec_real,forward}` (127 / 70), `daemon.rs::fulfill` | reviewed by inspection; `shim.rs` module contract |

**Low-severity note A (doc-vs-code + defense-in-depth): the runtime `find_real`
implements only rule 1, not the proxy-dir exclusion (rule 2) the design claims.**
`docs/design/proxy-aliasing.md` §"hard problem 1(a)" states two exclusion rules —
(1) canonical == `current_exe` **and** (2) skip any candidate inside the proxy
dir. `paths::find_real` (the resolver that actually chooses what to exec/spawn)
implements only rule 1; rule 2 exists only in the **diagnostic** path
(`proxy.rs::ProxyStatus::detect_with`, via `is_shim_dir`). Impact: a **non-symlink**
executable resident in `~/.sigil/bin` under a tool's name (a hard copy, a script,
or a same-UID-planted non-sigil binary) is not excluded by `find_real`, so the
daemon-up path would treat it as "the real tool" and spawn it **with the injected
SA token**. Every route requires same-UID write to `~/.sigil/bin` — already
game-over (such an attacker can read the approved tool's `/proc/<pid>/environ` or
replace the real binary), so it is not a distinct escalation — but it is a real
gap between the doc's claimed guarantee and the code, and it diverges from the
diagnostic path. **Recommend implementing rule 2 in `find_real`** (skip any
candidate whose parent canonicalises to `shim_bin_dir()`): trivial, restores
doc/diagnostic parity, guarantees the daemon never injects a token into a
proxy-dir-resident binary, and as a bonus makes the hard-copy case resolve to the
real tool instead of fail-closed-looping.

**Low-severity note B (display correctness post-split, no security impact):**
`paths::find_real` keys its exclusion on `own_binary()` (= `current_exe`), while
aliases point at `alias_target()` (the sibling `sigil` runtime binary). In the
runtime `sigil` and the daemon these coincide, so **execution is correct**. But
called from `sigil-config` (`current_exe` != the runtime the aliases point at),
rule 1 fails to exclude the proxy-dir alias, so `Alias.real` (used only for
`proxy list`/`doctor` **display**) can show the alias path instead of the real
binary, disagreeing with `ProxyStatus.real` (which uses `alias_target`, correct).
Display-only; no execution/security impact. Recommend `find_real` exclude against
`alias_target()` (or both) for correct post-split diagnostics.

**RESOLVED (`0fc85a9`).** Both notes landed and are verified sound. `find_real`
now delegates to a testable pure core `find_real_in(cmd, path, own, alias_target,
proxy_dir)` that applies **rule 2** (skip any candidate whose parent dir
canonicalises to the proxy dir — so a non-symlink executable planted in
`~/.sigil/bin` is excluded, closing the daemon-up credential-injection corner and
making the hard-copy-in-proxy-dir case resolve to the real tool instead of
fail-closed-looping) **and rule 1 against both `own_binary()` and
`alias_target()`** (so from `sigil-config` the alias is excluded and `list`/`doctor`
`.real` agrees with `ProxyStatus.real`). Proven by
`paths::find_real_skips_a_non_symlink_planted_in_the_proxy_dir` and
`find_real_excludes_via_own_and_alias_target`; the design doc's rule 1/2 wording
was aligned so code and brief agree. Note A/B closed; §18 is now sound with no
open recommendations.

## 19. The inline `env` provider (sealed KEY=VALUE injection)

The inline `env` provider (provider id `env`) lets the user set secret VALUES
directly (`KEY=VALUE`) instead of pointing at a plaintext env-file. It is the
same direct-injection *shape* as §12's `env-file` — resolved values transit
daemon RAM only as the child's spawn env, for the spawn instant, and it never
leases — but unlike `env-file` the values are **sealed at rest under the DEK**,
so the daemon-at-rest holds no plaintext value (invariant #1) even here. This
section records behavior and residuals; the verdict is the independent
reviewer's.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| VALUES are **never in `config.json`**: the config holds only the KEY names (public) plus the provider tag; the values are AES-256-GCM sealed under the DEK in the account store (`sigil.db`), keyed by the source name, exactly as a service-account token is | `config.rs::Source::keys` (names only, `#[serde skip_if empty]`), `secrets.rs::{SealedEnv,AccountStore::{set_env_blob,env_blob,remove_env_blob}}` (ciphertext, base64), `provider.rs::encode_env_pairs` (sealed plaintext) | `secrets.rs::env_blob_is_ciphertext_at_rest_and_round_trips` (greps the on-disk store: the VALUE is absent, the NAME present), `config.rs::resolve_flattens_inline_env_keys_and_source_name` (names round-trip, values were never there) |
| The value never reaches **argv** (`ps`-visible): `source env set --key` reads the VALUE from stdin into a `Zeroizing` buffer; `--stdin` reads `KEY=VALUE` lines the same way; the CLI rejects a value on argv by construction (there is no value flag) | `cli.rs::{read_secret_value_stdin,read_env_pairs_stdin,config_source_env_set}` | manual E2E (values piped on stdin); reviewed by inspection |
| `describe()` is **zero-knowledge**: it surfaces the KEY NAMES only (from config), never a value, and never reads the sealed blob (which it could not open pre-approval anyway) | `provider.rs::EnvProvider::describe` (maps `source.keys` to `SecretRef`s), `daemon.rs::fulfill` (builds `SourceView{keys}` before the decision) | `provider.rs::env_provider_flags_and_describe_shows_keys_not_values` |
| The blob is **decrypted only after the grant**: the ciphertext is fetched before the approval wait (safe to hold), the DEK arrives with the phone approval (or is unwrapped from the keystore on a local approval, the same as `op`), is used for the one decrypt, and is dropped at once | `daemon.rs::fulfill` (`sealed_ct` fetched pre-decision; the `else if let Some(ct)=&sealed_ct` arm unwraps `outcome.dek`/keystore, `decrypt_token`, `drop(dek)`) | `daemon.rs::inline_env_command_runs_gated_and_injects_sealed_values` |
| The decrypted pairs live in a `Zeroizing` map wiped at end of `run()`; the decode borrows out of the `Zeroizing` plaintext with `str::from_utf8` (no owned/un-zeroized value `String`) and fails closed on truncation or non-UTF-8 without panicking | `provider.rs::{decode_env_pairs,EnvProvider::run,spawn_with_env}`, `daemon.rs::fulfill` (`drop(sealed_env)`) | `provider.rs::{env_encode_decode_round_trips_including_awkward_values,env_decode_rejects_truncated_and_bad_utf8_without_panicking,env_provider_injects_decrypted_pairs_into_the_child}` |
| **Never leases** (`needs_account()==false`, `needs_sealed_env()==true`): like `env-file`, resolved values must not persist in daemon RAM across a TTL, so it is gated on every run | `provider.rs::EnvProvider::{needs_account,needs_sealed_env}`, `daemon.rs::fulfill` (the sealed-env arm never calls `leases.grant`; the lease short-circuit is `if needs_account`) | `daemon.rs::inline_env_command_runs_gated_and_injects_sealed_values` (`leases.active()==0`) |
| An **unset** source (no sealed blob) fails closed, never runs the child with a blank environment | `daemon.rs::fulfill` (`sealed_ct == None` → `fail_closed`) | `daemon.rs::inline_env_with_no_sealed_values_fails_closed` |
| **Readout integrity (invariant #3):** the decoded blob's KEY set is reconciled against `action.env_keys` (the set the phone readout/audit was built from) *before* injection; any divergence fails closed. This closes the two ways names could drift from values without breaking crypto — a crash between the store save and config save in `seal_env_pairs`, and an import that kept a source NAME but changed its keys while a stale blob survived — so the approver can never consent to "will set FOO" and have the child receive a hidden BAR | `daemon.rs::fulfill` (the sealed-env arm's `BTreeSet` compare of decoded keys vs `action.env_keys` → `fail_closed`) | `daemon.rs::inline_env_blob_keys_must_match_the_approved_set_or_fail_closed` (blob has an extra key vs config → refused, nothing injected) |
| Bulk `--stdin` parse errors report the **line NUMBER, never the line content**, so a mistakenly-piped secret line is not echoed to the terminal/logs | `cli.rs::read_env_pairs_stdin` (`"line {n}: no '=' found"`) | reviewed by inspection |
| `list`/`export` cannot leak a value (they render config only, which has no value), and `import` cannot round-trip a value into the clear (config carries names only); removing the source or clearing its last key **removes the sealed blob** (no orphan ciphertext), and an import that drops an env source prunes its blob | `cli.rs::{config_source_list,config_export,config_import,purge_env_blob,prune_orphan_env_blobs,seal_env_pairs}` | manual E2E (remove purges `env_sources`); reviewed by inspection |

The seal/open wire is length-prefixed (`u32 klen|key|u32 vlen|value`), pre-sized
so the encode buffer never reallocates, so a VALUE may hold any bytes (newline,
`=`, quotes) without an escaping ambiguity and decode borrows without a
non-zeroized copy. See **residual 13** for the two un-wiped copies this shape
inherits from §12 (the `Command` env map and the child's environ) — identical to
`env-file`, plus the CLI-side merge copy at set time (the user is providing the
value, so it is in CLI RAM regardless; held `Zeroizing`).

**Independent review verdict — CONFIRMED SOUND for the crypto/at-rest core; one
P2 readout-integrity gap and two P2 hygiene notes, none a value leak.** Written by
the security-reviewer, which did **not** author the inline `env` provider
(rust-core); not a self-certification. The six implementer claims were verified,
not taken on faith:

- **At-rest is ciphertext (claim 1) — CONFIRMED.** The on-disk `sigil.db` grep
  test proves the VALUE is absent and only the (public) source name + sealed bytes
  persist; `config.json` carries KEY names only (`Source::keys`,
  `skip_serializing_if = "Vec::is_empty"`). Values are sealed with the same
  AES-256-GCM `encrypt_token` under the DEK as service-account tokens. No value
  reaches a log/error/`{:?}` on the seal or decrypt paths (decrypt/decode failures
  print the GCM error or a fixed "corrupt" string, never plaintext).
- **list/export/import cannot leak a value (claim 2) — CONFIRMED.** Export/list
  render config only (no value present to render); import carries names + provider
  tag, so it can only ever *remove* ciphertext (prune), never introduce plaintext.
- **`describe()` is zero-knowledge (claim 3) — CONFIRMED for values.** The
  approval request's `secret_refs` and the audit label are built from KEY names
  only; no value crosses the wire or enters the sealed request.
- **decrypt→inject→zeroize, never leases (claim 4) — CONFIRMED.** The DEK
  (`Zeroizing<[u8;32]>`) is opened only after the grant (phone-delivered
  `outcome.dek`, or a local keystore unwrap on a local approval — the same v1
  model as `op`), used for one decrypt, `drop`ped at once; the decoded pairs
  (`Zeroizing`) are dropped after the spawn instant; the sealed-env arm never
  calls `leases.grant` and the lease short-circuit is `if needs_account`. The
  reused `spawn_with_env` splice/exec path is #22's reviewed one.
- **remove/unset purges the blob (claim 5) — CONFIRMED.** `remove_env_blob` on
  source-remove, empty-after-unset, and `prune_orphan_env_blobs` on import; no
  orphan accumulation.
- **DEK/value buffers zeroized on set/unset (claim 6) — CONFIRMED.** `Dek` and
  `Token` are `Zeroizing`; the CLI holds value buffers as `Zeroizing<String>`,
  reads them from stdin never argv (no `ps` leak), and the merge copy is
  `Zeroizing`.
- **Hostile input — CONFIRMED fail-closed.** `decode_env_pairs` uses checked
  slicing and `str::from_utf8`, returning `None` (fail closed) on truncation, an
  over-long length, or non-UTF-8 without panicking; a tampered `sigil.db` fails the
  GCM tag on decrypt (a same-UID attacker cannot forge attacker-chosen values, only
  *relocate* an existing blob — see the P2 below); `valid_env_key` rejects `=`,
  NUL, whitespace, and control bytes; the proxy-depth env is set *after* the
  injected pairs so a supplied key cannot spoof the recursion fuse.

**P2-1 (readout-integrity gap): the phone readout (`describe`/audit, from
`config.keys`) is never reconciled with what is actually injected (the decoded
sealed blob).** `fulfill` injects whatever `decode_env_pairs` yields, while the
approver was shown `action.env_keys` from the config. Nothing checks the two key
*sets* agree. They can diverge two ways, both without breaking any crypto: (a) a
crash between `store.save()` and `save_config()` in `seal_env_pairs` (the store is
persisted with the new keys before the config is), leaving the blob ahead of the
config; (b) an `import` of a config whose env source keeps its **name** but changes
its `keys` list while a pre-existing blob under that name (with different keys)
remains — `prune_orphan_env_blobs` only drops blobs whose *name* is gone. Outcome:
the approver consents to "will set FOO" but the child is injected FOO **and** a
hidden BAR. This is **not a value leak** (values are never shown to the phone in
either case) — it is a readout-*accuracy* break of invariant #3's "the approver
sees what will happen." Proven with a scratch test (config `[TOKEN]`, blob
`{TOKEN, SECRET}`): the readout showed `TOKEN`, the child received
`secret=hidden-exfil`. **Fix:** after `decode_env_pairs` in `fulfill`, assert the
decoded key set equals `action.env_keys` and `fail_closed` on mismatch (this also
closes the crash window and the import-leftover case); or inject only keys present
in `action.env_keys`. Severity **P2**: reaching it needs a crash or a same-UID
config/import manipulation, and same-UID is already outside the defended boundary —
but readout integrity is a stated approval property, so a cheap inject-time check
is warranted.

**P2-2 (terminal echo of raw stdin): `read_env_pairs_stdin` prints a malformed
line verbatim** — `eprintln!("sigil: line without '=': {:?}", line)`. On the
`--stdin` bulk path a piped line lacking `=` is reflected to stderr; if the user
accidentally pipes secret-bearing content, a bare-secret line is echoed to the
terminal/logs. Low blast radius (CLI-side, the user's own terminal, malformed
input only), but it is the one place raw stdin is reflected. **Fix:** report the
line index only, not its content.

**P2-3 (at-rest threat-model note): inline-`env` values are sealed under the
host/v1 DEK, not the v2 two-party threshold key.** Unlike a v2 `op` account (whose
token the daemon **cannot** open without the phone's partial), an inline-`env`
value is recoverable by a **local** approval — the daemon unwraps the host DEK from
the keystore itself (Touch ID / SE presence, `outcome.dek == None` path). This is
by design and identical to v1 accounts and local-approval mode, and is a strict
improvement over the plaintext `env-file` (§12) — but it means inline-`env` does
**not** inherit v2's "daemon cannot open it alone" guarantee. Worth stating plainly
in residual 13 so inline-`env` is not assumed to have threshold-grade at-rest
protection.

Net: the sealing, zeroization, fail-closed decoding, no-lease, and
zero-knowledge-of-values properties all hold as claimed. The one substantive
finding (P2-1) is a readout/injection reconciliation gap that should get an
inject-time key-set check; the other two are hygiene. No P0/P1.

---

## Residuals (honest limits)

These are real and deliberately surfaced, not defects hidden.

1. **The local control-socket approver is not an adversarial gate — now gated
   behind an explicit arm-time factor policy (MITIGATED).** The control socket
   is same-UID-forgeable: an approval is granted by whoever sends
   `Frame::Approve { id }` on the 0600 unix socket, and the request `id` is only
   printed to the daemon's stderr, so a same-UID attacker who can read it can
   self-approve. A compromised same-UID agent (a rogue `claude`/`op`) is exactly
   the adversary Sigil exists to stop, so this path must never be the sole gate.

   The mitigation, added with the network transport: at arm time the daemon
   resolves an explicit **approving factor** (`factor.rs::resolve`,
   `daemon.rs::build_gate`), in order:
   - a **paired phone** reachable over a `Transport` (`RemoteApprover`) — the
     sealed, signed `ApprovalResponse` a same-UID peer cannot forge;
   - a **verified hardware biometric** (`Keystore::is_biometric()` true) — the
     Secure Enclave unwrap is the gate;
   - otherwise **fail closed**: a `NullApprover` denies every gated request,
     **unless** started with `--dev-insecure` / `SIGIL_DEV_INSECURE=1`.

   Only under `--dev-insecure` are `SIGIL_DEV_AUTOAPPROVE` (`with_dev`) and the
   control-socket park (`with_control_socket`) wired at all, and that mode prints
   a loud multi-line stderr warning naming the same-UID risk on every start
   (`factor.rs::warn_dev_insecure`). A normal `sigil daemon` with no phone and no
   biometric is **not** silently self-approvable: it runs the `NullApprover` and
   refuses. With a biometric factor, an unresolved local decision fails closed
   rather than parking on the socket (`approve.rs::LocalApprover::decide_local`
   returns `Deny` when `allow_control_socket` is false).

   Proving tests: `daemon.rs::no_factor_daemon_fails_closed_on_a_gated_request`
   (no factor + no dev flag denies, delivers no secret),
   `approve.rs::without_control_socket_an_unresolved_decision_fails_closed_at_once`
   and `null_approver_denies_every_request`, the `factor.rs::tests` suite
   (`resolve` precedence: phone > biometric > dev-insecure > fail-closed, and the
   warning names the same-UID risk), and the phone factor proven end to end over
   the real relay by
   `daemon.rs::remote_approval_over_the_real_relay_delivers_the_secret` and
   in-process by `remote_softphone_approval_delivers_secret_over_the_socket`
   (both with no dev flag set). Severity: **Medium-High reduced to a documented
   dev-only mode that fails closed by default and is loudly labelled.**

2. **Secure Enclave biometric unwrap and kernel peer/ancestry are unproven on
   hardware.** `keystore_macos.rs::{ensure_dek,unwrap_dek}`, `lease.rs::peer_pid`,
   and the code-signing `identity` all carry NEEDS-VERIFICATION and cannot be
   exercised away from a Mac. Until verified, the biometric factor is inert
   (returns `NeedsVerification`), so the effective shipping gate is either the
   phone or residual #1.

3. **The SA token transits daemon RAM (unavoidable) and one copy is not
   zeroized.** The token is the injected credential, so it must reach the child
   env. `daemon.rs::fulfill` holds it in a `Zeroizing` `Token` and `drop`s it
   after spawn, and `spawn_op` never logs it. But `std::process::Command`'s env
   map holds an ordinary `String` copy of the token until the local `cmd` drops
   at the end of `spawn_op`, and `Command` does not zeroize. So one plaintext
   copy of the token lives, un-wiped, for the span of the child spawn. This is a
   std limitation, not a logic error; it is bounded to the spawn and the value
   is the SA token (not the DEK, not the resolved secret). Documented, not
   fixed.

4. **The DEK's base64 form transits daemon RAM in a non-zeroized `String`.** The
   raw 32-byte DEK is now zeroized on every path (`Dek` is `ZeroizeOnDrop`; the
   decode buffer in `request.rs::ApprovalResponse::dek` is `Zeroizing` as of this
   review), but the `ApprovalResponse.wrapped_dek: Option<String>` still holds
   the base64 of the DEK until the response struct drops. serde deserializes into
   a plain `String`; zeroizing it would need a custom wrapper type. Low severity
   (same-process, requires scraping daemon memory).

5. **Lease-window / approved-consumer misuse (by design).** A lease is a
   time-boxed grant to a *caller code-identity + project + scope*. Within an
   active lease, the same process tree can re-fetch **the same-scope secret**
   without re-prompting; a compromised ancestor in that tree (e.g. `claude`) can
   exploit its own lease for the exact secret it was already approved for. It
   **cannot** widen scope: a different secret is a different `scope` string →
   different grant key → fresh approval (`lease.rs::grant_key`,
   `daemon.rs::fulfill`). The token itself never leaves the daemon, so the lease
   cannot be exfiltrated, only re-exercised for its one scope. Bound by TTL and
   killed by lockdown/restart.

6. **Metadata at the relay.** The relay learns that two anonymous mailbox
   parties exchange envelopes, and the sizes/timing of those envelopes. This is
   inherent to any store-and-forward transport and is the accepted trust surface
   (`docs/design/sigil-design-brief.html`, Trust model).

7. **The "inert at rest" claim is strong for cold-disk theft, weaker for live
   same-UID compromise.** Cold-disk theft yields only `pairing.json` (public);
   the daemon private identity is in the login Keychain, encrypted at rest, so a
   powered-off disk/backup reveals no key material — the strong form of the
   claim holds. But an attacker running live as Tom with the Keychain unlocked
   can read the identity blob and then originate `ApprovalRequest`s to the phone
   with **attacker-chosen provenance** (`process_chain`, `cwd`, `machine` are
   filled by whoever builds the request; the daemon normally derives them from
   kernel-verified ancestry, but a raw holder of the signing key writes them
   directly). The phone's readout cannot then distinguish an attacker's request
   from a legitimate one, so the last line of defense is the human declining a
   request they did not initiate. This is inherent to holding a signing key, not
   a defect; and a live same-UID attacker could already trigger a *real* request
   through the shim. The DEK still never releases without a fresh hardware-gated
   tap, so nothing is released automatically. Documented so the phone UX does not
   over-trust the displayed provenance.

8. **`pairing.md` doc drift (cosmetic).** The pairing design note states "the
   pairing secret is used only to key the confirmation MAC and is then
   destroyed." As of the rendezvous work the secret is *also* an input to
   `rendezvous_mailbox` (a distinct one-way BLAKE2b over `domain ‖ daemon_pub ‖
   secret`). This is a second, independent one-way use of a 256-bit CSPRNG value
   — no key reuse across a shared construction, no oracle, non-invertible — so it
   is not a weakness, but the sentence in `docs/design/pairing.md` should be
   updated to name both uses. Flagged to the doc owner.

9. **The `env-file` provider relaxes invariant #2: resolved secret VALUES
   transit daemon RAM, and two copies are un-wiped (by design, bounded).** Unlike
   the `op` shape — where the daemon injects only a *credential* and the `op`
   child streams the resolved secret straight to the caller's fd, so no secret
   value ever enters the daemon — a direct-injection provider **is** the source:
   it reads KEY=VALUE pairs and places the actual values into the child's
   environment. The daemon holds those values in a `Zeroizing` buffer that is
   wiped on drop, and never logs them (`provider.rs::EnvFileProvider::run`). But
   two un-wiped copies are unavoidable:
   - **`std::process::Command`'s env map** holds a second, plain `OsString` copy
     of each value (std does not zeroize; it is freed, not scrubbed, when `cmd`
     drops at the end of the spawn). This is the *same* std limitation as the SA
     token in residual #3, except the value here is the resolved secret itself,
     not a credential. Bounded to the spawn. (The provider source comment was
     corrected in review to state this honestly rather than claim the `Zeroizing`
     buffer was the values' only in-process home.) The previously-noted
     invalid-UTF-8 lossy-`String` copy is now **FIXED**: `parse_env_file` borrows
     with `str::from_utf8` and returns `None` on non-UTF-8, so an invalid file
     fails closed with no owned `String` ever allocated (`provider.rs::{env_file_with_invalid_utf8_is_rejected,env_file_run_fails_closed_on_invalid_utf8}`).
   - **The child's `/proc/<pid>/environ`** carries the injected values for the
     child's whole lifetime, readable by a same-UID process (`ps eww`, `/proc`).
     For a short-lived child this is a blink; for a long-running one the secrets
     sit in its environment the whole time. This is inherent to *any* "inject env
     and exec" model (the `op` SA token has the same exposure in `op`'s environ),
     and same-UID is already the boundary Sigil does not defend below.

   Leasing is **disabled** for this shape precisely so resolved values never also
   persist in daemon RAM across a TTL (`daemon.rs::env_file_lease_decision_grants_no_lease`).
   Net: `env-file` is strictly more exposed than `op`, the doc says so plainly,
   and it is the reason `op`'s credential-injection shape remains the recommended
   default. Severity: **Medium, inherent to direct injection, documented not
   fixed.** The daemon-RAM copy is same-process-scrape only.

10. **The SSH agent's `op` signer holds the whole private key in RAM for one
    signature (unchanged from `0f41ee4`, now isolated behind the signer seam).**
    On an approved `SIGN_REQUEST` the `OpSshSigner` fetches the key via the
    service account into a `Zeroizing` buffer, signs once, and wipes. Because the
    SA token can read the *whole* key, a compromise at the instant of an approved
    request leaks durable signing power, not one signature — strictly worse than
    a secret release. The seam does not change this; it isolates it to that one
    signer (`FileSshSigner` reads a local file into `Zeroizing` with the same
    per-signature discipline, and a future SE-resident signer would keep the key
    in hardware). Bounded to an *approved* request. Severity: **Medium, v1
    custody exception, documented; v2 moves keys to the Secure Enclave**
    (`docs/design/ssh-agent.md` §4).

11. **The SSH `session-bind` host line is attacker-nameable (advisory only).**
    The agent protocol carries no authenticated hostname; the host key a client
    sends over `session-bind` is not verified by the agent, so a malicious
    same-UID client can label the approval screen with any destination, including
    a real public host key. The host line is therefore *context*, not a gate: the
    binding is the human approving the **data hash** for a **named key**, and an
    unexpected signature prompt is itself the signal. `derive_host` never
    fabricates a name (it falls back to the honest `SHA256:` fingerprint). Severity:
    **Low, inherent to the agent protocol; the data hash is the real binding.**

12. **The P-256 SE DEK wrap carries no sender authentication (correct for the
    local-only use; a constraint for any future remote use).** ECIES to the SE
    public key gives confidentiality and (via GCM) integrity, but not *sender*
    authentication: the SE public key is public, so anyone can wrap an arbitrary
    value to it. This is safe as designed because the wrap is produced and consumed
    **locally** — the daemon wraps the DEK to the same Mac's SE key, and the SE
    unwraps it under Touch ID — so forging or swapping the stored blob already
    requires same-UID write (outside Sigil's boundary) and yields only a fail-closed
    denial (a substituted DEK cannot decrypt the real AES-256-GCM token ciphertext),
    never a secret. AAD binding is **impossible** anyway: `SecKeyCreateDecryptedData`
    for this ECIES algorithm accepts no AAD, so any AAD would break SE interop.
    **Design constraint, recorded so it is not lost when the wrap is wired in:** if a
    wrapped-DEK-to-SE blob is ever delivered by a *remote* party (over the relay, or
    phone→different-machine), it MUST travel inside the signed `Envelope` (Ed25519
    sender auth + replay guard), never bare and never via GCM AAD the SE cannot
    validate. Severity: **None today (local-only, fail-closed); a tripwire for the
    integration step.** Enforcing code: `se_ecies.rs` module docs §"Binding and
    sender authentication".

13. **The inline `env` provider inherits §12's direct-injection RAM residual (by
    design, bounded), improved by sealing the values at rest.** Like `env-file`
    (residual 9), on an approved run the resolved VALUES transit daemon RAM as the
    child's spawn env: a second, un-wiped `OsString` copy sits in
    `std::process::Command`'s env map (std frees but does not scrub it, bounded to
    the spawn — the same std limitation as the op SA token in residual #3), and the
    child's `/proc/<pid>/environ` carries the values for its lifetime (readable by a
    same-UID process; inherent to any inject-env-and-exec model, and same-UID is
    already the boundary Sigil does not defend below). The daemon's own decrypted
    copy is `Zeroizing`, wiped on drop, and never logged; leasing is disabled so
    resolved values never persist across a TTL. **Improvement over `env-file`:** the
    values are AES-256-GCM sealed under the DEK at rest (`sigil.db`), so — unlike a
    plaintext env-file readable by any same-UID process at any time — the
    daemon-at-rest holds no plaintext value (invariant #1 holds for this provider).
    One extra transient copy exists at **set time**: `sigil-config source env set`
    decrypts the current blob, merges the new pair, and re-seals; the merged pairs
    (and the value the user is supplying, which is in CLI RAM regardless) are held
    `Zeroizing` for that CLI invocation only. Severity: **Medium at run time
    (inherent to direct injection, same as §12), reduced at rest (sealed, not
    plaintext).** Enforcing code: `provider.rs::{EnvProvider,spawn_with_env,
    decode_env_pairs}`, `daemon.rs::fulfill`, `cli.rs::seal_env_pairs`. See §19.

---

## Independent review verdict: pairing-security unit (f1192b6, 37035ee, 13e56c2)

**Reviewer:** independent security-reviewer (did NOT write this code). **Date:**
2026-07-06. **Scope:** the SAS-confirm stdin gate on `sigil pair --json`
(f1192b6), the real P-256 Secure Enclave DEK wrap in `keystore_macos.rs`
(37035ee) plus its uncommitted `for_test`-isolation follow-up in the working
tree, and the relocation of the DEK unwrap from ceremony-start to
post-SAS-confirm (13e56c2). Static/adversarial review only; no biometric
hardware was exercised (see residuals). This verdict is written by the
independent reviewer per the review-integrity rule; the implementer did not
self-certify.

**Bottom line: SOUND at the logic/code level, assuming the Secure Enclave FFI
behaves as Apple documents.** No P0 or P1 confirmed. The central claim holds:
**there is no path that delivers the DEK without both a genuine SAS gate and a
fresh Secure-Enclave-gated biometric.** Two P2 code findings and a set of
hardware-verification residuals are recorded below; one P2 is a data-loss
footgun in the committed hardware test that the uncommitted working-tree change
correctly fixes and that must be committed.

### CONFIRMED SOUND (static)

1. **SAS bypass on the `--json` path is closed.** `run_pairing_json`'s
   `confirm` closure (`crates/sigil/src/cli.rs:1428`-`1440`) now emits the `sas`
   event, then blocks on one line of stdin and returns `true` only for a
   trimmed, case-insensitive `"confirm"`; `Ok(0)` (EOF), any other line, and
   `Err(_)` all return `false`. `run_ceremony` (`crates/sigil/src/pair.rs:153`)
   treats `false` as `bail!` before any unwrap or deliver. The pre-fix
   auto-`true` is gone. Fail-closed on every non-confirm input.

2. **Confirm → biometric → deliver ordering is correct and has no
   pre-biometric delivery path.** In `run_ceremony`
   (`crates/sigil/src/pair.rs:149`-`177`) the strict order is: `confirm_sas`
   (human) → `daemon.confirm()` → `unwrap_dek()` (on an SE keystore, the Touch
   ID moment) → `deliver_dek` → `channel.send`. `daemon.confirm()` transmits
   nothing over the channel; the *only* `channel.send` of DEK material is at
   line 173-175, strictly after `unwrap_dek()` at line 162. A declined/EOF/error
   SAS bails before line 162; an `unwrap_dek` error (`Declined` or `Backend`,
   mapped to `anyhow` in cli.rs:1310-1312 / 1440-1442) bails before any send.
   Fail-closed throughout.

3. **The 13e56c2 relocation genuinely closes the same-UID stdin-writer
   threat.** Because the biometric now fires at `unwrap_dek` (after the stdin
   `confirm`), a process that can only write `"confirm"` to the pair
   subprocess's stdin cannot complete a pairing: it still faces a fresh
   Secure-Enclave biometric it cannot satisfy. The stdin `confirm` and the
   biometric are *not* separable into a single reusable authorization — the
   biometric is enforced by the SE key's own access control on
   `SecKeyCreateDecryptedData`, not by any token the caller holds. Encoded as a
   regression test: `pair.rs::the_dek_is_never_unwrapped_when_the_sas_is_declined`
   (added by this review) asserts `unwrap_dek` is invoked **zero** times and no
   envelope is sent when `confirm_sas` returns `false`. A refactor that moved the
   unwrap back ahead of the SAS gate fails this test.

4. **No error-code mapping can cause a fail-OPEN.** The residual flagged by the
   implementer (errSecUserCanceled `-128` vs errSecAuthFailed `-25293`) is a
   *classification* question, not a safety one: the **only** success path out of
   `unwrap_dek` is a non-null `plaintext_ref` of exactly 32 bytes
   (`keystore_macos.rs:249`-`279`). Every `CFError` — whichever code — routes
   through `cf_error_to_keystore` to either `Declined` or `Backend`, and **both**
   abort the pairing ceremony (`pair.rs:162` bails) and deny in the local-approve
   path (`approve.rs:420`-`422`: only `Ok(_dek)` approves; `Declined` denies;
   any other error falls through to a `Deny` under production config). So even a
   fully wrong `-128`/`-25293` mapping changes only the deny-vs-hard-error UX,
   never approve-vs-deny. Confirmed for both the pairing and approval surfaces.

5. **The `SecKeyCreateDecryptedData` FFI is memory-safe and leak-free (modulo
   hardware behavior).** `keystore_macos.rs:249`-`279`: the out-error is checked
   before the plaintext; a non-null `CFErrorRef` is taken under
   `wrap_under_create_rule` (create-rule ownership, no double-free/leak); a
   null-plaintext-with-null-error case is handled as a `Backend` fault; the
   `CFData` result is taken under the create rule; the recovered bytes are
   length-checked to 32 and copied into a `Zeroizing<[u8;32]>`. `key` and
   `ciphertext` are live `TCFType`s across the call. The DEK plaintext exists
   only in the `Zeroizing` buffer and is never logged or copied elsewhere.

6. **DEK protected at rest; wrap/unwrap matched.** Only the SE-wrapped blob is
   persisted (`DEK_ENVELOPE_LABEL`, ciphertext); the DEK plaintext is built in
   pure Rust (`sigil_proto::wrap_dek_p256`), used, and dropped/zeroized in
   `ensure_dek` (`keystore_macos.rs:213`-`220`). The wrap
   (`p256::ECDH` + ANSI-X9.63-SHA256 KDF + AES-128-GCM, 16-byte variable IV,
   65+32+16 = 113-byte blob) and the SE unwrap
   (`ECIESEncryptionCofactorVariableIVX963SHA256AESGCM`) are the same
   construction, already reviewed under #23; the KDF is pinned by a
   known-answer test. At the code level the access control is
   `kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet`
   (biometric mandated, **no** `.devicePasscode`/`.userPresence` fallback), so a
   passcode alone cannot unwrap.

### CONFIRMED FINDINGS (code-level, need a fix)

- **P2 — the SE access control is created with a NULL protection class,
  diverging from every reference and the design's stated intent.**
  `keystore_macos.rs:186`-`189` calls
  `SecAccessControl::create_with_flags(...)`, which in security-framework 2.11.1
  is `create_with_protection(None, flags)` — it passes a **null** protection
  value to `SecAccessControlCreateWithFlags`
  (`.cargo/.../security-framework-2.11.1/src/access_control.rs:51`-`76`). Every
  Swift counterpart pins `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
  (`apps/mac/Tools/se-selftest.swift:29`,
  `apps/mac/Latch/Security/SecureEnclaveApprover.swift:52`,
  `apps/phone/.../SigilSeModule.swift:95`) and `apps/mac/RESEARCH.md:70`
  specifies exactly that class. Consequence is **fail-closed, not
  fail-open**: on hardware this most likely makes `SecKeyCreateRandomKey`
  reject the request (ensure_dek → `Backend`, denies), or at best mints the key
  without the intended `WhenUnlocked`/`ThisDeviceOnly` guarantee the brief calls
  for. Fix: `SecAccessControl::create_with_protection(Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly), flags)`.
  Not a disclosure risk (the biometry flag and SE non-extractability are
  independent of the protection class), but it is a real divergence that should
  be corrected before the on-hardware verification, or the verification will
  test the wrong construction.

- **P2 (data-loss footgun, not disclosure) — the committed 37035ee hardware
  test deletes the REAL production DEK blob.** As committed, the ignored test
  `se_dek_round_trips_through_a_real_touch_id` ran `MacKeystore::new()` (real
  labels) and `delete_blob(DEK_ENVELOPE_LABEL)` (the real production envelope),
  then `ensure_dek()` — minting a **fresh** DEK under the real label. Running it
  on Tom's Mac would have bricked every account whose token was sealed under the
  prior DEK (the new DEK cannot decrypt them; fails closed, but the tokens are
  unrecoverable without re-add). **Resolved in HEAD by df78e8f** ("make the SE
  round-trip harness isolation-safe"), which landed during this review:
  per-instance labels via `MacKeystore::for_test`, `.selftest` suffixes, and
  always-cleanup with `catch_unwind`, so the test can never touch the production
  `SE_KEY_LABEL`/`DEK_ENVELOPE_LABEL`. Recorded so the reason the isolation
  exists is not lost: never let a hardware test run against the real labels.

### RESIDUALS — require Tom's on-hardware verification (cannot be settled statically)

- **Declined-biometric error code** (`ERR_SEC_USER_CANCELED` `-128` vs
  `ERR_SEC_AUTH_FAILED` `-25293`, `keystore_macos.rs:66`-`79`): confirm which
  `SecKeyCreateDecryptedData` actually returns on a declined prompt. Per finding
  #4 this affects only deny-vs-hard-error UX, never safety.
- **SE-key re-query** (`find_se_private_key`, `keystore_macos.rs:286`-`300`):
  `ItemSearchOptions` has no `kSecUseDataProtectionKeychain`; confirm a key
  minted in the `DataProtectionKeychain` actually surfaces by label. If not, it
  returns `NoDek` → fails closed.
- **SE decrypt interop**: that Apple's `SecKeyCreateDecryptedData` opens a blob
  produced by `wrap_dek_p256` byte-for-byte. The in-crate tests only prove
  Rust-side self-consistency. Confirm with `apps/mac/Tools/se-selftest.swift`
  and the ignored round-trip test on Apple-silicon with an enrolled biometric.
- **`.biometryCurrentSet` mandates biometric with no passcode fallback** on
  macOS as documented — confirm the prompt is biometric-only and that a fresh
  evaluation fires on *each* unwrap (no LAContext is passed, so there is no
  biometric-reuse window by construction; verify the OS honors that).
- **Generic prompt copy (social-engineering residual).** `unwrap_dek` does not
  thread `reason` into an `LAContext`, so the Touch ID sheet shows default
  system copy. The biometric therefore proves *fresh human presence at DEK
  release*, not *human authorizing this specific device* — the device-binding
  backstop remains the human's SAS-word eyeball comparison, not the biometric.
  Acceptable (the SAS is the MITM gate; the biometric is presence), but until an
  `LAContext` names the action the prompt cannot itself disambiguate a
  legitimate pairing from a same-UID-triggered one to a distracted user.

### SECONDARY — relay v4 trust-model relaxation (opinion, not the primary verdict)

The end-to-end crypto **still holds** despite the relay becoming a
content-free "blind doorbell": every envelope remains opaque and sealed by
`crates/sigil-proto` (Ed25519 sender auth + `crypto_box`/threshold + replay guard),
the relay never parses one, and the push body is fixed and generic. The relay's
new powers — a shared publisher APNs signing key held as a platform secret, and
a phone push token seen transiently per deposit and never stored — do not let it
read a secret, forge an approval, or learn an outcome. Invariant #3's "powerless
and anonymous" is genuinely relaxed to "blind doorbell, holds a push secret";
the README records this honestly and defers the verdict here, which is correct.

The **per-mailbox (not per-token) push cap** (`PUSH_MAX=5/min`) is an
acceptable residual with a named limit: a party who has already obtained a
victim's push token (itself not secret-bearing) can ring that phone's doorbell
and evade the cap by rotating the `mailbox_id` in the deposit URL, since the cap
is keyed per mailbox and the push targets whatever token the body carries. Worst
case is generic "Approval requested" notification spam / battery drain — **not**
a secret disclosure and **not** an approval (the phone still needs the real
sealed request plus a biometric to approve anything). Acceptable as a
nuisance-only vector; a per-token bucket, or requiring the doorbell deposit to
be bound to the sealed envelope, would close it if push-spam becomes a concern.

**Verdict recorded by the independent security-reviewer. The pairing-security
unit is sound; fix the two P2s (commit the `for_test` isolation; give the SE
access control an explicit `WhenUnlockedThisDeviceOnly` protection class) and
clear the hardware residuals before treating the SE path as verified.**

---

## §15 — relay long-poll v5.1: coexisting waiters + newest-wins delivery (commit `33b464f`)

Independent adversarial review of the delivery-semantics change in
`relay/shared/protocol.ts` (`longPoll`/`wake`/`MAX_WAITERS`). Reviewer did not
author the change. Focus: delivery integrity (no silent loss beyond honestly
stated residuals, no starvation/steal by a hostile party, no unbounded memory);
envelope crypto is unchanged and out of scope. Invariant at stake throughout is
**everything fails closed** (#5) and the relay's no-silent-drop promise, not
confidentiality (#3 holds — envelopes stay opaque, and every worst case below is
a *non-delivery*, never a disclosure).

**The change, restated adversarially.** Old `longPoll` flushed every existing
waiter empty on each new GET (`waiters.splice(0)`), manufacturing instant-empties
a client re-fired on (the poll storm). New: waiters coexist, each held its full
window; `wake` delivers a deposit to the **newest** waiter (`waiters.pop()`);
`MAX_WAITERS=8` caps memory, and past the cap a new GET drops the **oldest**
waiter (resolved empty). Both suites green locally (Bun 37 / Worker 21);
reviewer's scratch suite (`relay/scratch-adversarial.test.ts`, 4 tests) proves
the four properties below.

| Claim | Enforcing code | Proving test | Verdict |
|-------|----------------|--------------|---------|
| **Newest-wins delivers correctly for the shipped clients.** Both the daemon (blocking `reqwest`, one GET at a time) and the phone (`relay-http.ts` `activeWaits` aborts any prior poll before a new one; `phone-relay.ts` `inFlight` collapses concurrent wakes) are **strictly single-flight per slot**. Two waiters therefore only coexist via disconnect-then-reconnect, which makes the OLDER the dead orphan and the NEWER the live reconnect. `wake` → newest → the connection that can still receive. | `wake` (`protocol.ts:325`, `waiters.pop()`); `sigil-relay-client/src/http.rs` (blocking); `apps/phone/src/transport/relay-http.ts:95` (`activeWaits`) | `protocol.test.ts` disconnect/reconnect test; scratch `NOT reachable by a single-flight client…` | **SOUND** |
| **`MAX_WAITERS` drop-oldest never loses a queued deposit.** Eviction runs only on the empty-slot branch (the `drain` above returned nothing), synchronously, with no `await` between the drain and the `while` loop, so single-threaded JS guarantees the slot is provably empty at eviction; the dropped waiter is resolved `[]` with nothing to lose. | `longPoll` (`protocol.ts:249-273`) | scratch `MAX_WAITERS drop-oldest never loses a queued deposit…` | **SOUND** |
| **Neither paired party can starve the other's inbound delivery.** `toPhoneWaiters` (phone reading) and `toDaemonWaiters` (daemon reading) are disjoint arrays. A flood of GETs on one slot evicts only that slot's own oldest waiters; it cannot touch the other slot. So one misbehaving side can only self-DoS its own reads. | `Mailbox` (`protocol.ts:130-143`); slot-specific `wake`/`longPoll` calls in `src/index.ts`, `bun/server.ts` | scratch `STRUCTURAL: one party's slot-flood cannot evict the other party's delivery waiter` | **SOUND** |
| **No duplicate delivery / no misdelivery across mailboxes.** `wake` calls `drain` (empties the list) before handing off; an item leaves the queue exactly once. Waiters are per-mailbox-per-slot, so a deposit can only ever reach one of the two legitimate parties' connections. | `drain` (`protocol.ts:217`), `wake` (`protocol.ts:325`) | reviewed by inspection (drain-empties invariant); Bun/Worker `deposit and drain` | **SOUND** |

### Findings (ranked)

**No P0 or P1.** The change is a net improvement: it removes the fast-empty
hammer and introduces no new loss vector relative to the prior design (the old
evict-all design *also* delivered to the newest/only waiter, so it lost in
exactly the same "newest waiter is dead" case — see below).

**P2 — the two "still open" residuals are one root cause, and honestly stated
but slightly over-decomposed.** Both open residuals in the module header reduce
to a single invariant: *`wake` loses a deposit iff the newest waiter is a dead
orphan at deposit time* (drained into a connection nobody reads).
- *Residual A (deposit in the disconnect gap):* reachable by the shipped clients
  — a real disconnect whose abort didn't fire, then a deposit landing before the
  reconnect re-attaches. Proven real by the scratch `RESIDUAL IS REAL…` test.
  This is genuine, bounded (one delivery, requires an actual disconnect plus
  unlucky timing), fail-closed (a lost approval request or response just means
  no secret is released), and is what client-side resend must cover regardless.
  Correctly tracked as **task #53** (verify/mitigate at a real Cloudflare deploy).
- *Residual B ("newer connection dies while older lives"):* the header presents
  this as a second, distinct residual. **It is not reachable by any shipped
  client**, because both are strictly single-flight per slot (see row 1): they
  never hold two genuinely-live overlapping polls on one slot, so the newer of
  two coexisting waiters is never the dead one. It becomes reachable only for a
  hypothetical *future* concurrent/multi-poll client. Recommendation: keep it
  documented, but note explicitly that it is unreachable given today's clients —
  as written the README slightly overstates its current reachability (harmless
  direction: it over-warns, it does not under-warn).

**P2 — MAX_WAITERS bounds per-slot waiters, not mailbox count (pre-existing,
unchanged by this commit).** `MAX_WAITERS=8` caps waiters at 16 per mailbox (8×2
slots). It does **not** cap the number of distinct mailboxes: the Bun `boxes`
Map grows one entry per distinct id seen, and the rate limiter is per-mailbox so
it does not bound distinct-id creation. An attacker who can reach the relay can
inflate the Map with random ids (each holding held GETs) until the sweep
(`TTL_MS`, only deletes idle+unwatched boxes) or the OS connection limit stops
it. The Worker variant offloads this to Cloudflare's isolate lifecycle. This is
the pre-existing "rate limiter is non-load-bearing; the front is the real bound"
posture, not a regression from v5.1, and acceptable for a personal/self-host
deployment — flagged so it is not mistaken for a bound this change added.

**Steal/eviction as a weapon — not reachable by a third party.** Forcing a
victim's legit waiter out (8 GETs past the cap) and positioning an attacker
waiter as newest to *steal* the next deposit requires registering GETs on the
victim's slot, i.e. knowing the `mailbox_id`. That id is
`BLAKE2b(domain ‖ canonical(pinned_pub_a, pinned_pub_b))` (`fingerprint.rs:83`),
a 256-bit value derived from two pinned public keys, carried inside TLS to the
relay and never published — unguessable by a third party. Only the relay
operator (who sees the id in the URL) is positioned to do this, and a hostile
relay can already deny delivery arbitrarily; the theft still yields only an
opaque sealed envelope and a non-approval (fail-closed). Acceptable; worth one
line in the module header that delivery-slot integrity rests on the mailbox id
staying unknown to third parties (it does).

**Verdict (independent security-reviewer, not the implementer of `33b464f`).
The v5.1 coexisting-waiter / newest-wins change is SOUND for delivery
integrity.** It removes the fast-empty hammer, adds no new message-loss vector,
cannot be used by one paired party to starve the other, is memory-bounded
per slot, and every worst case is a bounded, fail-closed non-delivery — never a
disclosure or a fail-open approval. The one client-reachable residual (deposit
in the disconnect gap) is real, honestly documented, and correctly deferred to
task #53 for real-edge verification plus client-side resend. Recommend two
documentation tightenings (both non-blocking): (1) mark residual B as not
reachable by today's single-flight clients rather than an open peer of residual
A; (2) note that slot-steal presupposes knowledge of the unguessable mailbox id.
