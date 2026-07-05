# Security claims → enforcing code → proving test

This is the map a skeptical adopter reads. Every row is a claim Latch makes,
the exact code that enforces it (`file::symbol`), and the test that proves it.
A claim with no test is marked **UNPROVEN** in bold; a claim proven only for a
seam that is not yet wired into the shipping daemon is marked **PARTIAL** with
the gap named.

Paths are relative to the repo root. Test names are the `#[test]` fn names;
run any with `cargo test <name>`.

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

## 10. Pairing persistence stays inert at rest (the `latch pair` at-rest format)

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
| An **unconfigured** command is refused, never run ungated; the caller gets the exact `latch config add` hint | `daemon.rs::fulfill` (`commands.resolve` → `None` → `fail_closed`), `command.rs::CommandStore::resolve` (only `op` resolves by default) | `daemon.rs::unconfigured_command_is_refused_with_a_config_hint`, `command.rs::an_unconfigured_command_does_not_resolve` |
| A config entry naming an **unknown provider** fails closed, never runs | `daemon.rs::fulfill` (`providers.get` → `None` → `fail_closed`) | reviewed by inspection (the `unknown provider` branch); exercised structurally by `provider.rs::registry_dispatches_by_id_and_lists_defaults` |
| The env-file **source path comes only from the CLI-side config (0600), never from the caller's argv**, so a caller cannot redirect env-file at an arbitrary file (`/etc/shadow`, a co-worker's `.env`) | `daemon.rs::fulfill` (`source = cfg.source`, argv is never consulted for the source), `command.rs` (config is a CLI-only mutation surface) | reviewed by inspection; the config-store add/get/remove path is `command.rs::add_get_remove_round_trip_and_reject_duplicates` |
| A command that **shadows a reserved verb** fails toward the built-in verb (safe), never toward ungated execution; the escape hatch is `latch run -- <cmd>` | `cli.rs::main` dispatch + `is_reserved_verb`, `shim.rs::dispatch` (the daemon's `fulfill` is the sole injection chokepoint) | `cli.rs::reserved_verbs_take_precedence_over_command_dispatch` |
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
already outside Latch's boundary. Not a distinct escalation; noted for
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

---

## Residuals (honest limits)

These are real and deliberately surfaced, not defects hidden.

1. **The local control-socket approver is not an adversarial gate — now gated
   behind an explicit arm-time factor policy (MITIGATED).** The control socket
   is same-UID-forgeable: an approval is granted by whoever sends
   `Frame::Approve { id }` on the 0600 unix socket, and the request `id` is only
   printed to the daemon's stderr, so a same-UID attacker who can read it can
   self-approve. A compromised same-UID agent (a rogue `claude`/`op`) is exactly
   the adversary Latch exists to stop, so this path must never be the sole gate.

   The mitigation, added with the network transport: at arm time the daemon
   resolves an explicit **approving factor** (`factor.rs::resolve`,
   `daemon.rs::build_gate`), in order:
   - a **paired phone** reachable over a `Transport` (`RemoteApprover`) — the
     sealed, signed `ApprovalResponse` a same-UID peer cannot forge;
   - a **verified hardware biometric** (`Keystore::is_biometric()` true) — the
     Secure Enclave unwrap is the gate;
   - otherwise **fail closed**: a `NullApprover` denies every gated request,
     **unless** started with `--dev-insecure` / `LATCH_DEV_INSECURE=1`.

   Only under `--dev-insecure` are `LATCH_DEV_AUTOAPPROVE` (`with_dev`) and the
   control-socket park (`with_control_socket`) wired at all, and that mode prints
   a loud multi-line stderr warning naming the same-UID risk on every start
   (`factor.rs::warn_dev_insecure`). A normal `latch daemon` with no phone and no
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
   (`docs/design/latch-design-brief.html`, Trust model).

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
     and same-UID is already the boundary Latch does not defend below.

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
    requires same-UID write (outside Latch's boundary) and yields only a fail-closed
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
