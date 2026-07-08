# Security claims → enforcing code → proving test

This is the map a skeptical adopter reads. Every row is a claim Sigil makes,
the exact code that enforces it (`file::symbol`), and the test that proves it.
A claim with no test is marked **UNPROVEN** in bold; a claim proven only for a
seam that is not yet wired into the shipping daemon is marked **PARTIAL** with
the gap named.

Paths are relative to the repo root. Test names are the `#[test]` fn names;
run any with `cargo test <name>`.

**Authorship convention (review integrity).** The claim/code/test rows and the
residuals are maintained by whoever touches the surface. But a *verdict*, any
"reviewed and found sound" / "CONFIRMED SOUND" statement about whether a
construction is correct, is written **only by an independent security-reviewer
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
CLI-only pairing persistence), sections 11-13 and residuals 9-11 below.
Extended again at commit `747b3a4` (the P-256 Secure Enclave DEK wrap), section
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
| The Secure Enclave DEK unwrap fires Touch ID on real hardware | `keystore_macos.rs::unwrap_dek` | **UNPROVEN, PARTIAL**: FFI is documented but returns `NeedsVerification`; must be exercised on a Mac (see NEEDS-VERIFICATION block). Until then, the shipping local approver falls through to the control socket (see Residuals). |

## 7. Caller identity is daemon-verified (invariant #6)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Peer pid is read from the kernel, not the client | `lease.rs::peer_pid` (`LOCAL_PEERPID`/`SO_PEERCRED`) | **UNPROVEN, PARTIAL** on hardware (`NEEDS-VERIFICATION` in `lease.rs`); logic exercised via injected pid in daemon tests |
| Ancestry is walked kernel-side; the grant key binds code identity, never pids | `lease.rs::walk_ancestry`, `grant_key` (excludes pids) | `lease.rs::ancestry_walk_is_root_first_and_stops_at_init`, `grant_key_ignores_recycled_pids`, `grant_key_changes_with_root_scope_or_ancestry` |
| The ancestry walk terminates on cycles / bounded depth | `lease.rs::walk_ancestry` (`MAX_ANCESTRY_DEPTH`, `seen` set) | `lease.rs::ancestry_walk_terminates_on_a_cycle` |
| A phone-claimed grant key is ignored; the daemon derives and trusts its own | `daemon.rs::fulfill` (uses `gk`), `request.rs::InstallLease` (echo only), `softphone/lib.rs` (empty `grant_key`) | reviewed by inspection; exercised by `daemon.rs::lease_decision_covers_the_next_identical_request` |
| The ancestor "code identity" is a real code-signing measurement | `lease.rs::SysProcessTable::identity` | **UNPROVEN, PARTIAL**: interim BLAKE2b of the exe bytes; the design calls for the cdhash / Developer ID (NEEDS-VERIFICATION in `lease.rs`) |

## 8. Fail closed, leases bounded, lockdown (invariants #7, #8)

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Every failure path denies (deny, timeout, dead phone, decrypt failure, lockdown) | `daemon.rs::fulfill` (`fail_closed` on each branch), `remote.rs::round_trip` (`?`/`None` → Deny) | `daemon.rs::denied_request_fails_closed_and_delivers_no_secret`, `remote_softphone_denial_fails_closed_with_no_secret`, `approve.rs::local_timeout_fails_closed` |
| Leases are RAM-only, triple-scoped (grant key + account + scope) | `lease.rs::LeaseStore`, `Lease` | `lease.rs::lease_grant_lookup_and_scope_isolation` |
| Leases expire on TTL and are purged (and zeroized) | `lease.rs::token_for`/`grant` (`retain(expires>now)`; token is `Zeroizing`) | `lease.rs::lease_expires_and_is_purged` |
| Lockdown clears (zeroizes) every lease and refuses new requests | `daemon.rs::handle_conn` (`Lockdown`), `lease.rs::LeaseStore::clear`, `fulfill` (lockdown check first) | `lease.rs::lockdown_clears_all_leases`, `daemon.rs::lockdown_refuses_new_requests` |
| Daemon restart / ctrl-c zeroizes leases | `daemon.rs::serve` (`core.leases.clear()` on ctrl-c) + RAM-only storage | **UNPROVEN** by test (process-exit path); RAM-only + `clear()` reviewed by inspection |
| A revoke drops matching leases | `lease.rs::LeaseStore::revoke` | `lease.rs::revoke_by_grant_prefix` |
| A **run-once** rule never leases, even if the approver returns a lease | `daemon.rs::fulfill` (`action.lease.clamp_secs(...)` gates both grant sites; `LeasePolicy::RunOnce.clamp_secs` → `None`), `request.rs::LeasePolicy` | `daemon.rs::run_once_rule_never_leases_even_when_a_lease_is_returned`, `request.rs::lease_policy_defaults_to_run_once_and_clamps` |
| A **leasable** rule clamps any lease to the per-rule cap (no over-lease) | `daemon.rs::fulfill` (`clamp_secs` = `min(requested, cap)`) | `daemon.rs::leasable_rule_clamps_an_over_cap_lease_to_the_rule_max`, `request.rs::lease_policy_defaults_to_run_once_and_clamps` |
| The lease policy the approver consents to rides inside the sealed/signed envelope | `request.rs::ApprovalRequest.lease_policy` (default `RunOnce` on absence), carried by `remote.rs::build_request` | `request.rs::request_serializes_camel_case_and_stays_provider_agnostic` (asserts `leasePolicy`), `remote.rs::build_request_is_provider_blind` |
| An **allow** (passthrough) rule is a deliberate, user-authored ungating scoped strictly to its match | `config.rs::RuleMode::Allow`, `Config::resolve` (returns `Resolution::Allow` only on a matching allow rule), `add_rule` (rejects an empty match in both modes, and an allow rule that names a source or is leasable) | `config.rs::allow_rule_resolves_to_passthrough_and_layers_above_a_gate`, `add_rule_rejects_an_allow_with_a_source_or_lease_and_a_gate_without` |
| An allow rule bypasses the gate for its match ONLY; an unmatched command still refuses (fails closed) | `daemon.rs::fulfill` (`Resolution::Allow` -> `provider::run_passthrough`, no approval/injection/lease; `None` -> `fail_closed`), first-match-in-order is the only precedence | `daemon.rs::allow_rule_runs_the_command_directly_without_gating`, `config.rs::allow_rule_resolves_to_passthrough_and_layers_above_a_gate` (unmatched still `None`) |
| Mode defaults to gate: a config missing/dropping `mode` gates, never allows | `config.rs::RuleMode` (`#[default] Gate`, `#[serde(default)]`) | `config.rs::action_defaults_to_run_once_when_lease_field_absent` (same absent-field config resolves as a gate) |

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
| The bootstrap **rendezvous mailbox** is domain-separated and non-invertible: leaking it reveals nothing about the secret | `pairing.rs::rendezvous_mailbox` (`BLAKE2b(RENDEZVOUS_DOMAIN ‖ daemon.verifying ‖ daemon.agreement ‖ secret)`, distinct from `mailbox_id`/`fingerprint`/confirm-tag domains; secret is 256-bit CSPRNG so preimage-resistant) | reviewed by inspection (domain constants distinct; length-prefixed absorb is injective); **UNPROVEN** by a dedicated test, no negative test asserts domain separation of the rendezvous id |
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
| A **down daemon** makes the shim exec the bare tool with **no injected secret** (fail-safe: nothing is released); a protocol error while the daemon is **up** fails closed (exit 70), never runs ungated | `shim.rs::dispatch` (`Ok`→exit code; `forward` error→exit 70; only a *down* socket → `exec_real`), `shim.rs::exec_real` (no env injected) | reviewed by inspection (the module contract; no negative test asserts the exec fallback injects nothing), **UNPROVEN** by a dedicated test |

## 12. The `env-file` direct-injection provider (invariant #2, honestly relaxed)

`env-file` is the reference provider that proves the seam is not op-shaped. It is
the **one** path where resolved secret VALUES (not a credential) transit daemon
RAM, and the doc is explicit about the exact residual that buys.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| `describe()` names the source **without reading it**, so no secret value enters daemon memory before the decision | `provider.rs::EnvFileProvider::describe` (uses `Path::file_name` only, never `read`) | reviewed by inspection; `provider.rs::env_file_parses_pairs_and_strips_quotes_and_comments` covers the parser that runs only at `run()` time |
| The file is read into a `Zeroizing` buffer and every value lands in a `Zeroizing` string; both are wiped when the map drops at end of `run()` | `provider.rs::{EnvFileProvider::run,parse_env_file}` (`Zeroizing::new(bytes)`, `Zeroizing<Vec<(String, Zeroizing<String>)>>`) | `provider.rs::env_file_provider_injects_the_vars_into_the_child` (values reach the child), parser by `env_file_parses_pairs_and_strips_quotes_and_comments` |
| **Leasing is disabled for env-file**: a lease would hold resolved values in RAM across a TTL, so a direct-injection provider is gated on **every** run, even when the decision grants a session lease | `daemon.rs::fulfill` (the lease short-circuit and the `grant` are both inside `if needs_account` / `if let Some(ciphertext)`, and `EnvFileProvider::needs_account()==false`) | `daemon.rs::env_file_lease_decision_grants_no_lease` (Lease decision → runs once, `leases.active()==0`), `env_file_command_runs_gated_and_injects_env` (`active()==0`) |
| `needs_account()==false` correctly gates that env-file **never** routes an account, unwraps the DEK, or touches leasing | `provider.rs::EnvFileProvider::needs_account`, `daemon.rs::fulfill` (all account/DEK/lease work guarded by `needs_account`) | `provider.rs::op_provider_needs_an_account_and_env_file_does_not`, `daemon.rs::env_file_command_runs_gated_and_injects_env` |
| No value is ever logged: every env-file error line names the **path / io error only** | `provider.rs::EnvFileProvider::run` (all `eprintln!` carry `run.source` or `command[0]`, never a value) | reviewed by inspection (no negative-logging assertion), **UNPROVEN** by test |
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
between arm and sign makes the agent emit a signature under a *different* key,
which the SSH client then rejects (it does not match the offered identity), so
this breaks the connection rather than forging anything. A same-UID file swap is
already outside Sigil's boundary. Not a distinct escalation; noted for
completeness.

## 14. The P-256 Secure Enclave DEK wrap (`747b3a4`)

The Mac local-approval factor unwraps the DEK *inside* the Secure Enclave under
Touch ID, and the SE holds only P-256 keys, so the Mac-SE wrap is a second,
independent envelope of the same DEK (the phone path is unchanged X25519). It
reproduces Apple's `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`
so `SecKeyCreateDecryptedData` opens it.

**Independent review verdict, CONFIRMED SOUND.** This verdict is written by the
security-reviewer, which did **not** author `se_ecies.rs` (implemented by
rust-core in `747b3a4`); per the review-integrity rule the implementer documents
behavior and residuals, and only the independent reviewer records a "reviewed"
verdict, this is not a self-certification. The adversarial pass covered the
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
| The construction matches Apple's ECIES exactly: ephemeral P-256 → cofactor ECDH (P-256 h=1) → ANSI-X9.63 KDF-SHA256 with sharedInfo = ephemeral X9.63 pubkey → **AES-128** key ‖ 16-byte **variable IV** → AES-128-GCM, empty AAD, 16-byte tag; wire `eph_pub(65) ‖ ct(32) ‖ tag(16) = 113` | `se_ecies.rs::{wrap_dek_p256,x963_kdf_sha256,split_key_iv,Aes128GcmVarIv}` | `se_ecies.rs::{wrap_unwrap_round_trips_the_dek,sealed_blob_has_the_apple_wire_length,x963_kdf_matches_a_known_answer}`; on-device interop is **UNPROVEN, NEEDS-VERIFICATION** (`apps/mac/Tools/se-selftest.swift`, blob must read 113) |
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

**Independent review verdict, CONFIRMED SOUND (two low-severity hardening
notes).** Written by the security-reviewer, which did **not** author `config.rs`
or the `fulfill` rewrite (rust-core, `b66404c`); per the review-integrity rule
this is not a self-certification. The adversarial pass covered: whether a crafted
argv/rule can route to the wrong account or the wrong threshold key; whether
removing the `op` hardwiring opens a fail-open path; and whether the deferred
`arg_regex` can be smuggled into an always-true match.

| Claim | Enforcing code | Proving test |
|-------|----------------|--------------|
| Account routing is **config-derived, never caller-argv-derived**: the hint is the matched source's `account` label; the caller's argv no longer influences which account unlocks (it only selects which of Tom's own rules matches, and every match still requires a fresh approval/lease). This is *stronger* than the old `--vault` sniff | `daemon.rs::fulfill` (`vault = action.account.clone()`; `parse_vault` deleted), `config.rs::Config::resolve` | `daemon.rs::v1_and_v2_accounts_coexist_and_each_takes_its_own_path`, `config::tests::resolve_first_match_wins_and_flattens_source` |
| The v2 threshold path selects **one** account atomically (`record.clone()`): the phone's partial `Z_F` is agreed against that record's `E` and combined with the SAME account's Mac share `m` and token ciphertext, no cross-account share splicing is reachable via label/vault confusion | `daemon.rs::fulfill` (`v2 = store.route_exact(...).map(\|a\| (label, a.record.clone()))`), `threshold.rs::route_exact` | `daemon.rs::remote_v2_threshold_approval_decrypts_via_two_party_combine`, `threshold::tests::each_account_gets_a_unique_ephemeral_and_routes`, `full_two_of_two_round_trip_{raw_x,x963}` |
| `route_exact` stays **exact** when v1 accounts coexist (v2 claims only a label/vault match, never the single-account fallback), so a migration store never lets v2 over-capture a v1 request | `daemon.rs::fulfill` (`route_exact(...).or_else(\|\| if v1_empty { route(...) } else { None })`) | `daemon.rs::v1_and_v2_accounts_coexist_and_each_takes_its_own_path` |
| An invocation that **no rule matches** is refused, never run ungated; removing `default_op`/`parse_vault` leaves **no** built-in rule for any command (a zero-config daemon refuses everything until configured) | `config.rs::Config::resolve` (`None`), `daemon.rs::fulfill` (`fail_closed`) | `daemon.rs::unconfigured_command_is_refused_with_a_config_hint`, `config::tests::empty_match_never_matches` |
| An **empty match** never matches (a malformed/partial rule fails closed, never gates every command) | `config.rs::Match::matches` (`is_empty() -> false`) | `config::tests::empty_match_never_matches`, `add_rule_rejects_unknown_source_and_empty_match` |
| The deferred **`arg_regex` cannot be smuggled into an always-true match**: `Match::matches` returns `false` whenever `arg_regex.is_some()`, independent of how the config was authored, so even a hand-edited/imported regex rule is a dead rule (fails closed), only ever *more* restrictive, never always-true | `config.rs::Match::matches` (`if self.arg_regex.is_some() { return false }`) | `config::tests::regex_condition_is_deferred_and_fails_closed` |
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
reach it, and the worst effect is a *downgrade* to a later broader rule, still
gated, never ungated. Recommend a matched-rule-with-unknown-source hard
fail-closed (refuse the invocation) rather than fall through, so a misconfigured
specific rule can never silently resolve to a broader one. Informational.

## 16. The zero-knowledge phone reduction (`cdeebb7`, `ec59737`, `6e3d485`)

The phone dropped the R5 `consentConsistent` account<->secret cross-check, all
provider/account display surfaces, and all Mac-outcome reasoning, becoming a
pure provider-blind approve/deny approver that renders only the opaque
Mac-provided display fields.

**Independent review verdict, CONFIRMED SOUND.** Written by the
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
| **Crypto byte-identical.** The only crypto-path edit is the Face ID `reason` string (`Approve ${label}` -> `"Approve request"`), which is a display-only `LAContext` prompt, the ECDH is `sharedSecretFromKeyAgreement(f, E)`, independent of `reason`. `requests.ts` is doc-comment only; wire fields unchanged; `ephemeralPub` is the sole crypto input, authenticated by the enclosing signed envelope; `accountId`/`seKeyId` travel in one signed challenge | phone `SigilSeModule.swift::computePartial` (reason feeds only the prompt), `controller.ts` (loadDek/computePartial/shapeEcdh/session.respond unchanged), `requests.ts` (doc only) | phone protocol **vectors 15/15**, `proto:selftest` all green (envelope, replay, forged-sender, wrong-recipient, tamper, fingerprint/mailbox, pairing tag/rendezvous vs rust); Rust `sigil-proto` 26 pass |

**Minor doc-drift (non-security, both changes).** A stale comment at
`apps/phone/modules/sigil-se/ios/SigilSeModule.swift:138` still reads "Bind the
Face-ID prompt to the account being unlocked (R5): the reason is the account
label", the reason is now the generic "Approve request". Flagged to the
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

**Independent review verdict, CONFIRMED SOUND on the happy path (two
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
| **Fails closed on the input path**: there is no daemon-buffered-stdin fallback anywhere, the daemon never reads stdin, so a missing/failed fd cannot fall through to daemon-read input; the child simply gets `None` for that slot | `daemon.rs::fulfill`, `provider.rs::run` (no daemon read of stdin exists) | reviewed by inspection (grep: `run.stdin`'s only use is `Stdio::from`) |
| A **malicious client passing a weird fd** as stdin gains nothing: the daemon splices it to the child (same UID as the attacker) and never acts on the fd's identity, so it is no more than what the attacker could feed a tool it ran itself | `provider.rs::run` (passthrough only) | reviewed by inspection; same trust model as the pre-existing stdout/stderr passing |

**Low-severity hardening note A (missing-fd inherit, invariant-#2-adjacent,
defense-in-depth).** The daemon does not validate that a `Run` frame carries
exactly three descriptors, and a missing fd makes the child **inherit the
daemon's** corresponding stdio (`provider.rs::run`: `if let Some(fd) = run.stdout
{ cmd.stdout(Stdio::from(fd)) }` with no `else` -> std default is *inherit*). So a
non-conforming same-UID client that sends fewer than three fds (e.g. zero) makes
an approved `op` child write its **secret to the daemon's inherited stdout**
(under launchd, a same-UID-readable log) instead of to the caller, secret bytes
leaving the intended splice path. The `None`->inherit pattern pre-dates this
change for stdout/stderr, but the stdin splice makes the three-fd positional
contract load-bearing with still no validation, and a *short* count now also
**misassigns** slots (a two-fd `[stdout, stderr]` sender is read as `[stdin,
stdout]`, leaving `stderr = None` -> inherit and shifting stdout). Bounded:
requires a crafted non-standard frame from a same-UID client **and** a granted
approval or active lease, and a same-UID attacker can read the secret more
directly, no real escalation. Cheap to close and recommended for an airtight
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

**Low-severity hardening note B (caller-stdin stall, DoS, post-approval +
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
fix, the `Run` fd path is now airtight); see §18.

## 18. The auto-aliasing proxy (`f5448cf`, `65d75d2`)

`~/.sigil/bin` goes first on `PATH`; each intercepted command is a symlink there
at the `sigil` runtime binary. Running `op` resolves the symlink -> `sigil`
re-enters as `sigil op ...` -> gates on the phone -> execs the **real** `op`
(resolved with the proxy excluded). Management is `sigil-config proxy
add|remove|list|status|doctor|env`. Design: `docs/design/proxy-aliasing.md`.

**Independent review verdict, CONFIRMED SOUND (two low-severity notes, neither a
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
| The **daemon-up** path is immune to **caller PATH poisoning**: the `Run` frame carries only `argv`/`cwd`/`proxy_depth`/fds, never the caller's `PATH`/env, so the daemon resolves the real binary in its **own** trusted (launchd-pinned) `PATH`; a caller cannot redirect what the daemon spawns or steer the injected SA token to an attacker binary. The daemon-**down** path uses the caller's `PATH` but injects **no** secret (transparent exec), so a poisoned `PATH` there just runs the caller's own binary with no token, identical to no-Sigil | `local.rs::Frame::Run` (no env field), `provider.rs::OpProvider::resolve` -> `paths::find_real` (daemon env), `shim.rs::exec_real` (no env injected) | reviewed by inspection; `daemon.rs` provider tests spawn from the daemon's own resolution |
| A **hard copy** of the `sigil` binary planted as `<cmd>` (not caught by canonical equality) **fails closed**: `find_real` returns it -> re-enter -> loop, bounded by the depth fuse to exit 70 (shim) / daemon refuse at `MAX_DEPTH`. No ungated run, no secret leak, a bounded self-DoS requiring same-UID to plant a copy of the binary | `shim.rs::dispatch` (`depth_exceeded` -> exit 70), `daemon.rs::fulfill` (`proxy_depth >= MAX_DEPTH` -> `fail_closed`) | `daemon.rs::proxy_depth_is_incremented_on_the_child_and_fuses_at_the_limit`, `proxy::depth_fuse_reads_and_increments` |
| **PATH-order bypass is documented as a residual, never claimed prevented.** A real `<cmd>` before the proxy routes an *unmodified* caller ungated; `doctor` reports it as an operator convenience, and a caller that *wants* to skip the gate always can (real binary is never moved). No code treats PATH order as a control | `proxy.rs::ProxyStatus::issue` ("a real {cmd} precedes the proxy on PATH (requests would be ungated)"), `docs/design/proxy-aliasing.md` §"not a containment boundary" | `proxy::drift_when_a_real_binary_precedes_the_alias_is_a_bypass` |
| The **recursion guard cannot be cleared to escape gating.** `proxy_depth` is used in exactly one decision, `fulfill`'s `>= MAX_DEPTH -> fail_closed` (deny, safe direction), and is **never** consulted by the phone gate, account routing, caller-identity derivation, or lease keys. Setting `SIGIL_PROXY_DEPTH` high -> self-deny; setting it to 0 -> only prolongs a loop that exists solely if `find_real` is buggy (self-DoS), never a bypass; `saturating_add` prevents wrap | `daemon.rs::fulfill` (sole `proxy_depth` decision + `child_depth` env), `proxy.rs::{current_depth,depth_exceeded,next_depth_value}` | `daemon.rs::proxy_depth_is_incremented_on_the_child_and_fuses_at_the_limit`, `proxy::depth_fuse_reads_and_increments` |
| Caller identity (#6) is **not weakened**: the daemon derives identity from the kernel peer pid + ancestry walk, independent of anything the proxy supplies (argv/cwd/depth are decorative for identity) | `daemon.rs::handle_conn` (`peer = lease::peer_pid`), `lease.rs::walk_ancestry` | existing `lease.rs` ancestry/grant-key suite (unchanged) |
| Fail-closed (#7): a resolution failure execs nothing (`exit 127`); a protocol fault while the daemon is up is `exit 70`, never an ungated run; only a **down** daemon execs transparently (by design, injecting no secret) | `shim.rs::{exec_real,forward}` (127 / 70), `daemon.rs::fulfill` | reviewed by inspection; `shim.rs` module contract |

**Low-severity note A (doc-vs-code + defense-in-depth): the runtime `find_real`
implements only rule 1, not the proxy-dir exclusion (rule 2) the design claims.**
`docs/design/proxy-aliasing.md` §"hard problem 1(a)" states two exclusion rules,
(1) canonical == `current_exe` **and** (2) skip any candidate inside the proxy
dir. `paths::find_real` (the resolver that actually chooses what to exec/spawn)
implements only rule 1; rule 2 exists only in the **diagnostic** path
(`proxy.rs::ProxyStatus::detect_with`, via `is_shim_dir`). Impact: a **non-symlink**
executable resident in `~/.sigil/bin` under a tool's name (a hard copy, a script,
or a same-UID-planted non-sigil binary) is not excluded by `find_real`, so the
daemon-up path would treat it as "the real tool" and spawn it **with the injected
SA token**. Every route requires same-UID write to `~/.sigil/bin`, already
game-over (such an attacker can read the approved tool's `/proc/<pid>/environ` or
replace the real binary), so it is not a distinct escalation, but it is a real
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
canonicalises to the proxy dir, so a non-symlink executable planted in
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
same direct-injection *shape* as §12's `env-file`, resolved values transit
daemon RAM only as the child's spawn env, for the spawn instant, and it never
leases, but unlike `env-file` the values are **sealed at rest under the DEK**,
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
| **Readout integrity (invariant #3):** the decoded blob's KEY set is reconciled against `action.env_keys` (the set the phone readout/audit was built from) *before* injection; any divergence fails closed. This closes the two ways names could drift from values without breaking crypto, a crash between the store save and config save in `seal_env_pairs`, and an import that kept a source NAME but changed its keys while a stale blob survived, so the approver can never consent to "will set FOO" and have the child receive a hidden BAR | `daemon.rs::fulfill` (the sealed-env arm's `BTreeSet` compare of decoded keys vs `action.env_keys` → `fail_closed`) | `daemon.rs::inline_env_blob_keys_must_match_the_approved_set_or_fail_closed` (blob has an extra key vs config → refused, nothing injected) |
| Bulk `--stdin` parse errors report the **line NUMBER, never the line content**, so a mistakenly-piped secret line is not echoed to the terminal/logs | `cli.rs::read_env_pairs_stdin` (`"line {n}: no '=' found"`) | reviewed by inspection |
| `list`/`export` cannot leak a value (they render config only, which has no value), and `import` cannot round-trip a value into the clear (config carries names only); removing the source or clearing its last key **removes the sealed blob** (no orphan ciphertext), and an import that drops an env source prunes its blob | `cli.rs::{config_source_list,config_export,config_import,purge_env_blob,prune_orphan_env_blobs,seal_env_pairs}` | manual E2E (remove purges `env_sources`); reviewed by inspection |

The seal/open wire is length-prefixed (`u32 klen|key|u32 vlen|value`), pre-sized
so the encode buffer never reallocates, so a VALUE may hold any bytes (newline,
`=`, quotes) without an escaping ambiguity and decode borrows without a
non-zeroized copy. See **residual 13** for the two un-wiped copies this shape
inherits from §12 (the `Command` env map and the child's environ), identical to
`env-file`, plus the CLI-side merge copy at set time (the user is providing the
value, so it is in CLI RAM regardless; held `Zeroizing`).

**Independent review verdict, CONFIRMED SOUND for the crypto/at-rest core; one
P2 readout-integrity gap and two P2 hygiene notes, none a value leak.** Written by
the security-reviewer, which did **not** author the inline `env` provider
(rust-core); not a self-certification. The six implementer claims were verified,
not taken on faith:

- **At-rest is ciphertext (claim 1), CONFIRMED.** The on-disk `sigil.db` grep
  test proves the VALUE is absent and only the (public) source name + sealed bytes
  persist; `config.json` carries KEY names only (`Source::keys`,
  `skip_serializing_if = "Vec::is_empty"`). Values are sealed with the same
  AES-256-GCM `encrypt_token` under the DEK as service-account tokens. No value
  reaches a log/error/`{:?}` on the seal or decrypt paths (decrypt/decode failures
  print the GCM error or a fixed "corrupt" string, never plaintext).
- **list/export/import cannot leak a value (claim 2), CONFIRMED.** Export/list
  render config only (no value present to render); import carries names + provider
  tag, so it can only ever *remove* ciphertext (prune), never introduce plaintext.
- **`describe()` is zero-knowledge (claim 3), CONFIRMED for values.** The
  approval request's `secret_refs` and the audit label are built from KEY names
  only; no value crosses the wire or enters the sealed request.
- **decrypt→inject→zeroize, never leases (claim 4), CONFIRMED.** The DEK
  (`Zeroizing<[u8;32]>`) is opened only after the grant (phone-delivered
  `outcome.dek`, or a local keystore unwrap on a local approval, the same v1
  model as `op`), used for one decrypt, `drop`ped at once; the decoded pairs
  (`Zeroizing`) are dropped after the spawn instant; the sealed-env arm never
  calls `leases.grant` and the lease short-circuit is `if needs_account`. The
  reused `spawn_with_env` splice/exec path is #22's reviewed one.
- **remove/unset purges the blob (claim 5), CONFIRMED.** `remove_env_blob` on
  source-remove, empty-after-unset, and `prune_orphan_env_blobs` on import; no
  orphan accumulation.
- **DEK/value buffers zeroized on set/unset (claim 6), CONFIRMED.** `Dek` and
  `Token` are `Zeroizing`; the CLI holds value buffers as `Zeroizing<String>`,
  reads them from stdin never argv (no `ps` leak), and the merge copy is
  `Zeroizing`.
- **Hostile input, CONFIRMED fail-closed.** `decode_env_pairs` uses checked
  slicing and `str::from_utf8`, returning `None` (fail closed) on truncation, an
  over-long length, or non-UTF-8 without panicking; a tampered `sigil.db` fails the
  GCM tag on decrypt (a same-UID attacker cannot forge attacker-chosen values, only
  *relocate* an existing blob, see the P2 below); `valid_env_key` rejects `=`,
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
remains, `prune_orphan_env_blobs` only drops blobs whose *name* is gone. Outcome:
the approver consents to "will set FOO" but the child is injected FOO **and** a
hidden BAR. This is **not a value leak** (values are never shown to the phone in
either case), it is a readout-*accuracy* break of invariant #3's "the approver
sees what will happen." Proven with a scratch test (config `[TOKEN]`, blob
`{TOKEN, SECRET}`): the readout showed `TOKEN`, the child received
`secret=hidden-exfil`. **Fix:** after `decode_env_pairs` in `fulfill`, assert the
decoded key set equals `action.env_keys` and `fail_closed` on mismatch (this also
closes the crash window and the import-leftover case); or inject only keys present
in `action.env_keys`. Severity **P2**: reaching it needs a crash or a same-UID
config/import manipulation, and same-UID is already outside the defended boundary,
but readout integrity is a stated approval property, so a cheap inject-time check
is warranted.

**P2-2 (terminal echo of raw stdin): `read_env_pairs_stdin` prints a malformed
line verbatim**, `eprintln!("sigil: line without '=': {:?}", line)`. On the
`--stdin` bulk path a piped line lacking `=` is reflected to stderr; if the user
accidentally pipes secret-bearing content, a bare-secret line is echoed to the
terminal/logs. Low blast radius (CLI-side, the user's own terminal, malformed
input only), but it is the one place raw stdin is reflected. **Fix:** report the
line index only, not its content.

**P2-3 (at-rest threat-model note): inline-`env` values are sealed under the
host/v1 DEK, not the v2 two-party threshold key.** Unlike a v2 `op` account (whose
token the daemon **cannot** open without the phone's partial), an inline-`env`
value is recoverable by a **local** approval, the daemon unwraps the host DEK from
the keystore itself (Touch ID / SE presence, `outcome.dek == None` path). This is
by design and identical to v1 accounts and local-approval mode, and is a strict
improvement over the plaintext `env-file` (§12), but it means inline-`env` does
**not** inherit v2's "daemon cannot open it alone" guarantee. Worth stating plainly
in residual 13 so inline-`env` is not assumed to have threshold-grade at-rest
protection.

Net: the sealing, zeroization, fail-closed decoding, no-lease, and
zero-knowledge-of-values properties all hold as claimed. The one substantive
finding (P2-1) is a readout/injection reconciliation gap that should get an
inject-time key-set check; the other two are hygiene. No P0/P1.

---

## 20. The single ToDaemon owner (demux to approval waiters)

*Implementer note (behavior + residuals only; the verdict is the independent
security-reviewer's).*

**Problem it fixes.** The phone deposits its APNs push token as a sealed
`PushRegister` on the `ToDaemon` channel the moment it arms
(`apps/phone/.../controller.ts`), not only alongside an approval. The relay holds
a deposit for `TTL_MS` (180s) and then drops it. Previously the daemon read
`ToDaemon` **only** at the start of an approval `round_trip` (`drain_pending` +
the response wait), so unless a gated command fired within 180s of arming, the
token expired unseen: `record_registration` never ran, `~/.sigil/push.json` was
never written, and every later deposit carried no `PushHint`, so the relay rang
no doorbell. The background doorbell simply never worked.

**Design: one reader, demultiplexing.** The relay hands each deposit to exactly
ONE reader, so two concurrent readers of `ToDaemon` would steal each other's
messages. The fix makes exactly one thread ever read `ToDaemon`:
`RemoteApprover::run_todaemon_owner` (spawned once by `daemon.rs::serve`, phone
factor only). It continuously long-polls `ToDaemon`, `classify`s each envelope
through the one shared `ReplayGuard` (now touched by this thread alone), and
routes by type:

- a `PushRegister` -> `record_registration` to the disk-backed `PushStore` (0600,
  survives restart via `PushStore::load`). This is how the arm-time token is
  captured the instant it lands, long before any command fires;
- an `ApprovalResponse` -> looked up in a `Mutex<HashMap<request_id,
  std::sync::mpsc::Sender<ApprovalResponse>>>` (`RemoteApprover::waiters`) and
  handed to the waiting `round_trip`; a response with no registered waiter is
  stale (its approval already timed out and removed itself) and dropped, exactly
  as the old inline demux skipped a non-correlating response;
- anything that fails verify/replay/decode -> dropped (fail closed).

`round_trip` no longer reads `ToDaemon` at all. It **registers its waiter (the
`Sender`) under `req.request_id` BEFORE it deposits the request**, then blocks on
the paired receiver (`recv_timeout(self.timeout)`); on timeout, or a seal/deposit
error, it fails closed to deny and always removes the waiter on the way out.

**Why this is race-free (no stolen responses, no lock).** Registering before
depositing closes the only window: the phone answers only after it *receives* the
deposited request, so a response can never arrive before its waiter exists. There
is exactly one `ToDaemon` reader, so no two reads ever contend for a deposit;
there is no mutex around the channel, and thus nothing couples an approval's
latency to the relay's long-poll. The owner is already parked in the very
long-poll that will receive the response, so an approval piggybacks it with no
added latency (strictly better than the pre-bug path, which issued a fresh GET per
approval). Any number of concurrent approvals with distinct `request_id`s are
served by the one reader via independent map entries; a test drives two at once
and asserts each waiter receives exactly its own DEK (no cross-delivery).

**Verify/replay semantics unchanged, and now single-threaded.** Every envelope
still goes through the same `classify` over the same single `ReplayGuard`, so the
phone's one monotonic outbound counter is enforced across responses and
registrations together exactly as before; because only the owner reads, that guard
is now touched by one thread (simpler, no lock-ordering question). The owner
grants nothing and never touches a DEK or `Z_F`; a `PushRegister` only writes
`{token, platform}`. A token is not a credential (§9 / the `push_store` module
docs): it unlocks nothing and the doorbell payload is a static string.

**Residuals for the reviewer to weigh:**

- *Stale-response drop is intentional and fail-closed.* If a `round_trip` times
  out and removes its waiter, a late response for that `request_id` finds no
  waiter and is dropped. The approval has already denied; the dropped response
  cannot resurrect a grant. A duplicate/replayed response is also stopped by the
  `ReplayGuard` counter regardless.
- *Owner liveness.* The doorbell depends on the owner thread running. If it exits
  (only on the shutdown flag) or panics, arm-time registrations stop being
  captured and, more importantly, in-flight approvals get no response and fail
  closed to deny at their timeout. It never fails open. On the network relay a
  single poll blocks inside the relay's ~25s hold, so shutdown/join can take up to
  one hold; the process is exiting regardless.
- *No relay spam.* The owner holds exactly one `ToDaemon` long-poll at a time and
  no more; approvals reuse it rather than opening a second. This respects the
  standing "NO SPAMMING, ONLY APNS wakeups" rule and adds no polling beyond the
  single idle long-poll the relay already expects.
- The relay stays powerless and anonymous: the token rides only as an opaque
  `PushHint` on a deposit, the daemon signs no push, and `push.json` stays 0600
  under `~/.sigil`. None of that changed.

**Independent review verdict, CONFIRMED SOUND (no findings; three accepted
residuals).** Written by the security-reviewer, which did **not** author the
demux-owner refactor (`7cbb24b`) or the allow-mode / lease-policy engine
(`e51b4ef`); per the review-integrity rule this is not a self-certification. The
adversarial pass covered both commits on `feat/config-rule-engine`: the
push-doorbell demux (race, stale-drop vs the replay counter, owner liveness,
token opacity) and the consent-surface changes (allow-mode fail-closed, lease
authority, passthrough splice discipline). The gate is green: `cargo test` 365
passed / 0 failed, `cargo clippy --all-targets -- -D warnings` clean, `cargo fmt
--check` clean.

**Demux owner (`7cbb24b`).**

| Claim | Enforcing code | Proving test | Verdict |
|-------|----------------|--------------|---------|
| Register-before-deposit closes the only response-loss window: the waiter is inserted under `request_id` before the request is deposited, and the phone answers only after it receives the deposit, so no response can arrive before its waiter exists | `remote.rs::round_trip` (register then `deposit_and_wait`), `remote.rs::register_waiter` | `remote::tests::an_approval_receives_its_own_response_via_the_owner` | SOUND |
| No cross-delivery: responses route by sealed, phone-signed `request_id` (uuidv7, unique); a relay cannot forge/redirect a response (fails `Envelope::open` signature) and a response for approval A can never resolve B (distinct ids) | `remote.rs::route_response` (`waiters.get(&resp.request_id)`), `envelope.rs::open` | `remote::tests::two_concurrent_approvals_each_receive_their_own_response` (distinct DEKs asserted) | SOUND |
| Stale/late/duplicate response cannot resurrect a grant: no waiter -> dropped; a replay is rejected by the `ReplayGuard` monotonic counter (no state change on reject, so it cannot desync a later legitimate response) | `remote.rs::route_response`, `replay.rs::check_and_record` | `hostile_relay::reordering_queued_envelopes_is_caught`, `replay` unit tests | SOUND |
| Single reader: exactly one production `recv(ToDaemon)` exists (the owner); no second reader can steal a deposit | `remote.rs::run_todaemon_owner` (only `Direction::ToDaemon` `recv` in the crate) | grep-confirmed sole reader | SOUND |
| Fail-closed on owner death: a panicked/exited owner routes no responses; every `round_trip` `recv_timeout`s to `None` -> deny. No path opens fail-open | `remote.rs::deposit_and_wait` (`Err(_) => None`), `RemoteApprover::decide` (`unwrap_or_else -> Deny`) | `daemon::tests::denied_request_fails_closed_and_delivers_no_secret` | SOUND |
| The token path cannot influence a decision: a `PushRegister` only writes `{token, platform}` to the 0600 store; it never touches `waiters`, a DEK, or `Z_F`. The daemon signs no push; the token rides only as an opaque `PushHint` | `remote.rs::dispatch` / `record_registration`, `push_store.rs` (0600) | `remote::tests::the_owner_captures_an_arm_time_registration`, `push_store` 0600 test | SOUND |

**Allow-mode + lease engine (`e51b4ef`).**

| Claim | Enforcing code | Proving test | Verdict |
|-------|----------------|--------------|---------|
| Allow can never become allow-everything: an empty `Match` matches nothing in **both** modes, and an unmatched invocation resolves to `None` (refuse), never a silent passthrough | `config.rs::Match::matches` (`is_empty() -> false`), `config.rs::resolve` (`None` on no match) | `config::tests::empty_match_never_matches`, `allow_rule_resolves_to_passthrough_and_layers_above_a_gate` (unmatched refuses) | SOUND |
| Absent `mode` defaults to Gate, never Allow: `#[serde(default)]` + `#[derive(Default)] #[default] Gate`, so an older/hand-edited config that omits `mode` fails safe to gating. An **unknown** mode string fails the whole parse; the daemon then falls back to an empty config that refuses everything (stronger than gate) | `config.rs::RuleMode` (`#[default] Gate`), `Action.mode` (`#[serde(default)]`), `daemon.rs::serve` (parse error -> `Config::default()`) | `config::tests::allow_rule_..._layers_above_a_gate` (round-trips `Gate` by default) | SOUND |
| A matched **gate** rule with a missing source REFUSES (`None`), it does not fall through to a broader rule (this implements section-15 note B's recommendation: no fail-open downgrade) | `config.rs::resolve` (`let Some(src) = ... else { return None }`) | `config::tests::matched_rule_with_unknown_source_fails_closed_not_downgrade` | SOUND |
| `run_passthrough` injects no env and preserves invariant #2: it is `spawn_with_env(run, &[])`, reusing the one reviewed splice/exec path (caller fds to the child, absent fd -> `Stdio::null` never inherit, proxy-depth fuse). Allow never mints a lease, never creates a pending approval, never reaches the phone | `provider.rs::run_passthrough` -> `spawn_with_env`, `daemon.rs::fulfill` allow arm (`credential: None`, `env: None`, `source: ""`) | `daemon::tests::allow_rule_runs_the_command_directly_without_gating` (0 leases, 0 pending, exit 0) | SOUND |
| Lease authority is the daemon alone: a run-once rule yields no lease even when the approver returns one; a leasable rule clamps to `max_secs`. Every grant site consults the single clamped `lease_ttl` | `request.rs::LeasePolicy::clamp_secs`, `daemon.rs::fulfill` (`lease_secs = decision.lease_ttl().and_then(clamp)`; both `leases.grant` sites gated on `lease_ttl`) | `daemon::tests::run_once_rule_never_leases_even_when_a_lease_is_returned`, `leasable_rule_clamps_an_over_cap_lease_to_the_rule_max`, `request::tests::lease_policy_defaults_to_run_once_and_clamps` | SOUND |
| First-match-in-config-order is the only precedence; no second ordering path | `config.rs::resolve` (single `for rule in &self.rules` returning on first match) | `config::tests::resolve_first_match_wins_and_flattens_source`, `allow_rule_..._layers_above_a_gate` | SOUND |
| `lease_policy` rides inside the sealed+signed envelope (part of what the approver consents to); a relay cannot read or alter it without breaking the AEAD/signature | `remote.rs::build_request` (`lease_policy` in `ApprovalRequest`), `envelope.rs::seal/open` | `hostile_relay` tamper/forge suite (any bit flip breaks `open`), `request::tests::lease_policy_round_trips_through_json_camel_case` | SOUND |

**Accepted residuals (not defects, called out per the honesty rule):**

- *Hostile-relay reordering is a denial vector, never a wrong approval.* If the
  relay reorders `ToDaemon` envelopes so a higher counter is opened first, the
  earlier legitimate response is rejected by the monotonic `ReplayGuard`
  (counter regression) and dropped; its `round_trip` then times out and denies.
  This is the intended fail-closed property (invariant #4/#7): the relay can
  induce a denial (it can already do that by dropping), but cannot induce a grant
  or a replay. Documented, not fixable without weakening the counter.
- *Owner liveness is a single point of failure for the doorbell, but fail-closed.*
  A poisoned `waiters`/`guard` mutex (only reachable if a `round_trip` panics
  while holding it) or an owner panic stops response routing; all in-flight and
  future approvals then deny at timeout. It never fails open. A restart respawns
  the owner. Accepted.
- *An unknown `mode` (or any parse error) in the hand-edited 0600 `config.json`
  disables the entire rule set*, not just the malformed rule, because the daemon
  falls back to `Config::default()` (empty -> refuse all). This is fail-closed
  (safe) but an availability foot-gun: one typo bricks all gating until fixed. A
  same-UID hand-edit is already outside Sigil's trust boundary. Informational.

**Test-coverage note (informational, not a finding).** The "absent `mode`
defaults to Gate" property is guaranteed by construction (`#[serde(default)]` +
`#[default] Gate`) and exercised indirectly, but there is no focused test that
deserializes a rule JSON with the `mode` key omitted and asserts `Gate`. A
one-line test would harden the invariant against a future refactor that drops the
`#[serde(default)]`.

---

## Residuals (honest limits)

These are real and deliberately surfaced, not defects hidden.

1. **The local control-socket approver is not an adversarial gate, now gated
   behind an explicit arm-time factor policy (MITIGATED).** The control socket
   is same-UID-forgeable: an approval is granted by whoever sends
   `Frame::Approve { id }` on the 0600 unix socket, and the request `id` is only
   printed to the daemon's stderr, so a same-UID attacker who can read it can
   self-approve. A compromised same-UID agent (a rogue `claude`/`op`) is exactly
   the adversary Sigil exists to stop, so this path must never be the sole gate.

   The mitigation, added with the network transport: at arm time the daemon
   resolves an explicit **approving factor** (`factor.rs::resolve`,
   `daemon.rs::build_gate`), in order:
   - a **paired phone** reachable over a `Transport` (`RemoteApprover`), the
     sealed, signed `ApprovalResponse` a same-UID peer cannot forge;
   - a **verified hardware biometric** (`Keystore::is_biometric()` true), the
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
   powered-off disk/backup reveals no key material, the strong form of the
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
, no key reuse across a shared construction, no oracle, non-invertible, so it
   is not a weakness, but the sentence in `docs/design/pairing.md` should be
   updated to name both uses. Flagged to the doc owner.

9. **The `env-file` provider relaxes invariant #2: resolved secret VALUES
   transit daemon RAM, and two copies are un-wiped (by design, bounded).** Unlike
   the `op` shape, where the daemon injects only a *credential* and the `op`
   child streams the resolved secret straight to the caller's fd, so no secret
   value ever enters the daemon, a direct-injection provider **is** the source:
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
    request leaks durable signing power, not one signature, strictly worse than
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
    **locally**, the daemon wraps the DEK to the same Mac's SE key, and the SE
    unwraps it under Touch ID, so forging or swapping the stored blob already
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
    the spawn, the same std limitation as the op SA token in residual #3), and the
    child's `/proc/<pid>/environ` carries the values for its lifetime (readable by a
    same-UID process; inherent to any inject-env-and-exec model, and same-UID is
    already the boundary Sigil does not defend below). The daemon's own decrypted
    copy is `Zeroizing`, wiped on drop, and never logged; leasing is disabled so
    resolved values never persist across a TTL. **Improvement over `env-file`:** the
    values are AES-256-GCM sealed under the DEK at rest (`sigil.db`), so, unlike a
    plaintext env-file readable by any same-UID process at any time, the
    daemon-at-rest holds no plaintext value (invariant #1 holds for this provider).
    One extra transient copy exists at **set time**: `sigil-config source env set`
    decrypts the current blob, merges the new pair, and re-seals; the merged pairs
    (and the value the user is supplying, which is in CLI RAM regardless) are held
    `Zeroizing` for that CLI invocation only. Severity: **Medium at run time
    (inherent to direct injection, same as §12), reduced at rest (sealed, not
    plaintext).** Enforcing code: `provider.rs::{EnvProvider,spawn_with_env,
    decode_env_pairs}`, `daemon.rs::fulfill`, `cli.rs::seal_env_pairs`. See §19.

14. **Pairing-authorization biometric now gates the persist step, independent of
    DEK delivery (#48), implementer behavior note, awaiting an independent
    verdict.** `pairing_store::save` runs a hardware user-presence check
    (`Keystore::verify_presence`, gated on `is_biometric()`) as its FIRST action,
    before any state is written, and deny-closes: a declined or unavailable
    biometric returns an error and NOTHING is persisted (no identity blob, no
    config file). On the real macOS keystore `verify_presence` reuses the same
    Secure Enclave `.biometryCurrentSet` private-key op the approval path uses
    (`keystore_macos.rs::verify_presence` -> `unwrap_dek`), performed purely as a
    presence probe and the recovered `Zeroizing` DEK dropped immediately, no DEK
    crosses any boundary, which is what makes the gate independent of DEK
    *delivery*. **Residual A (double biometric prompt on real hardware):** the
    pairing ceremony still unwraps the DEK to seal it to the phone
    (`pair.rs::run_ceremony` step 4), and this new persist-time probe is a second
    SE op, so a real-hardware v1 pairing currently prompts Touch ID twice. The
    codebase has no `LAContext` reuse-window plumbing yet (see the
    `keystore_macos.rs::unwrap_dek` NEEDS-VERIFICATION note), so the two prompts
    cannot presently be collapsed into one; a shared `LAContext` with
    `touchIDAuthenticationAllowableReuseDuration` would reduce it to one and is the
    natural follow-up. **Residual B (default fail-closed for a mis-declared
    keystore):** the `Keystore::verify_presence` trait default returns `Err`, so a
    keystore that reports `is_biometric() == true` but omits the override refuses
    to pair rather than passing unchecked. The dev keystores keep
    `is_biometric() == false` (only reachable under `SIGIL_DEV_KEYSTORE`, behind
    its loud warning) and are never asked, so headless dev and tests still pair.
    Enforcing code: `pairing_store.rs::save` (gate), `keystore.rs::verify_presence`
    (fail-closed default), `keystore_macos.rs::verify_presence` (SE probe). Proving
    tests: `pairing_store.rs::{a_declined_biometric_refuses_the_pairing_and_writes_nothing,
    a_biometric_keystore_that_grants_presence_persists_the_pairing,
    a_biometric_keystore_missing_a_verify_presence_override_fails_closed}`. The
    on-hardware Touch ID firing is **UNPROVEN** (shares the §6 NEEDS-VERIFICATION
    gap: the SE op is exercised only against the memory stand-in in tests).

15. **Config hot-reload swaps the rule set live and stays fail-closed (#59),
    implementer behavior note, awaiting an independent verdict.** A watcher thread
    stat-polls `~/.sigil/config.json` every 2s and, on an mtime change, calls
    `Core::reload_config`, which loads and fully parses the file and only THEN
    atomically swaps the in-memory `Arc<Config>` (`daemon.rs::{ConfigCell,
    spawn_config_watcher,reload_config}`). **Fail-closed proof:** the swap
    (`ConfigCell::store`) is on the `Ok` arm exclusively; a malformed, truncated
    (half-written save), or unreadable file returns `Err` WITHOUT touching the
    cell, so the last-good rules stay in force and gating is never downgraded by a
    bad reload, a bad reload never falls open, nor to refuse-all. **Torn-read
    safety:** a gating decision takes `ConfigCell::snapshot` (read-lock, clone the
    `Arc`, unlock) and evaluates the whole `resolve` against that one `Arc`, so a
    reload landing mid-decision is invisible to it (it sees the entire old or the
    entire new config, never a blend). **Residuals:** (a) legacy `commands.json`
    is not watched, only `config.json`, the current authoring surface, so a raw
    legacy edit still needs a restart (migration is one-time); (b) removing
    `config.json` entirely reloads to the empty default, which refuses every
    command (fail-closed, but a surprising "everything stopped" if deleted by
    accident); (c) the poll is mtime-based on APFS's high-resolution timestamps,
    a same-nanosecond rewrite of identical length is theoretically missed, but
    edits here are human-paced and single-user. Proving tests:
    `daemon.rs::{config_hot_reload_swaps_in_the_on_disk_rules,
    config_reload_is_fail_closed_on_a_malformed_file}`.

16. **One authoritative default socket, resolved with zero environment (#59),
    implementer behavior note.** `local::socket_path` and `sshagent::socket_path`
    both derive from a single `local::runtime_dir` anchored on the stable per-user
    temp dir (`confstr(_CS_DARWIN_USER_TEMP_DIR)` on macOS), not the `$TMPDIR` env
    var, so the daemon, the `op` shim, the `sigil` CLI, and a bare shell all
    resolve the SAME `daemon.sock` / `ssh-agent.sock` with no `SIGIL_SOCK`.
    `SIGIL_SOCK` / `SIGIL_SSH_SOCK` remain full-path overrides for tests and
    bespoke deployments. The confstr path is short (~50 bytes), keeping the socket
    well under `sun_path` (the existing `service::socket_path_fits` check still
    guards it). **Residual:** if the confstr lookup ever returns empty we fall back
    to `/tmp/sigil` (world-visible dir, but the socket itself is still 0600 and its
    parent dir 0700 via `prepare_socket`); this is the same posture as the prior
    `$TMPDIR`-absent fallback. Proving tests:
    `local.rs::{socket_path_honors_the_sigil_sock_override,
    daemon_and_ssh_sockets_share_one_authoritative_runtime_dir}`.

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
   biometric are *not* separable into a single reusable authorization, the
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
   (`keystore_macos.rs:249`-`279`). Every `CFError`, whichever code, routes
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

- **P2, the SE access control is created with a NULL protection class,
  diverging from every reference and the design's stated intent.**
  `keystore_macos.rs:186`-`189` calls
  `SecAccessControl::create_with_flags(...)`, which in security-framework 2.11.1
  is `create_with_protection(None, flags)`, it passes a **null** protection
  value to `SecAccessControlCreateWithFlags`
  (`.cargo/.../security-framework-2.11.1/src/access_control.rs:51`-`76`). Every
  Swift counterpart pins `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
  (`apps/mac/Tools/se-selftest.swift:29`,
  `apps/mac/Sigil/Security/SecureEnclaveApprover.swift:52`,
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

- **P2 (data-loss footgun, not disclosure), the committed 37035ee hardware
  test deletes the REAL production DEK blob.** As committed, the ignored test
  `se_dek_round_trips_through_a_real_touch_id` ran `MacKeystore::new()` (real
  labels) and `delete_blob(DEK_ENVELOPE_LABEL)` (the real production envelope),
  then `ensure_dek()`, minting a **fresh** DEK under the real label. Running it
  on Tom's Mac would have bricked every account whose token was sealed under the
  prior DEK (the new DEK cannot decrypt them; fails closed, but the tokens are
  unrecoverable without re-add). **Resolved in HEAD by df78e8f** ("make the SE
  round-trip harness isolation-safe"), which landed during this review:
  per-instance labels via `MacKeystore::for_test`, `.selftest` suffixes, and
  always-cleanup with `catch_unwind`, so the test can never touch the production
  `SE_KEY_LABEL`/`DEK_ENVELOPE_LABEL`. Recorded so the reason the isolation
  exists is not lost: never let a hardware test run against the real labels.

### RESIDUALS, require Tom's on-hardware verification (cannot be settled statically)

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
  macOS as documented, confirm the prompt is biometric-only and that a fresh
  evaluation fires on *each* unwrap (no LAContext is passed, so there is no
  biometric-reuse window by construction; verify the OS honors that).
- **Generic prompt copy (social-engineering residual).** `unwrap_dek` does not
  thread `reason` into an `LAContext`, so the Touch ID sheet shows default
  system copy. The biometric therefore proves *fresh human presence at DEK
  release*, not *human authorizing this specific device*, the device-binding
  backstop remains the human's SAS-word eyeball comparison, not the biometric.
  Acceptable (the SAS is the MITM gate; the biometric is presence), but until an
  `LAContext` names the action the prompt cannot itself disambiguate a
  legitimate pairing from a same-UID-triggered one to a distracted user.

### SECONDARY, relay v4 trust-model relaxation (opinion, not the primary verdict)

The end-to-end crypto **still holds** despite the relay becoming a
content-free "blind doorbell": every envelope remains opaque and sealed by
`crates/sigil-proto` (Ed25519 sender auth + `crypto_box`/threshold + replay guard),
the relay never parses one, and the push body is fixed and generic. The relay's
new powers, a shared publisher APNs signing key held as a platform secret, and
a phone push token seen transiently per deposit and never stored, do not let it
read a secret, forge an approval, or learn an outcome. Invariant #3's "powerless
and anonymous" is genuinely relaxed to "blind doorbell, holds a push secret";
the README records this honestly and defers the verdict here, which is correct.

The **per-mailbox (not per-token) push cap** (`PUSH_MAX=5/min`) is an
acceptable residual with a named limit: a party who has already obtained a
victim's push token (itself not secret-bearing) can ring that phone's doorbell
and evade the cap by rotating the `mailbox_id` in the deposit URL, since the cap
is keyed per mailbox and the push targets whatever token the body carries. Worst
case is generic "Approval requested" notification spam / battery drain, **not**
a secret disclosure and **not** an approval (the phone still needs the real
sealed request plus a biometric to approve anything). Acceptable as a
nuisance-only vector; a per-token bucket, or requiring the doorbell deposit to
be bound to the sealed envelope, would close it if push-spam becomes a concern.

**Verdict recorded by the independent security-reviewer. The pairing-security
unit is sound; fix the two P2s (commit the `for_test` isolation; give the SE
access control an explicit `WhenUnlockedThisDeviceOnly` protection class) and
clear the hardware residuals before treating the SE path as verified.**

---

## §15, relay long-poll v5.1: coexisting waiters + newest-wins delivery (commit `33b464f`)

Independent adversarial review of the delivery-semantics change in
`relay/shared/protocol.ts` (`longPoll`/`wake`/`MAX_WAITERS`). Reviewer did not
author the change. Focus: delivery integrity (no silent loss beyond honestly
stated residuals, no starvation/steal by a hostile party, no unbounded memory);
envelope crypto is unchanged and out of scope. Invariant at stake throughout is
**everything fails closed** (#5) and the relay's no-silent-drop promise, not
confidentiality (#3 holds, envelopes stay opaque, and every worst case below is
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
exactly the same "newest waiter is dead" case, see below).

**P2, the two "still open" residuals are one root cause, and honestly stated
but slightly over-decomposed.** Both open residuals in the module header reduce
to a single invariant: *`wake` loses a deposit iff the newest waiter is a dead
orphan at deposit time* (drained into a connection nobody reads).
- *Residual A (deposit in the disconnect gap):* reachable by the shipped clients
, a real disconnect whose abort didn't fire, then a deposit landing before the
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
  documented, but note explicitly that it is unreachable given today's clients,
  as written the README slightly overstates its current reachability (harmless
  direction: it over-warns, it does not under-warn).

**P2, MAX_WAITERS bounds per-slot waiters, not mailbox count (pre-existing,
unchanged by this commit).** `MAX_WAITERS=8` caps waiters at 16 per mailbox (8×2
slots). It does **not** cap the number of distinct mailboxes: the Bun `boxes`
Map grows one entry per distinct id seen, and the rate limiter is per-mailbox so
it does not bound distinct-id creation. An attacker who can reach the relay can
inflate the Map with random ids (each holding held GETs) until the sweep
(`TTL_MS`, only deletes idle+unwatched boxes) or the OS connection limit stops
it. The Worker variant offloads this to Cloudflare's isolate lifecycle. This is
the pre-existing "rate limiter is non-load-bearing; the front is the real bound"
posture, not a regression from v5.1, and acceptable for a personal/self-host
deployment, flagged so it is not mistaken for a bound this change added.

**Steal/eviction as a weapon, not reachable by a third party.** Forcing a
victim's legit waiter out (8 GETs past the cap) and positioning an attacker
waiter as newest to *steal* the next deposit requires registering GETs on the
victim's slot, i.e. knowing the `mailbox_id`. That id is
`BLAKE2b(domain ‖ canonical(pinned_pub_a, pinned_pub_b))` (`fingerprint.rs:83`),
a 256-bit value derived from two pinned public keys, carried inside TLS to the
relay and never published, unguessable by a third party. Only the relay
operator (who sees the id in the URL) is positioned to do this, and a hostile
relay can already deny delivery arbitrarily; the theft still yields only an
opaque sealed envelope and a non-approval (fail-closed). Acceptable; worth one
line in the module header that delivery-slot integrity rests on the mailbox id
staying unknown to third parties (it does).

**Verdict (independent security-reviewer, not the implementer of `33b464f`).
The v5.1 coexisting-waiter / newest-wins change is SOUND for delivery
integrity.** It removes the fast-empty hammer, adds no new message-loss vector,
cannot be used by one paired party to starve the other, is memory-bounded
per slot, and every worst case is a bounded, fail-closed non-delivery, never a
disclosure or a fail-open approval. The one client-reachable residual (deposit
in the disconnect gap) is real, honestly documented, and correctly deferred to
task #53 for real-edge verification plus client-side resend. Recommend two
documentation tightenings (both non-blocking): (1) mark residual B as not
reachable by today's single-flight clients rather than an open peer of residual
A; (2) note that slot-steal presupposes knowledge of the unguessable mailbox id.

## 21. The delivery receipt (task #41) + lease-window wire alignment

*Implementer note (behavior + residuals only; the verdict is the independent
security-reviewer's). This closes the daemon side of three phone-opened gaps.*

**A. Delivery receipt, a fourth-kind display-only inbound.** The phone seals a
`{ type: "delivered", requestId }` to the `ToDaemon` slot the instant it opens and
verifies an inbound request (`apps/phone/.../session.ts`). Daemon side:

- `sigil-proto` gains `DeliveryReceipt { message_type:"delivered", request_id }`
  and a `ToDaemonMessage::Delivered` variant. `ToDaemonMessage::from_value`
  classifies by the `type` tag: `"pushRegister"` -> `Push`, `"delivered"` ->
  `Delivered`, anything else (in practice its absence) -> `Response`. A `"delivered"`
  tag with no `request_id` fails the parse and the caller drops it (fail closed).
  An `ApprovalResponse` carries no `type`, so a receipt tag can never shadow a real
  decision, and a receipt carries no DEK/partial/lease, so it can never *be* one.
- The single `run_todaemon_owner` reader routes `Delivered` through the SAME one
  `classify`/`ReplayGuard` pass as every other inbound envelope, then calls
  `RemoteApprover::mark_delivered(request_id, now)`. It NEVER touches the waiter
  channel (`route_response`), so a receipt cannot deliver, forge, or short-circuit a
  decision. `mark_delivered` sets `delivered_at_ms` on the matching in-flight entry
  only if unset; an unknown/late (no entry) or duplicate (already set) receipt is a
  silent no-op. A replayed receipt is additionally rejected by the `ReplayGuard`
  (single-use request id), proven in `hostile_relay.rs::
  delivery_receipt_rides_the_sealed_signed_replay_protected_envelope`.
- **The receipt is display-only and NEVER changes gating.** It cannot move a
  decision, DEK, lease, or timeout; it only sets a boolean/timestamp the requester
  UI reads. A lost receipt leaves `delivered=false` ("couldn't confirm") while the
  approve/deny path resolves the request exactly as before.

**Surface (the DTO the Mac reads).** In-flight remote requests are now enumerated
onto the existing `pending` surface. `RemoteApprover`'s waiter map entry carries a
plaintext snapshot of its request (names/provenance only, never a secret) plus the
delivery state; `daemon.rs::pending_json` appends these under the phone factor.
`json::PendingJson` gains `delivered: bool` and `delivered_at_ms: Option<u64>`
(camel-free snake wire: `delivered`, `delivered_at_ms`). A `subscribe_pending`
client re-emits promptly because the approver bumps the shared `PendingRegistry`
version on request arrival, receipt, and completion (`PendingRegistry::
notify_change`, which resolves nothing and touches no waiter). Tests:
`remote.rs::a_delivery_receipt_marks_delivered_without_resolving_the_approval`,
`remote.rs::the_owner_routes_a_sealed_delivery_receipt_over_the_channel`,
`request.rs::to_daemon_message_classifies_a_delivery_receipt`.

**B. Lease response is a window, not a key (daemon is sole lease authority).**
`ApprovalResponse.lease` (proto `InstallLease`) dropped its `grant_key` field; it
is now `{ ttl_ms }` only, matching the phone's `lease?: { ttlMs } | null`. The
zero-knowledge phone picks only a window; nothing daemon-side ever trusted a
phone-supplied grant key (`remote.rs::outcome_for` reads only `lease.ttl_ms` and
maps it to `Decision::Lease(ttl)`; the daemon's own `lease::grant_key` over the
kernel-verified caller mints/binds the grant, and `LeasePolicy::clamp_secs`
enforces run-once => no lease / leasable => `min(requested, max_secs)`). This only
removed a field the daemon never read.

**C. `lease_policy` populated; `risk` already retired from the wire.**
`remote.rs::build_request` sets `ApprovalRequest.lease_policy` from the resolved
rule's policy (via `ApprovalContext.lease`), so the phone's "keep approved for N"
offer appears for leasable rules (`build_request_is_provider_blind` asserts it).
The proto `ApprovalRequest` already carries NO `risk` field (a prior change retired
the risk tier in favour of mode/lease); the only remaining `risk` in `crates/` is
`config.rs`'s deliberate read-and-drop of the legacy on-disk config key during
migration (not the wire), so nothing dead needed removing daemon-side.

**Residuals for the reviewer to weigh:**

- *Delivery state is best-effort and unauthenticated as to liveness.* A receipt is
  authenticated (sealed + signed + replay-guarded), so a hostile relay cannot forge
  a "delivered" the phone did not send; but its ABSENCE proves nothing (offline
  phone, lost deposit in the relay's TTL, dropped ack). The UI must treat
  `delivered=false` as "couldn't confirm", never as "not seen", and it MUST NOT gate
  on it. The generous display bound lives in the Mac UI, not the gate.
- *Remote pendings now appear in `pending`.* This is display enumeration only:
  `pending_json` reads a snapshot; the local control-socket `approve`/`deny` path
  (`core.pending.resolve`) still targets the LOCAL `PendingRegistry` and finds no
  entry for a remote `request_id`, so it cannot resolve a phone-gated request. The
  snapshot copies the (already non-secret) `ApprovalRequest`; no DEK/partial is ever
  in it.

**Phone follow-up (not in this change, for the phone-app owner):**
`apps/phone/src/protocol/requests.ts` still carries a residual `risk: RiskLevel`
on `ApprovalRequest` (and the `RiskLevel` type). It is now dead on the wire (the
daemon never sends it); drop both there to match.

## Independent review verdict: hot-reload + pairing biometric + delivery receipt + relay #53 (75932b0..518d28f)

*Written by the independent security-reviewer (did NOT implement any of this
code), per the review-integrity rule. Adversarial pass over commits `d916b2e`
(#59 hot-reload + one socket, #48 pairing biometric), `88545c3` (#41 delivery
receipt daemon side, lease-window wire alignment), and relay `a5efd0d` (#53
offer-then-drain). This section is the verdict the implementer notes in §21
(and the §14-16 notes) defer to.*

**Gate run (this reviewer, on HEAD 518d28f):** `cargo test` = **378 passed, 0
failed** across all crates; `cargo clippy --all-targets -- -D warnings` =
**clean** (no warnings); `cargo fmt --check` = **clean**. Relay: worker vitest
(`test/worker.test.ts`) = **18 passed**; bun (`bun/server.test.ts`,
`shared/push.test.ts`, `shared/protocol.test.ts`, `longpoll-adversarial.test.ts`)
= **40 passed across 4 files, 0 fail**. Em-dash/emoji scan of every added line in
`crates` and `relay` (including `landing.html` and `README.md`): **none**.

**Overall verdict: GREEN. No P0/P1/P2 findings. Ship-clear on these three
changes.** Every adversarial item below verified sound against the code, not the
implementer notes. The residuals are pre-existing, honestly documented, and
fail-closed.

### #59 config hot-reload + one authoritative socket, GREEN

- **Fail-closed swap: GREEN.** `Core::reload_config` (`daemon.rs:341`) reaches
  `ConfigCell::store` ONLY on the `Ok(cfg)` arm of `Config::load()`; the `Err`
  arm returns the error string WITHOUT touching the cell, so a malformed,
  truncated (half-written save), or unreadable file leaves the last-good `Arc`
  in force. It never falls open and never downgrades to refuse-all, it keeps
  exactly what last parsed. Proven by
  `config_reload_is_fail_closed_on_a_malformed_file` (corrupts `config.json`,
  asserts `op` still gates after the failed reload) and
  `config_hot_reload_swaps_in_the_on_disk_rules`.
- **Torn-read safety: GREEN.** `ConfigCell` is `RwLock<Arc<Config>>`. A gating
  decision takes `snapshot()` (`daemon.rs:1144`), read-lock, clone the `Arc`,
  unlock, and evaluates the entire `resolve` against that one pinned `Arc`. A
  concurrent `store()` write-swaps a *new* `Arc` and drops the caller's
  reference to the old one only when the last snapshot holder releases it. A
  reload landing mid-`resolve` is therefore invisible: whole-old or whole-new,
  never a blend. The watcher thread is the sole writer.
- **Socket: GREEN.** The default runtime dir resolves from
  `confstr(_CS_DARWIN_USER_TEMP_DIR)` (`local.rs::darwin_user_temp_dir`), the
  OS-provided per-user temp dir (`/var/folders/.../T/`), not the
  attacker-strippable `$TMPDIR` env var, this is a *reduction* in attack
  surface versus the prior `$TMPDIR` derivation, which an attacker could
  override to redirect the bind. `prepare_socket` still forces the parent dir
  0700 (`daemon.rs:822`) and both sockets 0600 (`daemon.rs:620,629`);
  `service::socket_path_fits()` still guards `sun_path` length and is asserted in
  `daemon_and_ssh_sockets_share_one_authoritative_runtime_dir`. `SIGIL_SOCK` /
  `SIGIL_SSH_SOCK` remain full-path overrides; pointing a *client* elsewhere
  requires already controlling the victim's environment (a pre-existing
  compromise at which the secret is directly interceptable), and pointing the
  *daemon* elsewhere requires controlling its launch, neither is a new lever.

### #48 pairing biometric gate, GREEN

- **First action in the single chokepoint, deny-closed: GREEN.**
  `pairing_store::save` (`pairing_store.rs:169`) runs
  `if ks.is_biometric() { ks.verify_presence(PAIRING_PRESENCE_REASON)? }` as
  step 0, before the identity blob seal (step 1) and the config write. A decline
  returns `Err` and NOTHING is written, proven by
  `a_declined_biometric_refuses_the_pairing_and_writes_nothing` (asserts no
  config file, no identity blob). `save` is the only writer of
  `DAEMON_IDENTITY_LABEL`; both production callers (`cli.rs:1392,1503`) route
  through it and each runs `ensure_dek()` first, so the SE DEK envelope
  `verify_presence` exercises exists.
- **Trait default is `Err`: GREEN.** `Keystore::verify_presence`
  (`keystore.rs`) defaults to `Err(Backend(...))`; a keystore that reports
  `is_biometric() == true` but omits the override fails closed at the gate.
  Proven by `a_biometric_keystore_missing_a_verify_presence_override_fails_closed`.
- **Real hardware check: GREEN.** `MacKeystore::verify_presence`
  (`keystore_macos.rs`) performs the same `SecKeyCreateDecryptedData` SE
  private-key op (`.biometryCurrentSet`) the approval unwrap uses, purely as a
  presence probe, and drops the recovered `Zeroizing` DEK immediately, no DEK
  crosses any boundary. The dev bypass is reachable only when
  `is_biometric() == false`, which only `SIGIL_DEV_KEYSTORE` (behind its own
  loud warning) produces; the gate simply never calls `verify_presence` in that
  case. Residual: on-hardware Touch ID actually *firing* is UNPROVEN statically
  (shares the §6 NEEDS-VERIFICATION residual; Tom's device checklist covers it).
  Not a code finding.

### #41 delivery receipt, GREEN (highest-risk new inbound; verified hardest)

- **(a) Never mistaken for / never resolves a decision: GREEN.**
  `ToDaemonMessage::from_value` classifies strictly by the `type` tag:
  `"delivered"` -> `Delivered`, `"pushRegister"` -> `Push`, else -> `Response`.
  An `ApprovalResponse` carries no `type`, so a receipt tag cannot shadow a
  decision, and `DeliveryReceipt` carries no DEK/partial/lease so it cannot *be*
  one. In the owner loop, `Delivered` dispatches ONLY to `mark_delivered`
  (`remote.rs:508`) and never touches `route_response`/the waiter `tx`. Proven
  by `a_delivery_receipt_marks_delivered_without_resolving_the_approval`
  (waiter channel stays `Empty`).
- **(b) Forge/tamper/replay rejected: GREEN.** `Delivered` rides the identical
  seal/sign/replay path via the single `classify` -> `Envelope::open` ->
  shared `ReplayGuard` pass. `hostile_relay.rs::
  delivery_receipt_rides_the_sealed_signed_replay_protected_envelope` proves a
  ciphertext bit-flip -> `BadSignature` (no forge) and an exact-bytes replay ->
  `Replay(DuplicateRequest)` (no re-mark). A hostile relay cannot fabricate one.
- **(c) Cannot desync the shared monotonic ReplayGuard: GREEN.** The guard is
  consumed at envelope-open, before classification, identically for every
  inbound kind, matching the phone's single monotonic outbound counter. A
  `Delivered` advances `last_counter` exactly as a `Response` would. Worst case
  under relay reordering (hold a `Response`, deliver a later `Delivered` first)
  is a `CounterRegression` rejection of the delayed message, i.e. fail-closed
  deny of the *display or the decision*, never a bypass. `mark_delivered` itself
  only sets `delivered_at_ms` when unset (idempotent; duplicate/unknown/late =
  no-op).
- **(d) `pending` surface is display-only; no local-approval bypass: GREEN.**
  Remote in-flight requests are enumerated onto `pending_json` from
  `RemoteApprover::pending_snapshot` (names/provenance only, an
  `ApprovalRequest` never carries a secret value). The control `Approve`/`Deny`
  frames call `core.pending.resolve` (`daemon.rs:885,896`), which targets the
  LOCAL `PendingRegistry`; a phone-gated request lives in the RemoteApprover
  `waiters` map, not there, so `resolve` returns false ("no pending request with
  that id"). The control socket is moreover only wired under
  `Factor::DevInsecure`, not `Factor::Phone`. No new path lets a local
  `approve/deny` resolve a phone-gated `request_id`.

### lease-response wire (daemon sole lease authority), GREEN

- **GREEN.** `InstallLease` lost its `grant_key` field entirely (proto struct is
  `{ ttl_ms }`); no code can trust a phone-supplied key because the field no
  longer exists. `remote.rs::outcome_for` reads only `lease.ttl_ms` ->
  `Decision::Lease(ttl)`. In `fulfill`, the daemon mints the grant key itself
  from the kernel-verified caller (`lease::grant_key(&caller, cwd, &scope)`,
  `daemon.rs:1208`) and clamps via `action.lease.clamp_secs`
  (`daemon.rs:1354`): run-once -> `None` -> no lease; leasable ->
  `min(requested, max_secs)`. A hostile approver cannot widen a lease past the
  rule cap nor convert run-once to a lease, the per-rule policy is re-enforced
  daemon-side regardless of what the phone returns. `leasable_rule_clamps_an_
  over_cap_lease_to_the_rule_max` and the run-once tests cover it. The softphone
  now sets only `ttl_ms`.

### relay #53 offer-then-drain, GREEN (residual judged acceptable)

- **GREEN.** `wake` (`protocol.ts:365`) now offers `list.map(i => i.blob)` and
  empties the buffer (`list.length = 0`) ONLY after a waiter returns `true`
  (was live/unsettled). A settled waiter returns `false` (`longPoll`'s waiter
  closure guards on `settled`), leaving every `Item` in place with its ORIGINAL
  `exp`, no TTL reset, no reorder, no drain-into-void for a waiter whose death
  we can observe. `MAX_WAITERS` (8), coexisting-waiters, and newest-wins
  (`waiters.pop()`) are intact; the drop-oldest-at-cap path resolves with `[]`
  on a provably-empty slot. The `Waiter: (blobs) => boolean` contract has no
  double-resolve (the `settled` latch) and no settled-but-registered drain
  beyond the documented silent-orphan case.
- **Residual (silent disconnect orphan): ACCEPTABLE, no fix required now.** A
  connection that dies WITHOUT its abort signal firing is not `settled`, so it
  still accepts the offer and the one queued deposit drains into the void. This
  is **fail-closed**: the lost delivery makes the daemon time out and *deny*, it
  never releases a secret. It is bounded by the sender's poll backstop and the
  180s item TTL, requires an actual silent disconnect on top of unlucky timing,
  and is unreachable by any shipped client (both are strictly single-flight per
  slot). For a single-user personal instrument this does not warrant the
  at-least-once/wire-receipt path yet; the module header documents it honestly
  and flags confirming edge abort-signal behaviour on a real Cloudflare deploy.
  Judged acceptable.

### Cross-cutting invariants, GREEN

Daemon-at-rest inert (config hot-reload swaps rules only; no token/DEK involved),
secret-bytes-never-in-daemon-memory (the receipt and the `pending` snapshot carry
references/labels/provenance, never a secret value), relay
powerless/anonymous (no key-distribution role added; the receipt is opaque
ciphertext to the relay), and zero em-dash/zero emoji in user-facing strings all
hold across these diffs.

## Independent review verdict: #36 resolution broadcast + #51 direct transport (merged `feat/config-rule-engine` @ `f842e0d`)

*Written by the independent security-reviewer (did NOT implement any of this
code), per the review-integrity rule. Adversarial pass over commits `ea473fc`
(#36 resolution-broadcast wire + phone dismissal) and `db2f9e7` (#51 direct
transport rungs 1-2, new crate `crates/sigil-direct`). Both features are
ADDITIVE and DORMANT: neither is wired into the shipping approval/serve path, so
the review's first job was to confirm that, then to confirm no latent flaw can
bite once deliberately enabled.*

**Gate run (this reviewer, on HEAD `f842e0d`):** `cargo test` = **401 passed, 0
failed, 7 ignored** across all crates (233 sigil-core, 90 sigil-proto, 18
sigil-direct, plus proto/relay-client/softphone integration + doctests);
`cargo clippy --all-targets -- -D warnings` = **clean**; `cargo fmt --check` =
**clean**. Em-dash (U+2014) / en-dash (U+2013) / emoji scan of every added line
in both commits: **none**.

**Overall verdict: GREEN. No P0/P1/P2 findings. Ship-clear, and, more to the
point, dormant, so nothing here can affect the shipping path until an operator
deliberately wires it.** Every scope item verified sound against the code, not
the implementer notes.

### Dormancy, CONFIRMED for both features

- **#36 `broadcast_resolution` is dormant: CONFIRMED.** `grep` across `crates`
  and `apps` finds exactly one definition (`remote.rs:466`) and callers ONLY in
  its own unit test (`remote.rs:890`). The production `serve` path and the
  ToDaemon owner loop never call it; `build_gate` (`daemon.rs:197-246`, the sole
  production approver wiring) constructs a `RemoteApprover` and never invokes any
  resolution broadcast. No `RingApprover` / ring coordinator exists yet (deferred
  with design in `docs/design/multi-device.md`). The wire type, the daemon seal
  method, and the phone `dismissResolved` handler are all present and tested but
  reachable only when a future ring coordinator calls them.
- **#51 direct transport is dormant/OFF by default: CONFIRMED.** `grep` for
  `sigil-direct` / `sigil_direct` / `DirectLink` / `FallbackTransport` /
  `verify_link` finds ZERO references outside `crates/sigil-direct/` itself. The
  crate is a workspace member (so it compiles and is tested) but is a dependency
  of no other crate, not `sigil`, not the phone. Production `build_gate`
  (`daemon.rs:219`) wires `RemoteApprover::new(Arc::new(relay), …)` on a raw
  `DaemonRelay`, never a `FallbackTransport`; no primary is ever installed and
  the relay remains the sole transport. The phone `LadderTransport` is likewise
  imported nowhere in the shipping session wiring.

### #36 resolution broadcast, GREEN (per scope item)

- **(a) Sealed + signed + replay-protected; a hostile relay can neither forge
  nor replay a dismissal: GREEN.** `ResolutionBroadcast` rides the identical
  `Envelope::seal`/`open` path as every other message (crypto_box to the phone's
  pinned agreement key, Ed25519 signature over all fields, single-use request id,
  per-pairing monotonic counter, timestamp window). Proven by
  `hostile_relay.rs::resolution_broadcast_rides_the_sealed_signed_replay_protected_envelope`:
  a stranger's agreement secret fails `Decrypt`; a ciphertext bit-flip fails
  `BadSignature`; a forge from an unpinned key fails `BadSignature` (the phone
  still pins the daemon); the exact bytes replayed fail
  `Replay(DuplicateRequest)`. The daemon-side seal is re-proven end-to-end in
  `remote.rs::broadcast_resolution_deposits_a_sealed_dismissal_the_phone_can_open`,
  including the replay rejection on the phone's guard.
- **(b) Worst a hostile relay can do is withhold/delay; never a release, never
  an approval: GREEN.** The type carries only `{request_id, status}`, no DEK, no
  Z_F, no decision detail (`ResolutionStatus` deliberately does not say approve
  vs deny). A dropped/delayed broadcast degrades to single-device behavior: the
  loser device's own request timeout still expires the sheet
  (`broadcast_resolution` doc + `deposit_and_wait` fail-closed timeout). A
  (cryptographically impossible) forged-but-valid one at most hides a prompt,
  which withholds a release, it can never cause one, because the phone's
  `dismissResolved` records a neutral outcome and touches no key.
- **(c) Touches no waiter channel, no ReplayGuard, no DEK/Z_F: GREEN.**
  `broadcast_resolution` (`remote.rs:466-484`) shares only the daemon->phone
  `counter` and `Envelope::seal`, exactly like a request deposit. It registers no
  waiter (no `waiters` map mutation), locks no `guard` (that guards the inbound
  ToDaemon direction; this is an outbound ToPhone deposit), and never constructs
  or reads a DEK or partial. A seal/transport error is swallowed (best-effort),
  which is safe precisely because it gates nothing.
- **(d) Phone `dismissResolved` records a zero-knowledge neutral entry and
  cannot release anything: GREEN.** `store.ts::dismissResolved` no-ops on an
  unknown or already-terminal request (`approved`/`denied`/`expired`), then
  records `"superseded"` (or `"expired"` for an expiry), never `approved`/
  `denied`. `HistoryEntry.decision` is widened to `Decision | "expired" |
  "superseded"`; `RequestState` gains a terminal `"superseded"`. It carries no
  DEK path and cannot transition a request into an approve. `classifyToPhone`
  fails closed: a `"resolution"` tag with a missing/blank `requestId` or an
  out-of-set `status` returns `null` and the caller drops it. `handleInbound`
  opens the envelope ONCE to a raw payload (crypto verified regardless of shape),
  then demuxes, so a resolution rides the same signature/replay/decrypt gate as
  a request, and is never acknowledged with a delivery receipt.
- **Wire-shape stability: GREEN.** `ToPhoneMessage::from_value` uses a
  hand-rolled `type`-tag peek (not `#[serde(untagged)]`), so the untagged
  `ApprovalRequest` wire shape is byte-for-byte unchanged and the pinned vectors
  / pairing transcript do not shift. Mirrors the audited ToDaemon demux.

### #51 direct transport, GREEN (per scope item)

- **(a) Carries only opaque sealed envelopes; a rogue LAN/TCP peer's frames fail
  `Envelope::open` and are dropped: GREEN.** `DirectLink` frames the exact
  `serde_json` envelope wire the relay uses (`wire::{envelope_to_wire,
  wire_to_envelope}`), authenticates nothing, decrypts nothing, grants nothing
  (module doc + `tcp.rs`). Every frame is still opened by `Envelope::open` at the
  unchanged `RemoteApprover`/phone call site. A frame that does not even decode to
  an `Envelope` is dropped while framing stays synchronised (`read_loop` consumes
  exactly `len` bytes); one that decodes but is not sealed to the pinned peer
  fails `open` downstream. No plaintext and no new network trust.
- **(b) `FallbackTransport` with no primary is byte-identical to the relay:
  GREEN.** With `primary == None` (the default and the post-failure state),
  `send`/`deposit_to_phone`/`recv` delegate straight to the relay with no added
  behavior (`fallback.rs` + `with_no_primary_it_is_exactly_the_relay`). Spoofing
  or withholding mDNS cannot affect a daemon with no installed primary, because
  discovery is never consulted on the transport path.
- **(c) A primary is installed only after `verify_link` opens an envelope as the
  pinned peer; a TCP-only imposter fails closed: GREEN.** `verify_link`
  (`discovery.rs:127`) reads exactly one envelope off the dialled link and demands
  the caller-supplied predicate (wired to the same `Envelope::open` against the
  pinned peer key) accept it; otherwise `NotPinnedPeer` / `Timeout`, and the link
  is never installed. `install_primary` doc-contracts that the caller MUST have
  verified first. Proven by `verify_link_rejects_an_envelope_the_predicate_denies`
  and `verify_link_times_out_when_nothing_arrives`. The mDNS `ServiceRecord.hint`
  is explicitly a non-secret dial discriminator, never the mailbox id, never
  trusted.
- **(d) Downgrade safety, active LAN MITM is at worst a one-timeout
  fail-closed denial, never a forge/leak: GREEN (with a named residual).** A MITM
  can complete a TCP handshake and relay the phone's genuine verification envelope
  to get promoted, then black-hole traffic. The consequence is a `recv`/`send`
  error that retires the primary (`retire_if_current`, guarded by `Arc::ptr_eq`
  so a concurrent fresh install is not clobbered) and spends the remaining budget
  on the relay; if it black-holes silently within a single window the approval
  times out and fails closed. It cannot forge a request/response (envelope) or
  read a secret. The residual (a `PreferDirect` deposit black-holed by an active
  MITM costs one timeout before the demote-on-silence retry, which lives in the
  not-yet-landed owner-loop change) is the reason the crate ships OFF; it is
  documented in `docs/design/direct-transport.md` and inherits the fail-closed
  floor. `Mirror` policy removes even the one-timeout delay at the cost of always
  touching the relay.
- **(e) Fail-closed on drop/truncation/over-cap; rung-2 listener at-rest
  inertness: GREEN.** `MAX_FRAME_BYTES` (64 KiB) caps a declared frame length
  before allocation; an over-cap length, an unknown direction byte, EOF, or a
  truncated read all break `read_loop` and `shared.close()` (latched, never
  cleared), which `shutdown(Both)` propagates so both ends fail over together.
  `recv` drains buffered frames first, then surfaces `Closed`
  (`buffered_frames_survive_a_close_and_are_delivered_before_the_error`). A
  non-UTF8 or undecodable-but-length-valid frame is dropped while the link stays
  synchronised. `DirectListener::accept` hands back an explicitly UNVERIFIED link;
  at rest it holds no keys and grants nothing until `verify_link` promotes it.
- **(f) OFF by default, relay remains default: GREEN.** Covered under Dormancy
  above, no crate depends on `sigil-direct`, and `build_gate` wires the raw
  relay.

### Cross-cutting invariants, GREEN

Daemon-at-rest inert (neither feature holds a token/DEK; the resolution broadcast
and the direct link carry only opaque ciphertext), secret-bytes-never-in-daemon-
memory (a `ResolutionBroadcast` is `{request_id, status}`; a `DirectLink` frame is
an opaque `Envelope` never parsed for secret material), relay powerless/anonymous
(no key-distribution role added, the mDNS record is untrusted and the envelope
layer is the sole trust boundary), fail-closed everywhere (verify gate, drop/
truncation, timeout, unknown tag), and zero em-dash / zero emoji in user-facing
strings all hold across these diffs.

## Independent review verdict: native Rust blind relay `crates/sigil-relay` (merged `feat/config-rule-engine` @ `4b771f2`)

**Written by the security-reviewer, which did NOT author `crates/sigil-relay`**
(rust-core / relay, `4b771f2`); per the review-integrity rule this is an
independent verdict, not a self-certification. Scope: the from-scratch
tokio/hyper reimplementation of the blind relay SERVER (the clients
`crates/sigil-relay-client` and `apps/phone/src/transport/relay-http.ts` are
unchanged), reviewed against the TS originals it replaces (`relay/shared/
protocol.ts`, `relay/shared/push.ts`, `relay/src/index.ts`) and against what the
real clients send/expect. Gate run at `4b771f2`: `cargo test -p sigil-relay` =
**23 passed** (18 integration + 5 push, plus 8 protocol unit tests in the lib
build), `cargo clippy -p sigil-relay --all-targets -- -D warnings` = **clean**,
`cargo fmt -p sigil-relay --check` = **clean**.

**Overall: GREEN with one P2 availability-only hardening note. No P0/P1. No
confidentiality or integrity finding; every failure path fails closed (a lost or
denied delivery, never a wrong/duplicate delivery, a cross-mailbox/cross-direction
leak, or an ungated release).**

### Per-item verdict

| # | Property | Verdict |
|---|----------|---------|
| 1 | Powerlessness / anonymity / zero persistence | **GREEN** |
| 2 | Wire-compat exact (routes, methods, statuses, byte shapes, constants) | **GREEN** |
| 3 | offer-then-drain wake (#53 v5.2): newest-wins, drop-oldest, no lock across await | **GREEN** |
| 4 | APNs ES256 JWT signing + fail-safe caching, key never logged | **GREEN** |
| 5 | Knock modes + `POST /knock`: opaque-only, stores nothing, no amplifier/SSRF | **GREEN** |
| 6 | Rate limiting under a hostile peer; disjoint per-direction waiter lists | **GREEN** (see P2) |
| 7 | Fail-closed, no panic-DoS on malformed input, zero em-dash/emoji user-facing | **GREEN** |

**1. Powerlessness / anonymity / zero persistence: GREEN.** No code path reads,
parses, hashes, or branches on envelope contents. `parse_to_phone` / `parse_env`
(`server.rs`) extract only `env` (moved as an opaque `String`) plus the doorbell
`pushToken`/`platform`; `enqueue`/`drain`/`wake` (`protocol.rs`) move the String
verbatim. State is a single in-memory `HashMap<mailbox_id, Arc<Mutex<Mailbox>>>`
(`server.rs::AppState`); grep confirms no `std::fs` write, no DB, no `ctx.storage`
analogue anywhere. A restart drops all mailboxes, exactly as the short TTL would.
Routing is by the URL mailbox id (shape-checked by `valid_id`), never by envelope
content.

**2. Wire-compat exact: GREEN.** Verified field-by-field against `relay/src/
index.ts` and both real clients (`http.rs::{deposit,poll_slot}` sends
`{"env",..,"pushToken"?,"platform"?}` and reads `{"envelopes":[...]}`;
`relay-http.ts` the same). Routes `GET /`, `GET /health`, `GET|POST /mailbox/{64-hex}/
to-phone|to-daemon`; invalid id and unknown top-level path both 400 `bad_mailbox`;
unknown verb / unsupported method rate-checks then 404 `not_found`, matching the
TS order (rate-check precedes routing, exactly one increment per request).
Statuses 200/400/413/429/507/404 map identically; `QueueFull -> 507
INSUFFICIENT_STORAGE`, `TooLarge -> 413`. Response bytes are typed structs so
serde emits byte-exact field order (`{"ok":true,"service":"sigil-relay"}`,
`{"ok":true}`, `{"envelopes":[...]}`, `{"ok":false,"error":".."}`), asserted by
`protocol.rs::response_bodies_match_the_ts_wire_bytes`. All constants match the TS
(`TTL_MS 180000`, `MAX_QUEUE 32`, `MAX_ENVELOPE_BYTES 16384`, `LONG_POLL_MS 25000`,
`MAX_WAITERS 8`, `RATE_MAX 60/60000`, `PUSH_MAX 5/60000`). `GET /version` and
`POST /knock` are ADDITIVE endpoints absent from the TS variants; no shipping
client depends on them for the message path, so they cannot break a live client.
One deliberate, non-breaking hardening: a hard `MAX_BODY_BYTES` (`Limited`) read
cap the TS delegated to the runtime/content-length; it converges for legitimate
traffic (env <= 16 KiB + tiny wrapper < 20 KiB) and is only stricter on abuse.
Retry-After is absent on 429 in both implementations; the client treats its
absence as "back off" (`relay-http.ts::parseRetryAfter(null) -> null`), so no
divergence.

**3. offer-then-drain wake: GREEN.** `protocol.rs::wake` offers the still-queued
blobs to the newest waiter (`waiters.pop()`) and drains (`list.clear()`) ONLY on a
positive accept; a rejecting (settled/dead) waiter leaves every `Item` untouched
(same `exp`, no TTL reset, no reorder) and the loop tries the next-newest, else
leaves the queue for the next GET. The accept/reject signal is the oneshot
`send().is_ok()` in `server.rs::poll`. `MAX_WAITERS` drop-oldest
(`waiters.remove(0); oldest.offer(&[])`) only ever evicts within the same slot and
resolves the evicted waiter empty against a provably-empty queue. No lock is held
across an await: the mailbox `MutexGuard` lives only inside the synchronous `let rx
= { .. }` block; the `tokio::select!` awaits with no guard held; the timeout branch
re-locks. `WaiterGuard::drop` reaps the waiter on a mid-poll client disconnect. The
same-tick loss window (a silent disconnect whose abort never fires, deposit landing
in the gap before any reconnect) is the documented #53 orphan-gap residual: it
fails CLOSED (one delivery lost, recovered by the sender's poll backstop + item
TTL), never a wrong or duplicated delivery, never a cross-mailbox or cross-direction
leak. The two directions are disjoint `Vec<Waiter>`s, so a flood on one slot cannot
evict or steal the paired party's waiter on the other. Ported adversarial unit
tests (`residual_newest_silently_dead_...`, `hardened_newest_settled_dead_...`,
`newest_wins_delivers_to_the_live_reconnect`, and the HTTP-level
`deposit_survives_disconnect_then_reconnect`) all pass.

**4. APNs ES256 JWT signing + caching: GREEN.** `push.rs::bearer` signs
`base64url(header).base64url(claims)` with p256 `SigningKey` (RustCrypto,
RFC6979-deterministic) and emits `sig.to_bytes()` = raw 64-byte `r||s`, exactly
JWS ES256; header `{"alg":"ES256","kid":"5PCK76SDBA"}`, claims
`{"iss":"53W966FBFP","iat":<now/1000>}`. `tests/push.rs::rings_a_real_es256_jwt_...`
mints against a throwaway key and cryptographically verifies the signature,
header, claims, topic (`works.rainn.sigil`), and fixed doorbell body. The key is
resolved from `APNS_KEY_P8` / `APNS_KEY_P8_PATH` (`lib.rs::resolve_apns_key`) and
is never logged: every `eprintln!` carries a decode-error Display (no key bytes),
a status, or a token-free message; the token goes only into the `/3/device/{token}`
URL, never a log line. The JWT cache (`JWT_CACHE: Mutex<Option<Cached>>`) fails
safe: a poisoned lock on the read path returns an error that `ring_apns` logs and
swallows (no push, poll backstop); the write path skips caching but still returns
the fresh JWT, so it degrades to re-signing, never blocks delivery and never
serves a stale/wrong token. Every push failure is best-effort: `ring_apns` and
`send_push_direct` return `()` and are `tokio::spawn`ed detached from the deposit
response, so a push outcome can never block or alter message delivery (the 200 is
already returned).

**5. Knock modes + `POST /knock`: GREEN.** `direct` signs+sends locally; `upstream`
forwards `{opaque_token, mailbox_hash, platform}` only (`push.rs::forward_knock`),
never any `env`/message content; `off` and a `direct`-with-no-key both no-op and
fall through to the client poll (fail-open doorbell, correctness intact).
`/knock` accepts only `opaque_token` + `mailbox_hash` (`valid_id`-checked) +
`platform`, rate-limits on the tight per-mailbox `push_ok` (5/min), stores
nothing, and returns `{"ok":true}`. No SSRF/amplifier: `KNOCK_UPSTREAM` is an
operator-set env var (never attacker-supplied at request time), so the forward
target is fixed; a hostile peer can at most trigger one rate-limited forward per
knock. The upstream-trust note is documented honestly in `push.rs` (an upstream
knock relay learns only the opaque token and that *some* mailbox has traffic; it
cannot read, forge, or attribute).

**6. Rate limiting under a hostile peer: GREEN (one P2 note below).** Fixed-window
`rate_ok` / `push_ok` are per-mailbox, in-memory, non-load-bearing (clients verify
everything); the classic 2x fixed-window boundary burst is documented and
harmless. Waiter lists are disjoint per direction, so a flood is self-DoS and
cannot evict/steal the other party's waiter. Addressing any mailbox at all
presupposes the 256-bit mailbox id (BLAKE2b of both pinned keys, carried only
inside TLS); an outsider who does learn one and races the phone's poll still
cannot read or forge the sealed+signed envelope, and the intended party recovers
via replay/backstop, so a stolen delivery is a denial, never a leak.

**7. Fail-closed / no panic-DoS / no em-dash-emoji: GREEN.** Every parser is
`Option`-returning with no indexing panic: `valid_id` (len+byte range), the
serde `as_object`/`as_str` chains in `parse_env`/`parse_to_phone`/`knock`,
`content_length` (parse-error -> None), `read_body` (`Limited` cap -> None ->
413), `now_ms` (`unwrap_or(0)`). Response construction never panics
(`serde_json::to_vec(..).unwrap_or_else(|_| b"{}")`; `.expect` only on a static
status+header). A poisoned mailbox lock recovers the guard rather than panicking
mid-request (`server.rs::lock`). Fuzzing the inputs mentally (bad/short/long
mailbox id, oversized/short/empty/non-JSON body, missing `env`, weird verb,
unsupported method, non-numeric content-length) yields only the correct 400/404/
413 status, never a crash. User-facing strings hold invariant #6: all error codes
are ASCII snake_case, `relay/landing.html` has zero non-ASCII bytes, the
`/version` body is ASCII. (Informational, not a violation: one em-dash exists at
`push.rs:188`, but it is inside a `///` doc comment, i.e. source, not a
user-facing string; flagged only because the repo runs an aggressive em-dash
sweep and may want it changed for consistency.)

### P2 (availability-only hardening) - unbounded mailbox-map growth under a distinct-id flood

`server.rs::AppState::get_box` inserts a new `Arc<Mutex<Mailbox>>` for ANY
shape-valid 64-hex id, and shape-validity requires no secret (any 64 hex chars
pass `valid_id`). An unauthenticated remote peer can therefore mint arbitrarily
many distinct mailbox entries by hitting `/mailbox/<random-64-hex>/to-daemon`
(a deposit leaves a TTL-lived `Item`) or `/knock` (creates the entry just to hold
the push counter); the per-mailbox rate limiter does not bound the number of
DISTINCT mailboxes, and the idle-sweep only reaps every `TTL_MS` (180 s), so the
map can grow to ~180 s of request volume before reclamation. Held long-poll GETs
similarly accumulate open connections (25 s each). This is availability-only: it
touches no secret, causes no wrong/duplicate/cross-mailbox delivery, and OOM/fd
exhaustion fails CLOSED (a dead relay denies, never releases). It also mirrors an
architectural property of the TS variant, where Cloudflare's per-name Durable
Object model + edge DDoS protection mask it; the native single-process binary,
sold as "safe to run wide open," concentrates it in one heap with no such
backstop. Recommend (not blocking): a global cap on live mailboxes and/or
concurrent held connections that refuses NEW mailbox creation past the cap (fail
closed) while leaving established pairings' existing entries untouched, plus the
usual reverse-proxy connection/rate limits in the deploy guide. Severity P2:
worth closing before a wide public deploy, but no invariant is violated and no
change is required to land the crate.

### Cross-cutting invariants, GREEN

Relay powerless/anonymous (opaque envelopes, key-hash mailboxes, opaque push
token, no key-distribution role), zero persistence (in-memory only, gone on
restart), everything fails closed (denial never release; a push failure is
best-effort and detached), and zero em-dash / zero emoji in every user-facing
string (errors, landing, version) all hold for this crate.

---

## Independent review verdict: #36 multi-device core + #64 APNs identity env-sourcing (`3a18d17`, `ed5c4b6`, merged @ `afadede`)

*Written by the independent security-reviewer, who did NOT implement any of this
change (review-integrity rule). The implementer's record is
`docs/design/multi-device.md`; its residual list was treated as a set of claims
to break, not to trust.*

**Gate:** `cargo test --workspace` PASS (sigil-core 243, hostile_relay 18,
pairing_mitm 26, sigil-relay 12, relay integration 18, relay push 8,
relay-client 13, softphone 3, sigil-proto 18, plus the crates that report per
binary; 0 failed, 7 ignored). `cargo clippy --workspace --all-targets -D
warnings` PASS (0 warnings). `cargo fmt --check` PASS (clean).

**Overall verdict: GREEN. No P0/P1/P2 findings.** The multi-device approval core
is a genuine composition over N unchanged, previously-reviewed `RemoteApprover`s,
not a rewrite; every reviewed single-device guarantee is preserved by
construction, and the one new concurrency (loser cancellation + first-wins
commit) is correct: exactly one outcome reaches the gate per `decide`, and every
failure path denies. Two honest residuals are recorded below (both already known,
neither a release path). Held to the hostile bar.

### Primary scope (#36), per item

**1. N == 1 byte-identical: GREEN.** `build_gate` (`daemon.rs:241`) constructs a
bare `Arc<RemoteApprover>` for `devices.len() == 1` and only wraps a
`RingApprover` for N >= 2, so the common case never enters the ring coordinator.
The reviewed `RemoteApprover::round_trip` / `deposit_and_wait` /
`recv_timeout(self.timeout)` shape (`remote.rs:268-315`) is untouched by this
change; `round_trip_cancellable` is a *separate* method (option A per the design)
so no cancel check leaks into the single-device wait. `RingApprover::decide`
(`remote.rs:746`) also short-circuits N == 1 to `self.devices[0].decide(ctx)`, and
`pairing_store::load` returns `devices[0]` alone. Confirmed no behavior change for
one device.

**2. Cancellation correctness / exactly one outcome: GREEN.** The race is
serialized by `winner: Mutex<Option<(usize, ApprovalOutcome)>>` (`remote.rs:757`):
the first thread whose `round_trip_cancellable` returns `Some` finds the slot
empty, commits, and fires `cancel.cancel()`; any later thread that also returned
`Some` finds `w.is_some()` and drops its outcome (`remote.rs:770-778`). So even
when two phones both approve in the same tick, EXACTLY ONE outcome is returned to
the gate; the loser's `ApprovalOutcome` (DEK/`Z_F`) is dropped and zeroized,
never consumed, so there is no double-release and no two devices both releasing a
DEK. A dropped `ApprovalOutcome` releases nothing: the token decrypt/splice
happens only on the single value `decide` returns (`daemon.rs:535`, `1460`,
`1488`). A cancelled loser returns `None` within one `RING_CANCEL_TICK` (100 ms)
and `round_trip_cancellable` then calls `remove_waiter` (`remote.rs:337`), so a
late response for that device finds no waiter and is dropped by `route_response`
(`remote.rs:635`); the remove-vs-route ordering is itself serialized by the
`waiters` mutex, and in the losing branch the channel is never read, so a
late-but-real response can reach neither the gate nor a second commit. All threads
run in a `thread::scope` that JOINS before the winner slot is read
(`remote.rs:763-784`), so no loser outlives `decide`. All-timeout / all-`None`
leaves the slot `None` and returns `Decision::Deny` (`remote.rs:799`); the N == 0
guard also denies (`remote.rs:743`). Fail-closed confirmed. Proven by
`ring_first_wins_delivers_the_winners_dek_and_dismisses_losers`,
`ring_first_deny_wins_and_dismisses_losers`, `ring_all_timeout_denies`,
`ring_of_one_matches_the_single_device_path`.

**3. Broadcast-after-commit: GREEN.** The `Settled` broadcast loop runs only in
the `Some((idx, outcome))` arm, AFTER the scope has joined every device thread and
the winner slot is final (`remote.rs:783-795`); it can never race a still-running
approve. It is sent to every device EXCEPT the winner. `broadcast_resolution`
(`remote.rs:543`) seals a `ResolutionBroadcast` carrying only `request_id` +
`status` (no key material, no which-device, no approve/deny), rides the
daemon->phone monotonic counter and the pinned seal, registers no waiter, and
touches no `ReplayGuard`/DEK/`Z_F`. A forged/lost/replayed broadcast can only hide
or dismiss a prompt (withhold a release), never cause one; the phone verifies
signature + replay and a replay is rejected (proven by
`broadcast_resolution_deposits_a_sealed_dismissal_the_phone_can_open` and the
hostile-relay proof
`resolution_broadcast_rides_the_sealed_signed_replay_protected_envelope`). A seal
or transport error is swallowed and degrades to that phone's own timeout, never to
a release.

**4. Per-device replay isolation: GREEN.** `RingApprover` holds only
`Vec<Arc<RemoteApprover>>` and adds NO shared guard. Each `RemoteApprover` owns
its own `Mutex<ReplayGuard>` (`remote.rs:140`), its own monotonic `counter`, its
own pinned `phone` key, and its own `waiters` map. Devices have distinct mailboxes
(`mailbox_id(daemon_pub_i, phone_pub_i)`, distinct per pairing;
`add_device_is_additive_and_per_device_isolated` asserts `all[0].mailbox() !=
all[1].mailbox()`). A response sealed by phone B fails signature verification
inside device A's `classify`/`Envelope::open` against A's pinned phone key and is
dropped, so device A can never resolve device B's request nor pass B's replay
counter. Each device keeps its own single ToDaemon owner (`serve` spawns one per
device, `daemon.rs:694-704`), the sole reader of that mailbox.

**5. Storage migration windows: GREEN.** `add_device` (`pairing_store.rs:423`)
runs the #48 `gate_presence` FIRST (deny-closed, nothing written on decline;
proven by `add_device_gates_on_biometric_and_writes_nothing_on_decline`), then
seals the identity blob, then rewrites the container file: blob-then-file, so a
crash between leaves an ORPHAN blob (inert, referenced by no device row), never an
armed device without a pinned phone. `remove_device` (`pairing_store.rs:519`)
rewrites the file (row gone) BEFORE deleting the blob: file-then-blob, so a crash
leaves an orphan blob, never a dangling row pointing at a deleted identity. A pin
without an identity cannot arm: `device_to_config` fails LOUD
(`MissingIdentity`/`CorruptIdentity`) rather than arming without the keystore half
(`config_present_but_identity_missing_is_a_loud_error`). The v1->v2 migration
(`read_container` -> `from_v1`) is a pure in-memory read transform that keeps the
primary's `primary` sentinel + legacy keystore label and NEVER touches the
keystore; reads never rewrite (idempotent, crash-safe), and the rewrite defers to
the next mutating call (`a_v1_file_migrates_on_read`). The #48 gate also fires on
`save`. Confirmed no window with an armed-without-pin device or a pin without
identity.

**6. load_all fail-closed: GREEN.** `load_all` (`pairing_store.rs:469`) maps
`device_to_config` over every device and `.collect()`s into `Result<Vec, _>`,
which short-circuits on the FIRST error, so one half-broken device makes the whole
load fail. `load_remote_pairing` turns that error into an empty vector
(`daemon.rs:180`), which sets `phone_paired = false` (`daemon.rs:290`) and drops
the factor to Biometric or NoFactor: the daemon never arms a SUBSET of devices,
and the phone factor is disabled entirely rather than arming past a broken row.
That is the safe (fail-closed) direction. N tokens under N mailboxes is the
single-device push posture multiplied: the relay learns it can wake N devices for
N unlinkable mailbox hashes and nothing more (`PushStore` is keyed by mailbox; no
`daemon_pub` ever reaches the relay). Recorded as residual R-#36-2 below (a single
corrupt row disables all phone approval, an availability tradeoff, never a
release).

**Cross-cutting (re-verified for the ring): GREEN.** Daemon inert at rest (no DEK
persisted; the v2 container holds only public pins in a 0600 file; the private
identity stays in the keystore; `config_file_is_0600_and_holds_no_dek`). Secret
bytes never enter daemon memory (the decrypt/splice path is untouched; the ring
returns the same `ApprovalOutcome` the single-device path does). Relay powerless
(per-device mailbox is another opaque key-hash mailbox; the broadcast is opaque
and single-use). Approve requires the phone's hardware-gated key use (unchanged;
deny and dismiss require nothing). Everything fails closed (all-timeout deny,
half-broken-load deny, non-primary v2 deny).

### Secondary scope (#64), per item

**(a) Default build byte-identical: GREEN.** `ApnsIdentity::from_env`
(`push.rs:70`) reads `APNS_TOPIC` / `APNS_TEAM_ID` / `APNS_KEY_ID`, each falling
back to the pinned `DEFAULT_APNS_*` (`works.rainn.sigil` / `53W966FBFP` /
`5PCK76SDBA`) when unset OR empty, so `kid`/`iss`/`topic` are unchanged with the
env unset. Proven by `default-equals-pinned` and the `from_env` override/default
tests (relay push suite, 8 pass).

**(b) Self-hoster identity grants no new power: GREEN.** The identity only
addresses the APNs topic and signs the operator's own provider JWT with the
operator's own `.p8` key; it never enters the opaque-envelope / key-hash-mailbox
path (which carries no identity), so it can only sign that operator's own pushes.
The doorbell body is fixed and content-free.

**(c) No identity/secret logged: GREEN.** Only error branches `eprintln!` (JWT
mint failure, APNs rejection status/text, transport error); the `.p8` PEM, the
minted bearer, and the device token are never logged. Topic/team/key-id are not
secrets.

**(d) Stale bearer not reusable across a changed kid/iss: GREEN.** The JWT cache
hit requires `c.pem == pem && &c.id == id` AND freshness (`push.rs:154`), so any
change to `key_id`/`team_id`/`topic` (or the PEM) misses the cache and re-signs a
fresh token with the new `kid`/`iss`. A token minted under one identity can never
be served for another. `overridden-identity-rides-the-wire` proves the override
reaches the header/claims.

### Residuals (honest limits, neither a release path)

- **R-#36-1 (v2 threshold under multi-device, known/deferred).** A v2 account is
  armed against the PRIMARY device's Secure-Enclave share `F` only. In a ring, a
  non-primary phone's v2 approve returns a partial for the right `account_id` but
  the wrong `F`, which the coordinator treats as a real decision that can WIN the
  race; the downstream combine then reconstructs a wrong DEK and AES-256-GCM
  authentication fails (`secrets::decrypt_token` -> `SecretsError::Aead`), so the
  request DENIES. This is fail-closed (no partial release, no plaintext), but it
  is an availability quirk: a non-primary phone answering a v2 request first can
  cause a spurious deny of a request the primary would have approved. Must stay
  surfaced in `sigil doctor` (design doc §"v2 threshold under multi-device"), not
  silent. No release path; acceptable to land, worth closing with per-device `E_i`
  wraps before v2 multi-device is advertised.
- **R-#36-2 (one broken device disables all phone approval).** Because `load_all`
  fails loud on the first bad row, a single corrupt/unreadable device row (corrupt
  file, missing/rotated keystore identity, off-curve `F`) drops the WHOLE phone
  factor to Biometric/NoFactor. This is the intended fail-closed direction (never
  arm a subset), but it means local corruption of one row is a denial-of-service
  on all phone approval. An attacker who can corrupt a pairing row already has the
  local file/keystore access that is game-over for this threat model, so this is
  availability-only; noted for honesty, not blocking.

**Verdict recorded by the independent security-reviewer (did not implement
`3a18d17` / `ed5c4b6`). #36 multi-device core and #64 APNs identity env-sourcing
are GREEN and ship-clear; the two residuals above are fail-closed availability
limits, not release paths.**

