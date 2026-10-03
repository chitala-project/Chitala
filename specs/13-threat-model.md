# 13 — Threat Model v0.1

Sources: v13 §18 (Formal Threat Model & Verification Program), v8 §19 (mandatory testing), v10 §1/§17, v11 §17.

The goal is not to be "unhackable". It is to make compromise **hard to achieve, hard to spread, hard to persist, and recoverable** (v13).

## Trust boundaries

```
 ┌──────────── untrusted ────────────┐   ┌──────────── trusted core (Rust, no unsafe) ───────────┐   ┌─ adapter host (per adapter) ─┐
 │ LLM / prompt / web / tool output  │   │                                                       │   │ no private keys, empty env   │
 │ AI principal  (ai:*)              │──▶│ chitala-mcp ─intent─▶ IPC ─▶ Reference Monitor ───────│──▶│ OrderGate ─▶ adapter ─▶ device│
 │ local processes, other users      │   │ (holds AI key)   ─▶ Authority Engine ─▶ Safety       │ord│ (mock, Home Assistant)       │
 │ the network, legacy devices (SC0) │   │                  ─▶ (owner approval) ─▶ boundary     │◀──│ replies = untrusted data     │
 └───────────────────────────────────┘   │ domain authority key · node key · audit · state       │   └──────────────────────────────┘
                                          └───────────────────────────────────────────────────────┘
```

Assumptions: the node machine's OS and the account running the node are not compromised, and whoever holds the owner key is the legitimate owner.

## Attacks that are blocked — every row has a test

| Attack | Defence | Tests |
|---|---|---|
| An AI sends a command straight to a device, skipping the intent | A CSME `command` from an AI → `E_INTENT_REQUIRED` (Invariant 1); the broker only emits intents | `ai_commands_are_refused_intents_are_required`, `the_broker_never_sends_commands` |
| An AI controls a device without a delegation | `E_TOKEN_MISSING` (DELEGATION step) + policy `C12-ai-needs-token` (2 layers) | `case2_…`, `milestone_0_0_1_…` |
| An AI uses a light token to open the door | token scope (`E_TOKEN_DENIED`) | `milestone_0_0_2_…`, `tools_follow_the_token` |
| A child's AI opens the door (case 3) | the represented person is not entitled (`child-no-high-risk`), even if a token (wrongly) covers the door | `case3_child_ai_cannot_open_the_door` |
| The owner's AI opens the door on its own (case 4) | constitution in code + `C11-ai-no-high-risk`: ESCALATE, only an owner can approve; the door moves only after approval | `case4_owner_ai_opening_the_door_needs_a_human` |
| An AI asks another AI to do it (case 5, authority laundering) | a chain of signed `cause`s; authority = the intersection of every link; a relay must keep the represented person (`E_PROVENANCE`); an agent serves only the people declared for it (`E_ON_BEHALF_OF`) | `case5_…`, `authority::case5_…` |
| An AI claims `on_behalf_of` someone else | agency is declared at enrollment, never claimed in a request | `who_and_on_behalf_of` |
| A forged approval, an approval for another intent, or a modified intent | the approval is signed by an owner, bound to the intent digest, single-use, time-limited | `approvals_must_come_from_an_owner_for_this_exact_intent`, `only_an_owner_can_answer_…` |
| Cancelling someone else's escalation with a bogus answer | an invalid answer does not close the question | `only_an_owner_can_answer_and_bogus_answers_do_not_cancel` |
| Approval fatigue (an AI asking over and over) | ≤ 3 questions waiting per AI, ≤ 256 per domain | `an_agent_cannot_flood_its_owner_with_questions` |
| The world changes while a human is deciding | Authority and Safety run again when the answer arrives (revoked tokens, holds, stale state) | `safety_is_checked_again_when_the_human_answers` |
| A command based on unknown or stale state | `SAFE-3-STATE` for risk ≥ medium | `unknown_or_stale_state_fails_safe` |
| A command that contradicts physics (locking an open door) | `SAFE-4-PHYSICAL` before the command, the device invariant after it (C5) | `physics_beats_permission`, `safety_and_the_device_both_refuse_unsafe_commands` |
| An AI delegates, revokes or lifts its own quarantine | `C11-ai-no-domain-admin` (incl. `domain.revoke_all`); nobody changes their own state | `policy_checks`, `probing_ai_is_contained_…` |
| A stolen token, or one kept by an agent after it was re-enrolled with a new key | tokens are bound to the holder's key (proof of possession) | `proof_of_possession`, `a_token_is_bound_to_its_holders_key` |
| An agent serving several people uses one person's grant for another | an agent's token names the persons it acts for | `an_agents_token_acts_only_for_the_person_it_is_for` |
| A guest passes the owner's key on | tokens are non-transferable unless the grantor sets a budget | `non_transferable_by_default`, `delegation_cannot_amplify` |
| A lost phone or a compromised agent: tokens nobody can list | revocation floors by principal, or for the whole domain | `revocation_floors_cut_everything_issued_before` |
| Revocation arrives while an order is in flight | the authority fence re-checks the order's tokens and principals before it is sent | `a_revocation_stops_an_order_in_flight_but_an_unrelated_change_does_not` |
| A chain of agents launders authority | every link holds its own bound token; the chain is their intersection | `the_whole_chain_is_the_intersection_of_its_links` |
| One person alone acts on a resource that needs two | two-key resources: two different people, a direct request is refused | `a_two_key_door_needs_two_different_people`, `one_person_alone_never_turns_two_keys` |
| Another principal steals a token | tokens are holder-bound | `token_checks` |
| Amplifying authority through a delegation chain | child ⊆ parent, expiry, depth, no re-delegation of attenuated tokens | `delegation_never_amplifies` (property), `depth_is_bounded` |
| An attenuation block injects rights | Biscuit scoping | `attenuation_block_cannot_inject_rights_or_holder` |
| A token from another domain, or a tampered token | the domain's authority signature | `foreign_or_tampered_tokens_are_invalid` |
| Prompt injection through tool parameters or the purpose | parameters are data with a strict schema; the purpose grants nothing | `prompt_injection_is_just_data` |
| An AI keeps probing for authority | automatic containment up to QUARANTINED | `probing_through_the_broker_quarantines_the_ai` |
| Forging requests in someone's name to get them contained | only authenticated denials count | `forged_signature_is_not_attributed` |
| A one-bit change to a signed request | the COSE signature | `bit_flips_never_allow` (property) |
| Garbage bytes / malicious CBOR crash the parser | authenticate before parsing, canonical CBOR, size and depth limits | `garbage_never_opens`, `signed_garbage_never_panics` |
| Replaying a request or intent | nonce `(kid, id)`, bounded lifetime, single use | `freshness_and_replay`, `intent_admission_stages` |
| Replaying a denied request after the right was granted | the nonce is consumed even on deny | `denied_request_cannot_be_replayed_after_a_grant` |
| Replay after a node restart | anything signed before the start is refused | `replay_after_restart_is_refused` |
| Declaring a lower risk to dodge policy | `E_RISK_MISMATCH`; intents declare no risk at all | `capability_checks` |
| Dangerous values (140 % brightness) | registry and resource envelopes | `capability_checks`, `resource_envelope_is_stricter_than_the_registry` |
| A process impersonating the node on the socket | replies signed with the pinned node key and bound to the request | `client_refuses_an_impostor_node`, `forged_or_misbound_replies_are_rejected` |
| Pre-creating the socket path in `/tmp` | a private 0700 directory, owner check, no symlinks | `private_files_and_sockets` |
| Copying an old state over the current one to un-revoke a token | audit epoch ≤ state epoch | `rollback_truncation_and_deletion_refuse_to_start` |
| Deleting or truncating the audit log | the audit anchor in the state file | `rollback_truncation_and_deletion_refuse_to_start` |
| Editing the audit log | hash chain + signed checkpoints | `tampering_is_detected` |
| Secrets leaking into the log | redaction; tokens are never logged | `redaction`, `delegation_cannot_amplify` |
| Key files readable by others | refused | `private_files_and_sockets` |
| Leaking the Home Assistant token over HTTP | https or loopback only | `plaintext_http_only_to_loopback_or_when_explicitly_allowed` |
| The adapter host crashes or is killed | the node returns `X_DEVICE_UNAVAILABLE`; the Reference Monitor and the audit are unaffected; the host restarts | `crashed_adapter_host_never_reaches_the_monitor` |
| The adapter host hangs | timeout, kill; the node lock is released while waiting | `hung_adapter_host_does_not_stall_the_node` |
| The adapter host returns malicious data | replies are checked as untrusted data; a host that breaks the protocol is killed | `garbage_from_an_adapter_host_is_contained`, `replies_are_untrusted_data` |
| Fake, stale or replayed orders to the adapter host | `ExecOrder` signed with the boundary's order key, for one host instance, ≤ 30 s, single use, for the named device | `gate_admits_only_fresh_single_use_orders_for_this_instance`, `executes_only_admitted_orders_for_the_named_device`, `execution_boundary::*` |
| A second path to an actuator (node code, MCP, a plugin minting its own command) | only `chitala-boundary` holds the order key; executors accept only a `MintedOrder`; CI guard over every crate | `the_node_identity_key_cannot_command_a_device`, `check-execution-boundary.py --self-test` |
| Authority changes between decision and execution | the order carries the authority epoch and is not sent if it changed | `a_revocation_after_the_decision_stops_the_order` |
| An adapter host lies about what it did | receipts bound to the order bytes and the reported state; mismatches are not applied | `a_lying_adapter_host_is_not_believed` |
| A person's request skips Safety | every physical action is cleared, whoever asks | `safety_applies_to_people_too`, `an_ungoverned_device_is_never_actuated` |
| The adapter host reads the node's secrets from the environment | `env_clear`; only the needed variable is granted | `adapter_host_gets_an_empty_environment` |
| Setting the clock back to revive an expired token or request | `TrustedClock` never goes backwards; regressions are audited | `clock_rollback_cannot_revive_an_expired_token` |
| Setting the clock back before the node starts | compared with the last audited event; > 60 s behind → refuse to start | `startup_refuses_a_clock_behind_the_audit` |
| Request floods | per-actor rate limit, IPC connection/timeouts limits, a bounded replay cache | `rate_limit_per_actor` |

## Remaining risks (by priority)

| # | Risk | Mitigation | Milestone (v13 §21) |
|---|---|---|---|
| R1 | The authority and node keys live in files; whoever takes over the node account has both | Credential provider: TPM 2.0 / secure element, non-exportable keys (v5 §8, v7 §14) | v0.5 |
| R2 | Rolling back the state *and* truncating the audit to the old anchor at the same time cannot be detected on one disk | TPM NV monotonic counter, checkpoints pushed to another device or domain, a transparency log | v0.5 |
| R3 | ~~The node trusts the system clock~~ → **addressed** (see the notes below the table) | authenticated time source (NTS/Roughtime), multi-node sync | v0.2 |
| R4 | ~~Adapters run in the node process~~ → **addressed** (see below) | OS-level sandbox (separate user, seccomp/Landlock, network namespace) | v0.2 |
| R5 | No attestation of devices or the node yet (RATS/EAT) | v10 §5 | v0.5 |
| R6 | ~~No Human Decision Center~~ → **partly addressed** (see below); two-key approval exists for two-key resources (spec 16) | two keys by default for `critical`, notifications/UX for humans, conditional approvals (how long the door stays open), telling the AI the outcome after an escalation | v0.3 |
| R7 | Manual enrollment through the config file; no FIDO FDO-style onboarding or transfer of ownership, no ownership epoch | v10 §4 | v0.2 |
| R8 | ~~No coverage-guided fuzzing~~ → **addressed** (see below) | structure-aware fuzzing of CSME after the signature | v0.1 |
| R9 | ~~Supply chain~~ → **mostly addressed** (see below) | bit-for-bit reproducible builds, branch protection/required review on GitHub | v0.1 |
| R10 | Private keys read from files are not explicitly wiped from RAM (intermediate hex strings) | `zeroize` for key buffers | v0.2 |
| R11 | No Personal Vault, IFC, E2EE or federation yet | v7, v13 §2, v12 | after 0.5 |
| R12 | Agent B **hides** that a request came from agent A (drops the `cause`) | In v0.1, B then only uses its own authority: a high-risk action still goes to the owner, who sees that B is asking (`case5_residual_…`). Closing it fully needs mediated A2A, where agent-to-agent messages go through Chitala and carry provenance automatically | MCP/A2A |
| R13 | ~~Physical state is only refreshed by commands and observations~~ → **mostly addressed**: the node observes devices whose state a resource relies on before it gets old (spec 19) | adapter subscriptions (push) instead of polling | v0.3 |

What is already in place for the rows marked addressed:

- **R3 (time):** `TrustedClock` never goes backwards (the max of the system clock and the monotonic clock). Its floor is the last audited event, the node refuses to start when the clock is > 60 s behind the audit, and every regression of the system clock is audited and signed. The node and the adapter host use the same algorithm.
- **R4 (adapter isolation):** adapters run in `chitala-adapter-host`, one process per adapter type, with an empty environment and no private keys. A host executes only `ExecOrder`s signed with the boundary's order key, addressed to its own instance, fresh and single-use, and answers with a receipt the node checks (spec 19). The node treats replies as untrusted data, kills and restarts hung or broken hosts, and releases its lock while waiting (spec 10).
- **R6 (human decisions):** ESCALATE → an approval signed by an owner and bound to the digest, with a deadline. No response = deny (C14), and safety runs again after the answer.
- **R8 (fuzzing):** 11 libFuzzer + ASan targets on every trust boundary (`fuzz/`), checking invariants rather than just "does not panic". CI fuzzes 60 s per target on every PR and 15 minutes per target nightly, and the harnesses also run on stable in CI.
- **R9 (supply chain):** CI runs `fmt → clippy → test (x86_64/ARM64/macOS) → cargo audit → cargo deny`, MSRV, CodeQL, Dependabot and zizmor. The toolchain and actions are pinned (actions by SHA). Releases use `cargo auditable`, a CycloneDX SBOM, SLSA provenance + SBOM attestation, and a `SHA256SUMS` signed with cosign.

## Fuzzing (R8)

| Target | Boundary | Invariant checked |
|---|---|---|
| `csme_envelope` | COSE from an unauthenticated peer | parse/verify never panic |
| `csme_payload` | CBOR after authentication | `decode ∘ encode = id` |
| `token` | capability tokens | only domain-signed tokens verify |
| `intent` | intents from agents | `decode ∘ encode = id`; only enrolled signers open; relay chains are bounded |
| `approval` | human answers | `decode ∘ encode = id`; opens only for the approver it names |
| `node_request` | the whole Reference Monitor pipeline (CSME, intents, approvals) | never ALLOW without a valid signature of an enrolled principal; every reply signed and bound to its request; unauthenticated callers get no details; no single request but the owner's ever unlocks the door |
| `ipc` | request lines (server), reply lines (client) | a reply without the node's signature is never accepted |
| `ha_state` | JSON from Home Assistant | the resulting state is bounded |
| `audit_log` | the audit file during start-up/recovery | verify never panics |
| `exec_order` | orders entering the adapter host | only boundary-signed, fresh, single-use orders for this host instance and the right device execute; the receipt answers the order |
| `host_line` | request lines on the host, reply lines on the node | accepted replies are always bounded and typed |

The seed corpus is generated deterministically from test keys (`cargo run --example gen_corpus` in `fuzz/`), so the fuzzer starts from valid, signed inputs.

## Mandatory testing not done yet (v8 §19)

Automated red-team agents, mixed-version networks, chaos (network loss mid-task, key rotation mid-way), and a compromised cloud while the safety island stays safe. These will come with the simulator (v4 §21).
