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

Assumptions (Hosted): the node machine's OS and the account running the node are not compromised, and whoever holds the owner key is the legitimate owner. What changes when the Trusted Core runs Native is in [Hosted and Native](#hosted-and-native-v02-step-6).

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
| An AI places or lifts a safety hold (a hold also stops protective actions: a held door cannot be locked) | `C11-ai-no-domain-admin` covers `domain.safety_hold` and `domain.safety_release`; neither right can even be delegated to an agent | `an_agent_is_never_given_safety_holds`, `holds_are_a_domain_operation_of_owners` |
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
| The adapter host takes an order, then dies, hangs or answers garbage, and the node calls it "not delivered", so nobody watches what it did (concurrency audit R1) | once the order was written to the host, any failure is `X_EXECUTION_UNKNOWN`: watched by outcome verification, recovery when nobody can establish the result, never sent again; only an order that never reached the host is `X_DEVICE_UNAVAILABLE` | `an_adapter_host_that_takes_an_order_and_dies_leaves_its_fate_unknown`, `hung_adapter_host_does_not_stall_the_node`, `garbage_from_an_adapter_host_is_contained`, `a_stale_order_reaching_a_restarted_host_is_refused` |
| A second node is started on a running domain (an operator's mistake, a supervisor started twice): it appends to the running node's audit log, breaks its hash chain, and the running node refuses to start again (concurrency audit R2) | a node claims its domain (`<state_file>.lock`, an exclusive `flock`) before it starts anything, reads the state or opens the audit log; a second node stops at once, having written nothing; the claim ends with its process, a crash included | `instance::a_second_node_on_a_running_domain_writes_nothing`; `chitala-platform-host::a_claim_is_seen_across_processes_and_ends_with_its_holder`; the storage contract |
| The adapter host hangs | timeout, kill; the node lock is released while waiting | `hung_adapter_host_does_not_stall_the_node` |
| An adapter host never comes up at start (it never answers its init, or its guest is never scheduled), and so keeps the node from starting: a denial of service over Authority and Safety from outside the Trusted Core | the node starts degraded: the adapter is audited unavailable, `hello` says `degraded`, its devices refuse orders (`X_DEVICE_UNAVAILABLE`: not sent) and everything else runs; it is started again only on demand, at most once per second, in a new session (Project Lead, 2026-10-07) | `an_adapter_that_does_not_come_up_leaves_the_node_running_and_degraded`, `the_unavailable_adapters_devices_fail_closed_and_the_rest_runs`, `a_down_adapter_is_not_retried_blindly_and_comes_back_only_in_a_new_session` |
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
| An agent stretches an execution lease (more uses, other parameters, another resource or person, another token, after expiry) | every use checks the lease (window, uses, match, envelope) and runs the whole Authority chain again; refused uses are not counted (spec 21) | `a_use_must_be_what_the_lease_covers`, `an_agent_uses_a_lease_up_to_its_limit_and_each_use_is_an_order` |
| Someone else uses a lease id they learned | a use must be signed by the lease's actor, with the token the lease was granted on | `a_use_must_be_what_the_lease_covers` |
| A crash, a replay or a rolled-back state hands out a lease use twice | each use is counted and persisted before its order exists; using bumps the epoch, so a rollback is refused; a replayed use gets `E_REPLAY` | `a_replayed_use_is_refused_and_not_counted`, `lease_uses_survive_a_restart_and_a_rollback_is_refused` |
| A lease outlives what it stood on (a revocation, a quarantine, the approver's right, a hold) | Authority runs again for every use; an explicit revocation stops an order in flight; a hold refuses a use without spending it | `a_lease_ends_by_revocation_of_itself_its_token_its_agent_or_time`, `a_lease_revoked_while_its_order_is_in_flight_stops_the_order`, `a_hold_refuses_a_use_without_spending_it` |
| Approval fatigue becomes a standing permission | a high-risk lease is approved once, for exact terms (at most 3 uses within 1 hour); critical actions and two-key resources are never leased | `a_high_risk_lease_is_approved_once_for_exactly_its_terms`, `two_key_resources_and_critical_actions_are_never_leased` |
| A device reports an action as done but the world did not change (a jammed bolt, a dropped command) | the resource's witness is observed after every order that may have executed; `diverged` past the registry's `within_ms`; a broken promise of medium risk or more puts the resource in recovery (SAFE-8), and the node runs its declared safe state once (spec 22) | `a_stuck_lock_puts_the_door_in_recovery_and_the_node_locks_it_once`, `the_safe_state_brings_the_door_back_when_the_lock_works_again` |
| An agent keeps retrying an action that does not take | recovery lets nothing but the safe state through, whoever asks; only an owner or admin ends it, never an AI | `a_stuck_lock_…` |
| A compromised adapter host reports false states consistently | outcomes are judged by the resource's witness; an independent witness (another device on another adapter host instance) is recorded as such | `a_witness_on_another_adapter_host_is_independent` |
| Recovery is lifted by a restart or a rolled-back state file | recovery is persisted and bumps the epoch; a rollback past it is refused at start-up | `a_recovery_survives_a_restart_and_a_rollback_is_refused` |
| Recovery becomes a way to act without authority | the safe state is declared by the owners, at most medium risk, granted only by the Authority Engine (`RecoveryGrant`, no public constructor), cleared by Safety, minted by the boundary, run at most once per failed outcome and never chained | `only_a_declared_safe_state_of_at_most_medium_risk_is_granted_to_the_node`, boundary doc tests |
| A plan is used to gain authority, or to leave the world half changed | every step is an intent of its own, judged again in full when it runs; every step is prechecked before anything moves; the next step starts only after a verified outcome (spec 23) | `a_plan_creates_no_authority_each_step_is_judged_when_it_runs`, `a_plan_is_refused_whole_when_any_step_would_be`, `a_step_waits_for_its_outcome_and_a_broken_promise_stops_the_plan` |
| An approval covers more than the approver saw | a step that needs a person pauses the plan and only that step, with its own digest, is asked; an approval of the plan answers nothing | `a_step_that_needs_a_person_pauses_the_plan_and_asks_for_that_step_alone` |
| An agent's plan cannot be stopped | `domain.plan_cancel` (people, never an AI) stops the next step and, through the fence, the order in flight; unanswered steps expire on the server tick | `a_person_cancels_a_plan_and_its_order_in_flight_is_stopped`, `a_rejected_or_unanswered_step_stops_the_plan` |
| A backend's in-between or missing state passes for an outcome (a lock still `unlocking` read as unlocked, `unavailable` read as a state) | the Home Capability Profile leaves out what cannot be known: no `locked` while moving or jammed; `unavailable`/`unknown` and Matter `null` are failed observations; unknown values are refused (spec 24) | `profile::home_assistant_states_are_normalised_without_guessing`, `profile::matter_attributes_are_normalised_without_guessing`, fuzz `ha_state` |
| A command to Home Assistant is sent twice (a retry after a lost answer, a second transport) | one transport and one attempt per order; a call written to the link is never resent; a lost or late answer is indeterminate and outcome verification observes the world; no pooled HTTP connections (spec 25) | `ha_tests::a_command_lost_after_sending_is_indeterminate_and_never_sent_again`, `home_assistant::a_command_lost_after_sending_ends_applied_and_is_never_resent` |
| A stale or reordered Home Assistant state is served as current | states only from the live connection (a new generation per connection, bootstrap after reconnect); later `last_updated` wins; a silent connection is detected by ping | `ha_tests::duplicate_and_out_of_order_events_never_move_a_state_back`, `after_a_restart_the_link_reconnects_and_bootstraps_again`, `a_silent_connection_is_noticed_and_replaced` |
| A command may have executed and nobody can establish what happened (a lock Home Assistant accepted, then lost), and the door stays open to normal actions — or recovery sends a blind second command | `X_EXECUTION_UNKNOWN` is watched like a reported execution; `unconfirmed` at medium risk or more enters recovery; the safe state runs only on evidence (`diverged`), never after `unconfirmed`; a command never delivered is not watched and causes no recovery (spec 22) | `home_assistant::a_command_whose_fate_nobody_can_establish_puts_the_door_in_recovery_without_a_second_command`, `a_command_never_delivered_leads_to_no_recovery`, `a_command_whose_fate_is_unknown_takes_the_outcome_the_witness_shows` |
| A crash (or a rolled-back state file) makes the node forget that a command may have reached a device | write-ahead record before the decision (epoch bump: a rollback past it is refused), order id persisted before the order leaves, restored and watched after a restart; a failed write stops the action (spec 22) | `home_assistant::an_unknown_execution_survives_a_restart`, `crash_after_the_order_is_on_record_but_before_it_is_sent`, `crash_after_the_order_was_sent_but_before_its_outcome_is_on_record`, `node::memory_platform::an_action_whose_record_cannot_be_written_never_executes`, `an_action_on_record_survives_a_restart_and_a_rollback_past_it_is_refused`, the seeded property test |
| One resource bound to two devices takes two interleaving orders | SAFE-7 locks the resource as well as the device | `audit::one_resource_through_two_devices_takes_one_action_at_a_time`, `audit::one_door_two_controllers_many_clients_never_two_orders_at_once` |

## Time of check, time of use (v0.2 step 4)

The node decides under its lock, then releases it while a device works (spec 11). Everything that can change between a decision and its execution, or race with it, has a test that drives the three phases by hand (`crates/chitala-node/tests/adversarial.rs`, `execution_boundary.rs`, `delegation.rs`):

| What changes or races | Outcome | Test |
|---|---|---|
| A safety hold is placed after the decision | the order is not sent; new requests get `SAFE-1-HOLD` | `a_safety_hold_placed_after_the_decision_stops_the_order` |
| A token expires while its order is in flight | the order is not sent | `a_token_that_expires_in_flight_stops_the_order` |
| A token is revoked (id, cascade, floor) while its order is in flight | the order is not sent; an unrelated delegation does not stop it | `a_revocation_stops_an_order_in_flight_but_an_unrelated_change_does_not`, `a_revocation_after_the_decision_stops_the_order` |
| The actor, the represented person, a relaying agent, an approver or the device can no longer act | the order is not sent | `an_approver_demoted_in_flight_stops_the_order` |
| Authority or safety changes while a human decides | the answer re-runs Authority and Safety | `a_revocation_while_a_human_decides_voids_the_approval`, `safety_is_checked_again_when_the_human_answers` |
| Two conflicting actions on one device at once | the second is refused (`SAFE-7-BUSY`); other devices are unaffected; the device is free again when the order is answered or expires | `conflicting_actions_on_one_device_do_not_interleave`, `a_device_is_free_again_when_its_order_is_refused_or_expires` |
| The same intent submitted twice at once | it runs once (`E_REPLAY`) | `the_same_intent_submitted_twice_at_once_runs_once` |
| An approval replayed, or reused for the same intent | `E_REPLAY` | `an_approval_cannot_be_replayed` |
| Parameters changed after the approval | the approval answers one digest only | `parameters_cannot_change_after_the_decision` |
| Stale device state | refused (`SAFE-3-STATE`) until the node has looked again | `stale_state_is_refreshed_never_trusted` |
| A device that drops off, its last state still recent (a lock reported `unavailable`) | its last known state is no evidence: refused (`SAFE-3-STATE`) until a good observation | `a_lock_that_cannot_be_observed_is_not_known_to_be_locked`, `a_lock_home_assistant_reports_unavailable_is_not_known_to_be_locked` |
| An earlier reading, fetched outside the node lock and folded after a newer state or after a loss of observability, overwrites the twin: a door unlocked shows locked and fresh, or a lost device looks observable again (concurrency audit R3/R3b) | every answer is stamped as it arrives, through one lane per device; the twin applies only answers later than its latest, good or failed; a rejected answer is no outcome evidence | `outcome::an_earlier_reading_folded_late_never_overwrites_a_newer_state`, `an_earlier_good_reading_folded_late_never_hides_a_lost_device`, `an_earlier_failure_folded_late_never_hides_a_newer_reading`; `node::tests::answers_about_one_device_are_stamped_in_the_order_they_came` |
| A gateway re-emits a dead device's cached value with a new timestamp (Home Assistant after a Matter lock's optimistic `locking`), and an outcome is judged by it (step ③A, F9b) | an observation is evidence only if its adapter confirmed it current, by reaching the device after the state was produced; the Home Assistant adapter reads a Matter device itself through the Matter server (F10); otherwise `unconfirmed` and recovery (spec 22, spec 25). Other integrations keep Home Assistant's word: a lower assurance | `home_assistant::a_dead_matter_lock_s_cached_state_with_a_new_timestamp_is_no_evidence`, `outcome::only_a_state_confirmed_current_is_evidence_of_an_order`, `ha_tests::a_matter_device_is_read_itself_for_evidence` |
| Home Assistant's state of a Matter device lags the device (an interview's result overtakes the update it found, under backpressure), and an outcome is judged by it: `not_applied` with the door open (step ③A, F10) | Home Assistant's state of a Matter device is never evidence; the adapter reads the device through the Matter server's `read_attribute`: read only, allowlisted attributes, loopback only (its API has no authentication) | `home_assistant::a_matter_lock_s_own_state_beats_home_assistant_s_stale_one`; `ha_tests::a_matter_device_is_read_itself_for_evidence`, `the_matter_server_is_reached_on_this_machine_only_and_only_read` |
| The direct Matter adapter's controller is abused: a caller sends it an arbitrary Matter command, or two controllers share Chitala's fabric (v0.3 step ⑤) | the matter.js sidecar speaks a typed, allowlisted protocol on stdio only: profile operations, every path checked against its own copy of the profile and the endpoint's device type, its own table of commands; serve mode cannot commission; the fabric's storage is private and claimed by one sidecar at a time. A compromised sidecar holds the fabric's keys: a deployment boundary (spec 27) | `sidecars/matter-js/test/protocol.test.ts`; `matter_js_tests::the_sidecar_must_serve_this_protocol_on_this_profile`, `requests_are_typed_profile_requests`; the lab run of spec 27 |
| A device's subscription goes quiet before its controller notices (as long as an hour for a sleepy device), and Safety relies on its last values as fresh (v0.3 step ⑥, F12) | past the interval the device agreed to, and a margin, the direct Matter adapter treats the subscription's last values as no state, as an unavailable device's (F6); outcomes rest on reads anyway | `adversarial_home::a_quiet_subscription_is_no_state_once_past_its_interval`, `direct_matter::tests::a_subscription_quiet_past_its_interval_is_no_state` |
| A confirmed state outlives a newer one nobody can confirm: the lock confirmed locked, then unlocked, reported and died, and the unlock ends `not_applied` with no recovery (F11) | outcome evidence belongs to the answer that gave it; a newer answer that is no evidence and states another value for a promised key takes it away; `unconfirmed` and recovery | `home_assistant::a_confirmed_state_superseded_by_one_nobody_can_confirm_is_no_longer_evidence`, `outcome::a_divergence_superseded_by_an_unconfirmed_reading_is_not_known` |
| The clock set back | an expired question stays expired; an expired token stays expired | `a_clock_set_back_cannot_reopen_an_expired_question`, `clock_rollback_cannot_revive_an_expired_token` |
| A policy or ownership change | configuration: it takes a restart, which drops every waiting question and every order; old intents cannot be replayed into the new node | `an_ownership_change_needs_a_restart_that_drops_waiting_questions`, `orders_die_with_the_node_that_minted_them` |
| A restart in the middle of a transaction | no order survives it, nothing signed before it is accepted after it | `orders_die_with_the_node_that_minted_them`, `a_stale_order_reaching_a_restarted_host_is_refused`, `replay_after_restart_is_refused` |
| A compromised adapter host | forged receipts are not believed; replies are untrusted data; a hung or crashed host is stopped | `a_lying_adapter_host_is_not_believed`, `garbage_from_an_adapter_host_is_contained`, `hung_adapter_host_does_not_stall_the_node` |

Three of these were real gaps closed in this step: a safety hold and token expiry were not re-checked for orders in flight, and two actions could be cleared on the same state of one device and interleave. Disabling any of the three fixes makes its tests fail.

## Hosted and Native (v0.2 step 6)

Chitala runs in two modes:

- **Hosted**: the node is a service on Linux or macOS, using the hosted backend of the PAL (spec 18).
- **Native**: the same Trusted Core boots as a unikernel with no host operating system (spec 20). Today it is a lab spike on QEMU and Arm boards.

The decision logic is the same code in both modes. The core purity guard keeps it free of OS calls, and the required CI job *native* boots it on every pull request and checks that it makes the same 13 decisions. What changes is what those decisions rest on: where keys live, which clock and which randomness they use, whether the evidence survives, and what separates the core from the adapters.

For each of these, this section states what each mode trusts, what Native lacks today, and what must exist before a Native node leaves the lab.

### What each mode trusts

| Layer | Hosted | Native (spike) |
|---|---|---|
| Kernel and OS | the Linux or macOS kernel, libc, the init system and every process running as root: tens of millions of lines | the Hermit kernel (about 37,000 lines of Rust, 3,400 of them for aarch64) with Chitala's entropy patch. No shell, no other processes; no file system or network stack is compiled in |
| Runtime | Rust `std` for the host, stable toolchain | Rust `std` built for Hermit from source (`-Zbuild-std`, nightly toolchain) |
| Boot chain | the OS's boot chain. The node binary is a signed release (cosign signature, SLSA provenance) | the Hermit loader, pinned by SHA-256 when downloaded, and whatever image is on the boot medium. There is no verified boot |
| Core vs adapters | a process boundary: adapter hosts run as separate processes with an empty environment and no keys | one address space. Only the logical isolation of spec 19 separates them |
| Keys | files, owner-only (`0600` in a `0700` directory) | RAM. Generated at boot, gone at power-off |
| Evidence (audit, state) | files: a hash-chained, signed audit log with an anti-rollback anchor (spec 09) | RAM. Lost at power-off |
| Time | the system clock, floored at the last audited event | the board's real-time clock, floored at the image's commit time minus one day |
| Randomness | the OS CSPRNG | an admitted hardware entropy provider (spec 20; `arm-rndr`, the CPU's `RNDR`, today), with no start without one or when its health test fails. The kernel's own pool is also seeded from `RNDR` |
| Who can reach the node | local processes, through a Unix socket in a private directory, signed in both directions | nothing outside the image: the clients run inside it |
| Underneath | hardware or a hypervisor | the same; in a VM, the hypervisor sees all memory |

### What stays the same

Everything the Trusted Core decides is identical in both modes:

- signatures, freshness and replay protection;
- the capability registry and its envelopes;
- tokens: proof of possession, binding, revocation floors;
- policy and the Constitution, the Authority Engine and Safety;
- the single execution path, with single-use orders and receipts;
- the audit hash chain.

Three tests establish it:

- the core purity guard;
- the memory-platform test, which runs the whole node with no files, sockets or processes;
- the required CI job *native*, which runs the unchanged node as a unikernel.

Chitala's own code has no `unsafe` in either mode. The `unsafe` code it relies on is in `std` and the dependencies, plus the OS and libc (Hosted) or the Hermit kernel (Native).

### Threats that change with the mode

Each row says how Hosted handles the threat, where Native stands today, and what Native needs before it leaves the lab.

| # | Threat | Hosted | Native today | Before Native leaves the lab |
|---|---|---|---|---|
| N1 | **The Hermit kernel is compromised** (a bug, or a malicious change upstream) | the OS kernel is trusted (assumption above); the process boundary and file permissions sit between the node and other code | the kernel and Chitala share one address space and one privilege level, so a kernel compromise is a full compromise: keys, decisions and audit. In its favour, the kernel is small, memory-safe Rust, built without a network stack, PCI or a file system, and pinned to one commit with one reviewed patch | follow Hermit's advisories; pin releases, not git tags; a reproducible image; in the long term a kernel whose isolation can be relied on (formally verified seL4, a hypervisor or an own kernel; Native ADR, D4) |
| N2 | **No memory isolation**: memory corruption anywhere in the image | separate processes for the node and each adapter host; the OS isolates memory | one address space. Chitala's code has no `unsafe`, but `std`, the kernel and dependencies do, and a single memory-safety bug anywhere reaches keys and state | keep `unsafe` out of Chitala and audit the `unsafe` in the image; isolation boundaries from the platform (N1, ADR) |
| N3 | **A compromised adapter or driver** | separate process, empty environment, no keys; executes only boundary-signed, single-use orders for its own instance; receipts are checked (R4) | spec 19's logical guarantees hold (orders, sessions, receipts), but memory isolation does not (N2): an adapter bug could read keys or forge state inside the process | only built-in, reviewed adapters on Native (today: virtual devices); memory isolation for third-party adapters (ADR) |
| N4 | **The PAL-native backend is compromised or faulty** (time, entropy, storage, IPC or components answer wrongly) | the hosted backend (`chitala-platform-host`) is in the trusted base too, and runs the same contract tests | the backend is small (about 150 lines), has no `unsafe`, and has code owners (`native/`). It runs the PAL contract at every boot before any key exists, which catches faults, not malice. The core also defends itself: the trusted clock never goes backwards, signatures and the audit chain verify whatever storage returns, and orders verify whatever IPC carries | keep the backend minimal and reviewed; a hardware key store and storage with integrity (N7, N8) remove the most sensitive parts from it |
| N5 | **Entropy fails**: no RNG, `RNDR` failing at run time, a weak or backdoored RNG | the OS CSPRNG, which mixes several sources | reads `RNDR` through a reviewed wrapper and refuses to run without FEAT_RNG (exit 3); a read that keeps failing makes the node panic rather than continue. The kernel's pool is seeded from `RNDRSS` (carried patch; upstream hermit-os/kernel#2528, reported in #2736). Without a source Hermit falls back to a weak generator, which is why Chitala never takes keys from the kernel. A backdoored hardware RNG cannot be detected from inside. On QEMU, `RNDR` comes from the host, so the host is trusted | mix several sources (`RNDR` + virtio-rng + a hardware TRNG) so that one bad source is not fatal; an admitted source on other architectures (`RDSEED`) |
| N6 | **The clock is set back** to revive expired tokens, approvals or holds (a dead RTC battery, a hostile hypervisor, physical access) | refuses to start when the clock is more than 60 s behind the last audited event; every regression is audited | refuses to start when the board clock is before the image's floor (its commit time minus one day): exit 4. **Residual:** a rewind to a moment after the floor is accepted (a boot with the clock a few hours back runs), and an older image has an older floor (N12) | a persisted, monotonic floor (the audit anchor, N8), an authenticated time source (Roughtime, NTS), or both |
| N7 | **Key persistence and theft** | keys in files the node's account can read (R1); they survive restarts | keys live in RAM and are generated at every boot, so the domain's identity changes at each boot. This is fine for a lab and impossible for a real home, where people's keys are enrolled once. A memory disclosure reveals them (N2) | a hardware key store with non-exportable keys (secure element, TrustZone/OP-TEE, TPM; decision D3). Keys must **never** be persisted in plain flash as a shortcut |
| N8 | **A crash, reboot or power loss** | state and audit are on disk, and after a restart the node checks state against the audit. A lost receipt leaves the device's state unknown, so `SAFE-3-STATE` refuses risky actions until it is observed again. **Found by this analysis and fixed:** safety holds were not part of the persisted state, so a restart silently lifted every hold. They are now persisted, each change bumps the epoch, and a state file rolled back past a hold is refused (`safety_holds_survive_a_restart_and_a_rollback_is_refused`) | everything in RAM is lost: the audit, and also **safety holds, quarantines and revocations made during the boot**. A hold an electrician placed disappears with a power cut. A lost receipt is handled as on Hosted | persistent, integrity-protected storage (virtio-blk, flash) with the audit anchor. Until then, a Native node that restarts must come back restrictive: holds by default on resources whose state is unknown |
| N9 | **State and audit rolled back together** | possible on one disk (R2) | nothing persists, so nothing can be rolled back, but nothing is kept either (N8) | a hardware monotonic counter (TPM NV, eMMC RPMB), once N8 exists |
| N10 | **A malicious or modified loader** | the OS boot chain (Secure Boot where enabled) | `run.sh` checks the Hermit loader against its pinned SHA-256 when it downloads it. On a board, whatever is on the boot medium runs | the loader inside a verified boot chain (N11); a measured boot that records it |
| N11 | **A malicious or modified image; boot integrity** | the operator verifies the release (cosign signature, SLSA provenance) and the OS protects the installed binary | the board boots whatever image is on its medium. CI builds the image from pinned sources, but nothing checks it at boot | measured or verified boot (signed images checked by firmware), attestation of what booted (R5) |
| N12 | **The image is rolled back** to an older version with a known flaw | an operator can install an older release; package managers usually refuse a downgrade | nothing prevents booting an older image. An older image also carries an older clock floor, which widens N6 | an anti-rollback version in verified boot (monotonic counter or fuses); the image version in attestation |
| N13 | **DMA and device attacks** (a malicious device, or a compromised virtio backend in the hypervisor) | the OS drives devices, with an IOMMU where the platform has one | the spike drives no device that can do DMA (no PCI); only the UART, the interrupt controller and the timer. In the N1 partitioning spike, a guest's channel is a virtio console that its own VMM emulates, and that VMM maps the guest's memory anyway. Nothing in the spike configures an IOMMU (SMMU) | before the first DMA device (virtio-blk, virtio-net, USB): an SMMU configuration or bounce buffers limited to device memory, and an allowlist of devices |
| N14 | **Attackers on the same machine or network** | other local users and processes reach only the private socket, and every request and reply is signed | no other processes, no network stack, no file system, no external interface: the smallest surface Chitala has had | when a transport is added: an authenticated channel (messages are already signed end to end), connection limits, and fuzzing of the new parser |
| N15 | **Supply chain of the platform** | stable pinned toolchain; `cargo audit` and `cargo deny` on the workspace lock | adds a nightly toolchain, `std` built from source, Hermit from a git tag (commit pinned in `native/Cargo.lock`), the kernel's own dependency tree, and Chitala's patch. CI runs `cargo audit --deny warnings` on `native/Cargo.lock` (246 crates, clean). The kernel's lock reports 7 advisories (`rustls`, `rustls-webpki`, `tar`) and several warnings, all in build tooling (xtask, build scripts), except two warnings in the image itself: `event-listener` (unsound) and `generic_once_cell` (yanked). CI lists them on every run | move the pin to a release that contains #2528 and re-audit; a reproducible image; `cargo deny` for `native/` with an exception for the Hermit git source |
| N16 | **Debug channels** | — | QEMU semihosting is on, so that the exit code reaches QEMU; through it, guest code can open host files. The serial console prints the kernel log and the decisions, never keys or tokens | production images without the `semihosting` feature and without `-semihosting`; a policy for the console |
| N17 | **A hang or resource exhaustion** | rate limits; the OS restarts the node; adapter hosts are restarted with a rate limit | the same rate limits, but one core and one address space: a component that spins or leaks memory stalls the whole node | a hardware watchdog that leads to a safe state; devices that fail safe on their own (C5) |
| N18 | **The machine underneath** (hypervisor, side channels, fault injection, cold boot) | out of scope (assumption above) | the same assumption. In a VM the hypervisor sees all memory | confidential computing (Arm CCA realms, AMD SEV) on untrusted hosts; physical hardening on boards |

Tests: the CI job *native* boots the image and checks:

- the 13 decisions and the audit log;
- the refusal without a hardware RNG (exit 3, N5);
- the absence of the kernel's entropy fallback (N5);
- the refusal with the board clock set to 2020 (exit 4, N6);
- `cargo audit` on `native/Cargo.lock` (N15).

### Verdict

- **Decisions:** a Native node is as trustworthy as a hosted one, because it runs the same code and CI checks it on every pull request.
- **Where Native is already better:**
  - attack surface: no OS services, no shell, no network, no file system, no DMA devices (N13, N14);
  - size of what must be trusted: tens of thousands of lines of Rust instead of millions;
  - memory-safe code from the kernel up.
- **Where Native is still weaker:**
  - isolation, both from the kernel and between the core and its adapters (N1–N3);
  - keeping keys (N7) and evidence (N8, N9);
  - surviving a reboot without losing holds and quarantines (N8);
  - trusting time across reboots (N6);
  - proving what booted, and that it is not an older image (N10–N12).

Native therefore stays a lab target. Before a Native node controls real devices, it needs:

- N6: a persisted clock floor or authenticated time;
- N7: hardware keys;
- N8: persistent audit and state, coming back restrictive after a restart;
- N3: built-in adapters only, until memory isolation exists;
- N11, N12: verified boot with anti-rollback;
- N13: an IOMMU before the first DMA device;
- N16: a production profile without debug channels.

These gates feed the Native Architecture ADR (D4), which compares Hermit, seL4, a hypervisor and an own Chitala kernel against them, and the v0.5 items R1, R2 and R5.

## Remaining risks (by priority)

| # | Risk | Mitigation | Milestone (v13 §21) |
|---|---|---|---|
| R1 | The authority and node keys live in files; whoever takes over the node account has both | Credential provider: TPM 2.0 / secure element, non-exportable keys (v5 §8, v7 §14) | v0.5 |
| R2 | Rolling back the state *and* truncating the audit to the old anchor at the same time cannot be detected on one disk | TPM NV monotonic counter, checkpoints pushed to another device or domain, a transparency log | v0.5 |
| R3 | ~~The node trusts the system clock~~ → **addressed** (see the notes below the table) | authenticated time source (NTS/Roughtime), multi-node sync | v0.2 |
| R4 | ~~Adapters run in the node process~~ → **addressed** (see below) | OS-level sandbox (separate user, seccomp/Landlock, network namespace) | v0.2 |
| R5 | No attestation of devices or the node yet (RATS/EAT) | v10 §5 | v0.5 |
| R6 | ~~No Human Decision Center~~ → **partly addressed** (see below); two-key approval exists for two-key resources (spec 16) | two keys by default for `critical`, notifications/UX for humans, conditional approvals beyond execution leases (which already cover a number of uses within a window, spec 21), telling the AI the outcome after an escalation | v0.3 |
| R7 | Manual enrollment through the config file; no FIDO FDO-style onboarding or transfer of ownership, no ownership epoch | v10 §4 | v0.2 |
| R8 | ~~No coverage-guided fuzzing~~ → **addressed** (see below) | structure-aware fuzzing of CSME after the signature | v0.1 |
| R9 | ~~Supply chain~~ → **mostly addressed** (see below) | bit-for-bit reproducible builds, branch protection/required review on GitHub | v0.1 |
| R10 | Private keys read from files are not explicitly wiped from RAM (intermediate hex strings) | `zeroize` for key buffers | v0.2 |
| R11 | No Personal Vault, IFC, E2EE or federation yet | v7, v13 §2, v12 | after 0.5 |
| R12 | Agent B **hides** that a request came from agent A (drops the `cause`) | In v0.1, B then only uses its own authority: a high-risk action still goes to the owner, who sees that B is asking (`case5_residual_…`). Closing it fully needs mediated A2A, where agent-to-agent messages go through Chitala and carry provenance automatically | MCP/A2A |
| R13 | ~~Physical state is only refreshed by commands and observations~~ → **mostly addressed**: the node observes devices whose state a resource relies on before it gets old (spec 19) | adapter subscriptions (push) instead of polling | v0.3 |
| R14 | Outcomes are verified by the resource's witness, which by default is the device itself: a host that lies consistently about its own device is not caught, and whoever can make a witness lie can push a resource into recovery (a denial of service that fails safe) | independent witnesses (sensors on another adapter host), several witnesses with a quorum, attested devices (R5) | v0.3 |

What is already in place for the rows marked addressed:

- **R3 (time):** `TrustedClock` never goes backwards (the max of the system clock and the monotonic clock). Its floor is the last audited event, the node refuses to start when the clock is > 60 s behind the audit, and every regression of the system clock is audited and signed. The node and the adapter host use the same algorithm. A Native node has no audit across boots yet, so its image carries a floor instead (N6).
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
