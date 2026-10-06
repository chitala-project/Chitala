# 28 — Adversarial Home suite

**Status:** v0.3 step ⑥, software lane (Project Lead, 2026-10-06). Every fault class has its tests on every path where it applies. The fixed regression suite for R1/R2/R3/F11 follows. A subset reruns on physical devices with step ③B.

Step ⑥ puts the whole chain through what a real home does to it: backends that crash or hang, devices that drop off, jam or go quiet, reports that come late, twice or malformed, and Chitala itself restarting mid-order. It is all done with simulators and fault injection, so nothing here needs hardware.

Whatever happens, the invariants of specs 22 and 26 hold:

- **once:** a command reaches the device at most once; Chitala never resends it, and neither does a backend;
- **nothing made up:** what is not a state (unavailable, malformed, too old, unconfirmed) never becomes one;
- **unknown is said:** a command whose fate cannot be told is unknown (`X_EXECUTION_UNKNOWN`), and outcome verification decides by what the device shows after the order;
- **recovery, never blind:** what Chitala cannot establish ends `unconfirmed`, and puts a resource of medium risk or more in recovery. Its safe state runs only on evidence (spec 22), and only a person ends the recovery.

## The fake sidecar

The direct Matter path is tested through the real `MatterJsBackend` and the real sidecar protocol (spec 27), on a **fake sidecar**: the protocol served in process over pipes, on a fake backend's devices (`direct_matter::fake_sidecar`). It can:
- die before or after the device acts;
- hang;
- send lines that are not JSON, or too long.

The fake backend's devices can:
- lose answers;
- jam;
- go silent;
- go quiet: no reports, while still answering reads.

`MatterRig::over_sidecar` puts the whole conformance suite (spec 26) through that path too.

## The fault classes

The Project Lead's list, in order of priority. The paths are:
- **mock**: virtual devices;
- **HA**: the Home Assistant adapter, with the Matter evidence provider;
- **Matter**: the direct Matter adapter through the matter.js backend.

| # | Fault | Invariant | Tests |
|---|---|---|---|
| 1 | **A backend process crashes or hangs mid-command.** Matter: the sidecar. All paths: the adapter host | once; unknown is said; a hung sidecar is replaced | Matter: `adversarial_home::a_sidecar_that_dies_before_the_device_leaves_the_order_unknown_and_never_resent`, `…dies_after_the_device_acted…`, `a_hung_sidecar_is_replaced_and_its_command_is_never_resent`. Adapter host (R1): `node::an_adapter_host_that_takes_an_order_and_dies_leaves_its_fate_unknown`, `hung_adapter_host_does_not_stall_the_node` |
| 2 | **A subscription goes stale or reports late** | nothing made up: a subscription silent past its interval is no state (F12); a late report never overwrites a newer one (R3) | Matter: `adversarial_home::a_quiet_subscription_is_no_state_once_past_its_interval`, `direct_matter::tests::a_subscription_quiet_past_its_interval_is_no_state`. HA: `home_assistant::a_cached_state_from_before_the_order_never_settles_an_unknown_execution`, `a_dead_matter_lock_s_cached_state_with_a_new_timestamp_is_no_evidence`. Late: `outcome::an_earlier_reading_folded_late_never_overwrites_a_newer_state` and its siblings |
| 3 | **A device goes offline and rejoins** | nothing made up; recovery, never blind; a rejoined device stays in recovery until a person ends it | every path: conformance N4, N5, K7 (spec 26). Matter: `adversarial_home::a_lock_that_drops_off_and_rejoins_stays_in_recovery_until_a_person_ends_it`. HA: `home_assistant::a_lock_home_assistant_reports_unavailable_is_not_known_to_be_locked` (F6) |
| 4 | **Home Assistant restarts; the network partitions** | once; nothing made up | `home_assistant::a_broken_home_assistant_makes_nothing_up`, `a_command_lost_after_sending_ends_applied_and_is_never_resent`, the link's reconnection tests (spec 25). Partitions through the whole chain: `adversarial_home::cut_off_from_home_assistant_s_websocket_a_command_goes_once_by_rest`, `cut_off_from_the_matter_server_a_matter_lock_s_outcome_is_unconfirmed` |
| 5 | **Chitala restarts before or after sending** | once; an order minted before a crash is never sent after it; an unknown execution survives a restart | HA: `home_assistant::crash_after_the_order_is_on_record_but_before_it_is_sent`, `crash_after_the_order_was_sent_but_before_its_outcome_is_on_record`, `an_unknown_execution_survives_a_restart`, `random_faults_crashes_and_restarts_keep_every_invariant`. `node::replay_after_restart_is_refused`. Matter: `adversarial_home::a_crash_before_the_lock_is_sent_ends_on_the_lock_s_own_read` (`not_applied`: the lock's read after the restart is evidence, where Home Assistant has none and ends `unconfirmed`), `a_crash_after_the_lock_was_sent_ends_applied_and_never_resent` |
| 6 | **Reports come twice, or late** | idempotent; ordered by arrival (R3) | the R3 tests (`outcome`, `node::tests`). Matter: `adversarial_home::a_late_or_repeated_report_changes_no_outcome` (a subscription's values are no evidence; the lock's read decides) |
| 7 | **The wrong witness** | an observation of one device never settles another's outcome; an order cannot be redirected | `execution_boundary::an_order_cannot_be_redirected_to_another_device`, `outcome::a_witness_on_another_adapter_host_is_independent`. Matter: the sidecar checks the endpoint's device type; the backend keeps a target's own values only (`matter_js::tests::the_subscription_follows_the_sidecar_s_events`); through the whole chain: `adversarial_home::reports_for_another_device_never_reach_this_door` |
| 8 | **A state that is forged or malformed** | nothing made up | Matter: `adversarial_home::a_malformed_state_makes_nothing_up`, `malformed_lines_from_the_sidecar_are_ignored_or_end_it`. `execution_boundary::a_lying_adapter_host_is_not_believed`. HA: `unavailable`/`unknown` are not states (spec 24). A compromised sidecar can forge its device's state: that is a deployment trust boundary, not something an adapter can detect (spec 27) |
| 9 | **The backend's status is ambiguous** | unknown is said; recovery, never blind | Matter: `adversarial_home::a_lock_that_jams_puts_the_door_in_recovery_without_a_second_command`, `direct_matter::tests::every_answer_says_what_it_says_about_the_order`. HA: `home_assistant_error` is unknown (spec 25), `home_assistant::a_jammed_lock_puts_the_door_in_recovery_with_one_safe_state_attempt` |
| 10 | **The Home Assistant and direct Matter paths at once** | each order once; no cross-talk between paths or devices | `adversarial_home::the_home_assistant_and_matter_paths_at_once_each_order_once_no_cross_talk`: two doors, one on each path, ten rounds of orders run at the same time in two threads |

Afterwards, R1, R2, R3/R3b and F11 are closed into a fixed regression suite that runs on every path: crash and restart, observation ordering, and outcome persistence, with seeded stress.

## Findings

| Id | Finding | Severity | Status |
|---|---|---|---|
| F12 | **A quiet subscription stayed a state.** On the direct Matter path, a device whose subscription goes silent is noticed by the controller only after the subscription's interval and about 40 s, or longer, since a sleepy device may agree to an interval of up to an hour. Until then a plain observation kept returning the last values. Safety judges a state's age by when the node observed it, so the stale values looked fresh. Commands were still safe (a read just before every invoke), and outcomes were too (evidence is a read), but Safety's rules could rest on a state that was no longer true | medium | **fixed** in the adapter: the sidecar reports the interval the device agreed to (`max_interval_ms`); past it, and a margin (a quarter of it, at least 2 s), the subscription's last values are no state (`Unavailable`), as an unavailable device's are (F6). The Trusted Core does not change. Open for the Project Lead: whether Safety should judge a state's age by its source rather than by its observation, for every adapter (on Home Assistant, an unchanged state's source age grows without bound) |

Found by its test, not by review: the quiet-subscription test first expected Safety to refuse a state too old, and it did not.

## How the paths compare

- **Matter, by its own reads:** a node's periodic observations of a device it relies on are reads for evidence. So junk on the subscription alone, while the device answers reads with a real state, does not make the door unobservable: the device's own answer wins. Only a device whose answers are junk is no state (fault 8).
- **When a sidecar dies,** the backend starts another on its next call, at most every 5 s. One that hangs is stopped once a call to it times out. Either way, nothing it was sent is sent again.

## Part 2

The second part added no production code: only tests, and what the tests needed.
- the shared node harness restarts a node on its persisted state, and holds several doors on several paths;
- a rig's lock can be named;
- the fake Matter server can be cut off.

The tests found nothing new. Two results are worth keeping:
- **The direct path settles more than Home Assistant does.** After a crash before a send, the lock's own read is evidence. Through Home Assistant no state after the order exists, so the same case ends `unconfirmed`.
- **The rate limit applies to test runs too.** `SAFE-6-RATE` refused the fourth move of a door within a minute, as it should.

## Mutations

Six faults were put back into the code this part added, on purpose, and the suite caught every one:

- a quiet subscription still a state (F12);
- no margin past the interval;
- the agreed interval not taken from the sidecar;
- a hung sidecar kept;
- a line too long read whole;
- a dead sidecar never started again.
