# 22 — Outcome Verification and Recovery v0.1

Sources: v0.2 roadmap step 9; Blueprint v19 §5 (*outcome verification: command success must be confirmed by state or telemetry*) and §8 (a capability declares its *Outcome*); v20 §11 (a device action has a postcondition and a recovery: *stop, safe state, compensate, escalate*) and the reported/desired/observed twin; the Project Lead's decision of 2026-10-04 (the node may run a declared safe state by itself, once). Code: `chitala-model` (outcomes in the registry), `chitala-resource` (safe states), `chitala-safety` (`SAFE-8-RECOVERY`), `chitala-policy::authority` (`RecoveryGrant`), `chitala-boundary` (`Authority::Recovery`), `chitala-node` (`outcomes.rs`).

## Why

An execution receipt (spec 19) proves which order the adapter host answered, and binds the state it reported. It does not prove that the world changed. Some examples:

- a bolt jams while the motor runs;
- an actuator is slow;
- a device drops a command;
- a compromised adapter host reports a false state consistently.

Until v0.2 step 9 the node believed the report. Now an action is finished only when the resource's **witness** reports its outcome.

> An action promises an outcome. Chitala checks the promise against the world. When the promise is broken, the resource takes nothing but its safe state until a person has looked at it.

## Outcomes in the registry

Every device action in the registry (spec 04) declares the state it leads to, and how long the physical world may take to get there:

```json
"outcome": { "state": { "target_celsius": { "param": "celsius" } }, "within_ms": 2000 }
```

A robot's motion also promises a pose (spec 30): `"pose": {"motion": {...}, "tolerance_mm": …, "tolerance_mdeg": …}`. The node computes where the motion must end from the pose the robot was at when the order was minted, adds the motion's own time to `within_ms`, and verifies the outcome only when the robot reports a pose within the tolerance.

| Capability | Expected state | `within_ms` |
|---|---|---:|
| `light.turn_on` / `light.turn_off` | `on: true` / `on: false` | 2 000 |
| `light.set_brightness` | `brightness_pct: <brightness_pct>` | 2 000 |
| `switch.turn_on` / `switch.turn_off` | `on: true` / `on: false` | 2 000 |
| `climate.set_target_temperature` | `target_celsius: <celsius>` | 2 000 |
| `lock.lock` / `lock.unlock` | `locked: true` / `locked: false` | 5 000 |

The registry is refused at load when:

- a device action has no outcome, or anything else has one;
- an outcome expects no keys, or more than 16;
- `within_ms` is outside [100, 60 000];
- a `pose` (spec 30) refers to anything but required integer parameters, or has a zero tolerance;
- a `{"param": …}` names a parameter the action does not require.

The twin's desired state (spec 10) is the expected outcome; the node no longer has its own table.

## The witness

The witness of a resource is the device its state reference names (spec 14). Safety already trusts it for the resource's state, so it decides outcomes too.

A witness is **independent** when it is another device, served by **another adapter host instance** than the device that executed. A compromised host can lie about its own work consistently, but it does not control another host. In the sample home every resource is its own witness, so `independent` is `false`. A separate sensor bound as the state reference makes it `true`.

## Verification

1. **Observe (phase 2).** After an order that may have executed, the node observes the witness once, still outside the node lock. Executions fall into three classes:

   | Class | Results | Watched |
   |---|---|---|
   | **reported** | a success, with a receipt that answers the order | yes |
   | **unknown** — it may have executed | `X_EXECUTION_UNKNOWN` (the command was delivered, then the connection broke, no result came in time, or the backend failed after it started; or the adapter host took the order, then died, hung or broke the protocol); `X_RECEIPT_INVALID` (the host answered, but not for this order) | yes |
   | **certainly not executed** | `X_ORDER_REJECTED` (the gate or the authority fence); `X_DEVICE_REFUSED`; `X_DEVICE_UNAVAILABLE` (the command was not delivered: it never reached the adapter host, or the host could not reach the device); `X_ADAPTER` (the adapter could not map or run it) | no: nothing happened, and transport failure alone never leads to recovery |

   This distinction rests on what the adapter knows about delivery, not on the word of an outcome (Project Lead, 2026-10-05). The adapter never resends a command whose fate is unknown (spec 25).
2. **Judge (phase 3).** The observation goes into the twin. It is evidence only if it **postdates the order** and its adapter **confirmed it current** (below); the unvouched report of a failed receipt never is. An outcome is met when the witness reports every expected key with the expected value.

### Evidence must postdate the order

Reading a state after a command is not enough: the state itself must have been produced after the order could act. A backend can answer now with a state minutes old. Home Assistant serves a dead Matter device's last state for minutes (finding F9 of v0.3 step ③A; the Project Lead's invariant, 2026-10-05).

- **Every observation says how old it is.** An adapter answers a state with its `age_ms`, how long before the answer the state's source produced it:
  - 0 for a device read now;
  - for a state a backend keeps, the time since the backend last heard it from the device;
  - none at all when nobody can tell.

  The node takes `source_at = received_at − age_ms`. It measures `received_at` itself, when the answer arrives, and keeps `source_at` in the twin.
- **Each order has a send time.** It is set when the order is minted (and persisted with the action's record), then refined to when the order leaves for the adapter.
- **Only a post-order observation settles an outcome.** An observation of the witness counts for an outcome only if `source_at ≥` the order's send time, and it is confirmed current (next section). Every other observation is history: it updates the twin and settles nothing, however late it was read.
- **No evidence by the deadline means `unconfirmed`, never `not_applied`.** At medium risk or more that enters recovery, without a safe state.
- **The cost of this rule:** a command that changes nothing (locking a locked door) leads to no new report, and so to no evidence. Through a backend that does not report again, its outcome is `unconfirmed`. A device read directly (the virtual devices, and later the direct Matter adapter) always gives fresh evidence.

### Evidence must be confirmed current

A gateway's timestamp is not physical freshness. Home Assistant shows a lock command's optimistic `locking`, and when a dead Matter lock never confirms, it writes the value it held, with a **new** timestamp, 30 s later. That revert postdates the order, yet the lock said nothing (finding F9b of v0.3 step ③A). It falls inside an outcome's window whenever the window covers it: after a node restart, which gives a restored outcome a fresh window, or with a longer `within_ms`. The Project Lead's invariant, 2026-10-05: *a post-command observation is admissible only if the adapter can also establish current reachability or provenance of the underlying device.*

- **Every observation says whether it is tied to its device now.** The adapter adds a `provenance`:
  - `ConfirmedCurrent { age_ms }`: the adapter reached the device `age_ms` before its answer, and no earlier than the state was produced. A device read now is confirmed at age 0;
  - `Uncertain`: nothing ties the state to the device now.

  The node takes `confirmed_at = received_at − age_ms` and keeps it in the twin (`confirmed_at_ms`, spec 10).
- **The outcome engine trusts only `ConfirmedCurrent`.** An observation is evidence from `source_at` only if `confirmed_at ≥ source_at`; otherwise it is history. Together with the rule above, the state was produced after the order and the device was reached after the state.
- **The node asks for evidence when it needs it.** The observation right after an order that may have executed, and every observation of a pending outcome's witness, are observations *for evidence* (spec 10, `"evidence": true`). The adapter may then take an exchange with the device to confirm the state. Other observations (Safety's) never trigger one.
- **How an adapter establishes it is its own business.** No protocol-specific logic enters the Trusted Core. The Home Assistant adapter reads a Matter device itself, through the Matter server: a value read is its own evidence (spec 25, F10).
- **Evidence belongs to the answer that gave it** (finding F11, Project Lead 2026-10-06). An outcome keeps the witness's latest admissible state with the answer it came in. A newer answer that is no evidence itself — not confirmed current, or not provably after the order — and that no longer states the same fact (another value, or no value, for a key the action promised) takes that evidence away: the witness may have moved since, and nobody can confirm where to. A newer answer that states the same fact leaves the evidence as it was; keys the action did not promise do not count. Without evidence by the deadline the outcome is `unconfirmed` — never `not_applied` or `diverged` on a superseded state.
- **Not every confirmation is as strong.** A device read now, or a device that answered after the state, is physical proof. Home Assistant's word for the states of its other integrations is a lower assurance, kept so that those devices remain usable (Project Lead, 2026-10-06). Confirmations per integration, where a risk class needs them, are future work. The provenance stays the interface for every source: MQTT, a Modbus gateway, a camera, an independent witness.
- **The cost:** a state the adapter cannot tie to its device settles nothing, and the outcome is `unconfirmed`. For a lock that enters recovery.

| Status | Execution | When |
|---|---|---|
| `verified` | reported | the witness, observed after the execution, reports the expected state |
| `applied` | unknown | the witness reports the expected state: it took effect |
| `pending` | either | not settled yet. The server observes the witness on every tick (1 s) until `within_ms` after the execution |
| `diverged` | reported | the deadline passed, and the witness was observed after the execution but does not report the expected state: a broken promise |
| `not_applied` | unknown | the deadline passed, and the witness, observed after the order, reports a **settled** state (every promised key) with other values: it did not take effect, and the state is known. A witness in motion or at fault is not settled, and the outcome is `unconfirmed` |
| `unconfirmed` | either | the deadline passed and the witness could not be observed after the execution: **nobody can establish what happened** |
| `superseded` | either | a newer order on the same resource was minted while this one was pending; its witness now reports the newer action |

The first matching observation before the deadline settles an outcome (`verified` or `applied`). A contradicting one does not settle it early, because a bolt may still be moving. Every outcome view says `execution`: `reported` or `unknown`.

### Where outcomes appear

- **The response** (spec 11) carries `outcome`: `status`, `resource`, `capability`, `expected`, `observed` (the witness's values for the expected keys only, or `null`), `witness`, `independent`, and `deadline_ms` while pending. The MCP broker passes it to the AI. The Plan Engine (step 10) will read it to decide its next step.
- **The execution record** (spec 09) carries the same object as `verification`. Its existing `outcome` field (`ok` / `error`) is unchanged.
- **An outcome settled after the response** (pending → verified, applied, diverged, not applied, unconfirmed, or superseded) gets its own audit record (`kind: "outcome"`). The record points to `decision_seq` and `execution_seq` and says whether the order was a safe state (`safe_state`). It also produces an `outcome` event, a security-class event that is kept when a queue overflows (spec 10). Superseded outcomes produce no event.

### Uncertainty survives the node

Every action that may change the world is on record in the persisted domain state before it can: `inflight`, keyed by intent or request id (v0.2 release-candidate audit, finding H1).

1. **Reserve.** After Safety clears the action and before its decision is recorded, the node writes the entry (what the action promises, its witness, its risk) and bumps the authority epoch. The decision record and its context carry that epoch, so a state file rolled back past the entry is refused at start-up (spec 11).
2. **Minted.** The order id is written as soon as the boundary has minted the order, before the order can leave the node.
3. **Settled.** The entry is removed when the outcome settles, or when the execution certainly did not happen.

**Durability contract.** The state file is replaced atomically and synced (spec 18). If a write fails, the action does not happen:

- a failed reservation stops it with `X_INTERNAL` ("not executed");
- a failed order-id write drops the minted order unsent ("not sent").

No order leaves the node without its record (finding H1b).

**After a restart** the node watches every entry whose order was minted, as a pending outcome with a fresh window, against the send time on record. Its execution is "unknown" unless the adapter's success had been recorded. The start-up observation settles it only if it postdates the order. A device read directly does; a backend's cached state of unknown age does not, so the next report decides. An entry without an order was never sent and is dropped.

| The node crashed | After the restart |
|---|---|
| after the reservation, before or after the decision record, before the order was minted (crash points A, B) | dropped: nothing was sent |
| after the order was minted and on record, before it was sent (C) | watched as unknown: `not_applied` if a report after the order shows nothing happened, else `unconfirmed` (the node cannot know it was never sent); never sent |
| after the order was sent, before its answer or outcome were on record (D) | watched as unknown: `applied` / `not_applied` by a report after the order, else `unconfirmed`; never resent |
| with an outcome pending | watched again; `unconfirmed` at medium risk or more enters recovery |

A plan does not resume after a restart (spec 23). The uncertainty about what its last step did does. A recovery, once entered, is persisted.

## Recovery

An action whose effective risk is **medium or more**, and that was not itself a safe state, puts its resource in **recovery** when its outcome is:

- **`diverged`**: the device reported success and the witness contradicts it;
- **`unconfirmed`**, whether the execution was reported or unknown: the command may have taken effect and nobody can establish the physical state. A door that may or may not have locked is not left open to normal actions (Project Lead, 2026-10-05).

`not_applied` does not: the command did not take effect, the state is known, and the requester was told. A certain failure does not either: nothing executed. Low-risk outcomes are recorded and announced only. Raising a binding's `risk_floor` to medium turns recovery on for that action.

Recovery comes in two kinds, by the evidence behind it:

| | Evidence | The node's safe state |
|---|---|---|
| after `diverged` | the witness was observed after the action | runs at once (below), unless the witness already reports it; later, again only on new evidence of danger |
| after `unconfirmed` | none: the resource could not be observed | **does not run blind**. A second command "to be sure" could act on a device whose state nobody knows. It runs only once the witness is observed again and shows danger (below). A person still observes, reconciles and releases; the recovery's reason says so |

Recovery follows Blueprint v20 §11:

| | What happens |
|---|---|
| **Stop** | `SAFE-8-RECOVERY` (spec 17) refuses every action on the resource, or below it, whoever asks, except the resource's own safe-state action with exactly its declared parameters. Every other rule still applies to that action. Recovery is part of the persisted domain state (spec 11). Entering it bumps the authority epoch, so a state file rolled back past it is refused at start-up. The authority fence (spec 19) stops orders in flight on the resource, except its safe state. It is audited as `safety` / `recovery` by `service:node` and announced as `safety_changed` |
| **Safe state** | Each resource may declare one (below). The node runs it by itself, only on evidence: once a promise is broken on evidence, and again for each new observation that still shows danger, at most three times |
| **Escalate** | The outcome record, the `outcome` and `safety_changed` events, and the requester's response. Notifying people is part of the Human Decision Center (R6, v0.3) |
| **Compensate** | Not in v0.1 |

### Ending a recovery

Only a person ends a recovery: `domain.safety_release`, by an owner or admin, never by an AI (C11). The operation lifts the resource's hold and ends its recovery; its result says `was_held` and `was_recovering`.

A verified safe state does not end the recovery. The machine only escalates (spec 11): the resource is safe again, and a person still has to look at a device that broke its promise.

### Safe states

```json
{ "id": "resource:front-door", "safe_state": { "capability": "lock.lock" } }
```

A safe state is checked when the node starts (spec 14). It must:

- be an action bound at the resource;
- have valid parameters inside the resource's envelope;
- have an effective risk of **at most medium**.

Unlocking, or anything that needs a human, can never be a safe state. Resources without a safe state stay stopped until released.

### The node runs the safe state, on evidence

When a resource enters recovery after a `diverged` outcome and declares a safe state, the node runs that action at once, unless the witness already reports its expected state. After an `unconfirmed` outcome it runs nothing then. The path is the same as for any physical action (Invariant 1):

```text
failed outcome (audit seq S)
  ─▶ Authority Engine: authorize_recovery → RecoveryGrant
       (declared, bound, a device action with valid parameters, ≤ medium risk, actor = the node)
  ─▶ Safety: clear (SAFE-1…8; SAFE-8 lets exactly this action through)
  ─▶ decision record {decision: allow, safe_state: true, trigger: S, context}
  ─▶ boundary: mint(Authority::Recovery) ─▶ single-use order ─▶ receipt ─▶ its own outcome (safe_state: true)
```

- `RecoveryGrant` has no public constructor and is not `Clone` (a test that must not compile pins this down). Only the Authority Engine creates one, and only for the node (a `service:` principal), never for an AI or a person.
- Its digest binds the subject, the resource, the action, its parameters and the trigger.
- The decision context (spec 19) has `kind: "recovery"`, `actor: "service:node"` and `policy: ["safe-state:<resource>", "trigger:<S>"]`, with no tokens or approvers.
- **New evidence, a new order; never a resend** (Project Lead, 2026-10-06). The rule is one attempt per confirmed unsafe observation, not one forever per episode. A safe state that was refused, could not reach the device, or did not take effect is never sent again. While the resource stays in recovery, the node watches its witness closely, as evidence:
  - at least every 5 s (`RECOVERY_OBSERVE_EVERY_MS`);
  - a device back from silence included: F5's backoff is capped there.

  A new attempt is a new order, decided anew by Authority and Safety. It is made only when all of these hold:
  - **the evidence is fresh:** a state the witness's adapter confirmed current (F9b), produced after the broken order was sent, or after the last attempt was;
  - **it shows danger:** the witness states every key the safe state promises, with other values. A state that is safe already, or unknown (a jammed lock states no `locked`, a robot that lost its pose states none), is no reason to act, and nothing is sent blind;
  - **one at a time:** none while an attempt is on its way or awaits its outcome;
  - **one per observation:** the same observation triggers one attempt at most;
  - **at most three per episode** (`MAX_SAFE_STATE_ATTEMPTS`). Then a `deny` decision with `stage: "attempts"` tells, once, that a person must act.

  Every order still reaches its device at most once. The attempts are part of the persisted domain state (`safe_state_attempts`). They survive a restart and end with the recovery.

Why the node may act by itself (C9): a door that did not lock at night should go back to locked even when nobody answers. The bounds above keep this from becoming new authority:

- the owners declared the action in the domain configuration;
- it is at most medium risk;
- it runs only on evidence of danger, never blind, at most three times per recovery;
- Safety may still refuse it;
- it leaves the same evidence as every other order.

## Threats

| Threat | Defence | Test |
|---|---|---|
| A command may have executed and nobody can tell (lost answer, backend down), and the resource stays open to normal actions | an unknown execution is watched like a reported one; `unconfirmed` at medium risk or more enters recovery | `home_assistant::a_command_whose_fate_nobody_can_establish_puts_the_door_in_recovery_without_a_second_command` |
| Recovery sends a blind second command to a device whose state is unknown | the safe state runs only on fresh evidence that shows danger: after `diverged`, or when the witness is seen again after `unconfirmed`; never on an unobservable or unknown state | same test; `adversarial_home::a_door_back_from_silence_is_locked_on_evidence_only`, `a_lock_that_jams_puts_the_door_in_recovery_without_a_second_command` |
| A transport failure before delivery stops a resource for nothing | certain failures are not watched and never lead to recovery | `home_assistant::a_command_never_delivered_leads_to_no_recovery`, `outcome::a_command_whose_fate_is_unknown_is_watched_and_a_certain_failure_is_not` |
| An unknown execution is mistaken for a failure or a success | it settles as `applied` or `not_applied` by the witness, observed after the order | `home_assistant::a_command_whose_fate_is_unknown_takes_the_outcome_the_witness_shows` |
| A backend serves a dead device's last state as current (F9), and an outcome is judged by it | only a state produced after the order is evidence; otherwise `unconfirmed` and recovery | `home_assistant::a_cached_state_from_before_the_order_never_settles_an_unknown_execution`; the crash-point tests |
| A confirmed state, superseded by a newer one nobody can confirm (the lock unlocked, reported and died), still settles an outcome: `not_applied` with the door open (F11) | evidence belongs to its answer; a newer unconfirmed answer of another fact takes it away; `unconfirmed` and recovery | `home_assistant::a_confirmed_state_superseded_by_one_nobody_can_confirm_is_no_longer_evidence`, `a_newer_reading_of_the_same_fact_keeps_the_evidence`; `outcome::a_divergence_superseded_by_an_unconfirmed_reading_is_not_known`; `node::tests::the_same_fact_is_judged_by_every_promised_key` |
| An earlier reading of the witness, folded after a newer one, settles an outcome (concurrency audit R3) | readings are ordered by when their answers arrived (spec 10); one older than the twin's latest is history and no evidence | `home_assistant::an_earlier_reading_of_a_witness_folded_late_is_no_evidence`; `outcome::an_earlier_reading_folded_late_never_overwrites_a_newer_state` |
| A gateway re-emits a dead device's cached value with a new timestamp (F9b), and an outcome is judged by it | only a state the adapter confirmed current, by reaching the device after the state, is evidence; otherwise `unconfirmed` and recovery | `home_assistant::a_dead_matter_lock_s_cached_state_with_a_new_timestamp_is_no_evidence`, `a_live_matter_lock_s_fresh_state_settles_its_outcome`; `outcome::only_a_state_confirmed_current_is_evidence_of_an_order`, `after_a_restart_an_unconfirmed_state_settles_nothing` |
| A device reports success but the world did not change (stuck bolt) | witness observation after execution; `diverged`; recovery; the safe state, again only on newer evidence that the door is still unlocked | `a_stuck_lock_puts_the_door_in_recovery_and_the_node_locks_it_on_evidence_only` |
| A slow actuator is mistaken for a failure | `within_ms`; observed on every tick; a contradicting observation does not settle it early | `a_slow_device_is_pending_until_its_witness_reports_the_effect` |
| The witness goes silent after an action | `unconfirmed`; recovery at medium risk or more | `a_medium_risk_action_nobody_can_confirm_stops_its_resource`, `an_unconfirmed_low_risk_outcome_is_reported_not_recovered` |
| An AI keeps retrying an action that does not take | recovery refuses everything but the safe state, for everyone | `a_stuck_lock_…` |
| The safe state fails too, and the node loops, or a flapping link spams it | one attempt per newer observation that still shows danger, one at a time, three per episode, then a person; never a resend, never on a timeout | `a_stuck_lock_…`; `robot_adversarial::a_flapping_link_never_spams_stops`, `one_safe_state_attempt_at_a_time` |
| A stop that could not reach a moving robot is never followed up | back, the robot is observed first; still moving, a new stop is decided and sent once; at rest, nothing | `robot_adversarial::a_stop_lost_to_a_dropped_link_is_decided_anew_on_reconnect`, `the_robot_drops_off_mid_motion` |
| A compromised adapter host reports false states consistently | an independent witness on another adapter host instance; `independent` is recorded with every outcome | `a_witness_on_another_adapter_host_is_independent` |
| A timeout hides whether an action happened | an unknown execution is watched until `within_ms` (`applied`, `not_applied`, `unconfirmed`) | `outcome::a_command_whose_fate_is_unknown_is_watched_and_a_certain_failure_is_not`, `a_lying_adapter_host_is_not_believed` |
| An older outcome is judged against a newer action | `superseded` | `a_newer_action_supersedes_a_pending_outcome` |
| A restart or a rolled-back state file ends a recovery | persisted with an epoch bump; rollback refused | `a_recovery_survives_a_restart_and_a_rollback_is_refused` |
| An AI or another person ends a recovery | `domain.safety_release`: owners and admins only, never an AI | `a_stuck_lock_…` |
| A misconfigured safe state (unlocking, an envelope escape) | refused when the node starts | `safe_states_are_bound_valid_and_at_most_medium_risk` |
| A forged recovery authority | `RecoveryGrant` has no public constructor; the boundary checks subject, device, resource and parameters against the clearance | boundary doc test, `a_safe_state_is_minted_from_the_engine_s_recovery_grant_only_for_its_resource` |

**Residual risks:**

- Whoever can make a witness lie can push a resource into recovery: a denial of service that fails safe and that a person ends.
- A self-witness (the default) cannot catch a host that lies consistently; only an independent witness can.
- Pending outcomes do not survive a restart.

## Tests

- `crates/chitala-node/tests/outcome.rs`: end to end with the mock's fault injection, `Simulation::Stuck` (the device reports actions it did not do) and `Simulation::Lag` (the effect appears only at a later observation).
- `crates/chitala-node/tests/node.rs::memory_platform::a_recovery_survives_a_restart_and_a_rollback_is_refused`: on the memory platform, through the adapter host protocol.
- Unit tests in `chitala-model` (registry outcomes), `chitala-resource` (safe states), `chitala-safety` (SAFE-8), `chitala-policy` (`RecoveryGrant`) and `chitala-boundary` (`Authority::Recovery`).
- **SAFE-8 on new evidence (2026-10-06): mutations, 8 of 10 caught one by one.**
  - Caught: no cap; an unknown state taken for danger; no first attempt; the witness not observed as evidence; F5's backoff not capped; an attempt while another awaits its outcome; a stopped robot not at rest; the witness watched no closer.
  - The other two are the two guards against acting blind: an unobservable state used, or a state older than the last attempt used. Each alone is masked by the other, and removing both is caught (`a_stop_lost_to_a_dropped_link_is_decided_anew_on_reconnect`).

## Not in v0.1

- **Compensation:** undoing an action, rather than going to a fixed safe state.
- **Preconditions declared by the requester:** "only if the door is closed".
- **Several witnesses**, and a quorum between them.
- **Push observations** from adapters, instead of polling every tick.
- **Persisted pending outcomes.**
- **A query for resources in recovery**, and notifying people. Today recovery is visible through events and the audit log.
