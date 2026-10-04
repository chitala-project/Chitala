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
- a `{"param": …}` names a parameter the action does not require.

The twin's desired state (spec 10) is the expected outcome; the node no longer has its own table.

## The witness

The witness of a resource is the device its state reference names (spec 14). Safety already trusts it for the resource's state, so it decides outcomes too.

A witness is **independent** when it is another device, served by **another adapter host instance** than the device that executed. A compromised host can lie about its own work consistently, but it does not control another host. In the sample home every resource is its own witness, so `independent` is `false`. A separate sensor bound as the state reference makes it `true`.

## Verification

1. **Observe (phase 2).** After an order that may have executed, the node observes the witness once, still outside the node lock. "May have executed" means:
   - a reported success;
   - `X_DEVICE_UNAVAILABLE` or `X_ADAPTER`;
   - a receipt that does not match the order (`X_RECEIPT_INVALID`).

   It does not observe after `X_ORDER_REJECTED` (including an order the authority fence stopped) or `X_DEVICE_REFUSED`: nothing happened.
2. **Judge (phase 3).** The observation goes into the twin. It is evidence; the unvouched report of a failed receipt is not. An outcome is met when the witness reports every expected key with the expected value.

| Status | When |
|---|---|
| `verified` | success reported; the witness, observed after the execution, reports the expected state |
| `pending` | success reported; not confirmed yet. The server observes the witness on every tick (1 s) until `within_ms` after the execution |
| `diverged` | success reported; the deadline passed, and the witness was observed after the execution but does not report the expected state |
| `unconfirmed` | success reported; the deadline passed and the witness could not be observed after the execution. After an indeterminate failure: the witness could not be observed |
| `superseded` | a newer order on the same resource was minted while this one was pending; its witness now reports the newer action |
| `applied` | the execution failed indeterminately, yet the witness reports the expected state: it took effect |
| `not_applied` | the execution failed indeterminately and the witness does not report the expected state |

The first matching observation before the deadline verifies an outcome. A contradicting one does not settle it early, because a bolt may still be moving. After an indeterminate failure the single observation decides: such an outcome is never pending and never leads to recovery, because the requester was already told the action failed.

### Where outcomes appear

- **The response** (spec 11) carries `outcome`: `status`, `resource`, `capability`, `expected`, `observed` (the witness's values for the expected keys only, or `null`), `witness`, `independent`, and `deadline_ms` while pending. The MCP broker passes it to the AI. The Plan Engine (step 10) will read it to decide its next step.
- **The execution record** (spec 09) carries the same object as `verification`. Its existing `outcome` field (`ok` / `error`) is unchanged.
- **An outcome settled after the response** (pending → verified, diverged, unconfirmed, or superseded) gets its own audit record (`kind: "outcome"`). The record points to `decision_seq` and `execution_seq` and says whether the order was a safe state (`safe_state`). It also produces an `outcome` event, a security-class event that is kept when a queue overflows (spec 10). Superseded outcomes produce no event.

Pending outcomes live in memory. A restart drops them: the start-up observation refreshes every twin, and Safety's freshness rule (SAFE-3) still applies. A recovery, once entered, is persisted.

## Recovery

A **diverged** or **unconfirmed** outcome of an action whose effective risk is **medium or more**, and that was not itself a safe state, puts the resource in **recovery**. Low-risk failures are recorded and announced only. Raising a binding's `risk_floor` to medium turns recovery on for that action.

Recovery follows Blueprint v20 §11:

| | What happens |
|---|---|
| **Stop** | `SAFE-8-RECOVERY` (spec 17) refuses every action on the resource, or below it, whoever asks, except the resource's own safe-state action with exactly its declared parameters. Every other rule still applies to that action. Recovery is part of the persisted domain state (spec 11). Entering it bumps the authority epoch, so a state file rolled back past it is refused at start-up. The authority fence (spec 19) stops orders in flight on the resource, except its safe state. It is audited as `safety` / `recovery` by `service:node` and announced as `safety_changed` |
| **Safe state** | Each resource may declare one (below). The node runs it once by itself |
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

### The node runs the safe state, once

When a resource enters recovery and declares a safe state, the node runs that action at once, unless the witness already reports its expected state. The path is the same as for any physical action (Invariant 1):

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
- **At most once per failed outcome.** If the safe state is refused (by Authority or Safety, recorded as a `deny` decision with `safe_state: true`) or its own outcome fails, nothing more is tried. A safe state's failure never leads to another.

Why the node may act by itself (C9): a door that did not lock at night should go back to locked even when nobody answers. The bounds above keep this from becoming new authority:

- the owners declared the action in the domain configuration;
- it is at most medium risk;
- it runs at most once per failure;
- Safety may still refuse it;
- it leaves the same evidence as every other order.

## Threats

| Threat | Defence | Test |
|---|---|---|
| A device reports success but the world did not change (jammed bolt) | witness observation after execution; `diverged`; recovery; one safe state | `a_stuck_lock_puts_the_door_in_recovery_and_the_node_locks_it_once` |
| A slow actuator is mistaken for a failure | `within_ms`; observed on every tick; a contradicting observation does not settle it early | `a_slow_device_is_pending_until_its_witness_reports_the_effect` |
| The witness goes silent after an action | `unconfirmed`; recovery at medium risk or more | `a_medium_risk_action_nobody_can_confirm_stops_its_resource`, `an_unconfirmed_low_risk_outcome_is_reported_not_recovered` |
| An AI keeps retrying an action that does not take | recovery refuses everything but the safe state, for everyone | `a_stuck_lock_…` |
| The safe state fails too, and the node loops | at most once; a safe state's failure never leads to another | `a_stuck_lock_…` |
| A compromised adapter host reports false states consistently | an independent witness on another adapter host instance; `independent` is recorded with every outcome | `a_witness_on_another_adapter_host_is_independent` |
| A timeout hides whether an action happened | the witness is observed after indeterminate failures (`applied`, `not_applied`) | `a_failed_execution_reports_whether_it_took_effect_anyway`, `a_lying_adapter_host_is_not_believed` |
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

## Not in v0.1

- **Compensation:** undoing an action, rather than going to a fixed safe state.
- **Preconditions declared by the requester:** "only if the door is closed".
- **Several witnesses**, and a quorum between them.
- **Push observations** from adapters, instead of polling every tick.
- **Persisted pending outcomes.**
- **A query for resources in recovery**, and notifying people. Today recovery is visible through events and the audit log.
