# 17 — Safety

Sources: Blueprint v19 "Safety Fabric", v8 §10, Security Constitution C5/C9; crate `chitala-safety`.

Policy answers *who may do what*, and owners and administrators change it. Safety answers *what must never physically happen, whoever asks*. The two are kept apart on purpose:

- `chitala-safety` depends on neither the policy engine, nor tokens, nor identities;
- safety is consulted for **every** physical action — a person's request as much as an AI's intent (spec 19) — **after** Authority, and **again** right before the trusted boundary mints a command (the state may change while a human is deciding);
- safety **can only refuse**. No rule, setting or call turns a DENY from Authority into an ALLOW, and no policy can switch a safety rule off. A human's approval cannot override safety either.

## Rules

| Id | Refuses |
|---|---|
| `SAFE-1-HOLD` | any action on a resource under a *safety hold*, or below a held resource. Owners and admins place and lift holds (`domain.safety_hold`, `domain.safety_release`; CLI `hold`/`release`), never an AI (C11: a hold stops protective actions too). Holds are part of the persisted domain state, so they survive a restart; each change bumps the authority epoch, so a state file rolled back past one is refused at start-up; both are audited, and a hold also stops orders already in flight (spec 19) |
| `SAFE-2-DEVICE` | any action through a contained device (QUARANTINED/RECOVERY/RE_ATTEST); `high`+ actions through a device that is not TRUSTED |
| `SAFE-3-STATE` | `medium`+ actions when the resource's state is unknown or older than its `StateRef.max_age_ms` (120 s by default) — fail safe. Unknown includes a device that cannot be observed now: its last known state is not evidence (spec 10) |
| `SAFE-4-PHYSICAL` | actions that contradict the reported physical state (v0.1: `lock.lock` while the door is open) |
| `SAFE-5-ENVELOPE` | parameters outside the resource's own envelope (tighter than the registry) |
| `SAFE-6-RATE` | more actuations of one resource per window than it tolerates (6/60 s by default; 3/60 s for `high`+) — against oscillation and looping agents |
| `SAFE-7-BUSY` | an action through a device that is still executing another order, or on a resource that another order is still acting on, possibly through another device (one door, two controllers). Two actions cleared on the same state must not interleave. The device and the resource are free again when the order is answered or expires. Only the resource itself is locked, not its neighbours or the spaces around it |
| `SAFE-8-RECOVERY` | any action on a resource in *recovery* after a failed outcome, or below it, except that resource's own declared safe-state action with exactly its parameters (spec 22). The node puts a resource in recovery when an action of medium risk or more did not have its promised outcome; only an owner or admin ends it (`domain.safety_release`), never an AI. Recovery is persisted, bumps the authority epoch and stops orders in flight, like a hold. The node brings it to its safe state on evidence only: one new order per confirmed unsafe observation, never a resend, as often as the safe state's retry policy allows (spec 22) |
| `SAFE-9-MOTION` | a robot's motion (an action whose outcome declares a `pose`) with its emergency stop pressed, an obstacle detected, while it still moves, without a pose, from a pose fixed longer ago than the resource's `max_localization_age_ms`, or on a path that leaves the resource's convex geofence (spec 30) |
| `SAFE-10-HISTORY` | an action a history rule governs, without a valid record from the authorized history evaluator (bound to the request's evaluation context and the rule's version, fresh) that the rule's limit is kept: `LIMIT_EXCEEDED`, `INSUFFICIENT_HISTORY` or `EVALUATOR_UNAVAILABLE` (spec 32). History only ever adds a denial; an action without a rule is untouched, and a stop never has one |

**A stop always wins** (spec 30). Safety never refuses a capability that only halts (`"halts": true` in the registry: `robot.stop`): no rule applies to it, and it does not count against `SAFE-6`. The check right before an order is sent does not keep it back for a hold or a recovery either.

Queries (reading state) are not blocked by safety. A violation returns `E_SAFETY` with `stage: "safety"` and the rule id in the audit log. Safety violations do **not** count towards containment: they are not probing for authority.

## Clearance

- `Safety::check` runs every rule without side effects. It is used before asking a human, so nobody is asked to approve something safety would refuse anyway.
- `Safety::clear` runs the rules again, records the actuation, and returns a `Clearance` for exactly one action of one intent or request (subject, resource, capability, device, parameters, time).

`Clearance` has no public constructor and is not `Clone`. The trusted boundary demands it together with the authority proof of the same subject (`Grant` or `Authorized`, spec 19); the clearance of one intent never clears another.

## Tests and mutations

`chitala-safety`'s own unit tests cover every rule, `SAFE-1` to `SAFE-10`, and the clearance. The node's suites cover each rule again, end to end.

**The `safety-rules` mutation set** ([`mutation/sets/safety-rules.toml`](../mutation/sets/safety-rules.toml)) puts 33 faults into the rules and the clearance, and runs only those unit tests against them. Its first run (2026-10-07) caught 30. The three it missed were each given a test:
- the envelope's minimum ignored;
- a resource still acted on through another device;
- the safe state with other parameters.

Every one is caught now. The safety case ([`docs/safety/`](../docs/safety/README.md)) traces each rule to its hazards.

## Two layers of physical safety

Chitala's safety is the layer *before* the command. The device keeps its own local invariants (C5, `X_DEVICE_REFUSED`): the layer *after* the command, independent, and still right when Chitala is wrong.
