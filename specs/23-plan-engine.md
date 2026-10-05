# 23 — Plan Engine v0.1

Sources: v0.2 roadmap step 10; Blueprint v20 §8 (*Goal → Intent → Plan → Capability Resolution → Policy/Safety → Execution Lease → Action → Observation → Audit*; "the planner is replaceable"; "a plan creates no authority: every action proves its authority independently") and v19 §12 (*plan → proposed actions → policy precheck → execute step → observe outcome → re-plan*; "plan approval does not grant unlimited authority"; "a material deviation goes to a human"; "emergency stop and revoke are faster than the planner loop"); the Project Lead's decision of 2026-10-05 (a step that needs a person pauses the plan, and that step alone is asked). Code: `chitala-intent` (wire format, step derivation), `chitala-node` (`plans.rs`), `chitala-mcp` (`chitala_plan`), `chitala-cli` (`plans`, `plan-cancel`).

## Why

Agents rarely want one action. "Lock the door, set the living room to 21 °C, turn the light off" are three actions, and each is worth doing only if the one before took effect.

Sent as three separate intents, the agent must sequence them itself:

- nothing tells it in advance that the third step would be refused, so the world can be left half changed;
- it may run the second step while the first is still moving.

A **plan** lets the agent say the whole sequence once, while Chitala keeps every guarantee of a single action.

> A plan creates no authority. It is a sequence of intents, each judged in full when it runs, each started only once the one before has verifiably taken effect.

**Chitala is not the planner.** The plan comes from outside: from an AI, a rule engine or a person, wherever they run. Chitala admits it, checks it, runs it step by step, and stops it.

## Wire format

A plan is an intent (spec 15) with follow-up steps: intent **version 2**, key **17**. The intent's own action is step 1.

| Key | Field | Type |
|---:|---|---|
| 17 | follow-up steps: an array of 1..7 maps, so a plan has at most **8 steps** | array, optional (version 2) |

Each step:

| Key | Field | Type |
|---:|---|---|
| 1 | action | tstr capability id |
| 2 | resource | tstr `resource:` id |
| 3 | params (omitted when empty) | map |
| 4 | authority: the actor's token for this step; omitted means the plan intent's (key 14) | bstr, optional |

Everything else comes from the plan intent and holds for every step:

- the actor and the person;
- the deadline (at most 10 minutes, spec 15) and the constraints (`max_risk`, `no_escalation`);
- the purpose.

The decoder refuses:

- a plan with a lease clause (keys 15/16) or a relay (`cause`: plans are first-hand);
- more than 8 steps, or an empty array;
- version 1 with key 17;
- unknown step keys, or empty step params.

The whole plan is one signature. Its digest covers every step, and so does the replay check.

### Steps are intents

Only `chitala-intent` can turn a verified plan into its steps (`VerifiedIntent::plan_step(k)`). Each step is a `VerifiedIntent` of its own:

- **its id** is SHA-256(`"chitala-plan-step-v1" 0x00` ‖ plan id ‖ k ‖ n), truncated to 16 bytes;
- **its digest** is SHA-256 of the same prefix ‖ the plan digest ‖ the step's canonical body;
- **its contents** are the step's action, resource, parameters and token, with the plan's actor, person, deadline and constraints; no relay, no lease, no plan.

A step therefore has its own audit trail, its own orders and its own approvals. An approval of step k answers that step only: never the plan, and never a stand-alone intent with the same content.

## Running a plan

### 1. Admission

The plan intent is admitted once, like any intent (spec 08): signature, freshness and replay. An actor runs at most **2 plans** at a time, and the domain at most **64**; above that the plan is refused with `E_PLAN_DENIED`.

### 2. Precheck

Before anything moves, every step goes through:

- the Authority Engine (spec 16), whose decision is pure;
- Safety's side-effect-free check (spec 17), against the current state.

| Precheck verdict of any step | Result |
|---|---|
| DENY (Authority or Safety) | the whole plan is refused with that step's code (`E_TOKEN_DENIED`, `E_SAFETY`, …) and a reason naming the step (`plan step 3 of 3 …`); nothing runs |
| ESCALATE | allowed: the plan will pause there and ask (below) |
| ALLOW | allowed |

The precheck only predicts. It grants nothing: every step is judged again when it runs. A later step is checked against today's state, not the state the steps before it will create.

### 3. Steps

The steps run one at a time, in order:

1. **Judge.** The Authority Engine decides the step again, in full and now. A revocation, a quarantine, a change of policy, a hold or a recovery since the precheck applies.
2. **Execute.** An allowed step is cleared by Safety and executed as an ordinary single-use order (spec 19). Its outcome is verified against its witness (spec 22).
3. **Continue.** The next step starts only when this step's outcome is **verified**:
   - immediately, in the same request, when the witness confirms at once;
   - otherwise on the server tick that verifies it.

So a plan whose steps all verify at once completes in one round trip. Its reply shows every step.

| What happens to the current step | The plan |
|---|---|
| allowed, and its outcome is verified | goes on to the next step, or is **done** after the last |
| allowed, outcome pending | waits for the witness (spec 22) |
| needs a person | **waits** (below) |
| denied, refused by Safety, its execution fails, its outcome is diverged, unconfirmed or superseded, or nobody approves it in time | **stopped**: nothing more runs, and the remaining steps are cancelled |

There is no compensation. Stopping leaves the world as the steps that took effect left it. A broken promise of medium risk or more has already put its resource in recovery (spec 22).

### 4. A step that needs a person

Following the Project Lead's decision, a step that needs human approval pauses the plan. An example is an AI's `lock.unlock`, which C11 always escalates.

- The escalation is about **that step only**. The approval binds to the step's own digest, and an approval of the plan intent answers nothing (`E_APPROVAL_INVALID`).
- The approver decides with the world as it is when the plan reaches the step, not as it was when the plan was sent.
- The reply to the plan is `escalate`, with the step's id as `mid`, the approvers, the deadline, and the plan as `result.plan`.
- An approval runs the step and carries the plan on in the same request. A rejection stops the plan. So does no answer before the plan's deadline (C14): the server's tick closes the escalation even when no request comes in.
- Approving one step never approves another. A later step that needs a person asks again.

### 5. Ending a plan

| How | Status |
|---|---|
| its last step is verified | `done` |
| a step does not take effect (table above) | `stopped`, with a reason |
| `domain.plan_cancel` by the person it acts for, an owner or an admin; never an AI (C11) | `cancelled` |

A cancellation is the emergency stop:

- no further step starts;
- a step waiting for approval is no longer asked;
- an order of the plan still in flight is stopped by the authority fence (spec 19), because the plan id is one of the things an order depends on.

Holds, recovery and revocations stop a plan without cancelling it: its next step is refused when it is judged.

**Plans live in memory.** A restart stops every plan: nothing continues by itself after a restart. The audit shows how far each plan got.

## Seeing a plan

The plan appears in four places:

- **Every reply to a plan step** (the submission, an approval, a step run on a tick) carries `result.plan`:
  - `id`, `status` (`running`, `waiting_approval`, `done`, `stopped`, `cancelled`), `reason`;
  - `actor`, `on_behalf_of`, `current`, `of`, `deadline_ms`, start and end times;
  - `steps`: for each, `n`, `mid`, `capability`, `resource`, `status` (`planned`, `running`, `waiting_approval`, `done`, `denied`, `failed`, `cancelled`), `code`, `outcome` and `audit_seq`.
- **`domain.list_plans`**: owners and admins see every plan, everyone else the plans that act for them, never an AI. Ended plans are kept for at least an hour, and at most 256 of them.
- **The audit log**:
  - `plan` records: `accepted`, with every step's id and digest, then `step_done`, `waiting_approval`, `done`, `stopped`, `cancelled`;
  - every step has its own `decision`, `execution` and `outcome` records under its own id.
- **Events** of kind `plan`, a security class kept on overflow (spec 10).

**MCP** (spec 12). The broker offers `chitala_plan`: steps of `resource`, `action` and `params`, plus a `purpose`. It attaches to each step the agent's token that covers it.

**CLI**: `chitala plans --as …` and `chitala plan-cancel --as … <plan id>`.

## Threats

| Threat | Defence | Test |
|---|---|---|
| A plan is used to gain authority (approve or check once, act many times) | every step is judged again in full when it runs; a step's token is checked like any intent's | `a_plan_creates_no_authority_each_step_is_judged_when_it_runs` |
| A plan leaves the world half changed because a later step was always going to be refused | precheck of every step through Authority and Safety before anything moves | `a_plan_is_refused_whole_when_any_step_would_be` |
| A step runs while the one before has not taken effect (a lock still moving, a jammed bolt) | the next step starts only after a verified outcome; a broken promise stops the plan | `a_step_waits_for_its_outcome_and_a_broken_promise_stops_the_plan` |
| A human approves a plan and with it more than they saw | only a single step is ever asked about, with its own digest, when the plan reaches it; an approval of the plan answers nothing | `a_step_that_needs_a_person_pauses_the_plan_and_asks_for_that_step_alone` |
| No answer becomes consent | the escalation expires with the plan's deadline, also on the server tick, and stops the plan | `a_rejected_or_unanswered_step_stops_the_plan` |
| An agent cannot be stopped mid-plan | `domain.plan_cancel` by people; the fence stops the order in flight; holds and revocations refuse the next step | `a_person_cancels_a_plan_and_its_order_in_flight_is_stopped` |
| An AI or an unrelated person cancels or reads someone's plans | owners, admins and the person it acts for only; never an AI | `a_person_cancels_…` |
| An agent floods the node with plans | 2 running plans per actor, 64 per domain | `an_agent_runs_at_most_two_plans_at_once` |
| A step is replayed or confused with another intent | the plan is admitted once; step ids and digests are derived from the signed plan and bound to it and to their index | `plans_on_the_wire_and_their_steps`, `plans_have_limits` |

**Residual risks:**

- The precheck sees today's state, so a later step can still be refused when it runs. The plan then stops partway, without compensation.
- Plans do not survive a restart.

## Not in v0.1

- **Compensation:** undoing the steps of a stopped plan.
- **Branches and conditions:** "if the door is open, …".
- **Re-planning inside Chitala.** The planner outside reads the reply and sends a new plan.
- **Budgets beyond the step count and the deadline** (time, energy, money).
- **Plans that use execution leases.**
- **Persisted plans.**
- **Approving several steps at once.**

## Tests

- `crates/chitala-node/tests/plan.rs` (8 tests): order and verification, whole-plan refusal, the approval pause, rejection and silence, waiting for outcomes, judging each step anew, cancellation and the fence, the per-actor limit.
- `chitala-intent` unit tests: the wire format, step derivation and the limits.
- `chitala-mcp`: `a_plan_through_the_broker`.
- The fuzz seed corpus includes a person's plan and an agent's plan with a per-step token.
