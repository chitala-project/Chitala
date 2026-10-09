# 34 — Trusted approval (design)

**Status:** a design, not an implementation (Project Lead, 2026-10-09). It answers gap G-9 ([hazard H-GEN-018](../docs/safety/hazard-log.md)). It sits beside Safety Contract v0.1 (ROADMAP step 6), because what an approver is told about consequences and safe states comes from the contract. Nothing here is claimed as built.

It needs no wide change to the frozen core. An approval already binds to the digest of one intent (spec 16), and Safety already runs again when a person answers (specs 17, 19). What is missing is mostly in the interface, the policy and the contracts.

## The gap

Chitala decides who may approve, and binds an approval to exactly one intent. It does not say what the approver must be shown before signing.

Today:
- `domain.list_approvals` returns the request's terms: its digest, the actor, the person it acts for, the agents that relayed it, the resource, the capability, the parameters (redacted by the audit's rules), a lease's terms, the AI's `purpose`, the risk, the quorum and the deadline;
- `chitala approve` prints one line with the AI's `purpose` and not the parameters, and signs in the same step. The parameters are only in the raw listing of `chitala approvals`;
- nothing bounds how often one person is asked. The limits are per requester: at most 3 pending requests per actor, and 256 per domain;
- a refused request can be asked again at once, reworded.

No concrete exploit path has been shown. The gap is a missing requirement.

An AI can still persuade a person in its own conversation, outside Chitala. Chitala does not control that. H-GEN-018 stays a residual risk even when this spec is built.

## Requirements

### 1. Canonical content

Chitala builds what the approver is shown from the signed intent and the contract, never from the requester's words:
- **who:** the actor, the person it acts for, the agents that relayed it;
- **what:** the resource and the action;
- **the terms:** every parameter the approval covers;
- **when:** when it would act, and until when the question stands;
- **the scope:** one action, or a lease (how many uses, for how long, within which envelope). These are two different kinds of consent, and they are shown as such;
- **the risk:** from the registry and the resource, never from the requester;
- **from the contract:** what the action does, its safe state if it fails, the evidence it requires.

**Nothing is guessed.** If the contract does not state a consequence, a duration of effect or a safe state on failure, the approver is shown that it is unknown. Chitala never presents its own guess as a fact. A high-risk action whose contract states no safe state on failure is refused by policy. It is not offered for approval blind.

**Display is not redaction.** The audit's redaction rules are for the log, and they are not a display rule. Nothing the decision needs is hidden from the approver. A parameter that must never be shown is a reason to refuse the approval path, not to hide it.

**Bound to what was shown.** The summary is built from two things:
- the intent, identified by its digest;
- what is in force for it, which shapes what the person is shown:
  - the capability's entry in the registry;
  - the policy;
  - the resource's profile or contract;
  - the resource's own configuration, on the resource and every resource it is in: the binding of the capability (its device and its `risk_floor`), the envelope, the safe state, the owners, and whether it needs two keys.

It is a function of those two, so binding both binds what the person was shown. The approval signs both: the intent's digest, as today, and a **context digest**. That digest covers the content of what is in force, or a revision that changes whenever the content changes. It never covers a version label alone: if a binding, a risk floor, an envelope, the owners or the quorum changed while a profile's version stayed the same, an approval bound to the label would carry another meaning.
- **When the person answers,** the node computes the context digest again. If anything it covers changed since the question was asked, the approval does not verify (`E_APPROVAL_INVALID`). The person is asked again, with a summary built from what is now in force.
- **For a lease,** a change of anything the digest covers ends its approval, and its next use needs a new one.
- **A change to the action itself** (a parameter, a lease term) makes a new intent with a new digest, so an approval given before it is void.

The context digest changes the approval's wire format (spec 15). It is part of this design, not built. Until it is built, an approval binds only the intent's digest. Authority and Safety still run again, on what is then in force, when the person answers (specs 16, 17).

### 2. Trusted sources

- Names of devices and resources, the risk and the safety conditions come from the managed configuration and the profiles. Owners set them, and the changes are audited.
- An AI cannot set the risk, and cannot declare an action safe.
- A name the requester controls is labelled as the requester's.

### 3. Against spoofing

- The AI's words (`purpose`, any free text) are shown apart, as secondary, and labelled with their source ("ai:assistant says: …"). They never appear as Chitala's own text.
- The following are removed or escaped before display:
  - control characters;
  - bidirectional overrides;
  - characters that imitate Chitala's own markers.

  The length is bounded.
- Chitala's own fields never carry requester text.

### 4. What no approval removes

- Safety's rules and the evidence a contract requires hold whatever a person approved (specs 17, 19).
- Without the required evidence, the action is refused, or the resource goes to its declared safe state.
- An approval never makes a capability safe that its contract does not declare safe.

### 5. Against fatigue

- **A budget per approver** over a time window, counting the questions from every requester. It is added to the limits per requester.
- **Duplicates merged:** the same request asked again while it is pending is one question. "The same" means the same actor, resource, action and terms. The `purpose` is not part of it.
- **No reworded retry:** after a rejection, the same request with new words is refused without asking anyone, for a cool-down the owner sets.
- **A spent budget refuses:** a request beyond the budget is refused and reported, never queued in silence.

### 6. Control after approval

- The person sees the authority in force: tokens, leases, pending requests and plans.
- They can cancel a pending request, and revoke a token, a lease or everything (`domain.revoke_all`), through the existing Authority operations.
- The interface keeps **"authority revoked"** apart from **"device stopped"**. A revocation stops what still needs its authority checked (spec 05, *Revocation*). It does not cancel an order already accepted beyond the gate, and it does not stop a motion already running. Stopping takes a stop (spec 30).

## Order of work (Project Lead, 2026-10-09)

1. This spec, with H-GEN-018 and G-9.
2. **The CLI first:**
   - show every term before asking;
   - make `purpose` secondary and label it;
   - remove what could spoof Chitala's text;
   - confirm before signing.
3. The budget per approver, cancelling and revoking, on the existing Authority operations.
4. Tests:
   - of the code;
   - of what people understand: misleading AI text, repeated requests, a single approval against a lease.

## Tests to write

- For any intent, the summary shows every parameter and lease term that the digest covers.
- Requester text never appears in Chitala's own fields, and control characters never reach the display.
- A changed term voids an approval given before the change. So does any change between the question and the answer to what the context digest covers: the registry entry, the policy, the profile or contract, a binding, a `risk_floor`, an envelope, a safe state, the owners, two keys. A change to that content under an unchanged version label voids it too.
- A budget per approver; a duplicate is one question; a reworded request is refused during its cool-down.
- What a person sees after `revoke_all`: authority revoked, and the state of each device as observed. A revocation never implies a stop.
- With people: whether they tell a single approval from a lease, and whether misleading AI text changes what they approve.

## What this does not claim

- People do not become immune to persuasion. The aim is that what Chitala shows is true, complete and its own, and that no approval can carry an action past Safety.
- Nothing here is enforced until it is built and tested. Until then, G-9 stays open.
