# 16 — Authority Engine

Sources: Blueprint v19 "Authority Fabric", v9 "Authority Engine"; module `chitala_policy::authority`.

> AI produces Intent. **Chitala produces Authority.** Only the trusted execution boundary produces physical Commands.

For an authenticated intent, and every intent it relays, the Authority Engine answers a fixed chain of questions. The first question answered "no" decides DENY:

```text
WHO → ON_BEHALF_OF → WHAT → OBJECT → CONTEXT → DELEGATION → RISK → APPROVAL → ALLOW | DENY | ESCALATE
```

| Step | Question | Deny codes |
|---|---|---|
| WHO | Is every actor of the chain enrolled and allowed to act (security state)? | `E_UNKNOWN_KEY`, `E_PRINCIPAL_STATE` |
| ON_BEHALF_OF | Is the represented principal an enrolled, uncontained `person:*`, and does the actor serve that person (declared at enrollment)? | `E_ON_BEHALF_OF` |
| WHAT | Is the action a registry capability that targets devices, with valid parameters inside the registry envelope? | `E_UNKNOWN_CAPABILITY`, `E_UNSUPPORTED_BY_TARGET`, `E_PAYLOAD_INVALID`, `E_SAFETY_ENVELOPE` |
| OBJECT | Does the resource exist and bind the action to a known device? | `E_UNKNOWN_RESOURCE`, `E_UNSUPPORTED_BY_TARGET`, `E_UNKNOWN_TARGET` |
| CONTEXT | Is the intent still current? Is every relay faithful — same action/resource/params and **the same represented person** — with no loop, and no cause newer than its relay? | `E_EXPIRED`, `E_PROVENANCE` |
| DELEGATION | For every link: is the represented person entitled (Cedar, assuming they agree)? Does a non-human actor hold a valid, unrevoked, holder-bound token covering the resource (or an ancestor)? Does policy allow the actor at all (assuming a human approves)? | `E_POLICY_DENIED`, `E_TOKEN_MISSING`, `E_TOKEN_INVALID`, `E_TOKEN_REVOKED`, `E_TOKEN_DENIED` |
| RISK | Effective risk = max(registry risk, the binding's `risk_floor`). Is it within the security-state ceiling of every actor **and every represented person**, and within every requester's `max_risk`? | `E_PRINCIPAL_STATE`, `E_CONSTRAINT` |
| APPROVAL | Does policy or the constitution require a human? If so, is there a valid answer from an owner of the resource? | `E_CONSTRAINT`, `E_POLICY_DENIED`, `E_APPROVAL_INVALID`, `E_APPROVAL_REJECTED` |

## The authority of a chain is the intersection of its links

For a relay A → B, the effective authority is `person(A) ∩ token(A) ∩ policy(A) ∩ person(B) ∩ token(B) ∩ policy(B)`. No agent can lend its authority to another. The same holds for longer chains (Human → Personal AI → Home AI → Security Agent, up to four signed links): every agent holds its own token from the human, bound to its key and to the person it acts for (spec 05), and the chain can do only what every link can do.

Case 5 of the Physical Authority Slice (the child's AI asks the owner's AI to open the door) is refused in one of two places:

- at ON_BEHALF_OF, because B does not serve the child; or
- at CONTEXT, because B claims to act for the owner while carrying the child's request (laundering).

## When a human is needed

An actor needs a human's approval if either of these holds:

1. Cedar denies the actor with `human_approved = false` but allows it with `true`. Policies express "needs a human" with `unless { context.human_approved }`.
2. A **constitution rule in code**, which no policy can remove, requires it:
   - the actor is not a person and the risk is ≥ `high`; or
   - the risk is `critical` and the actor is not an owner of the resource acting in person.

An owner's own intent on their own resource counts as a human decision.

### Two keys

On a **two-key resource** (`two_key`, on the resource or an ancestor; spec 14), an action of effective risk ≥ `high` needs **two different people** to agree:

- an agent's intent needs approvals from two different approvers (quorum 2);
- an owner's own intent is the first key, and another owner must approve (quorum 1, the requester excluded from the approvers);
- a direct request (CSME) cannot be approved by anyone and is refused with `E_TWO_KEY_REQUIRED`: one person alone never turns two keys;
- if fewer than the needed owners can decide → DENY.

While the quorum is not reached the decision is ESCALATE again, with the approvers still missing and those who agreed. Any rejection decides `E_APPROVAL_REJECTED`. The grant records every approver; so does the decision context of the execution order (spec 19).

With no answer yet, the decision is **ESCALATE**. The approvers are the effective owners of the resource whose security state still allows them to decide at that risk. If not enough are left → DENY. With `no_escalation` → DENY.

An answer is valid when:

- it names the right intent id **and** digest;
- the approver is one of those approvers;
- `issued_at` is neither before the request nor in the future;
- it has not expired.

`reject` → `E_APPROVAL_REJECTED`.

## Execution leases (spec 21)

- **Asking.** An intent that asks for a lease is judged as the action it would cover, plus the lease rules:
  - at WHAT, the envelope names integer parameters of an action inside the registry's limits, and the parameters are valid at both ends of every range;
  - at RISK, nothing on a two-key resource or at critical risk is leased; at high risk, at most 3 uses within 1 hour; the envelope stays inside the resource's own limits.

  The grant carries the terms (`asks_lease`), and the boundary refuses to mint an order from it. When a human must approve, the approval binds to the intent's digest, so it covers exactly the terms.
- **Using.** `decide_lease_use` runs the whole chain again for every use. Only APPROVAL differs:
  - the lease's approval counts while one of its approvers can still approve this risk at this resource;
  - a use never escalates.

## Plans (spec 23)

A plan creates no authority. Every step of a plan is an intent of its own (`VerifiedIntent::plan_step`), derived from the signed plan with its own id and digest. The engine judges a step with `decide`, exactly like a stand-alone intent: once before anything moves (the precheck), and again, in full, when the step runs. A step that needs approval escalates on its own, and the approval binds to that step's digest; an approval never carries over to another step.

## Unforgeable in, unforgeable out

`decide(world, &VerifiedIntent, &[&VerifiedApproval])` (every answer so far):

- The intent and the approval can only come from a signature check (spec 15).
- The engine checks the tokens itself (`delegation_evidence`): signature, revocation (ids and floors), holder, proof of possession with the actor's enrolled key, the person the agent acts for, the window, and coverage of the resource or an ancestor.
- The result `Verdict::Allow(Grant)` is the proof the trusted boundary demands. `Grant` has no public constructor and is not `Clone`.

Every decision carries a `trace`, one line per question answered, written to the audit log.

## In the node

```text
Monitor::admit_intent  (envelope · identity · freshness · replay · relay chain)
  → decide_intent       (Authority Engine)
  → DENY      → audit + SecurityDenied + containment (AIs)
  → ESCALATE  → safety dry run → queue (≤ 3 per actor, ≤ 256 per domain) → ApprovalRequested
  → ALLOW     → Safety::clear → audit ("no evidence, no action") → boundary → ExecOrder → adapter host
Monitor::admit_approval → decide_intent(…, Some(answer)) → (as above, with Safety run again)
```

An answer from someone not entitled to give it does **not** close the question; otherwise anyone could cancel other people's escalations. Escalations expire with the intent's deadline and are audited (C14: no response ≠ consent).
