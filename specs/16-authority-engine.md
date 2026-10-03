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

For a relay A → B, the effective authority is `person(A) ∩ token(A) ∩ policy(A) ∩ person(B) ∩ token(B) ∩ policy(B)`. No agent can lend its authority to another.

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

With no answer yet, the decision is **ESCALATE**. The approvers are the effective owners of the resource whose security state still allows them to decide at that risk. If nobody is left → DENY. With `no_escalation` → DENY.

An answer is valid when:

- it names the right intent id **and** digest;
- the approver is one of those approvers;
- `issued_at` is neither before the request nor in the future;
- it has not expired.

`reject` → `E_APPROVAL_REJECTED`.

## Unforgeable in, unforgeable out

`decide(world, &VerifiedIntent, Option<&VerifiedApproval>)`:

- The intent and the approval can only come from a signature check (spec 15).
- The engine checks the tokens itself (`delegation_evidence`).
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
