# 15 — Intent and Approval

Sources: Blueprint v19 (Authority & Safety Fabric), v20 "Intent Model"; crate `chitala-intent`.

## Invariant 1

> **AI produces Intent. Chitala produces Authority. Only the trusted execution boundary produces physical Commands.**

This is the first invariant of the code base, ahead of C1–C14 (spec 00). It follows that:

| Who | May produce | Never produces |
|---|---|---|
| an AI principal | an `Intent` (signed with its own key) | a CSME `command` (`E_INTENT_REQUIRED`), a physical command |
| Chitala (Authority Engine, spec 16) | a `Grant` for exactly one intent | a physical command |
| Safety (spec 17) | a `Clearance` for exactly one action | authority (it can only refuse) |
| the Trusted Execution Boundary (`chitala-boundary`, spec 19) | the physical command = an `ExecOrder` signed with its order key (`application/chitala-order`) | — |

`Grant` and `Clearance` have no public constructor and are not `Clone`. `TrustedExecutionBoundary::mint` consumes both. It accepts only a clearance of the same intent that describes exactly the granted action (resource, capability, device, parameters) and is fresh (≤ 1 s).

The adapter host only executes `ExecOrder`s (spec 10). Persons and services keep their direct CSME path, but since v0.2 their device actions also pass Safety and the same boundary (spec 19); for an AI, the intent is the only path.

## Intent ≠ Command

```text
actor → on_behalf_of → action → resource → context → constraints → requested_at
```

| | Intent | Command (`ExecOrder`) |
|---|---|---|
| Signed by | the AI (actor) | the Trusted Execution Boundary (order key) |
| Target | a **resource** (`resource:front-door`) | a device (`device:front-door`) |
| Risk | not declared — Chitala computes it | decided |
| Capability version | no | yes |
| Validity | ≤ 10 minutes (long enough for a human to answer) | ≤ 30 s, single use |
| COSE content type | `application/chitala-intent` | `application/chitala-order` |

Because the content types differ, a signature of one kind is never accepted as the other (test `intents_are_not_commands`).

## Wire format

A `COSE_Sign1` (Ed25519, 16-byte kid) of a deterministic CBOR map with **exactly** these keys (unknown keys → refused):

| Key | Field | Type |
|---:|---|---|
| 1 | version (= 1) | uint |
| 2 | intent id | bstr(16) |
| 3 | actor — MUST be the signer | tstr entity id |
| 4 | on_behalf_of — MUST be `person:*` | tstr |
| 5 | action | tstr capability id |
| 6 | resource | tstr `resource:*` |
| 7 | params (omitted when empty) | map tstr → bool/int/tstr |
| 8 | context.purpose — data, never instructions | tstr ≤ 280, optional |
| 9 | context.cause — the signed intent this one relays | bstr, optional |
| 10 | constraints.deadline (ms) | uint |
| 11 | constraints.max_risk | uint, optional |
| 12 | constraints.no_escalation (present only as `true`) | bool, optional |
| 13 | requested_at (ms) | uint |
| 14 | authority — the actor's capability token | bstr ≤ 4096, optional |

Shape rules:

- `on_behalf_of` is a person, and a person acts only for themselves.
- `requested_at < deadline ≤ requested_at + 600 000`.

Constraints **only narrow** what Chitala may do:

- `max_risk` → refuse instead of executing when the risk is higher;
- `no_escalation` → refuse instead of asking a human.

### On behalf of

Agency is **declared at enrollment** (`serves` in the config, `IdentityRegistry::set_serves`) and never claimed per request. An AI may only send intents for the people it serves (`E_ON_BEHALF_OF`).

### Relay (agent-to-agent)

An agent relays another agent's request by attaching that agent's signed intent as `context.cause` (at most 3 causes). Every link is checked: actor = signer, with an enrolled key. The authority of the chain is the **intersection** of every link (spec 16): relaying never adds authority.

## Approval

A human's answer to an escalated intent. A `COSE_Sign1` with content type `application/chitala-approval`:

| Key | Field | Type |
|---:|---|---|
| 1 | version (= 1) | uint |
| 2 | intent id | bstr(16) |
| 3 | intent digest = SHA-256 of the intent body | bstr(32) |
| 4 | approver — MUST be the signer, `person:*` | tstr |
| 5 | verdict: 1 approve, 2 reject | uint |
| 6 | issued_at (ms) | uint |
| 7 | expires_at (ms), ≤ issued_at + 600 000 | uint |
| 8 | note | tstr ≤ 280, optional |

The digest binds the approval to **exactly** the intent content the human saw (`domain.list_approvals` returns the digest, the quorum and who has approved so far). An approval is single-use (replay protected by `(kid, intent id)`): one person answers an intent once, and a person who signed the intent itself cannot also approve it.

On a two-key resource (spec 14) the node keeps every valid approval and waits until two different people have agreed; until then it answers `escalate` with the people it is still waiting for. Any rejection ends the question (spec 16 "Two keys").

## Unforgeable types

`VerifiedIntent` and `VerifiedApproval` can only be created by `SignedIntent::open` / `SignedApproval::open`. Opening verifies the signature, decodes the body, checks actor/approver = signer, and opens every cause. The Authority Engine accepts only these two types, so code in the node cannot hand it an unauthenticated intent.
