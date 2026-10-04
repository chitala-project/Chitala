# 21 — Execution Lease v0.1

Sources: v0.2 roadmap step 8; Blueprint v20 §8, §11 (execution) and v19; threat model R6 (*conditional approvals*); the Project Lead's decisions of 2026-10-04 (high-risk leases are allowed when an owner approves the lease's terms, within tight limits; critical actions and two-key resources never). Code: `chitala-intent` (wire format), `chitala-policy::authority` (grant and use), `chitala-node` (lease store, counting, revocation).

## Why

An `ExecOrder` is one action, once (spec 19). Some situations need the same action several times within limits, for example:

- *let the cleaner in, at most twice, between 9 and 10*;
- *keep the bedroom between 20 and 24 °C this evening*.

Asking a human each time breeds approval fatigue. Handing out a standing permission breaks least privilege.

A **lease** is the middle ground. It records **one** authority decision, and for a high-risk action **one** human approval of exact terms: an action on a resource, a parameter envelope, a number of uses and a time window. Each use is still a separate intent that is judged again, cleared by Safety and executed as its own single-use `ExecOrder`.

> A lease grants execution inside an envelope; an `ExecOrder` is one use of it.

## What a lease holds

| Field | Meaning |
|---|---|
| `lease_id` | 16 random bytes, chosen by the node |
| `intent` | id and digest of the intent that asked for it; any approval binds to this digest |
| `actor`, `on_behalf_of` | who may use it, for whom |
| `resource`, `capability` | the one action, on the one resource |
| `fixed` | the parameters every use must repeat exactly (those of the asking intent outside the envelope) |
| `envelope` | per integer parameter, a range `[min, max]` the uses may choose from |
| `granted_at`, `expires_at` | the window; `expires_at` is never later than any backing token's expiry |
| `max_uses`, `uses` | how many orders it may yield, and how many it has |
| `risk` | the effective risk at the resource when granted |
| `approved_by` | the owners who approved the terms (high risk) |
| `tokens` | revocation ids of the capability tokens it was granted on |
| `epoch` | the authority epoch it was granted in. The grant's audit record carries the lease id, and so does every use's |

## Asking for a lease

An intent with a `lease` request (intent version 2, key 15; see *Wire format*) asks for a lease instead of an action. It names the action, the resource, its fixed parameters, and the terms: `max_uses`, `duration_ms` and the envelope. The asking intent itself **executes nothing**.

The full intent pipeline judges it, as if it were the action:

- identity, freshness and replay;
- the token and its proof of possession;
- the binding to the person;
- policy and the Constitution;
- the effective risk at the resource.

On top of that, the request is refused with `E_LEASE_DENIED` when:

- the resource is **two-key**, or the effective risk is **critical** (C9: one decision per critical action, always);
- the risk is **high** and the terms ask for more than **3 uses** or more than **1 hour**;
- the terms ask for more than **16 uses** or more than **8 hours** (any risk);
- the intent is relayed from another agent (v0.1 leases are first-hand only);
- the envelope names a parameter that is not an integer parameter of the capability, or reaches outside the registry's limits or the resource's envelope;
- the actor already holds **4 active leases**, or the domain holds **256**.

When a human must decide (C11, high risk for an agent), the escalation shows the terms. The owner's approval binds to the asking intent's digest, which **includes the terms**, so the owner approves exactly these uses, this window and this envelope, and nothing wider. A request with `no_escalation` that needs a human is refused, as for any intent.

If granted, the node records the lease and answers `ALLOW` with `{lease: {id, expires_at_ms, max_uses, envelope}}`.

## Using a lease

A use is an intent with key 16 (the lease id). It is accepted only if all of the following hold, in this order:

1. **Identity.** The intent is signed by the lease's `actor` (proof of possession), is fresh and is not a replay (spec 08). Being given a lease id is not authority.
2. **The lease.** It exists (`E_LEASE_UNKNOWN`), is not revoked (`E_LEASE_REVOKED`), is not past `expires_at` (`E_LEASE_EXPIRED`) and has uses left (`E_LEASE_EXHAUSTED`).
3. **The match** (`E_LEASE_MISMATCH`):
   - the same actor, the same person, the same action and the same resource;
   - the same tokens: the use presents the token the lease was granted on;
   - no relay.
4. **The envelope** (`E_LEASE_ENVELOPE`):
   - every fixed parameter is repeated exactly;
   - every envelope parameter lies in its range;
   - nothing else is present.
5. **Authority, again.** The Authority Engine runs its full pipeline, because tokens may have been revoked, floors raised, principals quarantined, roles and policy changed. Only the approval step differs:
   - the lease's own approval counts, if at least one owner who approved the terms **is still able to approve** this risk at this resource (`E_APPROVAL_INVALID` otherwise);
   - a use never escalates to a human;
   - anything the lease does not cover is refused.
6. **Safety** runs in full on this use's parameters and the current state of the world (spec 17). A hold, stale state or the device's own rules refuse it as they would any action. A use that Safety refuses is **not** counted.
7. **The use is counted, and persisted, before the order exists.** The node increments `uses`, bumps the authority epoch and writes its state. Only then does the boundary mint the order (spec 19). A crash after counting spends the use; it is never replayed.

The resulting order is an ordinary `ExecOrder`: single use, bound to one executor session, valid for at most 30 s, with its receipt checked. Its decision record names the lease and the use number (`n` of `max_uses`) and points to the grant's audit record. The provenance chain is: receipt → order → use decision → lease grant → (approval) → asking intent.

## Ending a lease

A lease ends when the first of these happens:

| How | Effect |
|---|---|
| its last use is counted | `E_LEASE_EXHAUSTED` afterwards |
| `expires_at` passes | `E_LEASE_EXPIRED` |
| `domain.lease_revoke` by an owner or admin, by the person it acts for, or by one of its approvers; never by an AI (C11) | `E_LEASE_REVOKED`. An order already in flight from it is stopped by the authority fence (spec 19) |
| a backing token is revoked, or a revocation floor covers it | every later use fails at Authority (`E_TOKEN_REVOKED`) |
| the actor or the person can no longer act (quarantine, removal) | refused at Authority |
| no approver of a high-risk lease can still approve | `E_APPROVAL_INVALID` |

A safety hold does not end a lease. It refuses each use while the hold lasts, and those refused uses are not counted.

`domain.list_leases` shows the active leases. Owners and admins see all of them; everyone else sees those they use or that act for them. AIs cannot list them (C11).

## Persistence and restart

Leases are part of the persisted domain state (spec 11), including `uses`:

- granting, using and revoking each bump the authority epoch, so a state file rolled back to fewer uses (or to an un-revoked lease) is refused at start-up;
- after a restart, every lease is exactly as it was;
- a lease stays in the state until an hour after its expiry, so a late use learns why it is refused; then it is dropped, and its audit records remain. The state keeps at most 1 024 leases, dropping ended ones first.

A lease use that is refused — by its lease, by Authority or by Safety — is never counted.

## Wire format

Intent **version 2** is version 1 (spec 15) plus two optional keys. An intent without them is encoded as version 1, byte for byte, so existing intents, digests and approvals are unchanged. Version 1 with key 15 or 16 is refused. So is version 2 without either.

| Key | Field | Type |
|---:|---|---|
| 15 | lease request | map: `1` max_uses (uint 1..16), `2` duration_ms (uint 1 000..28 800 000), `3` envelope (map tstr → [int min, int max], optional, ≤ 8 entries, `min ≤ max`) |
| 16 | lease id (a use) | bstr(16) |

At most one of keys 15 and 16 is present. A lease request may not be combined with a relay (`cause`).

## Deny codes

| Code | When |
|---|---|
| `E_LEASE_DENIED` | the request cannot be granted (terms, risk, two-key, relay, limits) |
| `E_LEASE_UNKNOWN` | no such lease (never granted, or ended and dropped) |
| `E_LEASE_MISMATCH` | the use is not what the lease covers (actor, person, action, resource, token, relay) |
| `E_LEASE_ENVELOPE` | a parameter outside the envelope, a changed fixed parameter, or an extra one |
| `E_LEASE_EXHAUSTED` | every use has been spent |
| `E_LEASE_EXPIRED` | past `expires_at` |
| `E_LEASE_REVOKED` | revoked explicitly |

## What a lease is not

- **Not a token.** It lives only in the node, is never handed out as a bearer object, and cannot be delegated or attenuated. A lease id alone is worthless without the actor's key.
- **Not new authority.** It never covers more than the asking intent was allowed: the same action, resource, person and tokens, inside the registry's and the resource's limits, and no longer than the tokens.
- **Not a bypass of Safety or the boundary.** Every use is cleared by Safety and executed as one single-use order.

## Tests

`crates/chitala-node/tests/lease.rs` and `chitala-intent`, `chitala-policy` unit tests:

- **Uses:**
  - a lease is used up to its limit, then refused;
  - an envelope escape, a changed fixed parameter or an extra one is refused;
  - another actor, person, action, resource or token is refused, and so is a relay.
- **Approval:**
  - a high-risk lease is escalated, approved once for exactly its terms, and used without asking again;
  - more than 3 uses or 1 hour at high risk is refused, and so are critical risk and two-key resources;
  - an approver who loses the right to approve stops the lease.
- **Ending:**
  - explicit revocation, revocation of the backing token, a revocation floor and quarantine each stop the next use;
  - a lease revoked while its order is in flight stops the order;
  - a hold refuses a use without spending it;
  - an expired lease is refused.
- **Persistence:**
  - uses survive a restart;
  - a state file rolled back to fewer uses is refused;
  - a replayed use intent is refused.
- **AIs:** an AI cannot revoke or list leases.
- **Wire:**
  - an intent without a lease encodes exactly as version 1;
  - malformed lease keys, version mismatches, both keys at once, and terms outside the limits are refused.
