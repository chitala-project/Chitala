# 05 — Capability Token

Sources: v8 §2 (very narrow capability tokens), v8 §8 (delegation never amplifies), v12 §18 (cross-domain capabilities), v13 §3 (audience-bound, object-scoped), v19 §4.2 (not-before, proof of possession); milestone v0.2 step 3 *Delegation, revocation and two-key approval*.

## Format (version 2)

A token is a [Biscuit](https://www.biscuitsec.org/) (Ed25519) signed with the **domain's authority key**, not a global key (C7). The authority block:

```datalog
chitala_token(2);                                    // format version; any other is refused
holder("ai:assistant");                              // only this principal can use the token…
holder_key("<hex key id>");                          // …in a message signed with this key (proof of possession)
issuer("person:alice");                              // who delegated it
depth(1);                                            // 1 = issued from ambient authority; at most 3
redelegate(0);                                       // further hops the holder may hand it on; 0 = non-transferable
for("person:alice");                                 // an agent's token: the persons it may act for
not_before_ms(0);  expires_ms(1790999985000);        // validity window (expiry aligned to whole seconds)
issued_epoch(41);                                    // the domain's revocation epoch at issue
chain("person:alice");                               // every issuer from the root grant down to this one
right("resource:living-room-light", "light.turn_on"); // 1..32 explicit rights, no wildcards
parent("<revocation id of the parent token>");       // only on re-delegated tokens
check if time($t), $t >= <not before>, $t < <expiry>;
```

Limits: ≤ 4096 bytes, ≤ 8 blocks, ≤ 32 rights, `depth + redelegate ≤ 3`. A token's revocation id is the hex signature of its authority block (128 hex characters).

A right's target is a device, the domain, or a **resource** (spec 14). On the intent path, a right on a resource also covers everything below it: the token is checked against the resource and then each of its ancestors.

## Mapping v8 §2 / v19 §4.2 → token

| Property | Token |
|---|---|
| Actor | `holder` + `holder_key`: the request, intent or relayed intent must be signed by the holder **with that key** |
| Target, Capability | `right(target, capability)` |
| Context | `for(person)` on an agent's token; attenuation blocks can add more constraints |
| Time | `not_before_ms`, `expires_ms` + `check if time` |
| Transfer | `redelegate(n)`: 0 by default (non-transferable) |
| Rate/quantity | per-actor rate limit in the monitor (30 requests / 10 s); per-token quotas come later (ExecutionLease) |
| Safety budget | registry envelope, resource envelope and the safety layer (not in the token) |
| Delegation chain | `issuer`, `depth`, `chain(...)`, `parent(...)` |
| Revocation | the domain's revocation list (ids, cascading to every child) and revocation floors (`issued_epoch`) |

## Verifying and authorizing a use

1. The block chain's signatures verify against the domain authority key, and the format is 2; otherwise `E_TOKEN_INVALID`.
2. The token is revoked if any of its revocation ids (every block and every `parent`) is in the revocation list, or if it was issued before a revocation floor that applies to it (below) → `E_TOKEN_REVOKED`.
3. The use must match the binding; otherwise `E_TOKEN_DENIED`:
   - **holder**: the actor is the holder;
   - **proof of possession**: the message was signed with the holder's key named in `holder_key`. A stolen token is useless without the key, and re-enrolling a principal with a new key retires all of its tokens;
   - **person**: on an agent's token, the person the agent acts for in this message (`on_behalf_of` of the intent; for a request, a person the agent serves) is one of the `for` persons;
   - **window**: `not_before_ms ≤ now < expires_ms`.
4. The authorizer inserts the request's `actor`, `target`, `capability` and `time` and runs
   `allow if actor($a), holder($a), target($t), capability($c), right($t, $c);`.
   Every `check` of every block must pass; otherwise `E_TOKEN_DENIED`.

A valid token only sets `context.token_granted = true` for policy. The constitution can still `forbid`: an AI holding a `lock.unlock` token still needs an owner's approval (`C11-ai-no-high-risk`, spec 16).

## Context binding

An **AI agent**'s token always names the persons it may act for. When a person delegates to an agent (`domain.delegate`), the binding is:

1. the person named in `for_person`, if any (the agent must serve them);
2. otherwise the delegator, if the agent serves them;
3. otherwise the one person the agent serves;
4. otherwise the delegation is refused: say for whom.

Persons act for themselves, and devices and services represent nobody, so their tokens are unbound (and a binding on them is refused). A family agent that serves alice and bob therefore cannot use alice's grant when it acts for bob. The binding never widens: a re-delegation of a bound token keeps the same persons or fewer, and can only go to another agent.

## Offline attenuation

A holder can add blocks containing only `check`s (narrower targets or capabilities, shorter expiry) without asking anyone. Biscuit guarantees that later blocks **only narrow**: `right`, `holder`, `holder_key`, `for` and `redelegate` facts in an attenuation block are trusted neither by the authority block nor by the authorizer (test `attenuation_block_cannot_inject_rights_holder_key_or_binding`).

## Delegating to another principal (server-mediated)

Changing the `holder` cannot be done offline; it goes through `domain.delegate` (spec 11), where the node checks:

| Rule | Error |
|---|---|
| The delegator holds the parent token (or, without a parent token, has ambient authority under policy) | `X_DELEGATION_DENIED` |
| The parent token is **transferable** (`redelegate > 0`); the child's budget is `min(requested, parent − 1)`. A grant is non-transferable unless the grantor says otherwise | `X_DELEGATION_DENIED` |
| `child.rights ⊆ parent.rights`, and the parent token really authorizes each right right now, for its holder, with the holder's key | `X_DELEGATION_DENIED` |
| `child.window ⊆ parent.window`: start = max, expiry = min | (clipped) |
| The binding never widens | `X_DELEGATION_DENIED` |
| `depth ≤ 3` | `X_DELEGATION_DENIED` |
| The parent token must **not** be an attenuated token (its checks would be lost in the new token) | `X_DELEGATION_DENIED` |
| Nobody delegates to themselves | `X_DELEGATION_DENIED` |
| The holder must be *able* to use the right under policy. On a device, an AI is never handed a right the constitution forbids it to use. On a resource, a right that needs a human's approval at each use may be delegated | `X_DELEGATION_DENIED` |
| An AI never delegates (`C11-ai-no-domain-admin`) | `E_INTENT_REQUIRED` / `E_POLICY_DENIED` |

The property test `delegation_never_amplifies` checks that for every parent/child right set, expiry and start, a child token never authorizes a right its parent lacks, and that its window and budget only shrink.

### The chain of agents

Because agents never hand rights on (C11), a chain such as *Human → Personal AI → Home AI → Security Agent* is a chain of **signed relays** (spec 15): each agent holds its own right from the human, and the chain can do only what **every** link can do, for the person they all act for (test `the_whole_chain_is_the_intersection_of_its_links`). Revoking any link's right stops the whole chain.

## Revocation

Revocation takes effect at once for everything that still needs its authority checked. The Reference Monitor and the Authority Engine check every use, approvals re-run Authority, and an order in flight is re-checked right before it is sent (spec 19, *authority fence*).

It reaches nothing past that point:
- **An order already sent.** Past the fence, nothing recalls it. Its lifetime (spec 19: 10 s by default, at most 30 s) bounds only how long the adapter host's gate still accepts it. It does not cancel an order the gate has accepted, nor one queued beyond the adapter host, in a gateway or a device.
- **What was carried out.** A revocation undoes nothing, and does not stop a motion already running. Stopping takes a stop (spec 30).
- **A device that cannot be reached.** An order whose fate is unknown stays unknown (spec 22). Chitala never sends it again, but a gateway or a device that accepted it may still carry it out.

Tests:
- before the fence, and after the action: `a_domain_wide_revocation_before_the_fence_and_after_the_action`;
- past the fence, before the device acts: `a_revocation_after_the_fence_does_not_reach_an_order_on_its_way` (it models a hostile or slow channel; it is no evidence of how the production transport classifies such an order);
- a motion already running: `a_revocation_does_not_stop_a_motion_already_running`.

- **One token** — `domain.revoke_token`: the token and, by cascade, everything delegated from it. An issuer in the chain, an owner or an admin may do it.
- **Revocation floors** — `domain.revoke_all`: the node raises the domain's revocation epoch to `N` and records a floor. Every token issued before `N` in which the principal appears as holder, issuer or anywhere in the `chain` dies at once, without anyone having to know its id (a lost phone, a compromised agent). Without a principal, the floor covers **every token of the domain** (the panic button). Floors only rise. Owners and admins may set a floor for anyone; everyone may set one for themselves. Tokens issued after the floor are unaffected.

## Security notes

- A token travels inside a CSME (key 13) or an intent (key 14), and so over IPC. An eavesdropper who captures a token **cannot use it**: it is bound to the holder's key and the message must carry the holder's signature.
- Tokens are never written to the audit log. The log only holds revocation ids (`parent_token` is redacted, spec 09), and every issue, revocation and floor with the epoch.
- Token files on disk have mode `0600` in a `0700` directory. A holder may keep several tokens, one base64 token per line.
- Format 1 tokens (before v0.2 step 3) are refused: they carry no key binding.
