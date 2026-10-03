# 05 — Capability Token

Sources: v8 §2 (very narrow capability tokens), v8 §8 (delegation never amplifies), v12 §18 (cross-domain capabilities), v13 §3 (audience-bound, object-scoped).

## Format

A token is a [Biscuit](https://www.biscuitsec.org/) (Ed25519) signed with the **domain's authority key**, not a global key (C7). The authority block:

```datalog
chitala_token(1);                                    // format version
holder("ai:assistant");                              // only this principal can use the token
issuer("person:alice");                              // who delegated it
depth(1);                                            // 1 = issued from ambient authority; at most 3
expires_ms(1790999985000);                           // aligned to whole seconds
right("resource:living-room-light", "light.turn_on"); // 1..32 explicit rights, no wildcards
parent("<revocation id of the parent token>");       // only on re-delegated tokens
check if time($t), $t < 2026-10-03T…Z;
```

Limits: ≤ 4096 bytes, ≤ 8 blocks, ≤ 32 rights. A token's revocation id is the hex signature of its authority block (128 hex characters).

A right's target is a device, the domain, or a **resource** (spec 14). On the intent path, a right on a resource also covers everything below it: the token is checked against the resource and then each of its ancestors.

## Mapping v8 §2 → token

| Property (v8 §2) | v0.1 |
|---|---|
| Actor | `holder`: holder-bound, so the request, intent or relayed intent must be signed by the holder itself |
| Target, Capability | `right(target, capability)` |
| Context | (reserved) an attenuation block can add constraints |
| Time | `expires_ms` + `check if time` |
| Rate/quantity | per-actor rate limit in the monitor (30 requests / 10 s); per-token quotas come after v0.1 |
| Safety budget | registry envelope, resource envelope and the safety layer (not in the token) |
| Delegation chain | `issuer`, `depth`, `parent(...)` |
| Revocation | the domain's revocation list, cascading to every child token |

## Verifying and authorizing a request

1. The block chain's signatures verify against the domain authority key; otherwise `E_TOKEN_INVALID`.
2. If any revocation id of the token (every block and every `parent`) is in the revocation list → `E_TOKEN_REVOKED`.
3. The authorizer inserts the request's `actor`, `target`, `capability` and `time` and runs
   `allow if actor($a), holder($a), target($t), capability($c), right($t, $c);`.
   Every `check` of every block must pass; otherwise `E_TOKEN_DENIED`.

A valid token only sets `context.token_granted = true` for policy. The constitution can still `forbid`: an AI holding a `lock.unlock` token still needs an owner's approval (`C11-ai-no-high-risk`, spec 16).

## Offline attenuation

A holder can add blocks containing only `check`s (narrower targets or capabilities, shorter expiry) without asking anyone. Biscuit guarantees that later blocks **only narrow**: `right`/`holder` facts in an attenuation block are trusted neither by the authority block nor by the authorizer (test `attenuation_block_cannot_inject_rights_or_holder`).

## Delegating to another principal (server-mediated)

Changing the `holder` cannot be done offline; it goes through `domain.delegate` (spec 11), where the node checks:

| Rule | Error |
|---|---|
| The delegator holds the parent token (or, without a parent token, has ambient authority under policy) | `X_DELEGATION_DENIED` |
| `child.rights ⊆ parent.rights`, and the parent token really authorizes each right right now | `X_DELEGATION_DENIED` |
| `child.expiry = min(requested, parent.expiry)` | (clipped) |
| `depth ≤ 3` | `X_DELEGATION_DENIED` |
| The parent token must **not** be an attenuated token (its checks would be lost in the new token) | `X_DELEGATION_DENIED` |
| Nobody delegates to themselves | `X_DELEGATION_DENIED` |
| The holder must be *able* to use the right under policy. On a device, an AI is never handed a right the constitution forbids it to use. On a resource, a right that needs a human's approval at each use may be delegated | `X_DELEGATION_DENIED` |

The property test `delegation_never_amplifies` checks that for every parent/child right set and every expiry, a child token never authorizes a right its parent lacks.

## Security notes

- A token travels inside a CSME (key 13) or an intent (key 14), and so over IPC. An eavesdropper who captures a token **cannot use it**: it is holder-bound and the message must carry the holder's signature.
- Tokens are never written to the audit log. The log only holds revocation ids (`parent_token` is redacted, spec 09).
- Token files on disk have mode `0600` in a `0700` directory. A holder may keep several tokens, one base64 token per line.
