# 08 — Reference Monitor

Sources: v8 §1 (non-bypassable AI Reference Monitor), v11 §16.1, v13 §3 (confused deputy), v17 §3 ("every sensitive operation must go through the Reference Monitor").

```
Person / Service → (signed CSME)   → Reference Monitor → Adapter / domain operation
AI               → (signed intent) → Reference Monitor → Authority Engine → Safety → trusted boundary
```

## Non-bypassable

In the reference implementation, an allowed CSME request is an `Authorized` value with no public constructor, no `Clone` and no `Default`. Adapters and domain operations only accept `&Authorized`, so no code path controls a device without going through `Monitor::check`, not even test code (spec 10). On the intent path the equivalent is the `Grant` of the Authority Engine (spec 16). The monitor lives outside the AI process and consists only of memory-safe Rust (`#![forbid(unsafe_code)]`).

## Pipeline

The first failing check stops the pipeline and returns its code. The order is part of the contract.

| # | Stage | Check | Code |
|---|---|---|---|
| 1 | envelope | valid COSE, size, headers | `E_DECODE` |
| | | alg = Ed25519 (-19) | `E_ALG` |
| | | no COSE `crit` | `E_CRITICAL_EXT` |
| 2 | identity | `kid` is enrolled | `E_UNKNOWN_KEY` |
| | | signature | `E_BAD_SIGNATURE` |
| | | payload: CBOR, canonical, version, crit, message type | `E_DECODE`, `E_NON_CANONICAL`, `E_VERSION`, `E_CRITICAL_EXT`, `E_UNSUPPORTED_TYPE` |
| | | actor = signer | `E_ACTOR_KEY_MISMATCH` |
| | | the security state allows acting | `E_PRINCIPAL_STATE` |
| | | ≤ 30 requests / 10 s / actor | `E_RATE_LIMITED` |
| | | an AI does not send `command`s (Invariant 1) | `E_INTENT_REQUIRED` |
| 3 | freshness | type ∈ {command, query} | `E_UNSUPPORTED_TYPE` |
| | | `timestamp ≤ now + 5 s` | `E_NOT_YET_VALID` |
| | | `timestamp < expiry`, `now < expiry` | `E_EXPIRED` |
| | | `expiry − timestamp ≤ 60 s` | `E_LIFETIME_TOO_LONG` |
| | | `timestamp ≥` the node's start time | `E_REPLAY` |
| | | `(kid, messageId)` never seen | `E_REPLAY` |
| 4 | capability | the target exists in the domain | `E_UNKNOWN_TARGET` |
| | | the capability is in the registry | `E_UNKNOWN_CAPABILITY` |
| | | the version matches | `E_CAPABILITY_VERSION` |
| | | the target supports the capability, right target kind | `E_UNSUPPORTED_BY_TARGET` |
| | | action ↔ command, query ↔ query | `E_KIND_MISMATCH` |
| | | declared risk = registry risk | `E_RISK_MISMATCH` |
| | | risk ≤ the security state's ceiling (spec 03 M3) | `E_PRINCIPAL_STATE` |
| | | payload matches the schema / is within the safety envelope | `E_PAYLOAD_INVALID` / `E_SAFETY_ENVELOPE` |
| 5 | authority | a non-person principal MUST carry a token | `E_TOKEN_MISSING` |
| | | token: domain signature, revocation, authorization | `E_TOKEN_INVALID`, `E_TOKEN_REVOKED`, `E_TOKEN_DENIED` |
| | | policy (Cedar) | `E_POLICY_DENIED`, `E_POLICY_ERROR` |

`E_INTERNAL` is reserved for unforeseen internal errors and is always a deny.

## Intents and approvals

Intents (spec 15) and approvals go through the same monitor, with corresponding stages:

| Stage | Intent (`admit_intent`) | Approval (`admit_approval`) |
|---|---|---|
| envelope | content type `application/chitala-intent` | `application/chitala-approval` |
| identity | kid, signature, body, actor = signer, every `cause` (signature + actor; failure → `E_PROVENANCE`), security state, rate | kid, signature, body, approver = signer, security state, rate |
| freshness | `requested_at ≤ now + 5 s`, `now < deadline`, ≤ 10 minutes, signed after the node started, `(kid, intent id)` used once | the same with `issued_at`/`expires_at`, `(kid, intent id)` |

After admission, `decide_intent` hands over to the Authority Engine (spec 16), in place of CSME stages 4–5. An allowed intent produces a `Grant` (no public constructor), the counterpart of `Authorized`.

## Security rules of the pipeline

- **Authenticate before parsing** (spec 07).
- **Never blame the unauthenticated.** A denial before the signature is verified has `authenticated = false` and carries no `actor`. An attacker forging requests in someone else's name cannot get the victim contained (spec 11).
- **Requests are single-use.** The `messageId` is consumed right after stage 3, even if a later stage denies. A request denied today cannot be replayed after the right is granted (test `denied_request_cannot_be_replayed_after_a_grant`).
- **Replay across restarts.** The replay cache lives in RAM, so every request signed before the node started is refused.
- **Declaring a lower risk** than the real one to dodge policy → `E_RISK_MISMATCH`.
- **Confused deputy** (v13 §3). The monitor always evaluates the authority of the *signing actor*: the MCP broker signs with the AI's key, not its own. On the intent path a relayed request carries its cause, and the chain gets the intersection of every link's authority (spec 16).
- The replay cache is bounded (100 000 entries). When it is full and cannot be pruned, requests are refused (`E_RATE_LIMITED`) instead of forgetting nonces.

## Replies to the sender

The detailed `reason` is only returned to authenticated requesters. Unauthenticated requests only get the code (v4 §5, minimal metadata exposure).
