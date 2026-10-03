# 11 — Home/Site Node, IPC and operations

Sources: v9 "Chitala Home/Site Server", v10 §2/§6–8/§10–11 (manager authentication, keys, revocation), v8 §9 (automatic containment), v13 §7 (anti-rollback), §8 (anti-DoS), §11 (security state machine), v17 §3–4.

## Config (`chitala.json`)

```json
{
  "domain": "domain:home",
  "node_id": "service:node",
  "authority_public_key": "<hex>",
  "node_public_key": "<hex>",
  "keys_dir": "keys",
  "socket": "chitala.sock",
  "audit_log": "audit.audit.jsonl",
  "state_file": "domain-state.json",
  "policy_file": null,
  "principals": [ { "id": "person:alice", "public_key": "<hex>", "roles": ["owner"] },
                  { "id": "ai:assistant", "public_key": "<hex>", "serves": ["person:alice"] } ],
  "devices":    [ { "id": "device:front-door", "name": "…", "adapter": "mock",
                    "capabilities": ["device.read_state", "lock.lock", "lock.unlock"],
                    "security_class": "SC3", "room": "entrance" } ],
  "resources":  [ { "id": "resource:front-door", "kind": "door", "name": "…", "parent": "resource:entrance",
                    "boundary": "perimeter",
                    "bindings": [ { "capability": "lock.unlock", "device": "device:front-door" } ],
                    "state": { "device": "device:front-door", "max_age_ms": 120000 } } ],
  "home_assistant": { "base_url": "https://…", "token_env": "HA_TOKEN", "entities": {}, "allow_insecure_http": false },
  "containment": { "window_ms": 60000, "suspicious_after": 5, "restricted_after": 10, "quarantine_after": 20 }
}
```

The config holds **public keys only**. Relative paths are resolved from the config's directory.

- `serves` declares the people an AI acts for (spec 15).
- `resources` is the governed physical world (spec 14), checked against `devices` at start-up.

## File permissions

| Object | Mode | Enforced by |
|---|---|---|
| `keys/`, `tokens/` | `0700` | `chitala init` |
| key files | `0600`; readable by group/others → **refused** (like ssh) | `read_key` |
| audit log, state file | `0600`; an audit log writable by group/others is refused | node |
| socket | `0600` | node |

## IPC

JSON Lines over a Unix domain socket: `{"op":"hello"}`, `{"op":"submit","csme":"<hex>"}`. Limits: lines ≤ 64 KiB, ≤ 64 concurrent connections, 30 s read/write timeout. A protocol error closes the connection.

`submit` accepts every signed Chitala message, and the node picks the path from the COSE content type:

| Content type | From | Path |
|---|---|---|
| `application/chitala-csme` | persons, services, devices (AIs: queries only) | the 5-stage Reference Monitor (spec 08) |
| `application/chitala-intent` | AIs (and persons) | admission → Authority Engine → Safety → (approval) → boundary (specs 15–17) |
| `application/chitala-approval` | persons (owners of the resource) | answers an escalation |

Replies carry `decision` ∈ `allow | deny | escalate`. The intent path adds `step` (the Authority Engine step). An `escalate` reply also carries `approvers`, `deadline_ms`, and `mid` = the intent id. CLI exit code 4 means escalated.

**The socket is not a trust boundary** (v9 §13): every request is a signed message and goes through the Reference Monitor.

### Authentication in the other direction (v10 §2)

Every reply is signed by the node:

```
reply.request = hex( SHA-256(request bytes)[0..16] )
reply.node, reply.kid
reply.sig     = Ed25519_node( "chitala-node-reply-v1" 0x00 ‖ JCS(the reply without "sig") )
```

A client MUST verify `sig` with the `node_public_key` **pinned in the config**, and check that `request` matches the request it just sent; otherwise it discards the reply. A process impersonating the socket therefore cannot report a fake "allow", hand out a fake token, or pass off the genuine reply to another request as the answer to this one (tests `client_refuses_an_impostor_node`, `forged_or_misbound_replies_are_rejected`).

### Socket path

Unix socket paths are limited to about 104 bytes (macOS). If the configured path is longer, node and clients both use `/tmp/chitala-<h>/<hash>.sock`, where `<h>` is a hash of the domain directory (one directory per domain).

- That directory MUST be a real directory (not a symlink), owned by the owner of the domain directory, with mode `0700`; otherwise the node refuses.
- The uid is only compared, never written into names or messages.
- The node removes an old file only if it really is a socket and nobody is listening on it.

## Domain operations

All are capabilities with `target = domain` and go through the same Reference Monitor and policy.

| Capability | Who (default policy) | Extra checks in the node |
|---|---|---|
| `domain.list_devices` | owner, admin, adult; an AI only with a token | — |
| `domain.list_approvals` | owner, admin, adult; **never an AI** (C11) | returns only the escalations the caller may answer, with the digest to sign |
| `domain.delegate` | owner, admin, adult; **never an AI** (C11) | spec 05 "Delegating to another principal"; the target may be a resource (spec 14 "Rights follow the tree") |
| `domain.revoke_token` | owner, admin, adult; never an AI | the caller must be an issuer in the token's delegation chain, or an owner/admin |
| `domain.set_principal_state` | owner, admin; never an AI | a valid transition (spec 03); nobody changes their own state |

Every change of authority: `epoch += 1` → write the state file → write an audit record with a signed checkpoint → publish an event.

## Automatic containment (v8 §9, v11 §16.4)

Containment applies only to **non-human** principals, and only to **authenticated** denials of the probing kind:

`E_PRINCIPAL_STATE`, `E_TOKEN_MISSING`, `E_TOKEN_INVALID`, `E_TOKEN_REVOKED`, `E_TOKEN_DENIED`, `E_POLICY_DENIED`, `E_UNKNOWN_TARGET`, `E_UNKNOWN_CAPABILITY`, `E_UNSUPPORTED_BY_TARGET`, `E_RISK_MISMATCH`, `E_REPLAY`, `E_RATE_LIMITED`, `E_INTENT_REQUIRED`, `E_UNKNOWN_RESOURCE`, `E_ON_BEHALF_OF`, `E_PROVENANCE`.

Within a 60 s window: 5 → `SUSPICIOUS`, 10 → `RESTRICTED`, 20 → `QUARANTINED`.

- Honest mistakes (expiry because of clock skew, wrong parameters) and safety refusals do not count.
- Forged requests in someone else's name do not count (they are not authenticated).
- The machine only **escalates** and never de-escalates by itself. Bringing a principal back to `TRUSTED` is a human decision, through `RECOVERY → RE_ATTEST → TRUSTED`.
- Humans are not contained automatically (so an owner cannot lock themselves out); they are still rate limited.

## Time (Blueprint v16 §4, threat model R3)

The expiry of tokens, requests, intents and execution orders all depends on the node's time. The system clock is only an **input**, not an authority:

```
now = max(system clock, previous reading + time elapsed on the monotonic clock)
```

- **Never backwards.** A system clock set back is ignored: an attacker trying to revive an expired token, a dead RTC battery, or a wrong NTP step. Time keeps advancing on the monotonic clock, and every regression ≥ 1 s is written to the audit log (`kind: "clock"`, `event: "wall_clock_regression"`) with a signed checkpoint.
- **Forward corrections are followed** (NTP syncing after boot). Moving forward is the safe direction: tokens and requests can only expire earlier.
- **Floor**: the node never starts earlier than the last event in the audit log (`max ts_ms`).
- **Start-up**: if the system clock is more than 60 s behind the last audited event, the node **refuses to start**; fix the system time first.
- The adapter host uses the same algorithm, so node and host agree on when an execution order expires.

Verified by `time::clock_rollback_cannot_revive_an_expired_token`, `time::startup_refuses_a_clock_behind_the_audit`, `clock::tests::*`.

Limits: there is no authenticated time source (NTS/Roughtime) or trusted hardware clock yet; synchronising time across nodes belongs to the distributed phase.

## Integrity at start-up

Before accepting requests, the node checks that:

1. The authority and node keys on disk match the public keys in the config.
2. The whole audit chain is valid and its checkpoints are correctly signed.
3. The audit log still contains the `audit_anchor` recorded in the state file. This detects an audit log that was **deleted, truncated or replaced**.
4. The highest `epoch` in the audit log ≤ the state file's `epoch`. This detects a state file that was **rolled back or deleted** — the attack of un-revoking tokens by copying an old state file over the current one.
5. The system clock is no more than 60 s behind the last audited event (see "Time").
6. Every request signed before the start is refused (the replay cache does not survive a restart).

If any check fails → `NodeError::Integrity` and **the node does not start**. Stopping is better than silently forgetting revocations or quarantines (fail closed).

The write order (state first, then audit) ensures that a power failure between the two steps only leaves a state *newer* than the audit. That case is accepted and not mistaken for a rollback.

### Recovery

When the node refuses to start because of integrity, the operator investigates (`chitala audit verify`), restores a consistent state + audit pair from a clean backup (v11 §21.1), and only then restarts. There is no "skip the checks" flag.

**Known limit**: someone with write access could replace the state with an old one *and* truncate the audit back to exactly the old anchor. Two files on the same disk cannot prove their own freshness. That needs an external anchor such as a TPM monotonic counter, checkpoints pushed to another device, or a transparency log (spec 13).

## Internal node failures

If a request makes the node panic half-way (a poisoned mutex), the node considers its state no longer trustworthy and **refuses every request** until it is restarted.
