# 09 — Audit Log

Sources: v16 §3 (Structured Logging Contract), §4 (time integrity), §7 (Tamper-Evident Audit), §8 (Privacy & Secret Redaction), §27 (when logging fails); v13 §7 (anti-rollback).

## Record format

JSON Lines: one object per line, in **canonical JSON** (RFC 8785, restricted to strings, integers, booleans, null, arrays and objects; no floats). Common fields:

| Field | Meaning |
|---|---|
| `v` | format version = 1 |
| `seq` | 1, 2, 3, … contiguous |
| `ts_ms` | node time |
| `kind` | `node` · `decision` · `execution` · `authority` · `security_state` · `approval` · `clock` · `checkpoint` |
| `prev` | `hash` of the previous record (64 zeros for the first one) |
| `hash` | see below |

```
hash = SHA-256( "chitala-audit-v1" 0x00 ‖ prev(32 bytes) ‖ JCS(the record without "hash") )
```

Fields by `kind` (all a stable contract, v16 §3):

- `decision` (CSME path): `decision` (allow/deny), `code`, `stage`, `reason`, `authenticated`, `actor`, `mid`, `target`, `capability`, `risk`, `token` (revocation id, issuer, depth), `policy` (the `@id`s), `policy_fp`, `epoch`, `payload` (redacted, only on allow).
- `decision` (intent path, `path: "intent"`):
  - common: `decision` (allow/deny/escalate), `mid` (intent id), `actor`, `on_behalf_of`, `relayed_from`, `resource`, `capability`, `purpose`, `digest`, `risk`, `trace` (one entry per Authority Engine step, spec 16), `policy`, `policy_fp`, `epoch`;
  - on deny: `stage`, `step`, `code`, `reason`;
  - on allow: `device`, `approved_by` (the approvers, a list), `tokens`, `safety: "cleared"`, `context` (spec 19);
  - on escalate: `approvers`, `reasons`, `deadline_ms`.
- `decision` (a safe state the node runs after a failed outcome, `safe_state: true`, spec 22): `decision` (allow/deny), `mid`, `actor` (the node), `resource`, `capability`, `trigger` (the failed outcome's `seq`); on allow `device`, `risk`, `payload`, `safety: "cleared"`, `context`; on deny `stage`, `reason`, `safety` (the rule ids).
- `execution`: `mid`, `decision_seq`, `outcome` (ok/error), `code`, `message`, `state_version`, and for device actions the order, its receipt and `verification` (spec 22: status, expected and observed state, witness, independence).
- `outcome`: an outcome settled after the response (spec 22): `status` (verified/diverged/unconfirmed/superseded), `order`, `mid`, `decision_seq`, `execution_seq`, `resource`, `capability`, `expected`, `observed`, `witness`, `independent`, `safe_state`.
- `safety`: `op` (hold/release/recovery), `resource`, `reason`, `by`, `epoch`. A release names what it lifted (`hold`, `recovery`).
- `authority`: `op` (issue/revoke), `token`, `holder`, `issuer`, `right`, `depth`, `expires_at_ms`, `parent`, `by`, `epoch`.
- `plan` (spec 23): `event` (accepted/step_done/waiting_approval/done/stopped/cancelled), `plan`, `status`, `step`, `of`, `step_status`, `step_mid`, `reason`. The `accepted` record carries the intent's fields and every step's `mid`, `capability`, `resource` and `digest`. Each step has its own `decision`, `execution` and `outcome` records under its `mid`.
- `security_state`: `principal`, `from`, `to`, `by`, `reason`, `epoch`.
- `approval`: `intent`, `approver`, `verdict` (approve/reject/expired), `note`, `waited_ms`.
- `clock`: `event` (`wall_clock_regression`), `behind_ms`, `kept_time_ms`: the system clock went backwards (spec 11 "Time").

## Signed checkpoints

```
sig = Ed25519_node( "chitala-audit-checkpoint-v1" 0x00 ‖ head(32 bytes) ‖ seq(u64 big-endian) )
```

The `checkpoint` record (`signer`, `kid`, `sig`) is part of the chain too. The node writes a checkpoint:

- every 64 records;
- **right after every change of authority** (`authority`, `security_state`, `approval`);
- on request.

The signing key is the node's service key, separate from the authority key (spec 02). There is no ecosystem-wide signing key (v16 §7).

## Verification

`chitala audit verify` only needs the node's **public key** from the config, so the verifier is independent of the node under investigation (v16 §7). It detects:

- edited content, deletion, insertion and reordering;
- non-canonical formatting;
- an attacker recomputing hashes without the node key (exposed at the next checkpoint).

The tail after the last checkpoint (`unsigned_tail`) is protected only by the hash chain, not by a signature.

## No secrets in the log (v16 §8)

- Tokens never enter the log, only revocation ids.
- Parameters whose names contain `password`, `passwd`, `secret`, `token`, `credential`, `private`, `pin`, or that are `key`/`*_key` → `"[REDACTED]"`.
- Text longer than 200 characters is truncated; an intent's `purpose` is kept up to 280 characters as data.
- The payload of a denied CSME request is not logged (it may be garbage or attack content).

## Operational safety

- The log file is created with mode `0600`, and the node refuses to open a log writable by group or others. Tamper-evident ≠ public (v16 §7).
- Opening the log verifies the whole chain first. A broken chain means the node does not start.
- **"No evidence, no action"**: an allowed action executes only after its `decision` record is on disk (`fsync`). If writing fails, nothing executes (`X_INTERNAL`). An escalation is recorded before anyone is asked.
- **Anti-rollback anchor**: the domain's state file stores the audit `(seq, hash)` at the time it was written. On start-up the log MUST still contain exactly that record and must not record a higher `epoch` than the state (spec 11 "Integrity at start-up").
