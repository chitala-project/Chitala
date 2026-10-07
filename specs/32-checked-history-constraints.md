# 32 — Checked history constraints

**Status:** v0.4 step 4. Parts ② (the design) and ③ (the threat model and failure semantics) were reviewed by the Project Lead on 2026-10-07 and approved with three changes, made here: `max_entries` and unknown time, a non-circular `evaluation_context_digest`, and the evaluator as a safety-relevant trusted dependency. Parts ④ and ⑤ implement and test it.

Some limits are about time, not about the state now:
- a pump may run at most 30 minutes in a row;
- a compressor needs 5 minutes off between runs;
- a motor may start at most 6 times an hour.

The history (spec 29) knows these things; the Trusted Core does not. This spec lets that history make Safety stricter, without letting it into the core, and without ever letting it make anything allowed.

## The rule above all others

> **History may make Safety stricter. It never supplies evidence that turns a DENY into an ALLOW.**

A history constraint has two outcomes, and only two:

- **PASS-THROUGH:** this constraint adds no denial. Authority and every other Safety rule still decide, as if the constraint were not there. "The pump ran 5 minutes" never means "allow the pump".
- **DENY:** Safety refuses the action.

There is no ALLOW result. The type has no such value, and the core has no code path that reads one.

## Decisions (Project Lead, 2026-10-07)

| Question | Decision |
|---|---|
| The evaluator is unavailable | **fail closed** for the actions a history rule governs; a stop is never blocked |
| Who declares history rules | an **owner, or an admin explicitly authorized**, through an authenticated, audited domain operation. An AI never creates, changes or removes one |
| Unknown time | a `max_unknown_ms` per rule is enough; no domain-wide default |
| Where the evaluator runs | **its own process from v0.1**, outside the Trusted Core |

## Flow

```text
owners / authorized admins
    │  domain.history_rule_set / _remove (authenticated, audited, versioned)
    ▼
history rules, in the domain state (trusted: the core holds them)
    │
    │      node, for an action a rule governs, after Authority, before Safety:
    │      request { evaluation context digest, resource, capability, rules (id, version, definition), now }
    ▼
history evaluator            its own process, outside the Trusted Core,
                             but a safety-relevant trusted dependency (below)
    │  reads the history log (hash-chained), measures each rule;
    │  unknown time counts against the rule
    ▼
CheckedHistoryConstraint     one per rule, signed by the evaluator's key, ≤ 5 s
    │
    ▼
Safety, SAFE-10-HISTORY      inside the core
    │  checks it against the TRUSTED rule and its version, the decision, the
    │  evaluator's identity and authority, and its freshness. It never reads
    │  the history, and never trusts a signature alone
    │
    ├── PASS-THROUGH   (the other rules decide)
    └── DENY           LIMIT_EXCEEDED | INSUFFICIENT_HISTORY | EVALUATOR_UNAVAILABLE
```

## History rules

A rule belongs to one resource and one capability.

```text
HistoryRule {
    rule_id,          unique on its resource
    version,          raised on every change; a record for another version is refused
    capability,       the action it governs (never one that halts: a stop always wins)
    key, value,       the device key it measures, and the value that counts
    predicate,        one of the four below, with its limit
    window_ms,        for the windowed predicates
    max_unknown_ms,   how much unknown time the window may hold before the verdict is INSUFFICIENT_HISTORY
                      (not for max_entries: there, any unknown time is too much, below)
}
```

The predicates of v0.1 are four, and only these. There is no query language.

| Predicate | Measured value (worst case) | DENY when |
|---|---|---|
| `max_continuous_ms` | how long the key has been in `value` without a known break, now | it is at or above the limit |
| `min_off_before_ms` | how long the key has been known to be out of `value`, now | it is below the limit |
| `max_entries` in `window_ms` | entries into `value` in the window | they are at or above the limit |
| `max_in_value_ms` in `window_ms` | time in `value` in the window | it is at or above the limit |

**Rules are managed as authority, not as configuration:**
- **Two new domain operations,** `domain.history_rule_set` and `domain.history_rule_remove`. They are high risk. The default policy lets owners use them, and admins only through an explicit grant; an AI never can, whatever its token (as for `domain.safety_release`).
- **Each change** is audited, raises the rule's version and the authority epoch, and is persisted in the domain state. A state file rolled back past it is refused at start-up.
- **An AI can read the rules** that govern what it was given, so that it understands a refusal. It cannot touch them.

## Unknown time counts against the rule

Unknown time is time the history cannot vouch for:
- the device was unobservable;
- the node or the recorder was down;
- the recorder missed events;
- a record's time cannot be trusted (below).

The evaluator never assumes a state went on across a gap, in either direction. It measures the bound that is worst for the rule:

| Predicate | Unknown time is counted as |
|---|---|
| `max_continuous_ms` | in `value`, joining the runs on either side: ON 20 min, unknown 15, ON 5 measures as 40 |
| `min_off_before_ms` | in `value`: the off-time counts only from the last moment it was known off |
| `max_entries` | **no bound at all.** Any unknown time in the window is INSUFFICIENT_HISTORY |
| `max_in_value_ms` | in `value` |

**Entries cannot be bounded through a gap.** Between "known off" and "known off", ten unknown minutes may hide one entry into ON, or ten: ON, OFF, ON, OFF and so on. No count of entries can be established across unknown time. So for `max_entries`, any unknown interval in the window gives INSUFFICIENT_HISTORY, whatever the count outside it and whatever `max_unknown_ms`; a small gap never passes on its own. A future profile may declare a trusted physical minimum time between transitions (a compressor cannot cycle faster than every 30 s), which would bound the entries a gap can hide. v0.1 has none.

So "ON 20, unknown 15, ON 5" is neither "40 minutes continuous, certainly" nor "only 25 minutes, so safe". It is "possibly 40". Against a 30-minute limit, the verdict is DENY for **INSUFFICIENT_HISTORY**, not for LIMIT_EXCEEDED: a person can tell "it ran too long" from "nobody can tell how long it ran". A window holding more unknown time than the rule's `max_unknown_ms` is INSUFFICIENT_HISTORY, whatever the arithmetic.

## The record

```text
CheckedHistoryConstraint {
    evaluation_context_digest,     the digest of the evaluation context (below): it answers that one request,
                                   at that authority epoch, under that rule set, and no other
    resource, capability,
    rule_id, rule_version,
    rule_digest,                   SHA-256 of the rule's definition, as the node sent it
    verdict,                       PassThrough | Deny { LimitExceeded | InsufficientHistory }
    measured_value,                the worst-case measure, in ms or entries
    window_start, window_end,      measured on the node's clock, as given in the request
    unknown_duration,              unknown time in the window
    evidence_digest,               the history chain's hash at the last record the measure used
    evaluated_at, expires_at,      expires_at ≤ evaluated_at + 5 s
    evaluator_id, evaluator_version,
    sig                            the evaluator's Ed25519 signature over all of the above
}
```

## The evaluation context: what a record is bound to

A record cannot be bound to "the decision": SAFE-10-HISTORY is part of that decision, and a digest of the final decision would include the very record that refers to it. A record is bound instead to the **evaluation context**: the verified request as it stands *before* Safety, in a canonical form.

```text
HistoryEvaluationContext {
    subject,              the intent id or request message id
    actor, on_behalf_of,
    resource, capability,
    parameters,           canonical, as verified
    authority_epoch,      the domain's epoch when the context was made
    rule_set_digest,      SHA-256 over the governing rules (id, version, definition), sorted by id
}
evaluation_context_digest = SHA-256(the domain separator "chitala-history-context-v1",
                                    then each field above, length-prefixed, in this order)
```

It never contains a Safety result, SAFE-10's or any other, nor the final decision.

```text
verified request (Identity, Authority)
      ↓
canonical evaluation context ─▶ evaluation_context_digest
      ↓
history evaluator ─▶ signed constraint, bound to evaluation_context_digest
      ↓
Safety, with SAFE-10-HISTORY
      ↓
final decision (it records the context digest and the constraints)
```

The core computes the digest again from the request it is deciding, and compares it to the record's. A record made for another request, at another epoch, or under another rule set is refused.

## What the core checks, and why a signature is not enough

A signature proves only that a record was made by a given key and not changed since. It does not prove the measure is right. The core therefore checks four separate things, and the checks fail closed.

| | The question | The check |
|---|---|---|
| **Authentication** | who made this record? | the signature verifies against the enrolled public key of `evaluator_id` |
| **Authorization** | may that evaluator answer for this rule? | `evaluator_id` is the domain's configured history evaluator, and the evaluator principal is TRUSTED (not contained or quarantined) |
| **Binding** | is it about this request and this rule? | `evaluation_context_digest` equals the digest the core computes for the request it is deciding, and resource, capability, `rule_id`, `rule_version` and `rule_digest` match the rule the core holds now. A record for an old version of a rule, for another request or epoch, or for a rule the core no longer has is refused |
| **Freshness** | is it current? | `evaluated_at ≤ now < expires_at`, and `expires_at − evaluated_at ≤ 5 s`, on the node's clock |

**The integrity of the history itself** is the evaluator's to establish, and the core cannot. The log is private, and from v0.1 it is hash-chained, record to record, like the audit log. The evaluator refuses to measure over a broken chain (INSUFFICIENT_HISTORY). `evidence_digest` names the chain's hash at the last record measured, so an audit can re-measure the same records later. A time that cannot be trusted is unknown time:
- a record whose source time is after the time the node observed it, beyond the clock skew allowed;
- a record whose time goes back before the record before it.

## `SAFE-10-HISTORY`

For an action whose capability a history rule on its resource governs, Safety requires one valid record per rule. The result is one of:

| Logged as | When |
|---|---|
| PASS-THROUGH | every rule has a valid record whose verdict is PassThrough. Nothing is added: the other rules decide |
| `LIMIT_EXCEEDED` | a valid record measured the rule over enough history, and the limit is reached |
| `INSUFFICIENT_HISTORY` | a valid record found too much unknown time, or a broken chain, to show the limit is kept |
| `EVALUATOR_UNAVAILABLE` | no valid record. It covers no answer in time, a crashed evaluator, a bad signature, an unknown or untrusted evaluator, a wrong binding or version, and an expired record. The decision record names which |

All three refusals are DENY (`E_SAFETY`, rule `SAFE-10-HISTORY`). They are logged apart for operations and investigation.
- **Untouched actions:** actions with no history rule are untouched, and a capability that halts can never have one.
- **Fully removable:** removing every rule returns the domain to exactly its behaviour today.
- **Recorded:** every record checked is in the action's decision record, with its digests.

## The evaluator: outside the Trusted Core, but trusted for its rules

**The history evaluator is not part of the Chitala Trusted Core, but it is a safety-relevant trusted dependency for any rule it evaluates.** A compromise cannot create Authority or bypass any other Safety rule. It can, though, suppress the additional denial that a configured history rule was meant to provide (Project Lead, 2026-10-07).

```text
Chitala Trusted Core
        │  verifies (identity, authority, binding, freshness)
        ▼
history evaluator
  outside the Trusted Core
  a safety-relevant trusted service, for history-governed actions
```

So the evaluator is in the trusted computing base of each history rule's own safety property. It is not in the trusted computing base of anything else. It is kept small, isolated and narrow for that reason. For history rules that protect high-consequence equipment, a later version may use two independent evaluators, both of which must pass, or a smaller evaluator in a protected domain. v0.1 needs neither.

## The evaluator process

- **What it is:** a separate binary, `chitala-history-evaluator`. The node starts and supervises it like an adapter host and speaks a typed, allowlisted JSON Lines protocol with it over stdio. Its one request is `Evaluate { evaluation_context_digest, resource, capability, rules, now }`; it never takes a query language.
- **Its key:** it holds its own signing key, in the domain's key store under its principal (`service:history`). The node does not load that key.
- **Its access:** it reads the history log and nothing else, and writes nothing.
- **A slow answer:** the node waits at most 2 s. A late answer is EVALUATOR_UNAVAILABLE, and a hung evaluator is replaced, as a hung sidecar is (spec 27).

## Threat model and failure semantics (part ③, for review)

| Threat | What it could do | Defence | What remains |
|---|---|---|---|
| A forged record | allow a governed action past its limit | the signature, against the enrolled key of the authorized evaluator | — |
| A record replayed from another request or an older rule | reuse an earlier PASS-THROUGH | the evaluation context digest (request, epoch, rule set), rule version and digest bind it; it expires within 5 s | — |
| A rule changed while a record is in flight | an action checked against the old rule | the rule version: the record for the old version is refused | the action is refused once, and asked again |
| An AI changes the rules | lift a limit that protects people | the rule operations are owners' and authorized admins' only, audited; no token gives them to an AI | — |
| A compromised or buggy evaluator | sign PASS-THROUGH when it should DENY | the worst it can do is add no denial: the action is still decided by Authority and every other rule, as today. Isolation keeps it from the core's keys; every record is audited with its digests and can be re-measured | a history limit not enforced while it is compromised (a pump may run past 30 minutes). This is why the evaluator is a safety-relevant trusted dependency for its rules (above) |
| A compromised evaluator that signs DENY | block governed actions | the DENY is visible in the record; a person removes the rule or the evaluator | availability of the governed actions |
| The history log edited or truncated by someone with host access | hide a long run | the hash chain shows an edit; a truncated tail shows as missing time (unknown). Anchoring the chain's head in the audit log, so truncation is provable, is an option for ④ | an attacker with the host's own access is out of scope for the hosted reference (spec 13) |
| Clocks | make a long run look short | windows on the node's clock; times that cannot be trusted count as unknown; the node's clock watch (spec 11) | — |
| The recorder lags or drops events | a run looks shorter | missed events are a gap (spec 29): unknown time, counted against the rule | — |
| The evaluator is slow, down or flooded | block governed actions | fail closed, bounded wait, supervised restart; a stop always passes | availability, by design |
| A huge history | slow evaluation | windows are at most 30 days, the log's retention | — |
| Same user, same host | the evaluator's process boundary is not a privilege boundary in hosted mode | separate keys and a narrow protocol; a separate OS user is a deployment option | Hosted Mode trusts the host OS: process separation is not claimed to protect against a root compromise (spec 13), as for adapter hosts (spec 19) |
| A gap hides many transitions | a motor started more often than its limit | for `max_entries`, any unknown time in the window is INSUFFICIENT_HISTORY: entries are never bounded across a gap | — |

## Out of scope for v0.1

- Predicates beyond the four.
- History rules that would end a run by themselves, for example stopping a pump at 30 minutes. That would be an action, not a constraint. It belongs to a future scheduler, which would go through Authority.
- A second, independent evaluator (two-of-two) for high-consequence rules.

## Implementation

**④a, outside the core's decisions (this step):**
- `chitala-history-check`, a core crate with no I/O:
  - history rules and their digests;
  - the evaluation context and its digest;
  - the record and its signing bytes;
  - `check`, the decision `SAFE-10-HISTORY` makes.
- The history log is hash-chained (`chitala_history::log::read_chained`). A line a crash cut short is ended before the next record, so the chain goes on.
- `chitala_history::eval`: the worst-case measures and a signing `Evaluator`.

**Tests:**
- `chitala-history-check` (5): rules, digests, binding, freshness, the three causes;
- `chitala-history`: `eval` (5) for each predicate's worst case, the Lead's examples and the signed record; `log` for the chain.

**Mutations: 13 of 13 caught.** They cover:
- unknown time taken as a break, or bounded for entries;
- a broken chain measured;
- an edit, or an unchained line, accepted;
- a record for another version or request, or one living too long, accepted;
- the context without its epoch, and a rule digest without its version.

**④b, next:**
- the rule operations;
- the evaluator process;
- `SAFE-10-HISTORY` in Safety, and the node's wiring;
- the adversarial suite (⑤).

