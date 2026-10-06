# 32 — Checked history constraints (DRAFT, for review)

**Status:** v0.4 step 4, part ②: the design, written before any code, for the Project Lead's review. Part ③ reviews its threat model and failure semantics. Parts ④ and ⑤ implement and test it.

Some limits are about time, not about the state now:
- a pump may run at most 30 minutes in a row;
- a compressor needs 5 minutes off between runs;
- a motor may start at most 6 times an hour.

The history (spec 29) knows these things; the Trusted Core does not. This spec lets that history make Safety stricter, without letting it into the core, and without ever letting it make anything allowed.

## The rule above all others

> **History may make Safety stricter. It never supplies evidence that turns a DENY into an ALLOW.**

A history constraint has two outcomes, and only two:

- **PASS-THROUGH:** this constraint adds no denial. Authority and `SAFE-1`…`SAFE-9` still decide everything, as if the constraint were not there. "The pump ran 5 minutes" never means "allow the pump".
- **DENY:** Safety refuses the action.

There is no ALLOW result. The type has no such value, and the core has no code path that reads one.

## Flow

```text
history log (spec 29, private)
    │
    ▼
history evaluator            outside the Trusted Core (chitala-history)
    │  measures one rule over a window; unknown time counted against it
    ▼
CheckedHistoryConstraint     signed by the evaluator's key; short-lived; bound to one decision
    │
    ▼
Safety, SAFE-10-HISTORY      inside the core: verifies the record, never reads the history
    │
    ├── PASS-THROUGH   (the other rules decide)
    └── DENY
```

The core never opens the history log, never runs the arithmetic, and never trusts a number it cannot authenticate.

## Rules on a resource

A resource declares its history rules next to its envelope. They are data that owners configure, like the envelope:

```json
"history_limits": [
  { "rule_id": "pump-continuous", "capability": "switch.turn_on", "key": "on", "value": true,
    "predicate": { "max_continuous_ms": 1800000 } },
  { "rule_id": "pump-cooldown", "capability": "switch.turn_on", "key": "on", "value": true,
    "predicate": { "min_off_before_ms": 300000 } },
  { "rule_id": "motor-starts", "capability": "switch.turn_on", "key": "on", "value": true,
    "predicate": { "max_entries": 6, "window_ms": 3600000 } },
  { "rule_id": "heater-daily", "capability": "climate.set_target_temperature", "key": "heating", "value": true,
    "predicate": { "max_in_value_ms": 14400000, "window_ms": 86400000 } }
]
```

The predicates of v0.1 are four, and only these. There is no query language.

| Predicate | Measured value | DENY when |
|---|---|---|
| `max_continuous_ms` | how long the key has been in `value` without a break, now | it is at or above the limit |
| `min_off_before_ms` | how long the key has been out of `value`, now | it is below the limit |
| `max_entries` in `window_ms` | entries into `value` in the window | they are at or above the limit |
| `max_in_value_ms` in `window_ms` | time in `value` in the window | it is at or above the limit |

A rule applies to one capability on one resource. A capability that only halts (`"halts": true`) can never be the subject of a history rule: a stop always wins (spec 30).

## Unknown time counts against the rule

Unknown time is time the history cannot vouch for:
- the device was unobservable;
- the node or the recorder was down;
- the recorder missed events.

**The evaluator never assumes a state went on across a gap**, in either direction. It measures the bound that is worst for the rule:

| Predicate | Unknown time is counted as |
|---|---|
| `max_continuous_ms` | in `value`, joining the runs on either side. ON 20 min, unknown 15, ON 5 measures as 40 min |
| `min_off_before_ms` | in `value`: the off-time is counted only from the last known moment it was off |
| `max_entries` | one possible entry per unknown interval |
| `max_in_value_ms` | in `value` |

So "ON 20, unknown 15, ON 5" is neither "40 minutes continuous, certainly" nor "only 25 minutes, so safe". It is "possibly 40": against a 30-minute limit that is a DENY, for **insufficient history evidence**. The reason is recorded apart from "limit exceeded". A person can tell "it ran too long" from "nobody can tell how long it ran".

Every rule also has `max_unknown_ms`. Its default is the predicate's own limit, and for `max_entries` it is the window. When the window holds more unknown time than that, the verdict is DENY (insufficient evidence), whatever the arithmetic.

## The record

```text
CheckedHistoryConstraint {
    resource, capability,          what it is about
    subject,                       the intent or request it was evaluated for (binds it to one decision)
    rule_id, predicate,            which rule, as configured
    verdict,                       PassThrough | Deny { reason: Exceeded | InsufficientEvidence }
    measured_value,                the worst-case measure, in ms or entries
    window_start, window_end,      the window measured, by the node's clock
    unknown_duration,              unknown time in the window
    evidence_digest,               SHA-256 of the history records the measure was taken over
    evaluated_at, expires_at,      expires_at ≤ evaluated_at + 5 s
    evaluator_id,                  the evaluator's principal (service:history)
    evaluator_version,
    sig                            the evaluator's signature over all of the above
}
```

- **Authenticated:** the evaluator is a principal (`service:history`) with its own key, enrolled in the domain like any service. The core verifies the signature against the enrolled key. In v0.1 the evaluator runs in the node's process, outside the core's code. The signature makes the record checkable all the same, and lets the evaluator move to another process later without changing the core.
- **Bound:** the record names the decision's subject, the resource and the capability. It is never reused for another decision, and it is never cached across decisions.
- **Short-lived:** it expires 5 s after evaluation at most. A history that moved on makes it worthless.
- **Audited:** the decision record of the action carries every constraint record it was checked against. That includes the digest, so an auditor can re-measure from the history log.

## `SAFE-10-HISTORY`, in the core

For an action on a resource that has history rules for its capability, Safety requires one valid record per rule:

1. the signature verifies against the enrolled evaluator key, and the evaluator is TRUSTED;
2. resource, capability, subject and `rule_id` match the action and the rule as configured;
3. `evaluated_at ≤ now < expires_at`;
4. the verdict is `PassThrough`.

Anything else is a DENY, with the rule's id and the reason. "Anything else" covers:
- a missing record;
- a bad signature;
- an expired record;
- a mismatch;
- a `Deny` verdict.

**Fail closed:** no history, no action, for the actions that have a history rule. Actions without one are untouched, and a stop is never touched.

`SAFE-10` only adds refusals. Removing every history rule from the configuration returns the domain to exactly its behaviour today.

## Failure semantics

| Failure | Result |
|---|---|
| The history log is missing, unreadable or corrupt | the evaluator reports InsufficientEvidence: DENY for the governed actions |
| The recorder is down or lagging | its gap is unknown time: counted against the rule |
| The evaluator is down, slow or crashes | no record: DENY (fail closed); the reason says so |
| The evaluator is wrong (a bug) | its worst case is a wrong PASS-THROUGH: the action is still decided by Authority and every other Safety rule, as today. A wrong DENY stops an action; a person can see the record and remove the rule |
| A record from another decision, or an old one, is replayed | refused: wrong subject, or expired |
| A forged record | refused: signature |
| The node's clock jumps (spec 11) | records are evaluated and checked against the same clock; a jump backwards is caught by the clock watch, and the window is measured on node time |
| The history is rolled back or edited by someone with host access | the log is private; the record's digest lets an audit compare. A full defence needs a tamper-evident history log: out of scope for v0.1, listed in the threat model |

## Open questions for the Project Lead

1. **Fail closed or fail open when the evaluator is unavailable?** Proposed: closed, for the governed actions only. A pump without its history must not run, but it can always be stopped.
2. **Who may declare history rules?** Proposed: the domain configuration, like envelopes. That means owners, through the config, never an AI.
3. **Is `max_unknown_ms` per rule enough,** or should a domain-wide default exist?
4. **Should the evaluator run as its own process from v0.1?** Proposed: in-process but signed. The format is ready for a separate process.

## Out of scope for v0.1

- Predicates beyond the four.
- History rules that would end a run by themselves, for example stopping a pump at 30 minutes. That would be an action, not a constraint; it belongs to a future scheduler, and that scheduler would go through Authority.
- A tamper-evident history log.
