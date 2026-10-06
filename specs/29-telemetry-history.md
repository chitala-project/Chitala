# 29 — Telemetry and history (local)

**Status:** v0.4, the first step after v0.3's software lane (Project Lead, 2026-10-06). It records history locally and answers questions about it, for people and AIs through the node, under Authority. Feeding Safety a checked constraint that can only refuse comes later.

Chitala records actions and outcomes in its audit log, but no state over time. Questions like these need a history:

- how long did the air conditioner run today?
- has the pump been on for four hours?
- how many times was it switched on?
- did the motor run past its safe time?

This spec records that history and answers those questions. It stays outside the Trusted Core (the Project Lead's proposal of 2026-10-05, ROADMAP):

```text
device → adapter → node: observation → twin ─┬─ Trusted Core: Authority, Safety, Outcome
                                             └─ bus: Observed / Unobservable
                                                  → history recorder → history log (local, private)
                                                  → queries: durations, cycles, runtime, utilization
```

## Rules

1. **Observed time, not command time.** A device is on from when its observation shows it on, not from when an order left. Each record keeps the time the state's source produced it (`at`: an adapter's `source_at`, F9) beside the time Chitala observed it (`observed_at`). Durations are measured by the source.
2. **Unobservable time is unknown.** While a device cannot be observed (F6, F12), its time counts as **unknown**, never as its last state. That time is reported apart, so a total never silently includes it.
3. **Changes outside Chitala count.** A switch turned by hand, or by another system, is part of the history: the observation sees it, whoever caused it.
4. **Nothing is made up.** A key a device stops reporting (a lock that is moving or jammed reports no `locked`, spec 24) is unknown from then on. Time before Chitala observed a device is unknown. So is time when the node was not running, and time when the recorder missed events.
5. **It stays out of the Trusted Core.** The node only publishes what it observed. Recording, storage and arithmetic happen in `chitala-history`, which decides nothing. When history feeds Safety later, the core will receive only a checked constraint, and that constraint can only refuse.

## What the node publishes

Two event kinds on the node's event bus (spec 10). Both are additive.

| Kind | When | `ts_ms` | `data` |
|---|---|---|---|
| `Observed` | an observation changed the device's state, or the device was unobservable before it | when the state's source produced it; when it was received, if no source time is known | the device's whole reported state |
| `Unobservable` | an observation failed, and the device was observable | when the failure was received | empty |

`StateChanged` (the changed keys) is unchanged.

## The history log

The recorder appends one JSON line per record to `history.jsonl`, in the domain's private storage:

| Record | Meaning |
|---|---|
| `start` | the recorder started: every device is unknown until observed |
| `observed` (`device`, `at`, `observed_at`, `state`) | from `at`, the device's state is `state`; a key absent from `state` is unknown |
| `unobservable` (`device`, `at`) | from `at`, the device's state is unknown |
| `gap` (`at`) | the recorder missed events: every device is unknown from `at` until its next record |

- **The recorder is a bus subscriber** with a bounded queue. When the bus drops events for it, it writes a `gap` and then reads every device's state again from the node, and writes it. So a missed event becomes known-unknown time, never a wrong value.
- **Retention:** records older than `retention_days` (default 30) are dropped when the recorder starts, and once a day after that. The log is rewritten atomically. A device's state when the window opens is kept as one record, so durations at the window's start stay right.
- **It is private:** the log is a private object (0600 on hosted platforms). It shows when people are home.

```json
"history": { "retention_days": 30 }
```

The history section is optional. Recording is on by default. `"enabled": false` turns it off.

## Queries

The queries are pure functions over the records, in `chitala_history::query`.

- **`timeline(device, key, from, to)`**: the intervals over the window, each with a value or *unknown*.
- **`summary(device, key, value, from, to)`**:

  | Field | Meaning |
  |---|---|
  | `in_value_ms` | time in `value` |
  | `known_ms` | time with any known value |
  | `unknown_ms` | time with no known value |
  | `cycles` | entries into `value` from a known other value |
  | `longest_run_ms` | the longest interval in `value` |
  | `current_run_ms` | how long it has been in `value`, if it still is |
  | `utilization` | `in_value_ms / known_ms` |

  A run broken by unknown time is not one run. Chitala cannot tell what happened while it could not see.

`chitala history --device D --key K --value V [--since 24h]` prints the summary and the timeline. It reads the log directly, as `chitala audit verify` reads the audit log, so it needs the host's access to the domain's private files. That is for the host's operator. Everyone else reads history through the node.

## Reading history through the node

People and AIs never read the history log. They ask the node, with the capability `device.read_history` (registry 0.1.3), and the node answers under Authority, like any other access:

```text
AI → MCP tool → intent: device.read_history on a resource → node: Identity, Authority (token), Safety
   → the node's history → a summary
```

- **A capability like any other.** Its risk is **medium**: history shows when people are home. Under the default policy, adults and owners may read it; guests and children may not; an AI only with a token that grants it, on the resource the token names. Policy and tokens grant it per resource: one AI the air conditioner, another the robot, nobody but the owner the front door.
- **A resource offers it.** A resource binds `device.read_history` like any capability. A token for a resource that does not offer it is refused when it is delegated. The node offers history for every device it observes (every device with `device.read_state`), whatever its adapter: the node answers it, never the device.
- **A summary, never the log.** The parameters are `key`, `value` (`"true"`, `"false"`, an integer, or text) and `since_s` (from 60 s to 30 days). The answer is the `summary` above, over `[now − since_s, now)`: `in_value_ms`, `known_ms`, `unknown_ms`, `transitions` (the summary's `cycles`), `longest_run_ms`, `current_run_ms`, `utilization`. No records, no timeline, no other device. There is no query language and no file access.
- **Queries pass Safety**, as `device.read_state` does. A device that is unobservable now still has a history; its unobservable time is reported as unknown.
- **A node that keeps no history** says so (`X_INTERNAL`, "this node keeps no history").
- An AI sees the capability as the MCP tool `device_read_history` only when a token grants it; its schema is the registry's.

Feeding Safety from history comes later. It will be a checked constraint that can only narrow or refuse, never allow. The core will receive the checked result and never read the history itself.

## Tests

- The arithmetic, including unknown time:
  - a device lost and found again;
  - a key that disappears;
  - time before the first observation;
  - restarts;
  - gaps.
- Source time beside observed time; changes made outside Chitala.
- The node publishes `Observed` and `Unobservable` on the right transitions only.
- The recorder writes a gap and resynchronises when the bus drops events.
- Retention keeps the state at the window's start.
- The whole chain: a device driven through the node, then queried.

| Test | What it shows |
|---|---|
| `chitala-history`: `query`, `log` and `recorder` tests (11) | the arithmetic, retention, gaps and resynchronising |
| `chitala-node/tests/history.rs` | the node's transitions; a lock driven through the node: locked for 5 minutes by an order, then 2 minutes by hand; lost for 3 minutes, which is unknown; 2 entries counted, and the third, after the loss, not counted |
| `chitala-node/tests/read_history.rs` (4) | `device.read_history` through the node: the owner and an adult read a summary, never the log; a guest and a child are refused; an AI reads only with a token, only the resource it names, and a resource that does not offer history cannot be delegated; no history and windows out of bounds are said plainly |
| `chitala-mcp/tests/broker.rs`: `an_ai_reads_history_only_through_its_token` | the MCP tool exists only with a token that grants it; how long the air conditioner was set to 24 °C in the last hour; the door's history refused |

**Mutations: 8 of 8 caught.**
- unobservable time taken as the last state;
- an entry from unknown counted as a cycle;
- a late source time rewriting the past;
- a run broken by unknown time taken as one;
- retention dropping the state at the window's start;
- no resync after missed events;
- a device back, unchanged, not published;
- every failed observation published.

**Reading through the node: 8 of 8 caught.**
- a person's read, or an AI's, sent to the device instead of the history (2);
- history read as low risk;
- the window ignored;
- the value taken as text only;
- the timeline handed out with the summary;
- a window shorter than a minute allowed;
- a device's history not offered by the node.

## Lab

Through a real node, on the Matter SDK's lock on Chitala's own fabric (spec 27):
- unlock, lock, unlock and lock, a few seconds apart;
- then `chitala history --device device:front-door --key locked --since 10m`.

**What the log showed.**
- **Its first records.** The recorder's `start`, and the lock as `unobservable`. The node had observed the lock before the sidecar's subscription was up, so the lock was unknown until it was. It was not guessed.
- **The timeline.** The lock's four changes, by the source's time.
- **Entries counted.** Two entries into `locked`. The first `locked`, coming from unknown, is not counted.
- **Privacy.** The log is private: `-rw-------`.
