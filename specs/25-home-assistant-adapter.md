# 25 — Home Assistant Adapter v0.3

Sources: v0.3 roadmap step ②; the Project Lead's decisions of 2026-10-05:

- WebSocket first, with REST to bootstrap and as a fallback;
- the adapter only executes and observes;
- it never retries a physical command;
- a command lost after sending is indeterminate;
- "not observable" never becomes a state.

Specs 10 (adapters, isolation), 19 (orders and receipts), 22 (outcome verification), 24 (the Home profile). Code: `chitala-adapters::home_assistant` (adapter, mapping, discovery), `home_assistant::link` (`ha_link.rs`, the WebSocket link), `fake_ha` (the test double). All of it lives outside the Trusted Core, in the adapter host process.

## Two roles, nothing else

The adapter **executes** orders the Trusted Execution Boundary signed, after the order gate admitted them (spec 19). It **observes** the entities it is configured for.

It does none of the following:

- **Decide authority.** Home Assistant users, and anything Home Assistant itself allows, are defence in depth below Chitala, never a source of authority.
- **Interpret policy.**
- **Retry a physical command**, ever.
- **Turn "I could not observe it" into a state.**

## Connections

```text
              ┌──────────── WebSocket link (one thread) ────────────┐
adapter ──────┤ connect → auth → subscribe state_changed → get_states → live
              │   pushed states, deduplicated and ordered            │
              │   ping after silence; no pong → reconnect (backoff)  │
              └──────────────────────────────────────────────────────┘
              └── REST: GET /api/states/<entity> when the link is not live;
                        POST /api/services/<domain>/<service> when the link is not live
```

| | |
|---|---|
| URL | `base_url` with `ws://` or `wss://` and `/api/websocket`; the same transport rule as REST: `https://`/`wss://`, or plain only to loopback unless `allow_insecure_http` (v7 §10) |
| Token | read from the environment variable `token_env`, never stored, printed or logged; the same token authenticates the link (`auth`) and REST (`Bearer`) |
| Live | authenticated, subscribed to `state_changed`, and bootstrapped with `get_states` on **this** connection |
| Lost | a read or write error, a close, or no `pong` within the call timeout after a `ping` sent after 20 s of silence: the link is no longer live and reconnects with exponential backoff (0.5 s to 30 s) |
| Restart | every connection starts a new generation: states from an earlier connection are never served; the new one bootstraps again |
| `websocket: false` | REST only (the config can turn the link off) |

## Observe

1. If the link is live and holds a state of the entity from this connection, the adapter uses it.
2. Otherwise it makes one REST read.
3. If neither works, the observation fails with `X_DEVICE_UNAVAILABLE`.

Nothing is kept or served as a state that Home Assistant did not report on the current connection.

The state is normalised by the Home profile (spec 24):

- a lock that is moving or jammed reports no `locked`;
- `unavailable` and `unknown` are failed observations;
- a state the profile does not know is refused.

**Duplicates and reordering.** A pushed state replaces the one held only if its `last_updated` is later. Home Assistant writes these timestamps in UTC with a fixed format, so they compare as text. A duplicate or a late event therefore never moves a state backwards. An event whose `new_state` is null (the entity was removed) makes the entity `unavailable`, never its old state.

## Execute: one transport, one attempt

```text
order ─▶ link live? ── yes ─▶ call_service written once ─▶ result ─▶ observe ─▶ state + receipt
                  │                   └─ lost / no result in time ─▶ indeterminate (never resent)
                  └── no ─▶ one REST POST ─▶ observe ─▶ state + receipt
```

- **One transport per order.** A command goes over the live link, or, if the link is not live, by one REST request. If the link never wrote the call (it went down first), the call is answered "not sent", and REST may carry it. A call the link wrote is never sent again, by any transport.
- **The answer.** After the call, the adapter answers with the entity's state as it is now. That may still be the old one, or `moving`. The receipt binds that state (spec 19), and outcome verification decides when the promise is kept (spec 22).

| What happened | Adapter error | Outcome (spec 22) |
|---|---|---|
| Home Assistant ran the call | — (the state) | `verified`, `pending`, `diverged` or `unconfirmed`, by the witness |
| link down and REST unreachable before sending | `X_DEVICE_UNAVAILABLE` (not sent) | the witness is observed: `not_applied`, or `unconfirmed` |
| the connection broke **after** the call was written, or no result came within the call timeout (10 s) | `X_DEVICE_UNAVAILABLE` ("it may have executed") | **indeterminate**: the witness is observed once: `applied`, `not_applied` or `unconfirmed`. Never resent |
| Home Assistant refused it: `not_found`, `invalid_format`, `service_validation_error`, `unauthorized`, or HTTP 4xx | `X_ADAPTER` ("did not run") | the witness is observed |
| any other error result (`home_assistant_error`, …) or HTTP 5xx | `X_DEVICE_UNAVAILABLE` ("it may have executed") | indeterminate |
| the call succeeded but the entity cannot be observed (it dropped off) | `X_DEVICE_UNAVAILABLE` | `unconfirmed`: the adapter has no state to vouch for |
| the access token is rejected | `X_ADAPTER` | — |

Nothing in the adapter or the link retries. The REST client keeps no idle connections, so it never resends a request on a stale pooled connection, the one case in which an HTTP client does so on its own.

## Configuration and discovery

`home_assistant` in the node config:

- `base_url`, `token_env`;
- `entities` (Chitala device → entity);
- `allow_insecure_http`;
- `websocket` (default `true`).

**At start-up** the adapter host refuses a device mapped to an entity of the wrong kind. A lock must map to a `lock.*` entity, a plug to a `switch.*` entity, and so on (`check_entity`, by the device's capabilities and the profile). Climate entities, outside profile v0.1, need `climate.*`.

**Discovery.** `chitala ha-discover --url … --token-env …` lists the entities the profile can drive: entity id, class, name, capabilities and normalised state (or why there is none). It only proposes. People decide what Chitala governs and who may act, and discovery never sends a command.

## Tests

`chitala-adapters` (`ha_tests.rs`) runs against `fake_ha`, a deterministic fake Home Assistant: WebSocket and REST over loopback, with fault injection. The tests cover:

- **the link:**
  - it bootstraps and serves pushed states without polling;
  - a command goes over the link exactly once;
  - after a restart it reconnects and bootstraps again, and while it is down, REST answers;
  - a silent connection is noticed and replaced;
- **states:**
  - a lock still moving never passes for its target;
  - jammed, unavailable, unknown and removed are never states;
  - duplicate and out-of-order events never move a state back;
- **commands:**
  - a command lost after sending is indeterminate and never sent again;
  - no result in time is indeterminate and never sent again;
  - errors are reported and never retried;
  - while the link is down, a command goes by REST once;
- **nothing made up:**
  - nothing is made up when Home Assistant is unreachable;
  - a wrong token is never accepted;
- **configuration:**
  - entities must be of their kind;
  - discovery proposes only the entities the profile drives, and never acts.

The adapter host test refuses a device mapped to the wrong kind of entity.

`chitala-node/tests/home_assistant.rs` runs the whole chain (Authority → Safety → boundary → adapter → fake → outcome verification):

- an owner's action reaches Home Assistant once and is verified;
- a command lost after sending ends `applied` and is never resent;
- a lock still moving is pending until it arrives;
- a jammed lock puts the door in recovery with exactly one safe-state attempt;
- a device that drops off leaves its outcome `unconfirmed`, not `diverged`;
- nothing is made up when Home Assistant is unreachable;
- an agent's "leaving home" plan (light off, plug off, door locked) runs step by step, each outcome verified, each command once.

Every guarantee was also checked by **mutation**: each of the following faults was put back into the code on purpose, and the suite failed every time.

- a REST retry after an indeterminate call;
- a lost pending call reported as never sent;
- `unlocking` read as unlocked;
- `unavailable` read as a state;
- events applied out of order;
- a stale state served while the link is down;
- any entity accepted for any device;
- a silent connection never noticed.

The adapter suite ran 40 times in a row and the full-chain suite 30 times, all green.

## Not in v0.3 step ②

- `subscribe_entities` (compressed states) instead of `state_changed`.
- Home Assistant's own retries and queueing in integrations, which Chitala cannot see.
- Lock codes.
- Several Home Assistant instances.
- TLS client certificates.
- Running against a real Home Assistant: that is step ③.
