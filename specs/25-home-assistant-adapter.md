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
| Live | authenticated, subscribed to `state_changed`, and bootstrapped with `get_states` on **this** connection. Then the link reads the entity registry's entries of its entities (`config/entity_registry/get_entries`): which integration provides each, and its device. What it read stays known until the next read succeeds |
| Lost | a read or write error, a close, or no `pong` within the call timeout after a `ping` sent after 20 s of silence: the link is no longer live and reconnects with exponential backoff (0.5 s to 30 s) |
| Restart | every connection starts a new generation: states from an earlier connection are never served; the new one bootstraps again |
| Token rejected | Home Assistant counts every request with a rejected token as a failed login, and with `login_attempts_threshold` set it bans the address for good. After a rejection (`auth_invalid` on the link, or HTTP 401 on a REST read, which any user's token may make), neither the link nor REST presents the token again for 5 s, doubling up to 10 min. Requests in between are answered at once with `X_ADAPTER`; nothing is sent. An accepted login opens the gate again (finding F4 of step ③A) |
| `websocket: false` | REST only (the config can turn the link off) |

## Observe

1. If the link is live and holds a state of the entity from this connection, the adapter uses it.
2. If the link is live, its inventory is good, and Home Assistant does not have the entity (see *Entities Home Assistant does not have*), the observation fails at once, with no REST read.
3. Otherwise it makes one REST read.
4. If nothing works, the observation fails with `X_DEVICE_UNAVAILABLE`. The node then treats the entity's last known state as history, not evidence (spec 10).

Nothing is kept or served as a state that Home Assistant did not report on the current connection.

The state is normalised by the Home profile (spec 24):

- a lock that is moving or jammed reports no `locked`;
- `unavailable` and `unknown` are failed observations;
- a state the profile does not know is refused.

**How old a state is (finding F9).** Every observation carries its age, and the node uses it to tell evidence from history (spec 22):

| The state comes from | Its age |
|---|---|
| an event pushed on the link | the time since the link heard it (its source produced it no later than that, within the network's delay) |
| the link's bootstrap (`get_states`) | unknown: nobody can tell how old a state Home Assistant held is |
| a REST read | Home Assistant's clock at the answer (`Date`) minus the last time the integration wrote the state (`last_reported`, else `last_updated`). Both times are Home Assistant's, so no skew between the machines counts. `Date` has whole seconds, so a second is added |

Consequences:

- **A command whose answer is lost** settles once a state Home Assistant produced after the order comes in. A lock that moves a moment later sends one. If the state changed at once and the connection broke at the same instant, nothing proves it came after the order: `unconfirmed`.
- **After a node restart** the bootstrapped states settle nothing, and the next report decides.
- **A command that changes nothing** gets no new report, so its outcome is `unconfirmed`.

**Whether a state is tied to its device (finding F9b).** A recent timestamp does not show that the device spoke. When a Matter lock does not confirm a command, Home Assistant writes back the value it held, with a new timestamp: 30 s after an unlock, 5 s after a lock. So every observation also says whether the adapter could confirm the state current (spec 22, `provenance`):

| The entity | Confirmed current when | Confirmed age |
|---|---|---|
| a Matter device's (registry `platform: matter`) | the device answered `matter/interview_node` (a read of its attributes, through Home Assistant and the Matter server) in an exchange that **began after** the link heard the state. A state read over REST is never confirmed (it has no time on the link's clock) | the time since that exchange began |
| another integration's, or one without a registry entry (Home Assistant's Demo locks have none; every Matter entity has one) | always, on Home Assistant's word: a **residual** (below) | the state's age |
| one whose registry entry was never read (`websocket: false`, or the read failed) | never | — |

- **Only an observation for evidence asks a device.** The node asks for evidence right after an order and while an outcome is pending (spec 22). Safety's observations never cause an exchange, and a plain observation reports a confirmation it already has.
- **One exchange at a time, bounded.** The adapter waits for an answer for 1 s at most, and the exchange goes on in the background: a later observation takes its answer. A device that did not answer, or answered with an error, is not asked again for 5 s. The link gives up on an exchange after its call timeout (10 s). A dead Matter device fails after about 15 s, so it never answers in time.
- **`matter/ping_node` is not used.** It is an ICMP ping of the device's addresses. In step ③A it answered `true` for a lock whose process had died, because its address was still up.
- **An administrator's token is needed.** Home Assistant allows `matter/interview_node` to administrators only. With another user's token every exchange fails, and the outcomes of Matter devices end `unconfirmed`. Reading the registry needs no administrator.
- **Residual: other integrations.** Their states keep Home Assistant's word: a gateway that writes a cached value with a new timestamp can still settle an outcome there. Closing that needs a liveness signal per integration, or a direct adapter (step ⑤ for Matter).

**Duplicates and reordering.** A pushed state replaces the one held only if its `last_updated` is later. Home Assistant writes these timestamps in UTC with a fixed format, so they compare as text. A duplicate or a late event therefore never moves a state backwards. An event whose `new_state` is null (the entity was removed) makes the entity `unavailable`, never its old state.

## Execute: one transport, one attempt

```text
order ─▶ link live? ── yes ─▶ call_service written once ─▶ result ─▶ observe ─▶ state + receipt
                  │                   └─ lost / no result in time ─▶ indeterminate (never resent)
                  └── no ─▶ one REST POST ─▶ observe ─▶ state + receipt
```

- **One transport per order.** A command goes over the live link, or, if the link is not live, by one REST request. If the link never wrote the call (it went down first), the call is answered "not sent", and REST may carry it. A call the link wrote is never sent again, by any transport.
- **Known or unknown.** The adapter tells "certainly not executed" (nothing was delivered, or Home Assistant refused it) from "may have executed" (`X_EXECUTION_UNKNOWN`). Only the second is watched by Chitala, and only the second can put a resource in recovery when nobody can establish what happened (spec 22).
- **Entities Home Assistant does not have.** Home Assistant answers *success* to a call on an entity it does not have, and nothing runs. The adapter refuses such a command **before sending it** (`X_ADAPTER`, certainly not executed), but only on the live connection's own word. That means all of these hold:
  - the link is live;
  - `get_states` succeeded on this very connection;
  - the entity was neither in that inventory nor reported since, or Home Assistant reported it removed.

  Without a live link, before the inventory, or when `get_states` failed, absence is never inferred: the command goes, and outcome verification decides. An entity that appears is there at once (finding F2 of step ③A).
- **The answer.** After the call, the adapter answers with the entity's state as it is now. That may still be the old one, or `moving`. The receipt binds that state (spec 19), and outcome verification decides when the promise is kept (spec 22).

| What happened | Adapter error | Outcome (spec 22) |
|---|---|---|
| Home Assistant ran the call | — (the state) | `verified`, `pending`, `diverged` or `unconfirmed`, by the witness |
| link down and Home Assistant unreachable (connection refused, no route, DNS) before anything was delivered | `X_DEVICE_UNAVAILABLE` (not delivered) | none: certainly not executed, never a recovery |
| the connection broke **after** the call was written, or no result came within the call timeout (10 s) | `X_EXECUTION_UNKNOWN` ("it may have executed") | **unknown**: watched until `within_ms`: `applied`, `not_applied` or `unconfirmed`; `unconfirmed` at medium risk or more enters recovery, without a safe state. Never resent |
| a REST request that may have been read before the connection broke | `X_EXECUTION_UNKNOWN` | unknown, as above |
| Home Assistant refused it: `not_found`, `invalid_format`, `service_validation_error`, `unauthorized`, or HTTP 4xx | `X_ADAPTER` ("did not run") | none: certainly not executed |
| any other error result (`home_assistant_error`, …) or HTTP 5xx | `X_EXECUTION_UNKNOWN` ("it may have executed") | unknown, as above |
| the call succeeded but the entity cannot be observed (it dropped off) | `X_EXECUTION_UNKNOWN` | unknown: the adapter has no state to vouch for |
| the access token is rejected, or was rejected and the wait is not over | `X_ADAPTER` | none: certainly not executed (nothing is sent while waiting) |

Nothing in the adapter or the link retries. The REST client keeps no idle connections, so it never resends a request on a stale pooled connection, the one case in which an HTTP client does so on its own.

## Configuration and discovery

`home_assistant` in the node config:

- `base_url`, `token_env`;
- `entities` (Chitala device → entity);
- `allow_insecure_http`;
- `websocket` (default `true`).

**At start-up** the adapter host refuses a device mapped to an entity of the wrong kind. A lock must map to a `lock.*` entity, a plug to a `switch.*` entity, and so on (`check_entity`, by the device's capabilities and the profile). Climate entities, outside profile v0.1, need `climate.*`.

**Discovery.** `chitala ha-discover --url … --token-env …` lists the entities the profile can drive: entity id, class, name, capabilities and normalised state (or why there is none). A light is proposed `light.set_brightness` only if one of its `supported_color_modes` is not `onoff` (Home Assistant's own rule); a light that declares none is not assumed to dim. Discovery only proposes. People decide what Chitala governs and who may act, and discovery never sends a command.

## Checked against a real Home Assistant (step ③A)

Home Assistant Core 2026.9.4 with its Demo integration, on loopback (lab report: [`docs/lab/v0.3-step3a-home-assistant.md`](../docs/lab/v0.3-step3a-home-assistant.md)). Audit item O2: for every error the adapter takes as "did not run", the entity was checked before and after the call, over both transports.

| Case | WebSocket answer | REST answer | Ran? | The adapter says |
|---|---|---|---|---|
| unknown service | `not_found` | HTTP 400 | no | did not run |
| parameter of the wrong type, or out of range | `invalid_format` | HTTP 400 | no | did not run |
| a feature the entity lacks (`lock.open`) | `service_validation_error` | HTTP 500 | no | did not run (WebSocket); may have run (REST): cautious, never wrong the other way |
| a read-only user | `home_assistant_error` "Unauthorized" (not `unauthorized`) | HTTP 401 | no | may have run (WebSocket): cautious; did not run (REST) |
| an entity that does not exist | **success** | HTTP 200 `[]` | no | with a live inventory: refused before sending (F2). Otherwise the call "succeeded" but the entity cannot be observed: may have run; outcome verification decides, and Safety refuses doors whose state is unknown (`SAFE-3`) |

Nothing the adapter classifies as "did not run" ran. Two cases are classified more cautiously than needed, and outcome verification then finds `not_applied`.

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
- **how old states are (F9):**
  - pushed states age from when they were heard; bootstrapped ones have no age; REST ages come from Home Assistant's own clock;
  - Home Assistant's timestamps and HTTP dates are read exactly;
- **whether a state is tied to its device (F9b):**
  - a Matter device's state is confirmed only by an answer to an exchange begun after it; a plain observation asks nobody; a newer state needs a newer answer; a dead device's re-emitted state is not confirmed, and it is not asked again at once;
  - another integration's state keeps Home Assistant's word; nothing is confirmed over REST only, or when the registry cannot be read;
  - a device is never waited for longer than 1 s; a slow answer counts when it comes, but not for a state reported while it was on its way;
- **nothing made up:**
  - nothing is made up when Home Assistant is unreachable;
  - a wrong token is never accepted;
- **a rejected token (F4):**
  - it is not presented again and again, by REST, by the link alone, or for a command, which is not sent;
  - the wait doubles up to its limit, and an accepted login starts it over;
  - a token rejected for a while is tried again and works;
- **configuration:**
  - entities must be of their kind;
  - discovery proposes only the entities the profile drives, and never acts;
  - discovery proposes brightness only for lights that dim (F1);
- **entities Home Assistant does not have (F2):**
  - a command to one is refused before sending, by the live inventory; it costs no REST read; one that appears is there at once, one removed is absent again;
  - an entity gone while the link was down is absent by the new connection's inventory;
  - absence is never inferred without a live link, before an inventory, or after `get_states` failed;

The adapter host test refuses a device mapped to the wrong kind of entity.

`chitala-node/tests/home_assistant.rs` runs the whole chain (Authority → Safety → boundary → adapter → fake → outcome verification):

- an owner's action reaches Home Assistant once and is verified;
- a command lost after sending ends `applied` and is never resent;
- a lock still moving is pending until it arrives;
- a jammed lock puts the door in recovery with exactly one safe-state attempt;
- a device that drops off leaves its outcome `unconfirmed`, not `diverged`;
- nothing is made up when Home Assistant is unreachable;
- an agent's "leaving home" plan (light off, plug off, door locked) runs step by step, each outcome verified, each command once;
- a dead Matter lock's cached state, written again with a new timestamp, is no evidence: `unconfirmed` and recovery, never `not_applied` (F9b);
- a live Matter lock's fresh state settles its outcome as before: `verified`, `applied`, `not_applied` (F9b).

Every guarantee was also checked by **mutation**: each of the following faults was put back into the code on purpose, and the suite failed every time.

- a REST retry after an indeterminate call;
- a lost pending call reported as never sent;
- `unlocking` read as unlocked;
- `unavailable` read as a state;
- events applied out of order;
- a stale state served while the link is down;
- any entity accepted for any device;
- a silent connection never noticed.

Step ③A added seven for the token gate (a REST read that does not close it, a link that does not close it, a link that ignores it, a command that ignores it, an accepted login that does not reset it, a racing rejection that doubles it, no doubling at all) and three for discovery (an `onoff` light that dims, a light without color modes that dims, no filter). F2 added eight more:
- absence inferred while the link is down;
- a failed `get_states` taken as an inventory;
- removals not tracked;
- a re-added entity still removed;
- the command or the observation ignoring absence;
- an older connection's states counting;
- absence never reported.

F9 added nine more, in the node and the adapter:
- source time ignored;
- an unknown age taken as evidence;
- the judgement or the periodic observation taking any state;
- the send time not kept;
- bootstrapped states looking fresh;
- the REST age not rounded up;
- the virtual devices' reads without an age;
- the age not subtracted.

The suite caught each one.

The adapter suite ran 40 times in a row and the full-chain suite 30 times, all green.

## Not in v0.3 step ②

- `subscribe_entities` (compressed states) instead of `state_changed`.
- Home Assistant's own retries and queueing in integrations, which Chitala cannot see.
- Lock codes.
- Several Home Assistant instances.
- TLS client certificates.
- Physical devices: step ③B. Step ③A ran against a real Home Assistant whose Demo integration simulates the devices.
