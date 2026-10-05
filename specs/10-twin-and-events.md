# 10 — Digital Twin, Event Bus and Adapters

Sources: v9 §3 (Event Fabric), §4 (Distributed State & Reconciliation), v15 §5 (World Model), v16 §27, v17 §6–9 (device model separate from protocol, mock-first), v5 §11 (hardware without native Chitala support), v7 §10.

## Digital Twin

Every entity has:

| Part | Meaning |
|---|---|
| `reported` | the state the device reports — the **source of truth** about the physical world |
| `desired` | the state Chitala asked for: the outcome the action's capability declares in the registry (spec 22) |
| `drift` | the desired keys that do not match `reported` yet |
| `version` | increases whenever `reported` changes |
| `reported_at_ms`, `source`, `freshness` | `freshness` is `fresh`, `stale` or `unknown` (stale after 5 minutes by default) |

Reconciliation rules (v9 §4):

- `desired` **never** overwrites `reported`. When a device refuses a command, the twin does not lie: `desired.locked = true`, `reported.locked = false`, and the `drift` is visible.
- After every order that may have executed, the node observes the resource's witness and folds that observation in. Whether `reported` reached what the action promised is the action's outcome (spec 22).
- An observation older than the current one is ignored, so reconnects and replays cannot pull the state backwards.
- No "last write wins by timestamp" for safety data.
- The safety layer reads the twin of a resource's state reference and treats an old or missing observation as unknown (spec 17, `SAFE-3`).

`device.read_state` returns the twin's view after observing the device again. If the observation fails, it returns the previous view with `observe_error` and the matching freshness.

## Event bus

An event has `id`, `kind`, `source`, `ts_ms`, `data` (flat payload) and `caused_by` (the message or intent id that caused it).

Kinds: `state_changed`, `security_denied`, `adapter_error`, `authority_changed`, `security_state_changed`, `approval_requested`, `approval_answered`, `safety_changed` (a hold placed or released, a resource entering or leaving recovery), `outcome` (an action's outcome settled after its response, spec 22).

- **Only events travel on the bus.** There is no API to send a command over the bus, so the bus can never become a way around Authority/Safety (v9 §3).
- Every subscriber has a bounded queue. When it is full, the oldest *non-security* event is dropped first; security events are dropped only when nothing else is left. Every drop is counted (v16 §27).
- A publisher is never blocked by a slow subscriber.

## Adapters

An adapter translates standard capabilities to a specific device or protocol. Being connected to a device grants no authority (v17 §6).

| Adapter | Purpose |
|---|---|
| `mock` | Virtual lights, switches, air conditioner and lock; fault injection (offline, a one-off failure, a stuck actuator that reports actions it did not do, a slow one whose effect appears only at a later observation — spec 22); a local invariant: the lock refuses `lock.lock` while the door is open → `X_DEVICE_REFUSED` (C5). Used as the simulated door of the Physical Authority Slice |
| `home-assistant` | REST bridge to an existing Home Assistant. Such devices cannot authenticate Chitala's command path, so they SHOULD be declared `SC0`/`SC1`. The HA token comes from an environment variable and is never written to config or logs. `http://` is only accepted for localhost unless the config sets `allow_insecure_http: true` (v7 §10). Lights, plugs and locks are mapped by the Home Capability Profile (spec 24): services and normalised states come from the profile, nothing is guessed (a lock still `unlocking` reports no `locked`), and `unavailable`/`unknown` are failed observations (`X_DEVICE_UNAVAILABLE`), not states |

Execution failures after an allow: `X_DEVICE_UNAVAILABLE`, `X_DEVICE_REFUSED`, `X_ORDER_REJECTED`, `X_RECEIPT_INVALID`, `X_ADAPTER`.

## Adapter isolation (Blueprint A.3, v8 §3, §12)

Adapters **do not run in the Trusted Core process**. A failing, hung or compromised adapter must not affect the Reference Monitor (A.3: "an adapter crash must not bring down the Authority/Safety Core").

```
 node (Trusted Core)                                                   chitala-adapter-host (1 instance per adapter type)
 Authority + Clearance ─▶ boundary: ExecOrder (order key, session) ─stdin─▶ OrderGate: order key, own session, expiry, single use
                                                                                  └▶ adapter (mock, home-assistant)
     verify_receipt ◀─stdout─ state + receipt: UNTRUSTED data (bounded, bound to the order) ─┘
```

### Execution orders (ExecOrder)

An execution order is the **physical command** of Invariant 1 (spec 15). It is a COSE_Sign1 (Ed25519) signed with the **order key** of the Trusted Execution Boundary, with content type `application/chitala-order`. That content type differs from CSME and intents, so a request or intent signature can never be used as an order and vice versa (v4 §14). The format (version 2: 18 keys, among them a random single-use id, the executor session, the subject and its digest, the parameter and context digests, the authority epoch and the evidence) is defined in spec 19. Only the boundary mints orders, for persons' requests and AI intents alike, from an authority proof and a matching `Clearance`.

The adapter host executes an order only if it is:

1. signed by the order key it was given at start-up;
2. addressed to its own executor session (a fresh one for every instance);
3. fresh: `issued_at ≤ now + 5 s`, `now < expires_at`, lifetime ≤ 30 s (10 s by default — a stale command is never run late, v15 §7);
4. carrying parameters that match their digest;
5. never executed before (order ids are single-use);
6. meant for the device it is sent to.

Otherwise → `X_ORDER_REJECTED`. After executing, the host answers with the state and an execution receipt bound to the order bytes and that state; the node applies the state only if the receipt matches (`X_RECEIPT_INVALID` otherwise, spec 19).

### Adapter host components

- The node starts **one adapter host per adapter type** through the platform's `ExecutionHost` (spec 18), so a Home Assistant failure does not take the virtual devices down with it. On the hosted platform each host is an OS process with its own address space (`isolated() = true`); the memory backend runs it as a thread and says so (`isolated() = false`, tests only).
- The channel is the component's private byte channel (hosted: the child process's stdin/stdout, private between parent and child, with no socket for another process to squeeze into). The protocol is JSON Lines (`init`, `execute`, `observe`, `simulate`), with each line ≤ 64 KiB.
- The adapter host **holds no private key**: only the boundary's public order key and its own executor session, both given in `init`.
- Its environment is exactly what it is granted, nothing inherited (hosted: `env_clear`). The Home Assistant host receives exactly the variable holding its token and nothing else.
- The host's replies are **untrusted data**:
  - state ≤ 64 entries, keys ≤ 64 characters;
  - values only booleans, integers or strings ≤ 256 characters;
  - error messages truncated and stripped of control characters.
- If a host does not answer in time (5 s; Home Assistant 30 s), exits or breaks the protocol, the node returns `X_DEVICE_UNAVAILABLE`, **stops** the component and restarts it on the next call (at most once per second of the platform's *monotonic* clock, so a wall-clock jump cannot bypass the limit).
- The node **releases its lock** while waiting for an adapter host. Requests are processed in three phases: decide → execute → record. A slow device does not delay decisions for other requests.

Verified by `isolation::crashed_adapter_host_never_reaches_the_monitor`, `hung_adapter_host_does_not_stall_the_node`, `garbage_from_an_adapter_host_is_contained`, `adapter_host_gets_an_empty_environment`, `memory_platform::adapter_host_restarts_follow_the_platform_clock`, the attack suite of spec 19, and the fuzz targets `exec_order` and `host_line`.

**Current limits**:

- The adapter host runs as the same user as the node. OS-level sandboxing (a separate user, seccomp/Landlock, sandbox-exec, network namespaces) is the next step.
- Requests to the same adapter host are processed one at a time.

Next: a production Home Assistant adapter and a direct Matter adapter (v0.3, `ROADMAP.md`). Later (v17 §8, after v0.3): MQTT and W3C WoT/Thingweb adapters.
