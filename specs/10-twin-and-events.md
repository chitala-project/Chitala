# 10 — Digital Twin, Event Bus and Adapters

Sources: v9 §3 (Event Fabric), §4 (Distributed State & Reconciliation), v15 §5 (World Model), v16 §27, v17 §6–9 (device model separate from protocol, mock-first), v5 §11 (hardware without native Chitala support), v7 §10.

## Digital Twin

Every entity has:

| Part | Meaning |
|---|---|
| `reported` | the state the device reports — the **source of truth** about the physical world |
| `desired` | the state Chitala asked for |
| `drift` | the desired keys that do not match `reported` yet |
| `version` | increases whenever `reported` changes |
| `reported_at_ms`, `source`, `freshness` | `freshness` is `fresh`, `stale` or `unknown` (stale after 5 minutes by default) |

Reconciliation rules (v9 §4):

- `desired` **never** overwrites `reported`. When a device refuses a command, the twin does not lie: `desired.locked = true`, `reported.locked = false`, and the `drift` is visible.
- An observation older than the current one is ignored, so reconnects and replays cannot pull the state backwards.
- No "last write wins by timestamp" for safety data.
- The safety layer reads the twin of a resource's state reference and treats an old or missing observation as unknown (spec 17, `SAFE-3`).

`device.read_state` returns the twin's view after observing the device again. If the observation fails, it returns the previous view with `observe_error` and the matching freshness.

## Event bus

An event has `id`, `kind`, `source`, `ts_ms`, `data` (flat payload) and `caused_by` (the message or intent id that caused it).

Kinds: `state_changed`, `security_denied`, `adapter_error`, `authority_changed`, `security_state_changed`, `approval_requested`, `approval_answered`.

- **Only events travel on the bus.** There is no API to send a command over the bus, so the bus can never become a way around Authority/Safety (v9 §3).
- Every subscriber has a bounded queue. When it is full, the oldest *non-security* event is dropped first; security events are dropped only when nothing else is left. Every drop is counted (v16 §27).
- A publisher is never blocked by a slow subscriber.

## Adapters

An adapter translates standard capabilities to a specific device or protocol. Being connected to a device grants no authority (v17 §6).

| Adapter | Purpose |
|---|---|
| `mock` | Virtual lights, switches, air conditioner and lock; fault injection (offline, a one-off failure); a local invariant: the lock refuses `lock.lock` while the door is open → `X_DEVICE_REFUSED` (C5). Used as the simulated door of the Physical Authority Slice |
| `home-assistant` | REST bridge to an existing Home Assistant. Such devices cannot authenticate Chitala's command path, so they SHOULD be declared `SC0`/`SC1`. The HA token comes from an environment variable and is never written to config or logs. `http://` is only accepted for localhost unless the config sets `allow_insecure_http: true` (v7 §10) |

Execution failures after an allow: `X_DEVICE_UNAVAILABLE`, `X_DEVICE_REFUSED`, `X_ORDER_REJECTED`, `X_ADAPTER`.

## Adapter isolation (Blueprint A.3, v8 §3, §12)

Adapters **do not run in the Trusted Core process**. A failing, hung or compromised adapter must not affect the Reference Monitor (A.3: "an adapter crash must not bring down the Authority/Safety Core").

```
 node (Trusted Core)                                              chitala-adapter-host (1 process per adapter type)
 Authority ─ Grant + Clearance ─▶ ExecOrder signed with the node key ─stdin─▶ OrderGate: node signature, expiry, single use
                                                                             └▶ adapter (mock, home-assistant)
                ◀─stdout─ reply: UNTRUSTED data (bounded size and types) ─┘
```

### Execution orders (ExecOrder)

An execution order is the **physical command** of Invariant 1 (spec 15). It is a COSE_Sign1 (Ed25519) signed with the **node key**, with content type `application/chitala-order`. That content type differs from CSME and intents, so a request or intent signature can never be used as an order and vice versa (v4 §14).

The body is deterministic CBOR with keys 1–9:

1. version
2. order id (= the id of the allowed request or intent)
3. actor
4. target
5. capability
6. capability version
7. decided-at
8. expires-at
9. payload

Unknown keys are refused. On the intent path, only the trusted boundary mints orders, from a `Grant` and a matching `Clearance`.

The adapter host executes an order only if it is:

1. signed by the node public key pinned at start-up;
2. fresh: `decided_at ≤ now + 5 s`, `now < expires_at`, lifetime ≤ 30 s (10 s by default — a stale command is never run late, v15 §7);
3. never executed before (order ids are single-use);
4. meant for the device it is sent to.

Otherwise → `X_ORDER_REJECTED`.

### Adapter host components

- The node starts **one adapter host per adapter type** through the platform's `ExecutionHost` (spec 18), so a Home Assistant failure does not take the virtual devices down with it. On the hosted platform each host is an OS process with its own address space (`isolated() = true`); the memory backend runs it as a thread and says so (`isolated() = false`, tests only).
- The channel is the component's private byte channel (hosted: the child process's stdin/stdout, private between parent and child, with no socket for another process to squeeze into). The protocol is JSON Lines (`init`, `execute`, `observe`, `simulate`), with each line ≤ 64 KiB.
- The adapter host **holds no private key**, only the node's public key.
- Its environment is exactly what it is granted, nothing inherited (hosted: `env_clear`). The Home Assistant host receives exactly the variable holding its token and nothing else.
- The host's replies are **untrusted data**:
  - state ≤ 64 entries, keys ≤ 64 characters;
  - values only booleans, integers or strings ≤ 256 characters;
  - error messages truncated and stripped of control characters.
- If a host does not answer in time (5 s; Home Assistant 30 s), exits or breaks the protocol, the node returns `X_DEVICE_UNAVAILABLE`, **stops** the component and restarts it on the next call (at most once per second of the platform's *monotonic* clock, so a wall-clock jump cannot bypass the limit).
- The node **releases its lock** while waiting for an adapter host. Requests are processed in three phases: decide → execute → record. A slow device does not delay decisions for other requests.

Verified by `isolation::crashed_adapter_host_never_reaches_the_monitor`, `hung_adapter_host_does_not_stall_the_node`, `garbage_from_an_adapter_host_is_contained`, `adapter_host_gets_an_empty_environment`, `memory_platform::adapter_host_restarts_follow_the_platform_clock`, and the fuzz targets `exec_order` and `host_line`.

**Current limits**:

- The adapter host runs as the same user as the node. OS-level sandboxing (a separate user, seccomp/Landlock, sandbox-exec, network namespaces) is the next step.
- Requests to the same adapter host are processed one at a time.

Next (v17 §8, after the feature freeze): MQTT and W3C WoT/Thingweb adapters.
