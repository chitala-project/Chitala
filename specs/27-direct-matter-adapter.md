# 27 — Direct Matter adapter

**Status:** v0.3 step ⑤, software lane (Project Lead, 2026-10-06). **Software complete, physical validation pending.** The adapter passes the conformance suite (spec 26) on a fake backend. The matter.js backend drives the Matter SDK's lock through the whole chain in the lab. Physical devices are step ③B.

Chitala governs Matter devices on its own fabric, not through Home Assistant:

- **Chitala owns the fabric.**
- **A Matter controller implements the protocol.** That is matter.js now, pure Rust later.
- **The Rust adapter host owns Chitala's semantics:**
  - which command a capability is;
  - what a state is;
  - what an answer says about an order;
  - when a state is tied to the device.
- **The Trusted Core does not change.**

It is also the test that the adapter abstraction is not shaped around Home Assistant (spec 26).

## Architecture

```text
node ──JSON Lines──▶ chitala-adapter-host (Rust)
                       OrderGate: verifies every order
                       DirectMatterAdapter: Chitala's semantics
                         │  DirectMatterBackend (typed, profile paths only)
                         ├─ MatterJsBackend ──stdio──▶ matter.js sidecar
                         │                             Chitala's own fabric
                         └─ RsMatterBackend (later)
                                                   │ Matter (UDP/IPv6)
                                                   ▼
                                                devices
```

The direct Matter adapter does not depend on Home Assistant, and Home Assistant does not depend on it.

## The backend

`DirectMatterBackend` is everything the adapter needs from a Matter controller, and nothing more:

| Operation | What it does |
|---|---|
| `subscribe(target, attributes)` | keeps the attributes subscribed. The device reports their changes, and sends a keep-alive at the subscription's interval |
| `read(target, attributes)` | a Read interaction with no data version filter, so the device sends every value. An attribute the device does not have is left out; none at all is an error |
| `invoke(target, command)` | the command, once, as a Timed Invoke when the profile says so. A backend never sends it again by itself. It reports `NotSent` only when the command certainly never left |
| `subscribed(target)` | the subscription's values, when the device was last heard (a report, or a keep-alive saying nothing changed), and whether the subscription is still up |

A backend has no attribute write, no commissioning, no fabric management and no generic passthrough. The paths it is handed are built from the Home profile only: `ProfileAttribute` and `ProfileCommand` have private fields, so the adapter cannot ask for anything the profile does not map. A backend that crosses a process boundary checks them again on the other side.

A device's class comes from its capabilities. Every capability it declares, other than reading its state, must map to a Matter command in the profile. A device that declares an unmapped capability (a light's `set_brightness`, for now) is refused when the adapter starts.

A target is a node and an endpoint on Chitala's fabric.

## Observing

| Observation | What it returns | Evidence? |
|---|---|---|
| plain | the subscription's state, as old as the last time the device was heard | no: `Uncertain` |
| for evidence | the device read itself, as of when the read began | yes: `ConfirmedCurrent` |
| for evidence, the read not back yet | the subscription's state | no |
| the subscription is down | the observation fails (`X_DEVICE_UNAVAILABLE`) | — |

- **The read for evidence runs in the background**, with the same rules as for Matter devices behind Home Assistant (F10):
  - the observation waits for it 1 s at most;
  - each read's values are evidence once;
  - one read of a device at a time;
  - a device that did not answer is not read again for 5 s.
- **A device that goes silent is still subscribed for a while.** The controller notices only after the subscription's interval and a margin. Until then, its state keeps the age since it was last heard, which grows. It confirms nothing, because no read answers. Safety's freshness rules and outcome verification see the true age.

## Executing

| The backend says | The order | Code |
|---|---|---|
| success | done: the adapter returns the device's state, read right after | — |
| success, and the device cannot be read right after | unknown: no state to vouch for | `X_EXECUTION_UNKNOWN` |
| not sent: no session, or no answer to the read just before | certainly not executed | `X_DEVICE_UNAVAILABLE` |
| a status the device gives before acting: `UNSUPPORTED_ACCESS`, `BUSY`, `ACCESS_RESTRICTED`, `INVALID_IN_STATE` | refused, certainly not executed | `X_DEVICE_REFUSED` |
| a status for a command the device cannot take: `UNSUPPORTED_ENDPOINT`/`_COMMAND`/`_CLUSTER`/`_NODE`, `INVALID_ACTION`/`_COMMAND`, `CONSTRAINT_ERROR`, `RESOURCE_EXHAUSTED`, `NEEDS_TIMED_INTERACTION`, `TIMED_REQUEST_MISMATCH`, `FAILSAFE_REQUIRED` | certainly not executed | `X_ADAPTER` |
| `FAILURE`, `TIMEOUT`, or any other status | unknown: a lock that jams may have moved part way, so outcome verification has to watch it | `X_EXECUTION_UNKNOWN` |
| no answer | unknown | `X_EXECUTION_UNKNOWN` |

- **Nothing is ever sent twice.** The order is spent when the backend is called.
- **Parameters:** commands with parameters are not mapped yet. An order with parameters is refused before anything is sent.

## What the step ⑤ spike measured

A matter.js 0.17.9 controller with its own fabric drove a door lock from the Matter SDK (connectedhomeip). It was run as the sidecar will run it.

| Finding | Consequence |
|---|---|
| Commissioning into Chitala's fabric over the IP network took 1.6 s. The SDK's test certificates need an attestation override, in the lab only | ③B devices have production certificates |
| A Read took 2–8 ms. `LockDoor`/`UnlockDoor` went as a Timed Invoke (TimedRequest, then Invoke). matter.js promotes commands the specification marks timed on its own | the adapter still asks for a Timed Invoke explicitly, from the profile |
| **A device paused for 2 s** during an invoke: MRP retransmission delivered the command once, and the answer came after 2 s | — |
| **A device paused for 30 s, or killed,** during an invoke: `PeerUnresponsiveError` after 13.5 s. The device had received only the TimedRequest. matter.js then reconnected (CASE resumption) and **did not send the command again**; the device's log shows no Invoke | no answer is unknown, never resent |
| After that failure, matter.js still showed the node `Connected` for 37 s more | the node's connection state is not proof of reach. A Read just before the invoke is: if it fails, the command was never sent |
| A second invoke while matter.js was reconnecting failed with `AbortedError` when its connection timeout ran out: nothing was sent | — |
| The subscription's maximum interval was 300 s by default (the controller's ceiling); with a 15 s ceiling, keep-alives came every 15 s (`connectionAlive`). A paused device was noticed 53 s after its last keep-alive | the age since the device was last heard is measurable; a silent device is noticed late, so its age grows meanwhile |
| The SDK lock reports `LockState` 3 (`Unlatched`) for a moment on unlock, then 2. It also relocks itself 60 s after an unlock (`AutoRelockTime`) | value 3 maps to unlocked and open, still provisional in the profile; tests must expect auto-relock |

## The matter.js backend

The sidecar ([`sidecars/matter-js`](../sidecars/matter-js)) is a small TypeScript program on matter.js 0.17.9, pinned exactly with a lockfile. Node.js 24 runs its TypeScript directly, with no build step.

**Its fabric and its channel**
- **It holds Chitala's fabric** in a private directory (0700).
- The Rust side claims `<storage>.lock` exclusively for as long as a sidecar runs (`flock`, as one node per domain, R2). A second sidecar on the same fabric cannot start, and neither can `chitala matter` while the node serves the fabric.
- It speaks **stdio only**: no network API, no socket. Its stdout carries the protocol and nothing else. Every log, matter.js's included, goes to stderr.
- It starts with an **empty environment**, and gets none of the command line's options for matter.js, which reads both.

**The protocol** (JSON Lines, version 1) is typed and allowlisted, never a generic `{command, args}`.

| Mode | Operations |
|---|---|
| serve (spawned by the adapter host) | `Hello`, `SubscribeProfileAttributes`, `ReadProfileAttributes`, `InvokeProfileCommand` |
| admin (run by `chitala matter`) | `Hello`, `CommissionDevice`, `RemoveDevice`, `ListDevices` |

- **A request is refused before anything reaches a device unless it is exactly right:**
  - only its operation's fields;
  - a class of the profile, with attributes the class maps (each once);
  - the capability's command exactly as the profile maps it, Timed Invoke included;
  - a decimal operational node id;
  - an endpoint other than the root (0);
  - an endpoint whose device type is one of the class's.
- **The sidecar checks against its own copy of the profile.** That copy is identical to the specification's; a test and `scripts/check.sh` compare them. It sends only the commands in its own table (On, Off, LockDoor, UnlockDoor), whatever the profile says.
- **Answers:** `ok`, or an error of kind `refused`, `not_sent`, `status` (with the Interaction Model status and cluster status), `indeterminate`, `read` or `failed`.
- **Events:**
  - `values`: the subscribed attributes' reports;
  - `heard`: a keep-alive;
  - `link`: the subscription is up or down. When it comes up, the subscribed values are read again.

**The Rust side (`MatterJsBackend`)**

| What happened | What the backend says |
|---|---|
| a request line could not be written | `NotSent` |
| written, and no answer within 20 s (an invoke) or 12 s (anything else), or the sidecar died | unknown |
| the sidecar refused the request itself | `Rejected`, `X_ADAPTER` |

- **The Hello must match:** protocol 1, the expected mode, and this profile's name and version.
- **A sidecar that dies is started again,** at most every 5 s, and its devices are subscribed again.
- **The node gives a matter adapter host 45 s:** the invoke, then a read.

**`chitala matter`** commissions a device onto Chitala's fabric (with a manual pairing code or a QR code), lists the fabric's devices with the Home profile class each endpoint fits, and removes one. It runs only while the node is stopped. `--accept-test-attestation` is for development devices in a lab, never a home. Commissioning grants nothing: a device is governed only once the config's `matter.devices` maps it.

```json
"matter": {
  "runtime": "/usr/local/bin/node",
  "sidecar": "sidecars/matter-js/src/main.ts",
  "storage": "matter-fabric",
  "subscription_ceiling_s": 60,
  "devices": { "device:front-door": { "node": 1, "endpoint": 1 } }
}
```

`runtime` is an absolute path. `sidecar` and `storage` are resolved against the config's directory.

**A trust boundary as well as a code rule.** The typed protocol bounds what the sidecar's caller can make it do, but not what the sidecar itself can do. A compromised sidecar process holds the fabric's keys and is a full controller of Chitala's devices. Deployment requirements:
- the sidecar runs as the node's user, with least privilege;
- it takes no network input;
- its storage stays private;
- its dependencies are pinned, installed without install scripts, and audited.

A pure-Rust backend (`RsMatterBackend`) can replace it later. The trait, the adapter's semantics and the Trusted Core stay as they are, and the new backend must pass the same suite.

## Lab: the whole chain on the Matter SDK's lock

On this machine, with a fresh Matter SDK lock commissioned onto a new Chitala fabric with `chitala matter commission`, through a real node and adapter host:

| Scenario | Result |
|---|---|
| `chitala matter devices` | node 1, endpoint 1: device types 0x000A (Door Lock) and 0x0011 (Power Source); class `lock` |
| the owner unlocks, then locks | each `verified`; the evidence is a read of the device (`source: matter`, `confirmed_at_ms`) |
| the lock is paused; the owner locks | `X_DEVICE_UNAVAILABLE` after 10 s: the read just before got no answer, so nothing was sent. The lock's own log shows no command |
| the sidecar is killed; the owner locks | a new sidecar is started, the lock subscribed again; `verified` |
| `chitala matter devices` while the node runs | refused: the fabric is in use |
| the lock stays silent for 80 s (subscription ceiling 15 s) | `SAFE-3-STATE`: the door's state is unknown, nothing is sent. About a minute after it is back, the unlock goes through again (matter.js reconnects, then the node observes) |
| the node stops | the sidecar stops with it |

## Tests

- Unit tests (`direct_matter/tests.rs`):
  - a lock is driven by the profile's timed commands, once each;
  - what each answer says about the order;
  - a plain observation is the subscription's and confirms nothing, and a silent device grows older, then cannot be observed;
  - evidence is a read of the device, given once, and a device that does not answer is not read again at once;
  - only what the profile maps.
- The conformance suite (spec 26): the adapter half and the node half, with `MatterRig` on the fake backend.
- **The matter.js backend's side of the protocol** (`direct_matter/matter_js_tests.rs`), against a scripted sidecar over pipes:
  - only a serving sidecar of this protocol on this very profile is used;
  - requests are the typed profile operations;
  - what each answer to an invoke says;
  - a sidecar that dies mid-command leaves it unknown, and takes no more;
  - the subscription follows the sidecar's events;
  - a read returns what was asked.
- **The sidecar's own tests** (`sidecars/matter-js/test`, `npm test`):
  - its profile is the specification's, byte for byte;
  - typed requests are accepted;
  - anything not exactly a profile operation is refused;
  - each mode has its own operations;
  - an oversized line is refused.
- **The lab run**, above.
- **Mutations of the matter.js backend and the sidecar's protocol: 13 of 13 caught.**
  - The Rust side:
    - a line never written taken as unknown, or no answer taken as not sent;
    - any mode, or any profile, accepted at Hello;
    - a refused request taken as not sent;
    - values of attributes not subscribed kept;
    - the fabric not claimed exclusively, or a fabric others can read accepted.
  - The sidecar:
    - the Timed Invoke not checked;
    - every operation in every mode;
    - extra fields accepted;
    - attributes not checked against the class;
    - the root endpoint accepted.
- **Mutations: 11 of 11 caught.**
  - `FAILURE` taken as a certain refusal;
  - not sent taken as unknown;
  - the subscription's state taken as evidence;
  - a read dated when it came;
  - a success that cannot be read taken as done;
  - a subscription that is down still observed;
  - parameters dropped instead of refused;
  - an unmapped capability accepted at start;
  - devices not subscribed at start;
  - an unknown fate sent again;
  - the Timed Invoke flag lost.
