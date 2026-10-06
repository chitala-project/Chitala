# 27 — Direct Matter adapter

**Status:** v0.3 step ⑤, software lane (Project Lead, 2026-10-06). The adapter and its backend interface are in place, and they pass the conformance suite (spec 26) on a fake backend. Next comes the matter.js backend; physical validation waits for step ③B.

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

## The matter.js backend (next)

The sidecar is a small TypeScript program on matter.js. Node.js runs its TypeScript directly, with no build step.

- **It holds Chitala's fabric** in a private directory (0600). It speaks **stdio only**: no network API, no socket.
- **Its protocol is typed and allowlisted, never a generic `{command, args}`:**
  - `CommissionDevice`
  - `ReadProfileAttributes`
  - `SubscribeProfileAttributes`
  - `InvokeProfileCommand`
  - `RemoveDevice`

  The sidecar checks every endpoint, cluster, command and attribute against its copy of the Home profile, and the endpoint's device type against the class, before it does anything.
- **Two modes:**
  - **serve**, spawned by the adapter host: reads, subscribes and invokes. It refuses `CommissionDevice` and `RemoveDevice`.
  - **admin**, run by `chitala matter commission`: it commissions and removes devices, and only while the node is stopped. The fabric's storage is claimed exclusively, as a domain is (R2).
- **A Read just before every invoke**, so that `NotSent` is certain.
- **A trust boundary as well as a code rule.** A compromised sidecar process still holds the fabric's keys, and is a full controller of Chitala's devices. A typed protocol bounds what the sidecar's caller can make it do, but not what the sidecar itself can do. So it runs with least privilege, takes no network input, and its storage is private (spec 25, *Deployment requirements*, by analogy).
- **CI** runs it against virtual devices built on matter.js; the lab runs it against the Matter SDK's devices. It must pass the conformance suite as `MatterJsBackend`.

A pure-Rust backend (`RsMatterBackend`) can replace it later. The trait, the adapter's semantics and the Trusted Core stay as they are, and the new backend must pass the same suite.

## Tests

- Unit tests (`direct_matter/tests.rs`):
  - a lock is driven by the profile's timed commands, once each;
  - what each answer says about the order;
  - a plain observation is the subscription's and confirms nothing, and a silent device grows older, then cannot be observed;
  - evidence is a read of the device, given once, and a device that does not answer is not read again at once;
  - only what the profile maps.
- The conformance suite (spec 26): the adapter half and the node half, with `MatterRig` on the fake backend.
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
