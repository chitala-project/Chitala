# 26 — Adapter conformance

**Status:** v0.3 step ⑤, before a second production adapter (Project Lead, 2026-10-06).

Chitala governs devices through adapters: the mock, Home Assistant (spec 25), and the direct Matter adapter (step ⑤). Each speaks to a different backend, and each could quietly bend the guarantees the Trusted Core relies on. This spec states the contract every adapter must keep, and the suite that checks it. The same tests run on every adapter. That is also the evidence that the adapter abstraction is not shaped around one backend.

## The contract

An adapter implements `DeviceAdapter` (spec 10): it executes admitted orders and observes devices. It never decides anything (spec 22).

| | The adapter… | Why |
|---|---|---|
| K1 | executes an admitted order **once**: one command reaches the device. Observing sends no command | no double actuation |
| K2 | when the answer to a command is lost after the command may have reached the device, says the fate is **unknown** (`Indeterminate`, `X_EXECUTION_UNKNOWN`), and **never sends it again** | Chitala observes the world to decide; a resend is a blind second actuation |
| K3 | says unknown even when the device did nothing: it cannot tell the two apart | the same |
| K4 | reports a refusal the backend states as a **certain failure** (`Refused` or `Failed`), never as an unknown | a certain failure needs no recovery |
| K5 | observes the device **as it is**, in the Home profile's terms (spec 24), follows changes made outside Chitala, and gives an age for every state it heard live | Safety and the twin rely on the state and its age |
| K6 | **confirms** a state (`Provenance::ConfirmedCurrent`) only when it is tied to the device itself, now | outcome evidence (F9, F9b, F10) |
| K7 | confirms **nothing younger than a device's silence**: once a device cannot be reached, no state is confirmed as more recent than the silence, a command does not succeed, and nothing is made up | an unreachable device is not a state (F6) |

And through the whole chain, whatever the adapter, Chitala reaches the same judgement:

| | The node… |
|---|---|
| N1 | verifies an order by what the device says, and sends each order once |
| N2 | settles a lost answer by what the device did after the order: `applied` when the lock locked; no recovery; never resent |
| N3 | settles a lost answer where the device did nothing as `not_applied`; never resent |
| N4 | ends a lost answer from a device that then went silent as `unconfirmed`, and puts the door in recovery. The safe state is not run blindly, and nothing is sent again |
| N5 | refuses to act on a door whose lock cannot be observed (`SAFE-3-STATE`), sending nothing, and acts again once the lock is observed |

## Rigs

A rig (`chitala_adapters::conformance::Rig`) is an adapter and the world behind it:

- the adapter, ready to serve;
- the door lock it drives, and the physical truth: whether the bolt is thrown;
- a hand that turns the bolt outside Chitala;
- a count of the commands that reached the device, or the backend in front of it;
- faults:
  - `Offline`: the device can no longer be reached;
  - `LoseAnswer`: the next command takes effect, and its answer is lost;
  - `LoseAnswerWithoutEffect`: the next command does nothing, and its answer is lost;
  - `LoseAnswerAndGoSilent`: the next command takes effect, its answer is lost, and the device can no longer be reached;
  - `Refuse`: the backend refuses the next command and says so.

| Rig | The adapter | The world |
|---|---|---|
| `MockRig` | the mock adapter | its virtual lock, through another handle on the same virtual devices. The mock loses answers itself (`mock::Lost`) |
| `HaRig` | the Home Assistant adapter, with the Matter evidence provider | a fake Home Assistant, and a fake Matter server holding the lock's node (F10). Offline: the node dies, and Home Assistant marks the lock `unavailable` and fails calls to it. A refusal: `service_validation_error` |
| direct Matter | the direct Matter adapter (step ⑤) | to come, with each of its backends |

## Running it

- Adapter half: `chitala-adapters/tests/conformance.rs`, one test per check (K1–K7, and K2 for a device gone silent) per rig.
- Node half: `chitala-node/tests/conformance.rs`, one test per check (N1–N5) per rig. The node runs with the rig's adapter in process, on a clock that moves with real time.
- Both build with the `conformance` feature of `chitala-adapters`. It is never part of a node or an adapter host.
- The rigs (`chitala_adapters::conformance`) build, admit and send no order. The adapter half signs its orders with a test key and admits them through a real gate, in test code. So the execution boundary's allowlist (`scripts/check-execution-boundary.py`) is unchanged.

Adding an adapter means adding its rig to both lists. An adapter that cannot pass a check does not ship.

**Mutations:** seven faults were put into the code on purpose, and the suite caught every one:

- Home Assistant:
  - taking a refusal for an unknown;
  - sending a lost call again by REST;
  - taking a lost call as done;
  - reusing a stale Matter read;
- the mock:
  - executing while offline;
  - reporting a lost answer as done;
- the node: never recovering an unconfirmed outcome.
