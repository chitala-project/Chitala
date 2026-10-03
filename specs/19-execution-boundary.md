# 19 — Trusted Execution Boundary

Sources: Invariant 1 (specs 00, 15); Blueprint v20 §8 (… → Action → Observation → Audit) and §11 (device actions carry evidence); milestone *Chitala Trusted Execution Boundary v0.2 — Single Path, Single Use, Provenance Bound*.

Crates: `chitala-boundary` (Trusted Core: the only producer of physical commands), `chitala-csme::order` (order and receipt wire formats), `chitala-adapters` (the order gate in the adapter host), `chitala-node` (wiring, receipt checks, audit).

## The invariant

> **No code path can change physical state without going through
> Authority → Safety → TrustedExecutionBoundary → ExecOrder → AdapterExecutor,**
> and CI and tests prove it.

```text
person / service request ─▶ Reference Monitor ─▶ Authorized ─┐
                                                              ├─▶ Safety ─▶ Clearance ─┐
AI intent ─▶ admission ─▶ Authority Engine ─▶ Grant ─────────┘                         │
                                                                                       ▼
                                             TrustedExecutionBoundary::mint (consumes both)
                                                                                       │
                       signed ExecOrder: one action, one adapter host instance, ≤ 30 s, single use
                                                                                       │
                                        adapter host: OrderGate ─▶ DeviceAdapter ─▶ device
                                                                                       │
                                  ExecutionReceipt ─▶ node: verify_receipt ─▶ twin + audit
```

| Who | Produces | Never produces |
|---|---|---|
| Reference Monitor (spec 08) | `Authorized` for one signed request of a person or service | a command |
| Authority Engine (spec 16) | `Grant` for one intent | a command |
| Safety (spec 17) | `Clearance` for one action of one intent or request | authority (it can only refuse) |
| **Trusted Execution Boundary** | `MintedOrder` = a signed `ExecOrder` | — |
| Adapter host | executes a `VerifiedOrder`; answers with an `ExecutionReceipt` | orders |
| Node | checks the receipt, folds the state into the twin, records everything | orders outside `mint` |

Since v0.2 **every** physical action takes this path: a person's or service's request as much as an AI's intent. A person's request is therefore also cleared by Safety (SAFE-1…6): an owner cannot bolt an open door or make a lock oscillate either. A device capability that no governed resource binds is never actuated (`E_SAFETY`), because Safety has nothing to check it against. Reading state (`device.read_state`) is not an action and needs no order.

## Single path: three layers

### 1. Types

| Type | Created only by | `Clone` | Consumed by |
|---|---|---|---|
| `Grant` | `chitala_policy::authority::decide` | no | `mint` |
| `Authorized` | `chitala_monitor::Monitor::check` | no | `mint` |
| `Clearance` | `chitala_safety::Safety::clear` | no | `mint` |
| `MintedOrder` | `TrustedExecutionBoundary::mint` | no | `Executor::execute` |
| `VerifiedOrder` | `OrderGate::admit` (adapter host) | no | `DeviceAdapter::execute` |

The node's executors accept only a `MintedOrder`, and adapters only a `VerifiedOrder`, both by value. `chitala-boundary` pins these properties down with tests that must not compile: forging or cloning a `MintedOrder`, cloning a `Clearance`, fabricating a `Grant`, reading the order key.

### 2. Keys

Orders are signed with the **order key** of the boundary. It is generated from the platform's entropy when the node starts and lives in one private field of one `TrustedExecutionBoundary` value. It is never stored, exported or logged; the start record of the audit log names its key id (`order_key`).

Adapter hosts are started with that public key (and nothing else) and accept no other signature. Consequences:

- code that does not go through `mint` cannot produce an order an adapter executes — not even with the node's identity key (`the_node_identity_key_cannot_command_a_device`);
- every outstanding order dies with the node process that minted it (`orders_die_with_the_node_that_minted_them`).

### 3. CI

`scripts/check-execution-boundary.py` (CI job **execution boundary (single path)**, and `scripts/check.sh`) fails if non-test code anywhere in `crates/` does one of these outside its allowlist:

| Rule | Guards | Allowed in |
|---|---|---|
| `mint` | building or signing an order (`ExecOrder { … }`, the order content type) | `chitala-csme/src/order.rs`, `chitala-boundary` |
| `boundary` | creating a boundary or calling `mint` | `chitala-node`: `lib.rs` (one per node), `node.rs`, `intents.rs`; the CLI demo |
| `admit` | decoding or admitting an order | `chitala-csme/src/order.rs`, `chitala-adapters`: `lib.rs`, `host.rs` |
| `dispatch` | sending an order to an executor or adapter | `chitala-node`: `node.rs`, `executor.rs`; `chitala-adapters/src/host.rs` |
| `host` | starting an adapter host (it pins the key it is given) | `chitala-node`: `executor.rs`, `lib.rs`; `chitala-adapters/src/host.rs` |
| `device-io` | `DeviceIo`, `DeviceChannel` | `chitala-platform`, `chitala-platform-host`, `chitala-adapters` |

A new path to an actuator therefore needs an edit to this code-owned allowlist. The script also fails when an allowlisted file disappears or a rule matches nothing in its own allowlist (stale patterns), and `--self-test` injects violations into a copy of the tree to prove that every rule still fires. Run on the code before this milestone, it reports exactly the two places that minted orders, one of them the direct path of persons that skipped Safety.

## The order (`application/chitala-order`, version 2)

A COSE_Sign1 (Ed25519, order key) over a deterministic-CBOR map with exactly these keys; anything else is refused, and version 1 is refused (`E_VERSION`).

| Key | Field | Type |
|---:|---|---|
| 1 | version (= 2) | uint |
| 2 | order id: 128 random bits, single use (the order's nonce) | bstr(16) |
| 3 | executor: session of the one adapter host instance that may execute it | bstr(16) |
| 4 | subject: id of the authorized intent or request | bstr(16) |
| 5 | subject digest: the intent digest approvals sign (spec 15), or SHA-256 of the signed request | bstr(32) |
| 6 | actor | tstr |
| 7 | resource | tstr |
| 8 | device | tstr |
| 9 | capability | tstr |
| 10 | capability version | uint |
| 11 | parameters (omitted when empty) | map |
| 12 | parameter digest: SHA-256 of the deterministic CBOR of the parameters | bstr(32) |
| 13 | context digest (below) | bstr(32) |
| 14 | authority epoch at the decision | uint |
| 15 | evidence: audit sequence number of the decision record | uint |
| 16 | cleared at: time of the safety clearance (ms) | uint |
| 17 | issued at (ms) | uint |
| 18 | expires at (ms): 10 s after issue by default, at most 30 s | uint |

**Context digest** = SHA-256 of the canonical JSON (the RFC 8785 subset of the audit log, spec 09) of

```json
{"v": 2, "domain": "…", "policy_fp": "…", "epoch": 7, "kind": "intent | request",
 "actor": "…", "on_behalf_of": "…", "relayed_from": ["…"], "approved_by": ["…"],
 "tokens": ["revocation id", "…"], "policy": ["policy id", "…"]}
```

The node writes this object into the decision's audit record (`context`), so an auditor can recompute the digest and tie every order to the authority context that justified it.

## Single use

- **Consumed proofs.** `mint` consumes the authority and the clearance. The clearance must describe exactly the authorized action (subject, device, capability, parameters, and for intents the resource) and be at most 1 s old.
- **Bound clearance.** A clearance names its intent or request: the clearance of intent A never clears intent B, even for the very same action (`a_clearance_of_one_intent_never_clears_another`).
- **Single use.** The adapter host executes an order id once (`a_replayed_order_is_refused`) and only before it expires (`an_order_delivered_after_its_ttl_is_refused`).
- **One executor.** Every adapter host instance gets a fresh executor session when it starts; an order names one. Another host refuses it (`one_order_is_executed_by_one_executor_once`). So does the same host after a restart, whose replay set is empty (`a_stale_order_reaching_a_restarted_host_is_refused`). The node does not even send an order minted for an instance that has stopped.
- **Authority fence.** The node releases its lock while a device works, so a revocation, a state change or a safety hold can happen between the decision and the execution. Every order carries what it depends on — the tokens of every link (with their ancestors, issuers and expiry), the principals of its decision (actor, represented person, relaying agents, approvers, device) and its resource with every resource it is in — and is re-checked right before it is sent: if one of its tokens was revoked (by id, by cascade or by a revocation floor) or expired, one of those principals can no longer act, or a safety hold now covers the resource, the order is not sent (`X_ORDER_REJECTED`, `a_revocation_after_the_decision_stops_the_order`, `a_revocation_stops_an_order_in_flight_but_an_unrelated_change_does_not`). An unrelated delegation does not stop it. An approval re-runs Authority and Safety (`a_revocation_while_a_human_decides_voids_the_approval`). The order also records the authority epoch for the audit.
- **Exact parameters.** Parameters are inside the signed order and must match their digest. A modified order does not verify (`parameters_cannot_change_after_the_decision`). An approval answers one intent digest and nothing else.
- **Exact device.** An order executes only on the device it names (`an_order_cannot_be_redirected_to_another_device`).
- **One at a time.** While a device executes an order, Safety refuses any other action through it (`SAFE-7-BUSY`, spec 17): two actions cleared on the same state never interleave (`conflicting_actions_on_one_device_do_not_interleave`).

## Provenance: execution receipts

After executing, the adapter host answers with the device state and a receipt:

| Field | Meaning |
|---|---|
| `order` | the order id |
| `order_digest` | SHA-256 of the order bytes it executed |
| `executor` | its own session |
| `device`, `capability` | what it did |
| `executed_at_ms` | when |
| `state_digest` | digest of the state it reports |

The node believes the report only if the receipt answers exactly the order it sent: same id and bytes, same executor, device and capability, a state digest that matches the reported state, and a time inside the order's validity (`chitala_boundary::verify_receipt`). Otherwise:

- the response is `X_RECEIPT_INVALID`;
- the state is **not** applied to the twin;
- an adapter-error event is published;
- the execution record carries `receipt_error`.

`a_lying_adapter_host_is_not_believed` covers a missing receipt, another order, other bytes, another instance, another device and an unvouched state.

The audit log ties the chain together (`every_physical_action_is_one_order_with_a_verified_receipt`):

```text
decision record (seq S, context) ──▶ order (evidence = S, context digest)
                                            │
execution record (decision_seq = S, order, order_digest, executor, receipt {executed_at_ms, state_digest})
```

## Device I/O

Only adapters reach hardware, through the PAL's `DeviceIo` (spec 18), and only while executing an admitted order. The node's own platform has no devices at all (`the_node_process_has_no_device_io`); the CI rule `device-io` keeps it that way.

## Safety for everyone, and fresh state

Because persons' requests are now cleared by Safety too, SAFE-3 (state freshness for medium and higher risk) applies to them. So that a long-running node does not refuse actions only because nobody looked at a device recently, the IPC server observes every device whose state a resource relies on once its state is older than half the age the resource allows (`STATE_REFRESH_INTERVAL` = 10 s).

## Attack tests

| Attack | Defence | Test |
|---|---|---|
| Replay the same order | single-use order ids in the host | `a_replayed_order_is_refused` |
| Deliver an order after its lifetime | expiry in the gate | `an_order_delivered_after_its_ttl_is_refused` |
| Change parameters after the decision or approval | signed parameters + digest; approvals bind the intent digest | `parameters_cannot_change_after_the_decision`, `parameters_must_match_their_digest` |
| Send the order to another device / clear another resource | device binding in the gate; clearance must match the authority | `an_order_cannot_be_redirected_to_another_device`, `a_clearance_must_describe_exactly_the_granted_action` |
| Policy or revocation change between decision and execution | authority fence (the order's own tokens and principals); approvals re-run Authority and Safety | `a_revocation_after_the_decision_stops_the_order`, `a_revocation_while_a_human_decides_voids_the_approval` |
| Clearance of intent A with the grant of intent B | subject-bound clearances | `a_clearance_of_one_intent_never_clears_another` |
| Two executors consume one order | executor sessions + single use | `one_order_is_executed_by_one_executor_once` |
| Restart, then replay | ephemeral order key; new session per host instance; request replay cache | `orders_die_with_the_node_that_minted_them`, `a_stale_order_reaching_a_restarted_host_is_refused`, `replay_after_restart_is_refused` |
| An adapter host forges a receipt | `verify_receipt` | `a_lying_adapter_host_is_not_believed`, `receipts_must_answer_exactly_the_order` |
| Bypass the boundary straight to devices | order key private to the boundary; no device I/O in the node; CI rules | `the_node_identity_key_cannot_command_a_device`, `the_node_process_has_no_device_io`, `check-execution-boundary.py --self-test` |
| A person bypasses Safety | requests are cleared like intents | `safety_applies_to_people_too`, `safety_and_the_device_both_refuse_unsafe_commands`, `an_ungoverned_device_is_never_actuated` |

The end-to-end versions are in `crates/chitala-node/tests/execution_boundary.rs`. The fuzz targets `exec_order` and `host_line` cover orders and receipts entering and leaving the adapter host.

## Not in this version

- **ExecutionLease.** A lease that grants execution inside an envelope (several uses, a plan) generalises the `ExecOrder`. It comes after single-action execution is proven safe; an order will then be one use of a lease.
- **Signed receipts and attested adapter hosts.** The adapter host holds no key. Its receipt is authenticated by the private channel and bound by digest, and the node records it in its signed audit log. A compromised host can still report a false state consistently; outcome verification (checking the physical world) is a later milestone.
- **Hardware-held order key, OS sandbox for adapter hosts.** See decision D3 (spec 18) and the threat model (spec 13).
