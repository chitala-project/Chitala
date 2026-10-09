# Chitala Specification v0.1 (provisional)

The current blueprint is **v20** (*Chitala OS Blueprint 2026–2046*, maintained outside this repository): Chitala is an operating-system architecture that runs Hosted first and aims for Native.

- Specs 00–13 specify the **Trusted Core**, which v20 §5 requires to be inherited intact. Where v20 does not change the meaning, they still cite section numbers of Blueprint v18, the most detailed version on security.
- Specs 14–17 are the **domain model** that makes Chitala different from an MCP gateway: Resource, Intent, Authority Engine and Safety (milestone *Physical Authority Slice v0.1*).
- Spec 18 is the **Platform Abstraction Layer**: the Trusted Core reaches the machine only through it (milestone *v0.2 — Platform Independence & Trusted Execution Boundary*).
- Spec 19 is the **Trusted Execution Boundary**: one path from authority to actuator, single-use orders, provenance-bound receipts.
- Spec 20 is the **Native platform** spike: the node core booted as a unikernel, with no host operating system.
- Spec 21 is the **Execution Lease**: one authority decision, and for high risk one approval of exact terms, covering a bounded series of single-use orders.
- Spec 22 is **Outcome Verification and Recovery**: every device action promises an outcome, the resource's witness confirms it, and a broken promise stops the resource until a person releases it, after the node has run its declared safe state once.
- Spec 23 is the **Plan Engine**: several intents in order, each judged when it runs and started only after the one before has verifiably taken effect; a step that needs a person pauses the plan.
- Spec 24 is the **Home Capability Profile**: lights, plugs and locks normalised across Home Assistant and Matter, with nothing guessed (v0.3).
- Spec 25 is the **Home Assistant adapter**: WebSocket first, REST as a fallback; it only executes and observes, never retries, and reports a command whose fate is unknown as indeterminate (v0.3).

How v20 and the repository differ is in [`docs/v20-alignment.md`](../docs/v20-alignment.md).

> **Invariant 1:** AI produces Intent. Chitala produces Authority. Only the trusted execution boundary produces physical Commands.

The original build order follows **v17 §1–4**:

> Specification → Identity → Capability/Authority → Reference Monitor → Messaging → Device Model/SDK → Logging → Digital Twin/State → Adapters → …

The specification is a contract that should outlive the code (v1: "the standard must outlive the code"). The reference implementation is the Rust code in `crates/`. Every wire format (CSME, intents, approvals, orders, tokens, audit) is defined tightly enough that an implementation in another language can interoperate (v11: "the protocol must be language-neutral").

## Index

| Spec | Content | Blueprint | Crate |
|---|---|---|---|
| [00-security-constitution.md](00-security-constitution.md) | Invariant 1, invariants C1–C14 and where they are enforced | v13 §1, v8 §8/§14/§18, v15 §12, v19 | all |
| [01-core-model.md](01-core-model.md) | Entities/principals, identifiers, payloads | §4, v12 §9, v17 §2 | `chitala-model` |
| [02-identity.md](02-identity.md) | Ed25519 keys, key ids, principal registry, roles, agency | v10, v12 §1 | `chitala-identity` |
| [03-classification.md](03-classification.md) | Unified classification scales + mapping to v18 | v4 §8/§13, v5 §15, v13 §2/§4/§11, v14 §17, v15 §10, v16 §15 | `chitala-model` |
| [04-capability-registry.md](04-capability-registry.md) | Capability Registry, safety envelopes, targets | Appendix A.1–A.2 | `chitala-model` |
| [05-capability-token.md](05-capability-token.md) | Capability tokens (Biscuit), attenuation, delegation, revocation | v8 §2/§8, v12 §18 | `chitala-token` |
| [06-policy.md](06-policy.md) | Policy engine (Cedar), schema generated from the registry | v9 "Authority Engine", v11 §15 | `chitala-policy` |
| [07-csme.md](07-csme.md) | Chitala Secure Message Envelope v1 (wire format) | v4 §3/§7/§14 | `chitala-csme` |
| [08-reference-monitor.md](08-reference-monitor.md) | Decision pipeline + deny codes | v8 §1, v17 §3 | `chitala-monitor` |
| [09-audit.md](09-audit.md) | Tamper-evident audit log, redaction | v16 §3/§7/§8 | `chitala-audit` |
| [10-twin-and-events.md](10-twin-and-events.md) | Digital Twin, event bus, adapters, execution orders | v9 §3–4, v15 §5, v17 §6–7 | `chitala-state`, `chitala-bus`, `chitala-adapters` |
| [11-node-ipc.md](11-node-ipc.md) | Home Node, config, IPC, containment, domain operations | v9 "Home/Site Server", v8 §9 | `chitala-node`, `chitala-cli` |
| [12-ai-broker-mcp.md](12-ai-broker-mcp.md) | AI Action Broker over MCP | v8 §1/§6, v12 §4, v17 §11 | `chitala-mcp` |
| [13-threat-model.md](13-threat-model.md) | Trust boundaries, blocked attacks (with tests), remaining risks | v13 §18, v8 §19 | — |
| [14-resource-model.md](14-resource-model.md) | The governed physical world: resources, ownership, parent/child tree, location, state references, bindings | v20, v19 | `chitala-resource` |
| [15-intent.md](15-intent.md) | **Invariant 1**; Intent ≠ Command; intent and approval wire formats; relays | v19, v20 | `chitala-intent` |
| [16-authority-engine.md](16-authority-engine.md) | WHO → ON_BEHALF_OF → WHAT → OBJECT → CONTEXT → DELEGATION → RISK → APPROVAL | v19, v9 | `chitala-policy::authority` |
| [17-safety.md](17-safety.md) | An independent safety layer that can only refuse: SAFE-1…8, clearances | v19, v8 §10 | `chitala-safety` |
| [18-platform.md](18-platform.md) | Platform Abstraction Layer: clock, entropy, key store, storage, IPC, network, execution, device I/O; core purity | v20 §2/§4 | `chitala-platform`, `chitala-platform-host` |
| [19-execution-boundary.md](19-execution-boundary.md) | **Single path** Authority → Safety → Boundary → ExecOrder → adapter; order v2, executor sessions, receipts, CI guard, attack tests | v20 §8, §11 | `chitala-boundary` |
| [20-native-platform.md](20-native-platform.md) | The node core as a Hermit unikernel on QEMU/Arm: Native PAL backend, hardware entropy (fail closed), the 13-decision run, trust notes | v20 §1/§2/§19 | `native/` |
| [21-execution-lease.md](21-execution-lease.md) | Execution leases: asking, using (each use judged again, cleared by Safety, counted before its order), ending, persistence, intent version 2 | v20 §8/§11, R6 | `chitala-intent`, `chitala-policy::authority`, `chitala-node` |
| [22-outcome-recovery.md](22-outcome-recovery.md) | Outcome verification and recovery: outcomes in the registry, the witness, statuses, recovery (SAFE-8), safe states the node runs once (`RecoveryGrant`) | v19 §5/§8, v20 §11 | `chitala-model`, `chitala-safety`, `chitala-policy::authority`, `chitala-boundary`, `chitala-node` |
| [23-plan-engine.md](23-plan-engine.md) | Plans: intent key 17, steps as intents of their own, precheck, step-by-step execution on verified outcomes, the approval pause, cancellation | v20 §8, v19 §12 | `chitala-intent`, `chitala-node`, `chitala-mcp` |
| [24-home-profile.md](24-home-profile.md) | Home Capability Profile v0.1: light, plug and lock classes, normalised state (nothing guessed), Home Assistant and Matter mappings; [profiles/home-v0.1.json](profiles/home-v0.1.json) | A.1, v19 §8 | `chitala-adapters::profile` |
| [25-home-assistant-adapter.md](25-home-assistant-adapter.md) | Home Assistant adapter v0.3: the WebSocket link, observe, execute with one transport and one attempt, error semantics, configuration and discovery, the fake Home Assistant | v0.3 ② | `chitala-adapters::home_assistant` |
| [26-adapter-conformance.md](26-adapter-conformance.md) | Adapter conformance v0.3: the contract every adapter keeps (execute once, never resend, unknown when the answer is lost, certain refusals, the device as it is, confirmation tied to the device, nothing younger than a silence) and the node's same judgement through the whole chain; rigs for every adapter | v0.3 ⑤ | `chitala-adapters::conformance` |
| [27-direct-matter-adapter.md](27-direct-matter-adapter.md) | Direct Matter adapter v0.3: Chitala's own fabric through a typed Matter controller backend (matter.js now, pure Rust later); observing (the subscription's state, evidence only from a read), executing (what each answer says about an order), the step ⑤ spike | v0.3 ⑤ | `chitala-adapters::direct_matter` |
| [28-adversarial-home-suite.md](28-adversarial-home-suite.md) | Adversarial Home suite v0.3: the fault classes (backend crash and hang, stale subscriptions, offline and rejoin, Home Assistant restart and partition, Chitala restarting around a send, duplicate and late reports, wrong witness, malformed state, ambiguous status, both paths at once), the invariants they keep, the tests on each path, the fake sidecar, finding F12 | v0.3 ⑥ | `chitala-node/tests/adversarial_home.rs` |
| [29-telemetry-history.md](29-telemetry-history.md) | Telemetry and history v0.1, local: what devices did over time, outside the Trusted Core; the node publishes `observed`/`unobservable`, a recorder keeps a private log with retention, queries give time in a value, cycles, runs, unknown time; `chitala history` | v0.4 | `chitala-history` |
| [30-robot-profile.md](30-robot-profile.md) | Robot Profile v0.1: a differential-drive ground robot (`robot.stop`, `move_linear`, `rotate`, `goto_pose`); `SAFE-9-MOTION` (emergency stop, obstacle, one motion at a time, stale pose, convex geofence); a stop always wins, in Safety and Authority; outcomes as a pose within a tolerance; the `robot-sim` simulator | v0.4 | `chitala-model::motion`, `chitala-safety`, `chitala-adapters::robot_sim` |
| [31-robot-adversarial-suite.md](31-robot-adversarial-suite.md) | The robot adversarial suite: obstacle, emergency stop, localisation lost or stale, lost answers, dropping off, a restart mid-motion, two AIs at once, a skewed clock (F13), malformed state, the geofence's edge | v0.4 | `chitala-node/tests/robot_adversarial.rs` |
| [32-checked-history-constraints.md](32-checked-history-constraints.md) | Checked history constraints (design approved, 2026-10-07): history may make Safety stricter, never allow; a signed, short-lived `CheckedHistoryConstraint` per rule; `SAFE-10-HISTORY` (PASS-THROUGH or DENY, fail closed); unknown time counted against the rule | v0.4 | `chitala-history-check`, `chitala-history::eval` |
| [33-hardware-qualification.md](33-hardware-qualification.md) | Hardware qualification (H0, decided 2026-10-08): one property catalogue (layers A–E, platform and Chitala levels), a manifest per platform that declares and never proves, a harness per platform, a report bound to what it tested; five statuses, only PASS establishes, an emulator establishes nothing | H0.0 | `native/h0/` |
| [34-trusted-approval.md](34-trusted-approval.md) | Trusted approval (design, 2026-10-09): what an approver is shown, built by Chitala from the signed intent and the contract; trusted sources; the requester's words apart and labelled; nothing guessed; limits no approval removes; a budget of questions per approver; "authority revoked" is not "device stopped" | ROADMAP step 6 | — |
| [registry/capabilities-v0.1.json](registry/capabilities-v0.1.json) | Core Capability Registry (normative) | A.2 | — |
| [policy/default.cedar](policy/default.cedar) | Default policy + Constitution | v13 §1 | — |

## Conventions

- **MUST / MUST NOT / SHOULD** as in RFC 2119.
- All times are Unix-epoch milliseconds (UTC), type `uint`.
- Every error code (`E_*`, `X_*`) is part of the conformance contract: its meaning never changes and codes are never reused (v4 §7).
- Registry/spec status: `experimental → provisional → stable → deprecated` (v4 §7). All of v0.1 is **provisional**.

## v0.1 scope against the v17 §18 roadmap

| Milestone | Content | Status |
|---|---|---|
| 0.0.1 | Virtual light: authorized ON/OFF + state + audit; an unauthorized AI is DENIED → security event → audit | **done** |
| 0.0.2 | Several users and devices; capability delegation and revocation | **done** |
| 0.0.3 | MQTT/HTTP/WoT adapters + a virtual home | partly: virtual home + Home Assistant REST; no MQTT/WoT yet |
| 0.1 | 10–20 devices, Digital Twin, rules/workflows, observability | twin + bus done; rules/workflows not yet |
| **Physical Authority Slice v0.1** | MCP → Intent → Authority → Safety → Approval → Capability → simulated door; the 5 required cases | **done** (`crates/chitala-mcp/tests/physical_authority_slice.rs`, `chitala demo`) |

Deliberately **not done yet**:

- Goal (type code 4 is reserved);
- two keys by default for `critical` actions (two-key resources exist, spec 16);
- mediated A2A;
- Matter/Home Assistant on the intent path;
- federation, PQC, the SC4/Q4 safety domain, the Personal Vault;
- Future Profiles (humanoid, eVTOL, mobility).
