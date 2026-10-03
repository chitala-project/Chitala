# Blueprint v20 versus this repository

The current blueprint is **v20** (*Chitala OS Blueprint 2026–2046*, 3 October 2026). The blueprint documents are maintained outside this repository. This page records:

- how v20 changes direction compared with v18 and v19;
- how far the repository meets it;
- what comes next.

## 1. What v20 changes

| | v18 | v19 | **v20** |
|---|---|---|---|
| Positioning | a very broad distributed OS fabric | an Authority & Safety Fabric (CASF); "OS" is only the ecosystem's name | **an independent operating system**: Hosted Mode now, Native Mode (booting directly on hardware) as the long-term goal |
| Relation to Linux | runs on Linux/RTOS | runs on existing OSes | Linux is a **bootstrap** platform, not the foundation. The architecture depends on no host OS, ISA, AI runtime, protocol or cloud |
| New layers | — | — | **Platform Abstraction Layer (PAL)**, System API, native substrate, Fabric |
| New core primitives | — | Intent, Context, Evidence… (conceptually) | **Intent & Execution Lease**, **Resource Model** (compute/storage/network/actuator), Robot/Compute/Organization principals |
| Scope | every domain in the core | Future Profiles separated from the Core | keeps v19's Profiles separation and adds a complexity rule (§21) |

Two things v20 **keeps**: the control chain (now with Intent), and the discipline "a small, verifiable Core; integrations outside the TCB".

```
Principal → Identity → Capability → Intent → Authority → Reference Monitor → Execution → State → Audit
```

## 2. The new v0.1 Definition of Done (v20 §22)

| Criterion | Status |
|---|---|
| A PAL exists; the Trusted Core imports no Unix API outside a backend | ✅ spec 18; core purity enforced in CI (`scripts/core-purity.py`); the node runtime moves onto the PAL next |
| The existing tests keep passing; PAL contract tests are added | ✅ memory and hosted backends pass the PAL contract |
| The CI/security pipeline works | ✅ fmt → clippy → test (x86_64/ARM64/macOS) → audit → deny, MSRV, CodeQL, SBOM, zizmor, signed release + attestations |
| Coverage-guided fuzzing for CSME/token/IPC | ✅ 11 libFuzzer + ASan targets, run in CI |
| Intent v0.1 and Resource Model v0.1: spec + minimal implementation | ✅ specs 14–17; `chitala-resource`, `chitala-intent`, `chitala-safety`, the Authority Engine; Physical Authority Slice v0.1 |
| Adapter isolation prototype | ✅ `chitala-adapter-host`; orders minted only by the Trusted Execution Boundary (spec 19), bound to one host instance, single use, with receipts; kill/restart; lock released while waiting |
| The Linux hosted node works as before | ✅ (macOS too) |
| Native architecture ADR + minimal boot experiment | ❌ |
| Threat model updated for the hosted vs native trust boundary | ❌ the threat model only covers hosted mode |

**7 of 9 met, 2 not yet.**

## 3. What v20 asks of the repository (§18)

| Item | Status | Notes |
|---|---|---|
| A `chitala-platform` crate with PAL traits: time, entropy, key store, storage, IPC, network, execution host | ✅ | plus device I/O; spec 18 |
| Move Unix sockets, POSIX permissions/paths and the system clock out of the Trusted Core | ✅ | The core crates and the node runtime are pure; only the node's hosted binding knows files, sockets and processes; see §4 |
| `chitala-mcp`, Home Assistant, MQTT/WoT live in the adapter layer and define no core semantics | ✅ | MCP is a broker that signs intents; HA lives in the adapter host |
| A `chitala-resource` crate | ✅ | physical resources (spec 14) |
| A `chitala-intent` crate: typed intents, plans, execution leases; prompts never go straight to device actions | 🟡 | Typed, signed intents with on-behalf-of, constraints and relay chains (spec 15). Every physical action goes through the Trusted Execution Boundary as a single-use, provenance-bound `ExecOrder` (spec 19). No multi-step *Plan* and no multi-use *ExecutionLease* yet (ROADMAP v0.2 steps 7 and 9) |
| Version negotiation and crypto agility for CSME and the wire formats | 🟡 | Version checks, `crit`, explicit algorithm ids. **No negotiation and no security-suite registry yet** |
| CI: fmt, clippy, test, audit, deny; SBOM, signed releases, reproducible builds | 🟡 | Everything except **verified reproducible builds** |
| Fuzz CSME/token/IPC/adapters | ✅ | intents and approvals included |
| Chaos / mixed-version tests | ❌ | |
| Separate adapter processes from the node/monitor; capability-scoped IPC | 🟡 | Processes are separate, and each instance accepts only single-use orders addressed to it, signed by the boundary (spec 19). **No OS-level sandbox yet** |
| A Native Architecture ADR; no kernel before the PAL is stable | ❌ | |

## 4. PAL: where the code is tied to the host OS

Host-OS dependencies by crate (✅ = done in v0.2, enforced by `scripts/core-purity.py`):

| Crate | Host-OS dependency | PAL trait |
|---|---|---|
| `model`, `policy`, `monitor`, `state`, `bus`, `resource`, `intent`, `safety` | **none** | — |
| `token` | ✅ the key chain of every Biscuit block comes from `Entropy` (no hidden OS RNG) | `Entropy` |
| `identity` | ✅ `Keypair::generate(&dyn Entropy)`; `Keypair` still keeps the seed in RAM | `Entropy`, later `SecureKeyStore` |
| `csme`, `intent` | ✅ message and intent ids from `Entropy` | `Entropy` |
| `audit` | ✅ an `AppendLog` in `Storage` (private, durable) | `Storage` |
| clock | ✅ `TrustedClock` lives in the PAL over `TimeSource` | `TimeSource` |
| `node::ipc` | ✅ server and client over `IpcTransport` | `IpcTransport` (Unix socket, named pipe, native IPC) |
| `node::config`, `setup`, state | ✅ keys in `SecureKeyStore`, state and audit in `Storage`; locations resolved by `node::hosted` | `Storage`, `SecureKeyStore` |
| `node::executor` | ✅ adapter hosts through `ExecutionHost`, restart limit on the monotonic clock | `ExecutionHost` (spawn an isolated component with a private channel) |
| `node::hosted` | the hosted binding: config files, key files, Unix sockets, processes (exempt by design) | — |
| `adapters::home_assistant` | `ureq` (HTTP) | `NetworkTransport` (in the adapter layer) |

So the PAL is mostly a refactoring of `chitala-node` and `chitala-audit`, plus small changes in `identity` and `csme`. The Trusted Core logic (monitor, policy, Authority Engine, token, CSME decoding) does **not** need rewriting, as v20 §2 requires.

Two design points:

- **Signing without exporting the key.** `TokenAuthority` currently builds a Biscuit `KeyPair` from a seed (`Keypair::seed()`). To keep the authority key inside a TPM or secure element, `SecureKeyStore` must sign through a key reference, and Biscuit token creation needs an external signing path (a third-party block, or a different token format). This is an ADR decision and does not block PAL v0.1.
- **File permissions.** The current `0600/0700` checks are a *security* property (private, owner-only), not a POSIX detail. The PAL expresses them as a semantic requirement (`Private`), so a Windows backend maps them to ACLs instead of ignoring them.

## 5. New v20 primitives versus the current Core

| v20 | Today | Gap |
|---|---|---|
| Principals: Human, AI/Agent, Robot, Device, Service, **Compute**, **Organization/Domain** (§6) | `person`, `ai`, `device`, `service`, `domain` | no `robot` or `compute` (see decision D1) |
| Resource Model: CPU/GPU/NPU/…/FutureCompute, storage, network, actuators by capability (§7) | physical resources (spec 14): sites, spaces, doors, locks, lights, robots, vehicles, vendor kinds | compute/storage/network resources |
| Intent → Plan → Capability Resolution → Policy/Safety → **Execution Lease** → Action → Observation → Audit (§8) | intent → Authority Engine → Safety → (human approval) → `ExecOrder` | Plan, leases with budgets/cancellation, outcome verification |
| Device actions: preconditions, safety envelope, evidence, **recovery** (§11) | risk, registry and resource envelopes, safety rules SAFE-1…6, device invariants | preconditions declared by the requester, geofences, recovery/safe states |
| Authority = identity + token + policy + context + safety + **human approval** (§5) | all of them, for one node | two-key approval, richer context (presence, time windows) |
| Risk class `safety-critical` (§11) | `critical` | a naming difference only: the wire label stays `critical`, with the mapping documented |

## 6. Relation to v19

v20 does not contradict v19's governance parts; it simply does not mention them. They remain useful and stay on the backlog:

- A spec is called **Stable** only when ≥ 2 independent implementations interoperate (v19 §9).
- Extra token fields (v19 §4.2): `not-before`, proof-of-possession and approval evidence are done (token format 2, spec 05; the approvers are in every order's decision context, spec 19); `max-use` comes with the ExecutionLease.
- Two-key approval for high-risk actions (v19 §5): done for two-key resources (spec 16); two keys by default for `critical` is still open.
- A compliance evidence package: CRA, ETSI EN 303 645, the EU AI Act, Vietnam's personal data protection law (v19 §15).

The only contradiction is the positioning (v19: "not a kernel", v20: "an independent OS"). The repository follows v20.

## 7. Decisions for the project owner

| # | Question | Proposal |
|---|---|---|
| D1 | Add the kinds `robot` and `compute` to `EntityId` (a long-lived wire change)? | Add `compute` together with compute resources. Keep representing a robot as a `device` plus its own `ai` principals (v12 §1) until ≥ 2 profiles need a separate kind (v20 §21) |
| D2 | A second PAL backend in v0.1: Windows, or a `MemoryPlatform` for tests and the simulator? | `MemoryPlatform` first: cheap, enables PAL contract tests and leads to the simulator. Windows when there is a real need |
| D3 | How to sign tokens when the authority key cannot be exported | A separate ADR before a hardware `SecureKeyStore` |
| D4 | The first Native path to try (§13: microkernel / hypervisor) | Only an ADR and a minimal boot experiment (e.g. a `no_std` Trusted Core on QEMU), after the PAL is stable |

## 8. Order of work

The project owner reordered v20's list: the most important missing piece was not protocols, adapters or the PAL, but **the domain model that makes Chitala different from a plain MCP gateway**. The outcome is the *Physical Authority Slice v0.1* (see `ROADMAP.md`):

- **Invariant 1**: AI produces Intent. Chitala produces Authority. Only the trusted execution boundary produces physical Commands (spec 15).
- **Resource Model v0.1** (spec 14) covers the **physical** world. v20's compute/storage/network resources are not in yet; D1 stays open, and new kinds come when ≥ 2 profiles need them (§21).
- **Intent v0.1** (spec 15) is intent → authority → command. v20's multi-step *Plan* and *Execution Lease* are not in yet; the physical command is still a single-use `ExecOrder` of ≤ 30 s.
- The **Authority Engine** (spec 16) and the independent **Safety** layer (spec 17) are the first implementation of v19's "Authority & Safety Fabric", for a single node.

Next, in order (details in `ROADMAP.md`):

1. delegation tokens for agents;
2. two-key approval;
3. revocation on the intent path;
4. outcome verification;
5. Home Assistant / Matter on the intent path;
6. mediated MCP/A2A;
7. a second independent implementation.

The PAL resumes after that, followed by CSME negotiation and crypto agility, the hosted-vs-native threat model, reproducible builds and the Native ADR.

Every new Core primitive must pass v20 §21's three questions:

1. Is it a long-term abstraction?
2. Do ≥ 2 profiles need it?
3. Would Chitala lose a core OS property without it?
