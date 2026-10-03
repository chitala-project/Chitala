# Roadmap

Current blueprint: **v20** (*Chitala OS Blueprint 2026–2046*, maintained outside this repository). How v20 maps to the repository in detail: [`docs/v20-alignment.md`](docs/v20-alignment.md).

Chitala is an operating-system architecture. The current phase is **Hosted Mode**: the Trusted Core runs as a set of services on Linux/macOS. The long-term goal is **Chitala Native**, booting directly on hardware. Every change made now must keep the road to Native open: the Trusted Core must not depend on any host OS, ISA, AI runtime, protocol or cloud (v20 §1, §19).

> **Invariant 1:** AI produces Intent. Chitala produces Authority. Only the trusted execution boundary produces physical Commands. (spec 15)

## Scope discipline (feature freeze)

The `0.0.x` line has a **product feature freeze**. Only these changes are merged:

- architectural items of the v0.1 Definition of Done below (PAL, Intent, Resource Model, version negotiation, ADRs…);
- bug and vulnerability fixes, with a test that reproduces them;
- more verifiability: tests, property tests, fuzz targets, test vectors, conformance;
- CI, supply chain, SBOM, artifact signing;
- changes that **isolate** or **shrink** the Trusted Core;
- documentation and specs.

No new capabilities, adapters, protocols, transports, profiles or AI components. MQTT/WoT, Robot/Mobility/Medical… wait until after v0.1.

Every new Core primitive must answer three questions (v20 §21):

1. Is this a long-term abstraction?
2. Do at least two independent profiles need it?
3. Would Chitala lose a core OS property without it?

## Definition of Done for v0.1 (v20 §22)

| Criterion | Status |
|---|---|
| A PAL (`chitala-platform`) exists; the Trusted Core imports no Unix API outside a backend | ✅ spec 18; the core crates are pure and CI enforces it; the node runtime moves next |
| The existing tests keep passing; PAL contract tests are added | ✅ memory and hosted backends pass the contract |
| The CI/security pipeline works | ✅ |
| Coverage-guided fuzzing for CSME/token/IPC | ✅ 11 targets (including intent and approval) |
| Intent v0.1 and Resource Model v0.1: spec + minimal implementation | ✅ specs 14–17, Physical Authority Slice v0.1 |
| Adapter isolation prototype | ✅ |
| The Linux hosted node works as before | ✅ (macOS too) |
| Native Architecture ADR + minimal boot experiment (no full kernel needed) | ⏳ |
| Threat model updated for the hosted vs native boundary | ⏳ |

## Current milestone: Chitala v0.2 — Platform Independence & Trusted Execution Boundary

No big new features. The goal is a foundation solid enough for Chitala to become an operating system that does not need Linux, in this order:

| # | Step | Status |
|---|---|---|
| 1 | **PAL** (spec 18): `Clock`, `Entropy`, `KeyStore`, `Storage`, `IPC`, `Network`, `Execution`, `Device I/O`; the Trusted Core calls no Unix/POSIX/Linux/macOS API | 🟡 the core crates are pure and CI enforces it; the node runtime (IPC, config/key/state files, adapter processes) moves onto the PAL next |
| 2 | **Trusted Execution Boundary v0.2** — prove there is no second path to an actuator (adapters, MCP, AI runtimes, plugins, network input); `ExecOrder` as a very short-lived, single-use capability bound to resource, action and context, never replayable | |
| 3 | **Delegation + approval + revocation hardening** — authority = the intersection of the whole chain (Human → Personal AI → Security AI → `door.unlock`); expiry, depth, non-transferable, context binding, immediate revocation; AI A → B → C escalation tests | |
| 4 | **Attack/regression suite** — TOCTOU between Authority → Safety → Execution, approval replay, stale device state, clock rollback, a policy change after approval, an ownership change, a compromised adapter, a restart mid-transaction, concurrent conflicting intents | |
| 5 | **Native spike** — a tiny Chitala that boots in QEMU, takes entropy/time/storage from a PAL-native backend and runs identity → intent verification → authority decision: Chitala does not need Linux, Windows, macOS, Android or iOS to exist | |

Then **v0.3 — Home Reference Implementation**: Claude / ChatGPT / a local AI → MCP/A2A → Chitala (Intent → Authority → Safety → human approval → ExecOrder) → Home Assistant / Matter → device, with Home Assistant and Matter **outside the Trusted Core** as the first adapters. After that: a second independent implementation → interop → Stable spec.

Not now: humanoid, eVTOL, marketplace, Web3, large UIs — they do not help prove Chitala's core claim.

## Previous milestone: Physical Authority Slice v0.1 — ✅ done

The domain model that makes Chitala different from a plain MCP gateway, proven end to end on a simulated door:

```text
MCP → Intent → Authority → Safety → Approval → Capability → simulated door
```

| # | Case | Required | Result |
|---|---|---|---|
| 1 | Owner AI → turn on the light | ALLOW | ✅ |
| 2 | Guest AI → turn on a delegated light | ALLOW | ✅ |
| 3 | Child AI → open the door without permission | DENY | ✅ (`E_POLICY_DENIED` at the DELEGATION step) |
| 4 | Owner AI → open the door (high risk) | ESCALATE → human approval | ✅ (the door moves only after the owner signs an approval) |
| 5 | AI A → asks AI B to open the door to dodge policy | DENY | ✅ (`E_ON_BEHALF_OF` / `E_PROVENANCE`) |

Tests:

- `crates/chitala-mcp/tests/physical_authority_slice.rs`, through the real MCP broker, node and adapter;
- `chitala_policy::authority`, the engine with real signatures and tokens;
- `chitala demo`.

## Done so far

| Item | Status |
|---|---|
| Feature freeze; a verifiable Trusted Core | ongoing |
| CI/security pipeline (fmt → core purity → clippy → test → audit → deny; CodeQL, Dependabot, SBOM, signed releases + attestations) | done — reproducible builds still to verify |
| Fuzzing the trust boundaries (R8) | done — 11 targets |
| Adapters out of the Trusted Core process (R4) | done — OS-level sandbox still to come |
| Trusted time: monotonic, clock-rollback detection (R3) | done — authenticated time source still to come |
| Physical Authority Slice v0.1 — Resource, Intent, Authority Engine, Safety | done |
| PAL — the Trusted Core is platform-independent | in progress (v0.2 step 1) |

Later, after v0.3: CSME version negotiation + crypto agility, the hosted vs native threat model, reproducible builds, the Native ADR, hardware keys (TPM / secure element) and attestation, enrollment, an OS-level sandbox for adapter hosts, the simulator and the multi-node Fabric.

## Long-term phases (v20 §17)

| Phase | Goal |
|---|---|
| 2026–2027 · Core | Stable specs; PAL; CI/SBOM/fuzzing; intent and resource model; sandboxed adapters; simulator |
| 2027–2029 · Host | Production Linux node; Windows/macOS backends when needed; Home/Robot/Medical pilots; multi-node fabric |
| 2029–2032 · Native Lab | A bootable Chitala Native prototype; evaluate microkernels/hypervisors; minimal drivers; secure keys and time |
| 2032–2036 · Native | Native nodes for edge, server and robots; compatibility VMs/containers; durable update/recovery |
| 2036–2040 · Fabric | Cross-domain federation, heterogeneous compute, provenance at scale, safety islands |
| 2040–2046 · Evolution | Crypto transitions, new compute models, new forms of intelligence — without resetting the architecture |

*"The goal for 2026–2046 is not to predict future hardware or AI precisely. It is to build abstractions stable enough that Chitala can absorb those changes without rewriting its foundation."* (v20 §23)
