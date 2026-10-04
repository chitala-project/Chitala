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
| A PAL (`chitala-platform`) exists; the Trusted Core imports no Unix API outside a backend | ✅ spec 18; the core crates and the node runtime are pure and CI enforces it |
| The existing tests keep passing; PAL contract tests are added | ✅ memory and hosted backends pass the contract |
| The CI/security pipeline works | ✅ |
| Coverage-guided fuzzing for CSME/token/IPC | ✅ 11 targets (including intent and approval) |
| Intent v0.1 and Resource Model v0.1: spec + minimal implementation | ✅ specs 14–17, Physical Authority Slice v0.1 |
| Adapter isolation prototype | ✅ |
| The Linux hosted node works as before | ✅ (macOS too) |
| Native Architecture ADR + minimal boot experiment (no full kernel needed) | ✅ boot experiment (spec 20: the node core as a Hermit unikernel in QEMU, in CI) and [ADR 0001](docs/adr/0001-native-architecture.md), accepted |
| Threat model updated for the hosted vs native boundary | ✅ spec 13 *Hosted and Native*: what each mode trusts, 18 threats with gates for Native; found and fixed a hosted gap (safety holds did not survive a restart) |

## Current milestone: Chitala v0.2 — Platform Independence & Trusted Execution Boundary

No big new features. The goal is a foundation solid enough for Chitala to become an operating system that does not need Linux, in this order:

| # | Step | Status |
|---|---|---|
| 1 | **PAL** (spec 18): `Clock`, `Entropy`, `KeyStore`, `Storage`, `IPC`, `Network`, `Execution`, `Device I/O`; the Trusted Core calls no Unix/POSIX/Linux/macOS API | ✅ the core crates are pure; the node runtime — keys, state, audit, IPC, adapter hosts, time — runs on the PAL, and the same node runs end to end on the memory platform; CI enforces both |
| 2 | **Trusted Execution Boundary v0.2 — Single Path, Single Use, Provenance Bound** (spec 19): only `chitala-boundary` mints orders, with an order key no other code holds; persons' requests pass Safety too; orders bound to one adapter host instance, single use, ≤ 30 s, carrying parameter and context digests, the authority epoch and their evidence; execution receipts checked before the state is believed; CI guard over every crate; 15 attack tests | ✅ |
| 3 | **Delegation + revocation + two-key approval** (spec 05, spec 16): tokens bound to the holder's key (proof of possession), to the person an agent acts for, and to a window; non-transferable by default (re-delegation budget); revocation floors per principal or for the whole domain; in-flight orders re-checked against their own tokens and principals; a chain of agents is the intersection of its links; two-key resources need two different people | ✅ |
| 4 | **TOCTOU and adversarial suite, extended** (spec 13 "Time of check, time of use"): every attack of the v0.2 list has a test; three real gaps closed — a safety hold or an expired token now stops an order in flight, and a device executes one order at a time (`SAFE-7-BUSY`); safety holds became an audited domain operation | ✅ |
| 5 | **Native QEMU spike** (spec 20) — Chitala boots in QEMU (or on hardware) with no Linux, Windows or macOS underneath, takes entropy/time/storage from a PAL-native backend and runs `Boot → Identity → Intent → Authority → Safety → ALLOW/DENY`. No LLM is needed: AI produces intents wherever it runs — in the cloud, on another machine, or later inside Chitala (AI runtime, sandbox or VM) — and Chitala decides authority and execution | ✅ the unchanged node core as a Hermit unikernel (aarch64): 13 decisions over signed IPC, audit verified, in CI; entropy from the CPU's RNG, and no start without one (Hermit's own source falls back to an LCG on aarch64) |
| 6 | **Hosted-vs-Native threat model** (spec 13 *Hosted and Native*) — what each mode trusts; 18 threats (kernel compromise, memory isolation, adapters, the PAL backend, entropy, clock, keys, crash/reboot, rollback, loader, image and image rollback, DMA, network, supply chain, debug channels, hangs, the machine underneath), each with Hosted, Native today and the gate before Native leaves the lab | ✅ new controls with tests: Native refuses a board clock before its image's floor (exit 4); `cargo audit` on the native lock; safety holds persist across restarts and a rollback past one is refused (a gap on Hosted too) |
| 7 | **Native Architecture ADR** ([ADR 0001](docs/adr/0001-native-architecture.md)) — Hermit vs seL4 vs a hypervisor vs an own Chitala kernel, judged against the gates of step 6 | ✅ accepted with amendments (2026-10-04): keep Hermit for the lab; make the core portable now (`no_std + alloc` pure crates, policy and token behind interfaces, tasks in the PAL); next Native milestone a partitioning spike (the core in a Hermit guest, adapters in another, on seL4 or Bao) with falsifiable pass criteria: memory and DMA isolation, crash containment, an authenticated replay-resistant channel, TCB and latency measured; seL4 the preferred long-term candidate, subject to that evidence; no own kernel |
| 8 | **ExecutionLease v0.1** (spec 21) — `lease_id`, the asking intent, actor and person, resource, capability, window, `max_uses`, a parameter envelope, the tokens and approvals it stands on, the authority epoch. A lease grants execution inside an envelope; an `ExecOrder` is one use of it | ✅ intent version 2 (keys 15/16, byte-identical without them); the asking intent is judged as the action plus lease rules; a high-risk lease is approved once for exact terms (≤ 3 uses, ≤ 1 h), never critical or two-key; every use is judged again in full, cleared by Safety, counted and persisted before its order; revocation, persistence, rollback refusal and fence; `domain.lease_revoke`/`list_leases` (never an AI) |
| 9 | **Outcome verification + recovery** (next) — did the world end up in the intended state; safe states and recovery when it did not | |
| 10 | **Plan Engine v0.1** — multi-step plans built from intents, each step judged on its own | |

Every step ships its attack and regression tests: TOCTOU between Authority → Safety → Execution, approval replay, stale device state, clock rollback, a policy change after approval, an ownership change, a compromised adapter, a restart mid-transaction, concurrent conflicting intents.

Then **v0.3 — Home Reference Implementation**: Claude / ChatGPT / a local AI → MCP/A2A → Chitala (Intent → Authority → Safety → human approval → ExecutionLease → ExecOrder) → Home Assistant / Matter → device, with Home Assistant and Matter **outside the Trusted Core** as the first adapters. After that: a second independent implementation → interop → Stable spec.

**Native track** (decided by the Project Lead on 2026-10-04): keep Hermit (spec 20) and carry Chitala's own kernel patches until upstream has them. Writing an own kernel now would stall v0.2/v0.3: the Trusted Core needs Rust `std` because Cedar and Biscuit do. After step 6, the Native Architecture ADR (decision D4) compares Hermit, seL4, an own kernel and a hypervisor. These preparations are useful even with Hermit, and are done step by step:

- the pure core crates (model, identity, CSME, intent, safety, …) build as `no_std + alloc`;
- the policy engine and the token format sit behind interfaces, so Cedar and Biscuit can be replaced without touching the rest;
- tasks instead of `std` threads in the PAL.

Not now: humanoid, eVTOL, medical, a compute marketplace, multi-node federation, Web3, large UIs — they do not help prove Chitala's core claim.

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
| PAL — the Trusted Core and the node runtime are platform-independent | done (v0.2 step 1) |

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
