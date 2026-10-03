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
| A PAL (`chitala-platform`) exists; the Trusted Core imports no Unix API outside a backend | 🟡 crate + Memory/Hosted backends + contract tests on the `feat/pal` branch (parked); the Core is not migrated yet |
| The existing tests keep passing; PAL contract tests are added | 🟡 166 tests pass on `main`; the PAL contract tests are on `feat/pal` |
| The CI/security pipeline works | ✅ |
| Coverage-guided fuzzing for CSME/token/IPC | ✅ 11 targets (including intent and approval) |
| Intent v0.1 and Resource Model v0.1: spec + minimal implementation | ✅ specs 14–17, Physical Authority Slice v0.1 |
| Adapter isolation prototype | ✅ |
| The Linux hosted node works as before | ✅ (macOS too) |
| Native Architecture ADR + minimal boot experiment (no full kernel needed) | ⏳ |
| Threat model updated for the hosted vs native boundary | ⏳ |

## Current milestone: Physical Authority Slice v0.1 — ✅ done

The domain model that makes Chitala different from a plain MCP gateway, proven end to end on a simulated door before any real Matter or Home Assistant wiring:

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

New crates: `chitala-resource`, `chitala-intent`, `chitala-safety`. `chitala-policy` became the Authority Engine.

## Priorities

| # | Item | Status |
|---|---|---|
| 1 | Feature freeze; a verifiable Trusted Core | ongoing |
| 2 | CI/security pipeline (fmt → clippy → test → audit → deny; CodeQL, Dependabot, SBOM, signed releases + attestations) | done — reproducible builds still to verify |
| 3 | Fuzz the trust boundaries (R8) | done — 11 targets |
| 4 | Move adapters out of the Trusted Core process (R4) | done — OS-level sandbox still to come |
| 5 | Trusted time: monotonic, clock-rollback detection (R3) | done — authenticated time source still to come |
| 6 | **Physical Authority Slice v0.1** — Resource, Intent, Authority Engine, Safety, vertical slice | **done** |
| 7 | **Delegation tokens for agents** — tokens carrying `on_behalf_of` and per-task constraints (not-before, max-use, proof-of-possession) | **next** |
| 8 | **Two-key approval** for `critical`; conditional approvals (duration, count) | |
| 9 | **Revocation** on the intent path: revoking mid-escalation, revoking per agent or person, epochs | |
| 10 | **Outcome verification** — compare the state after the command with the intent's goal; evidence | |
| 11 | Home Assistant / Matter adapters for the intent path (replacing the simulated door) | |
| 12 | Mediated MCP/A2A — agent-to-agent messages through Chitala, automatic provenance (closes R12) | |
| 13 | A second independent implementation (conformance through the wire formats and test vectors) | |
| 14 | PAL — continue migrating the Core to `chitala-platform` (branch `feat/pal`) | parked |
| 15 | CSME version negotiation + crypto agility; hosted vs native threat model; reproducible builds; Native ADR | |
| 16 | Hardware keys (TPM/secure element), attestation, enrollment, OS-level sandbox for the adapter host | after v0.1 |
| 17 | Simulator, Chitala Fabric (multi-node), Chitala Tiny, Future Profiles (humanoid, eVTOL, mobility, marketplace…) | once the Trusted Core is stable — v19 rightly keeps them in Future Profiles |

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
