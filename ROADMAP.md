# Roadmap

Current blueprint: **v20** (*Chitala OS Blueprint 2026–2046*, maintained outside this repository). How v20 maps to the repository in detail: [`docs/v20-alignment.md`](docs/v20-alignment.md).

Chitala is an operating-system architecture. The current phase is **Hosted Mode**: the Trusted Core runs as a set of services on Linux/macOS. The long-term goal is **Chitala Native**, booting directly on hardware. Every change made now must keep the road to Native open: the Trusted Core must not depend on any host OS, ISA, AI runtime, protocol or cloud (v20 §1, §19).

> **Invariant 1:** AI produces Intent. Chitala produces Authority. Only the trusted execution boundary produces physical Commands. (spec 15)

## Scope discipline

The product feature freeze of the `0.0.x` line ended when v0.2 was completed. Since then, scope is set by the current milestone (v0.3), under two rules.

- **The Trusted Core is in a core freeze.** Identity, intents, tokens, Authority, Safety, approvals, leases, the boundary, outcomes and plans are complete for now. A new Trusted Core abstraction is merged only when a v0.3 step cannot work without it, and only if it answers the three questions below.
- **The adapters and profiles of the current milestone are in scope, outside the Trusted Core.** That means the Home Capability Profile, the Home Assistant and Matter adapters, and MCP clients. They execute and observe; they never decide authority.

Always welcome:

- bug and vulnerability fixes, with a test that reproduces them;
- more verifiability: tests, property tests, fuzz targets, test vectors, conformance;
- CI, supply chain, SBOM, artifact signing;
- changes that **isolate** or **shrink** the Trusted Core;
- documentation and specs.

Still waiting, until after v0.3:

- other protocols and transports (MQTT, W3C WoT);
- other profiles (robot, mobility, medical);
- AI components inside Chitala.

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

## Current milestone: Chitala v0.3 — Home Reference Implementation

v0.2 proved the chain in a simulated world:

```text
Identity → Intent → Delegation/Token → Authority → Safety → Human approval → ExecutionLease
  → TrustedExecutionBoundary → ExecOrder → adapter isolation → physical action → receipt → witness
  → outcome verification → recovery → Plan Engine
```

v0.3 asks the harder question: **does it hold with real AIs and real devices?** It is a small vertical slice, and every part of it is real:

```text
Claude / ChatGPT / a local AI
        │ MCP
        ▼
   Chitala MCP ─▶ Intent → Authority → Safety → TrustedExecutionBoundary ─▶ ExecOrder
                                                                             │
             ┌───────────────────────────────────────────────────────────────┴──────────┐
             ▼                                                                          ▼
   Home Assistant adapter  [outside the Trusted Core]                 Matter adapter  [outside the Trusted Core]
             │                                                                          │
      Home Assistant ─▶ Matter / Wi-Fi                                            Matter fabric
             └──────────────────────────────┬───────────────────────────────────────────┘
                                            ▼
                         real devices ─▶ the physical world ─▶ independent observation ─▶ outcome verification
```

Three device types at first, which give three levels of authority:

| Device | Actions | Risk |
|---|---|---|
| light | `light.turn_on`, `light.turn_off` | low: runs on its own |
| smart plug | `switch.turn_on`, `switch.turn_off` | low by the registry; medium where the domain's policy raises it (a `risk_floor`, spec 14) |
| door lock | `lock.lock`, `lock.unlock` | unlocking is high: an AI needs a human's approval |

The demo plan "leaving home" is: turn the living-room light off, then the smart plug, then lock the front door. Chitala must verify each outcome before the next step.

### Principles (decided by the Project Lead, 2026-10-05)

- **Home Assistant and Matter are executors and witnesses, never a source of authority.**
  - Chitala decides "this AI may open the door" and signs the `ExecOrder`.
  - The adapter executes only orders Chitala signed.
  - Home Assistant users and Matter ACLs are defence in depth below Chitala, never a replacement for its decision (Invariant 1).
- **Two independent adapters behind one capability interface.** Matter is reached directly, not through Home Assistant: `Chitala → Home Assistant → Matter` alone would make Chitala depend on Home Assistant to control Matter. Two implementations also test whether the adapter abstraction is right or was shaped around Home Assistant by accident.
- **Small first.** Three device types, done for real, before any wider coverage of Home Assistant or Matter.

### Steps

Two lanes since 2026-10-06 (Project Lead). ③B is waiting for hardware, but it does not block the project:

- **hardware lane:** ③B physical devices → ④ the physical authority demo;
- **software lane:** ⑤ the direct Matter adapter → ⑥ the adversarial suite, with simulators and fault injection.

v0.3 is complete when the two lanes meet: ③B and ④ on real hardware, plus ⑤ and ⑥, with the subset of ⑥ that needs a real lab rerun on hardware.

| # | Step | Status |
|---|---|---|
| ① | **Home Capability Profile v0.1** ([spec 24](specs/24-home-profile.md)) — light, switch/plug and lock, normalised: resource kinds, capabilities, state keys, outcomes, default risks, and the mapping of each to Home Assistant (domain, service, state) and to Matter (cluster, command, attribute) | ✅ `specs/profiles/home-v0.1.json`, checked against the registry; the rule "what cannot be known is left out, never guessed" (a lock that is moving or jammed reports no `locked`; `unavailable`/`unknown`/`null` are failed observations); the Home Assistant adapter maps lights, plugs and locks from the profile only, which fixed two ways outcome verification could be fooled; the Matter column confirmed against public references except the lock command ids and `LockState` 3, provisional until step ⑤ |
| ② | **Home Assistant production adapter** ([spec 25](specs/25-home-assistant-adapter.md)) — discovery, execute, observe, reconnect, timeout and error semantics; still outside the Trusted Core | ✅ WebSocket first (auth, `state_changed`, `get_states` bootstrap, ping, reconnect with backoff), REST to bootstrap and as a fallback; it only executes and observes: one transport and one attempt per order, never a retry; a command lost after sending, or without a result in time, is indeterminate and outcome verification decides; duplicate and out-of-order events never move a state back; nothing unobserved ever becomes a state; wrong-kind entity mappings refused at start-up; `chitala ha-discover`. Tested against a deterministic fake Home Assistant with fault injection, adapter-level and through the whole chain (including the "leaving home" plan), and every guarantee checked by mutation. The integration found a safety gap, closed here by the Project Lead's decision: a command that may have executed (`X_EXECUTION_UNKNOWN`) is watched like a reported one, and when nobody can establish its outcome at medium risk or more the resource enters recovery — without a blind second command (spec 22) |
| ③ | **Real AI → MCP → Chitala → Home Assistant → real device** — Claude, ChatGPT or a local AI sends real intents and plans | 🟡 **③A done** (2026-10-05): a real AI, a real Home Assistant Core 2026.9.4, and virtual Matter devices from the Matter SDK behind it; only the actuators simulated. Findings F1–F6, F9 and F9b fixed (F9: outcome evidence must postdate the order; F9b: and be confirmed current by the device, which the Home Assistant adapter asks a Matter device for); F7 fixed (discovery through Home Assistant's entity registry); F8 a documented limitation of the Home Assistant path; F10 fixed (Home Assistant's state of a Matter device can lag the device, so a narrow, read-only, loopback-only `MatterEvidenceProvider` reads the device itself through the Matter server for evidence) — [lab report](docs/lab/v0.3-step3a-home-assistant.md). A concurrency and lifecycle audit of the whole codebase (2026-10-06) fixed R1, R2, R3/R3b and F11 under a core-freeze exception; no unbounded leak, ThreadSanitizer clean — [audit](docs/audit/v0.3-concurrency-and-lifecycle-audit.md). Next: ③B, physical devices |
| ④ | **Physical authority demo on real hardware** — low risk runs on its own; high risk needs approval; revoke and hold; the "leaving home" plan; an outcome failure and its recovery | |
| ⑤ | **Direct Matter adapter** — the same capabilities through another backend, not through Home Assistant: Chitala does not depend on Home Assistant | 🟡 software lane (2026-10-06). [Spec 26](specs/26-adapter-conformance.md): one conformance suite for every adapter. [Spec 27](specs/27-direct-matter-adapter.md): the adapter on Chitala's own fabric through a typed `DirectMatterBackend`; it passes the suite on a fake backend. The matter.js backend: a stdio sidecar on Chitala's own fabric, with a typed, allowlisted protocol and `chitala matter commission`; it drove the Matter SDK's lock through the whole chain in the lab. **Software complete, physical validation pending** ③B |
| ⑥ | **Adversarial Home suite** — Home Assistant dies or restarts, a network partition, stale state, a device offline, delayed state, a forged or wrong witness, duplicate execution, Chitala restarting mid-operation | 🟡 software lane (2026-10-06). [Spec 28](specs/28-adversarial-home-suite.md): the ten fault classes and their tests on each path. Every fault class has its tests on every path where it applies; the direct Matter path runs through the real sidecar protocol on a fake sidecar; R1/R2/R3/F11 run as a seeded regression suite on every path; finding F12 fixed. **Software complete, the real-lab subset pending** ③B |

### After ③A: device runtime and telemetry (outside the Trusted Core)

**v0.1 done (2026-10-06):** local history, [spec 29](specs/29-telemetry-history.md).
- The node publishes what it observed.
- A recorder outside the Trusted Core keeps a private log, with retention.
- Queries answer time in a value, cycles, runs and unknown time (`chitala history`).
- People and AIs read it through the node, as the capability `device.read_history` (medium risk), under Authority like any other access: a summary, never the log. An AI gets an MCP tool for it only from a token that grants it.

**Next, in the Project Lead's order (2026-10-06):**
1. ✅ Robot Profile v0.1 and a simulator: a differential-drive ground robot ([spec 30](specs/30-robot-profile.md)). The Lead's decisions:
   - robot Safety in the core, as `SAFE-9-MOTION`;
   - a stop always wins, in Safety and Authority;
   - outcomes are a pose within a tolerance;
   - every motion is medium risk.
2. ✅ A robot adversarial suite ([spec 31](specs/31-robot-adversarial-suite.md)). Finding F13 fixed: a robot clock ahead made a stale pose look fresh.
3. ✅ SAFE-8, "new evidence → a new safe-state action" ([spec 22](specs/22-outcome-recovery.md)): a safe state that could not reach the device or did not take effect is never resent; a new one is decided only on a fresh observation that still shows danger, as the safe state's retry policy allows (a robot stop: 3; a lock: 1).
4. ✅ A checked constraint from history for Safety, which can only narrow or refuse, never allow ([spec 32](specs/32-checked-history-constraints.md)). The design and threat model were approved on 2026-10-07. Built:
   - `SAFE-10-HISTORY`;
   - versioned history rules that only owners manage;
   - the evaluator as its own process;
   - a hash-chained history log;
   - the adversarial suite.

**After v0.4, in the Project Lead's order (2026-10-07, revised the same day):**
1. ✅ The history chain's head anchored in the audit log ([spec 32](specs/32-checked-history-constraints.md)): a log cut back is provable, and fails closed.
2. ✅ The safety case ([`docs/safety/`](docs/safety/README.md)): a hazard log, a safety traceability matrix (hazard → requirement → control → test → evidence), and a review rule for safety-affecting changes, checked in CI. Its evidence gaps are closed:
   - the mutation runs live in the repository ([`mutation/`](mutation/README.md)): 22 sets, run weekly in CI;
   - `SAFE-1` to `SAFE-10` have mutation evidence against `chitala-safety`'s own unit tests;
   - `SAFE-9` and `SAFE-10` have unit tests there.
3. Native N1, a partitioning spike: seL4 first, Bao as the comparison. It must prove seven things:
   - an adapter cannot reach the core's memory;
   - DMA from an adapter cannot reach it either;
   - the core survives an adapter crash or reboot;
   - orders and receipts over the inter-domain channel still resist replay and tampering;
   - the execution flow runs end to end;
   - latency and TCB size are measured;
   - an adapter that spins cannot delay the core (time isolation).

   The plan: [`docs/native/n1-partitioning-spike.md`](docs/native/n1-partitioning-spike.md). Progress: N1.0 ✅ (the toolchain pinned and verified; a local Linux VM and CI on both architectures) N1.1 ✅ (two protection domains and a channel on seL4) and N1.2 ✅ (libvmm's Linux guest under a VMM on seL4) and **N1.3 ✅, the go/no-go: GO**: the Chitala Native image runs as a guest on seL4, unchanged (13/13 decisions). seL4 stays the primary candidate, not yet chosen: N1.4 to N1.6 decide. **N1.4 ✅**: two guests and a relay that copies bytes; the node drives the adapter host in the other guest without knowing it, and an adapter guest that disappears after taking an order leaves its fate unknown, never "not sent" (14/14). Next N1.5, the isolation tests, in this order ([`native/spike/`](native/spike/README.md)):
   - N1.5a ✅: the adapter's guest loses the UART and the RTC it shares with the core's. Its VMM emulates them: a UART whose lines come out behind its prefix, and a read-only RTC. The system description is checked before boot, and a forged core verdict does not count;
   - N1.5b ✅: the adapter's guest, given a device tree claiming more RAM than seL4 granted it, reaches past the grant and faults at seL4's stage-2, on its own VMM; the core's state stays intact. The VMM holds no capability to the core's RAM (PlatformIsolationEvidence);
   - N1.5c ✅: the adapter's guest crashes before an order (the core finds it unavailable and lives on) and after taking one (that order's fate is unknown, never not-sent); a stale order or session is refused by the session gate. A true guest reboot/reload is not exercised (left to H0/N2);
   - N1.5d ✅: a hostile relay that corrupts, duplicates, withholds or replays cannot make execution happen twice or unsigned — shown with the device's own execution count, off the relay's path, and the core's audit;
   - N1.5e: DMA through an SMMU is **not demonstrated** on qemu_virt_aarch64 (seL4's platform has no SMMU driver); criterion 2 fails for this N1 platform and is carried to H0, not worked around.

   **N1.6 ✅**, the measurements (criteria 6 and 7):
   - an order's latency, boundary → channel → adapter → receipt, against hosted;
   - a stop's latency with the adapter's guest spinning, and under timer-interrupt pressure, against the unloaded baseline: the core is always scheduled, and every stop completes;
   - the TCB, as code size.

   The long tail found on the way was a timer bug in the Hermit kernel, fixed upstream and carried as a patch. **N1.7 ⚠️**, a bounded Bao comparison (mode C): Bao v2.0.0 builds reproducibly (LLVM), its isolation TCB is ~86 KiB (thin, unverified) against seL4's ~486 KiB (the ~241 KiB kernel, not in a verified configuration as N1 ran it, and ~245 KiB outside the kernel proof), and the static/scheduler-less trade-off is recorded for ADR 0002; Bao execution and Hermit-on-Bao are not demonstrated in the spike (its boot path needs U-Boot, outside scope — not a Bao failure); DMA is unresolved for both until H0.

   **N1.8 ✅, [ADR 0002](docs/adr/0002-production-native-architecture.md)** (accepted by the Project Lead, 2026-10-08):
   - seL4 + Microkit is the primary Native candidate, and Bao the fallback and comparison;
   - DMA is a mandatory H0 gate, for any platform;
   - the choice is conditional, not a production or high-assurance certification, and no formal-verification claim is made for the N1 runtime;
   - the carried patches are managed architectural debt ([the register](docs/native/carried-patches.md)).

   N1 selects an architecture to carry forward, not a production assurance level. H0 decides whether that architecture is admissible on a concrete hardware platform.
4. **Native Hardware Gate H0**, now: the Native architecture on real silicon, before more is built on it. Not a robot or a home, but the assumptions QEMU can hide:
   - the GIC, virtualization and the timer;
   - entropy;
   - the SMMU or IOMMU, where the board has one;
   - booting reliably;
   - basic latency;
   - isolation in practice.

   H0 is a multi-platform **hardware qualification framework**, not a script for one board ([spec 33](specs/33-hardware-qualification.md), [the plan](docs/native/h0-hardware-gate.md); Project Lead, 2026-10-08). It is software first, hardware later, and buys no board now:
   - ✅ H0.0, the framework, with QEMU `virt` as Platform 0 (#85);
   - ✅ entropy providers (#86): Native draws boot entropy from an admitted hardware entropy provider (`RNDR`, `RDSEED`, later a qualified board RNG), never from a software or silent fallback, and fails closed without one (spec 20);
   - ✅ H0.1, GICv2 for the Hermit kernel, on QEMU: directly, as a guest on seL4 through libvmm's virtual GICv2, and as the two guests and the relay (N1.4, N1.5);
   - H0.1x, x86: ✅ the Chitala image on x86-64 Hermit with the `x86-rdseed` provider, on QEMU; as a guest under seL4 and libvmm it waits for an x86 host with VT-x (QEMU's emulator has none);
   - ✅ H0.2, a CI build matrix for the target boards: N1.1's system for all five, and the two-guests system with its static PlatformIsolationEvidence for the three ZynqMP boards (the Pi 5 stops on libvmm's GIC; x86 waits for VT-x). Static evidence of the configuration only.

   Then the first Arm board available (layers A, B, C, E), and the first Intel machine with VT-x and VT-d (DMA). The ZynqMP's SMMU is H0-PX, a separate platform project off H0's critical path.

   **Device-side enforcement** (gap G-8, hazard H-GEN-017). A component that holds a device's credentials can act outside Chitala's decision, and protecting the core's memory does not protect control of the device. The [design note](docs/architecture/device-side-enforcement.md) comes now: an adapter forwards, and a trusted enforcement point near the device holds the credentials and carries out only verified orders. The implementation follows, on that design and on H0's platform evidence.
5. **Typed Evidence**: Safety receives evidence with its source, time, validity, scope, quality and provenance, never a bare `safe = true`.
6. **Safety Contract v0.1**: each capability declares its required evidence, envelope, denials, outcome, safe state and minimum assurance. The device-specific knowledge still in the core (`SAFE-4`'s door rule, `SAFE-9`'s robot state keys) moves into contracts.

   Beside it, two items to design next (Project Lead, 2026-10-08). Neither is implemented yet, and neither reopens the core as a whole:
   - **Cross-resource constraints and capacity reservation.** Actions that are each valid can together make a hazard the profile has declared:
     - a burner without ventilation;
     - two robots in one narrow passage;
     - loads above a shared electrical limit;
     - a door against a declared escape route.

     A contract states the dependencies and shared capacities. The core checks them, and reserves the shared capacity at once, so that two AIs that each see "enough power left" cannot both start. Execution leases (spec 21) are the natural starting point. Only the budgets a supported profile needs enter the core.
   - **Plan Engine v0.2: recovery obligations when a plan partly succeeds.** The 8-step limit stays: it is a deliberate bound, not a shortcoming. The design states:
     - a plan's safe points;
     - which states are acceptable when it stops partway;
     - which recovery actions are allowed, and on what evidence;
     - when it hands over to a person;
     - which obligations survive a power loss.

     Recovery is never a blanket "undo everything": a physical action may not be reversible, and reversing it may be worse. Every recovery action passes Authority and Safety.
7. **Loadable, signed profiles**, outside the binary, with vendor namespaces.
8. **Assurance levels A0 to A3**, the official scale. Each level's requirements are ones the node can check itself: a deployment reports its properties, and an action whose capability requires more than the deployment offers is refused.
9. The history evaluator in its own Native domain, and a spec for a Chitala deadman on the robot path, as defence in depth: the robot's hardware E-stop and its own watchdogs stay beneath it.
10. **Domain hardware validation**, once Typed Evidence, Safety Contracts and assurance levels are there to test the final abstractions:
    - a real robot;
    - real Matter devices;
    - a real pump or HVAC;
    - a real deadman and watchdog.
11. Home Profile v0.2 (climate, media, camera, pump); then kitchen, water and appliance profiles; then robots, industry and vehicles.
12. Later:
    - hardware-backed keys;
    - secure and measured boot;
    - updates and rollback;
    - federation across households and organisations;
    - a second, independent evaluator (2-of-2), only for high-consequence profiles.

Why this order, what stays invariant, information authority, and the questions each design must answer: [`docs/architecture/direction.md`](docs/architecture/direction.md) (Project Lead, 2026-10-07). Chitala is a **Physical Trust Fabric**: one specification, deployed as Hosted, Edge or Native.

**Toward high assurance** (Project Lead, 2026-10-07). Chitala does not need many more Safety features. It needs to show that the ones it has cannot easily be bypassed, delayed, rolled back or broken from below. Four themes, not yet ordered:
- **A typed Safety evidence framework.** `LocalizationEvidence`, `ObstacleEvidence`, `CollisionEvidence`, `MotionEnvelopeEvidence`, `ThermalEvidence`, …, each with its source, scope, measurement time, expiry, provenance and quality. Safety decides whether the evidence is enough.
- **Assurance levels, A0 to A3** (decided 2026-10-07): A0 consumer, basic governed execution; A1 verified execution and outcome; A2 high consequence, with isolation and a watchdog; A3 safety-critical, high assurance, with hardware keys, diverse evidence and independent safety. Each level's requirements are ones the node can check itself. There is no A4 until a real use case needs more than A3.
- **Temporal guarantees.** A profile states its decision deadline, its stop deadline and its evidence expiry. N1's seventh criterion measures the baseline first.
- **Independent and diverse evidence** for high-consequence systems. A single witness, corroborating witnesses, diverse witnesses, and a policy for evidence that conflicts.
- **Safety Contracts.** Each capability declares, in one place:
  - who may ask (Authority);
  - its limits and the evidence it needs (Safety);
  - its deadline and whether a watchdog is required (Execution);
  - its expected outcome and tolerance (Outcome);
  - its safe state (Recovery);
  - the minimum execution environment (Assurance).

  Home, robot, vehicle and industrial profiles then share one model.

Alongside these, the platform work the layer stands on is in the Native milestones N2 to N4:
- hardware-backed identity and keys;
- secure and measured boot with anti-rollback;
- updates that never break Safety, and rollbacks that never restore revoked authority.

Later still: interoperability, and a second, independent implementation of the specification.

**Growth by profiles, not by the core** (Project Lead, 2026-10-07). Chitala has to outlive today's catalogue of devices. A device that appears in 2035 should need a new profile and a new adapter, never a change to the Trusted Core. The core knows abstractions: resource, capability, state, evidence, authority, safety envelope, outcome, recovery. Profiles give them a domain's meaning, and a device may belong to several. Five principles:
1. The core holds no list of devices.
2. Profiles extend Chitala from outside the core, vendor extensions included, which Authority and Safety still bound.
3. Capabilities are typed and bounded.
4. An unknown capability is never taken as safe.
5. A device declares its outcome, evidence and safe state before it may take a risky action.

Where the code stands today:
- **Already so:**
  - the capability registry and the profiles are data;
  - parameters are typed and bounded, and risk is set per capability;
  - the registry refuses to load a device action without a declared outcome;
  - an unknown capability is refused (`E_UNKNOWN_CAPABILITY`), never guessed at;
  - resource kinds accept extensions.
- **Still device-specific in the core:**
  - `SAFE-4-PHYSICAL`'s one rule, locking a door that stands open;
  - `SAFE-9-MOTION`'s robot state keys.

  Both should become contracts a profile declares (Safety Contracts, above).
- **Not yet possible:**
  - the registry and the profiles are embedded in the binary;
  - the `x-<vendor>.` namespace (spec 04) is reserved but cannot be loaded.

**The next domain step, once N1 is under way: Home Profile v0.2.** It adds climate, media, camera and pump, four very different kinds of device, as typed capabilities, not switches:
- a pump has its running state, pressure, flow, level and faults, with dry-run and runtime limits;
- a camera brings privacy authority: viewing, recording and exporting a clip are separate rights, and an export needs a person.

They come through Home Assistant first, as the broad bridge. Direct adapters (Matter, BACnet, Modbus, ONVIF, MQTT) come later.

**The Authority and Safety layer is a near-frozen baseline** (Project Lead, 2026-10-07). Its core changes only:
- for a real safety or security defect;
- when N1 shows an abstraction is not enough;
- when a new domain shows a general primitive is missing.

New domains are expressed first with the existing Authority and Safety primitives, typed evidence and profile-specific contracts. No `SAFE-11` is added for a use case alone.

**Not now:** an OpenRAL integration or a full ROS 2 adapter; VLA models or planners; formal certification; the second evaluator. See [`docs/landscape/openral.md`](docs/landscape/openral.md).

Proposed by the Project Lead on 2026-10-05. Questions like these:

- "how long did the air conditioner run today?"
- "has the pump been on for four hours?"
- "how many times was it switched on?"
- "did the motor run past its safe time?"

need a history of state over time. Chitala records actions and outcomes, but has no runtime subsystem yet.

```text
device / Home Assistant → observation → state / witness ─┬─ Trusted Core: Authority, Safety, Outcome
                                                         └─ telemetry / history: state_started_at, state_ended_at,
                                                            duration, cycle_count, total_runtime, utilization
```

- **Observed time, not command time.** A device starts when its witness shows it, not when the `ExecOrder` left. Keep the source's own timestamp (Home Assistant's `last_changed`, a Matter report) beside the time Chitala observed it, and measure durations by the source.
- **Unobservable time is unknown.** While a device cannot be observed (spec 10), its time counts as unknown, never as its last state. A device that drops off can look alive for minutes through Home Assistant (step ③A, finding F9).
- **Changes outside Chitala count.** A switch turned by hand or by a Home Assistant automation is part of the history. The witness sees it.
- **Safety may only refuse.** History can later feed Safety, for example "a pump may run at most 30 minutes in a row". The history and the arithmetic stay outside the Trusted Core. The core only receives a checked constraint, and that constraint can only stop or refuse, never allow.

v0.3 is done when all six steps are done. Then: a second independent implementation → interop → Stable spec.

## Previous milestone: Chitala v0.2 — Platform Independence & Trusted Execution Boundary — ✅ done

Completed on 2026-10-05 at commit `106f3bc`. Released as the **`v0.2.0` pre-release** after the release-candidate audit ([`docs/audit/v0.2-rc-audit.md`](docs/audit/v0.2-rc-audit.md)), which found and fixed three gaps (H1, H1b, H2). The tag also contains v0.3 steps ① and ②, which the audit covered.

**Release-candidate audit** ([report](docs/audit/v0.2-rc-audit.md)). It covered the whole physical-authority path, with crash/restart and unknown executions first. It found and fixed three gaps:

- **H1:** a pending outcome was forgotten at a restart. Fix: a write-ahead record of every action that may change the world.
- **H1b:** that record could fail to persist while the order still left. Fix: the record fails closed.
- **H2:** one resource reached through two devices could take interleaving orders. Fix: SAFE-7 locks the resource as well as the device.

Thirteen intersections, the record's crash points, a seeded property test, a multi-threaded stress test and mutation checks now guard them. No Critical or High finding remains open.

No big new features. The goal was a foundation solid enough for Chitala to become an operating system that does not need Linux, in this order:

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
| 9 | **Outcome verification + recovery** ([spec 22](specs/22-outcome-recovery.md)) — did the world end up in the intended state; safe states and recovery when it did not | ✅ every device action declares its outcome in the registry (0.1.1); the resource's witness is observed after every order that may have executed: `verified`, `pending` until `within_ms`, `diverged`, `unconfirmed`, and `applied`/`not_applied` after an indeterminate failure; a broken promise of medium risk or more puts the resource in recovery (`SAFE-8-RECOVERY`: only its declared safe state runs; persisted; only an owner or admin ends it); the node runs that safe state once by itself (Project Lead decision: ≤ medium risk, `RecoveryGrant` from the Authority Engine, cleared by Safety, minted by the boundary, never chained) |
| 10 | **Plan Engine v0.1** ([spec 23](specs/23-plan-engine.md)) — multi-step plans built from intents, each step judged on its own and continued from the outcome of the step before | ✅ intent version 2 key 17 (up to 8 steps, a token per step); every step is an intent of its own derived from the signed plan; precheck of every step through Authority and Safety before anything moves; each step judged again in full when it runs and started only after the previous outcome is verified; a step that needs a person pauses the plan and is asked alone (Project Lead decision); stop on any failure, no compensation; `domain.plan_cancel` (the emergency stop, with the fence) and `domain.list_plans` (never an AI); 2 running plans per actor; MCP `chitala_plan`; CLI `plans`, `plan-cancel` |

All ten steps of v0.2 are done (2026-10-05). The current milestone is v0.3, above.

Every step shipped its attack and regression tests: TOCTOU between Authority → Safety → Execution, approval replay, stale device state, clock rollback, a policy change after approval, an ownership change, a compromised adapter, a restart mid-transaction, concurrent conflicting intents.

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
| A verifiable Trusted Core; core freeze from v0.3 on | ongoing |
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
