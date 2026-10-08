# 33 — Hardware qualification (H0)

**Status:** H0.0, the framework. The Project Lead decided its shape on 2026-10-08, after N1.8, and approved invariants 2 and 3 in the wording below the same day ([ADR 0002](../docs/adr/0002-production-native-architecture.md)). The plan and its steps are in [`docs/native/h0-hardware-gate.md`](../docs/native/h0-hardware-gate.md); the tool, the catalogue, the manifests and the harnesses are in [`native/h0/`](../native/h0/README.md).

ADR 0002 chose an architecture to carry forward, not a production assurance level. H0 decides whether that architecture is admissible on a concrete platform. It is not one script that runs alike on every board. It is:
- one catalogue of **properties**, the same for every platform;
- a **manifest** for each platform, declaring what it is expected to offer;
- a **harness** for each platform: its own commands, board support and boot;
- a **report** for each run: what was shown, on what exactly, by what evidence.

Not every board can run every test. That is not an inconsistency. A Raspberry Pi 5 has no IOMMU, so DMA isolation is not applicable there; a ZCU102 has an SMMU that the pinned stack does not drive, so it is unsupported there. The report says so, property by property, and never gives a board a single PASS or FAIL.

## The invariants

1. **A manifest is a declaration, never evidence.** It decides which properties a platform is tested for, and nothing else. `iommu = true` in a manifest establishes nothing. Properties are established, not claimed ([the direction](../docs/architecture/direction.md)).
2. **Only PASS establishes a property.** Every other status means the property is unavailable, for assurance as for anything else: FAIL, NOT_DEMONSTRATED, UNSUPPORTED and NOT_APPLICABLE alike.
3. **An emulator establishes no hardware qualification property.** A test on QEMU may PASS at the level of the emulation. That keeps its value for the logic, the integration and regressions, but a QEMU result of PASS is not a hardware property established. What an emulator's report establishes for a hardware deployment is nothing. A property whose subject is the hardware itself is NOT_DEMONSTRATED on an emulator, whatever the emulator showed. These properties are:
   - entropy;
   - DMA through an IOMMU;
   - absolute latency;
   - interrupt and timer behaviour on silicon;
   - boot reliability.

   The reason records what the emulator observed. No sixth status is added for it.
4. **A report is bound to what it tested.** It records the digest of every image and system it booted, the kernel's configuration, the pins of every component and the carried patches, the harness and the repository's commit. A PASS without that binding is invalid. A report that is not bound is a constant, and ADR 0002 forbids reporting a property as a constant.
5. **A report qualifies a configuration, not a node.** A deployment shows that it runs a qualified configuration through evidence it can check: PlatformIsolationEvidence from its built system today, measured boot or attestation later.
6. **Results come from the harness, never by hand.** The tool derives each status from the manifest and the logs of the steps it ran. A step that fails is not retried: every run counts.
7. **H0 creates evidence, and nothing in the Trusted Core reads it yet.** Typed Evidence, then Safety Contracts, then the assurance levels A0–A3 are where a node uses it to refuse a capability ([the roadmap](../ROADMAP.md)).

## The statuses

| Status | Meaning | Decided by |
|---|---|---|
| `PASS` | the property was tested on this platform, and every check of its test held | the harness, from the step's log |
| `FAIL` | the property was tested, and a check failed | the harness |
| `NOT_DEMONSTRATED` | the property applies and the stack supports it, but it was not shown. That covers:<br>• no test yet;<br>• the step did not run, or did not reach the test;<br>• a capability is undetermined;<br>• the platform is an emulator and the property's subject is the hardware | the harness, or the manifest for an undetermined capability |
| `UNSUPPORTED` | the stack does not drive the mechanism: the hardware has it, or whether it has one is not yet known | the manifest |
| `NOT_APPLICABLE` | the hardware does not have the mechanism | the manifest |

The two right-hand categories are kept apart on purpose. They lead to different work: an unsupported mechanism needs software, while a missing one needs other hardware.

## The properties

Two levels:
- **Platform qualification** shows that seL4, the Microkit and the VMM run on the platform: CPU, virtualization, interrupt controller, timer and boot. When a board fails here, nothing of Chitala needs to be debugged.
- **Chitala qualification** shows that the Chitala Native image runs there, isolated, with its orders, receipts, audit and recovery.

| Layer | Property | Level | Shown when | Needs |
|---|---|---|---|---|
| A, bring-up | `boot` | platform | seL4 and the Microkit start a system: protection domains exchange over a channel | microkit |
| A | `guest_vm` | platform | a VMM runs a guest under seL4 | microkit, virtualization, vmm |
| A | `guest_timer` | platform | the guest's timer interrupts are delivered through seL4 and its VMM, on the platform's interrupt controller and timer *(hardware subject)* | + hermit_guest |
| A | `hardware_entropy` | chitala | the core draws its keys from an admitted hardware entropy provider, which the report names, and refuses to run without one *(hardware subject)* | + entropy |
| B, isolation | `core_guest` | chitala | the Chitala Native image runs unchanged as a guest, every decision as expected | microkit, virtualization, vmm, hermit_guest, entropy |
| B | `end_to_end` | chitala | requests drive devices through an adapter in another partition; receipts are verified; an order whose fate is unknown is never called not sent | as `core_guest` |
| B | `device_isolation` | chitala | the adapter's partition shares no device with the core's; it cannot forge the core's log or set its clock | as `core_guest` |
| B | `memory_isolation` | chitala | the built system grants each partition only its own memory (static), and at run time the adapter's guest and the adapter's VMM fault when they reach for more | as `core_guest` |
| B | `crash_containment` | chitala | the adapter crashes before and after taking an order, and the core lives on; the order's fate is unknown, never not sent | as `core_guest` |
| B | `channel_integrity` | chitala | a hostile transport cannot make an order execute twice or unsigned | as `core_guest` |
| B | `guest_restart` | chitala | a crashed adapter guest is restarted; a new session starts; an order of the old one is refused | as `core_guest` |
| C, temporal | `temporal_isolation` | chitala | with the adapter's guest spinning, and under interrupt pressure, the core is always scheduled and every stop completes | as `core_guest` |
| C | `latency` | chitala | an order's and a stop's latency are measured *(hardware subject: absolute figures come only from hardware)* | as `core_guest` |
| D, DMA | `dma_isolation` | platform | a DMA-capable device in an untrusted partition reaches its own grant (positive) and nothing else (negative) *(hardware subject)* | microkit, iommu |
| E, reliability | `repeated_boot` | chitala | at least 30 boots in a row pass, none retried *(hardware subject)* | as `core_guest` |
| E | `long_run` | chitala | the system runs for hours under load without a fault | as `core_guest` |

The same property is shown by different mechanisms on different architectures: stage‑2 translation and an SMMU on Arm, EPT and VT-d on x86. The test's claim is the same; the mechanism is the platform's.

The machine-readable catalogue is [`native/h0/properties.toml`](../native/h0/properties.toml). A property is added there and here together.

## The capabilities

A manifest declares, for each capability, whether the **hardware** has it and whether the **stack** drives it. The stack is seL4, the Microkit, libvmm, the Hermit kernel and the Chitala Native image, at their pins. Each value is `true`, `false` or `"unknown"`, with its source.

| Capability | The hardware has it | The stack drives it |
|---|---|---|
| `microkit` | the board exists as a platform | the Microkit has a board for it |
| `virtualization` | Arm EL2, or Intel VT-x | seL4's hypervisor support |
| `vmm` | — | libvmm knows the board (its interrupt controller, its boot) |
| `hermit_guest` | — | the Hermit kernel runs as a guest there (its interrupt controller, its timer) |
| `entropy` | a hardware random number generator | an admitted hardware entropy provider of the Chitala Native image ([spec 20](20-native-platform.md); `arm-rndr` today). No deterministic, software-only or silent fallback counts |
| `iommu` | an IOMMU or SMMU | the kernel, the Microkit and the VMM confine a device's DMA through it |

**From a manifest to a plan.** Each property needs some capabilities, and each need is checked:
- if the hardware lacks a capability, the property is `NOT_APPLICABLE`;
- otherwise, if the stack does not drive one, it is `UNSUPPORTED`, whether the hardware's own is known or not;
- otherwise, if a capability is `"unknown"`, it is `NOT_DEMONSTRATED`;
- otherwise it is **required**: the harness must test it, and until it does, the result is `NOT_DEMONSTRATED`.

## The report

`chitala.h0.report/1`, JSON, written by `native/h0/h0.py report` and checked by `h0.py validate`:
- **`platform`**: the manifest's identity, its environment (`emulator` or `hardware`), and its digest.
- **`harness`**: the tool's version and digest, the harness's and the catalogue's digests, the repository's commit (and whether the tree was dirty), and the host.
- **`build`**, the binding:
  - the pins (seL4, the Microkit, libvmm, the Hermit loader);
  - the digest of every carried patch;
  - the digests of the SDK's kernel, loader, initialiser and monitor;
  - the kernel's configuration: its digest, and the options that set its distance from a verified configuration;
  - the Chitala images;
  - the emulator's version.
- **`steps`**: each step that ran, with:
  - the commit it ran on, and whether the tree differed from it;
  - its command and its exit status;
  - the digest of its log;
  - the digests of what it built and booted.
- **`observations`**: what the harness read from its steps' logs, each with its step and the log's digest. A name that a property must report, such as `entropy_provider` (the admitted provider the core named: `arm-rndr`, `x86-rdseed`, and so on), is read from the structured record the platform prints, parsed as JSON. It is never inferred from a log's text. A missing record, a record that is not JSON, or a missing field is an error the report states, and the property then fails; nothing falls back to the log (Project Lead, 2026-10-08). `check` refuses a harness that would read such a name any other way.
- **`results`**: one per property of the catalogue. Each carries:
  - its layer and level;
  - its planned status (from the manifest) and its final status;
  - the reason;
  - the evidence: which step, and which of its checks;
  - for a property that must name something, what it named (`hardware_entropy` names its `entropy_provider`).
- **`measurements`**, optional: what a step measured (N1.6's latencies and the TCB), with the file's digest.

A report is invalid, and `validate` fails, when:
- a property has no result, or two;
- a status is outside the five;
- the final status contradicts the plan, for example a PASS where the manifest says unsupported;
- a PASS has no evidence, or no build binding, or names a step that did not run, or rests on a step that ran on another commit than the report's or on a changed tree;
- a PASS names nothing the report observed, where it must (`hardware_entropy` without its provider), or, from tool version 0.2, names it from anything but a structured record;
- a property whose subject is the hardware passes on an emulator.

**What a report establishes** is the set of its PASS results, and only on hardware (`h0.py established REPORT`). For an emulator that set is empty, by invariant 3.

## Tiers

| Tier | Meaning |
|---|---|
| Reference | an emulator that runs the whole framework in CI: QEMU `virt` |
| 1 | documented and reproducible, a reference for its architecture |
| 2 | supported, validated by hand |
| Experimental | portable, but it gates no release |

A tier is declared in the manifest and changes with real data. Which board is tested first depends on what hardware is available, not on its tier (Project Lead, 2026-10-08).
