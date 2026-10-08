# ADR 0002 — Production Native architecture: seL4 + Microkit, with Bao as the fallback

Status: **Accepted** (2026-10-08, by the Project Lead)
Date: 2026-10-08
Context: [ADR 0001](0001-native-architecture.md) (the path and the seven pass criteria); [the N1 plan](../native/n1-partitioning-spike.md); the evidence in [`native/spike/`](../../native/spike/README.md) (N1.0–N1.6, on seL4) and [`native/spike/bao/`](../../native/spike/bao/README.md) (N1.7, Bao); [spec 13](../../specs/13-threat-model.md) (threats N1–N18); [spec 19](../../specs/19-execution-boundary.md) (orders and receipts); [spec 22](../../specs/22-outcome-recovery.md) (outcomes); [the direction](../architecture/direction.md) (assurance levels A0–A3, the Native Hardware Gate H0); [the carried-patch register](../native/carried-patches.md).

## Context

ADR 0001 set the path — Hermit today, a partitioning spike, an evaluation of seL4 and Bao, and only then a decision on the production Native architecture — and it named seven pass criteria. N1 carried that out on QEMU `virt` (aarch64): N1.0–N1.6 on seL4 with the Microkit and libvmm, and N1.7 a bounded comparison with Bao. This ADR is N1.8: the decision, on that evidence.

**What N1 showed on seL4.** The Chitala Native image (the unchanged Trusted Core, Rust `std`, Cedar, Biscuit, in a Hermit unikernel) runs as a guest; the adapter host runs in a second guest; a small relay in C copies bytes between them (65 lines in its normal build; N1.5d's hostile modes are compiled in only for that test).

| # | Criterion (ADR 0001) | Result on seL4 | Evidence |
|---|---|---|---|
| 1 | Memory isolation | ✅ | N1.5b, at run time: a guest that reaches past the RAM it was granted takes a stage‑2 fault on its own VMM; a hostile build of the adapter's VMM that reads the core's RAM is faulted by seL4 and named by the Microkit monitor. From the built system, PlatformIsolationEvidence (N1.5a) checks every physical range, capability and interrupt, and its self-test breaks the system to prove each check catches its break. The core's audit chain verifies throughout. |
| 2 | DMA isolation | ❌ **NOT DEMONSTRATED** on the N1/QEMU platform. A mandatory H0 gate before any DMA-capable untrusted partition | N1.5e: seL4's `qemu-arm-virt` has no SMMU driver, and no seL4 verified configuration covers an SMMU. Not worked around. This records that the N1 platform did not demonstrate DMA confinement; it is not a finding that seL4 cannot provide it. |
| 3 | Crash containment | ✅ crash · ⚠️ reboot not exercised | N1.5c: a crash before an order leaves the core running and the adapter unavailable; a crash after the adapter took an order leaves that order's fate *unknown*, never *not sent* (R1). A stale order or session after a disconnect is refused by the session gate (unit tests). An actual guest reboot/reload was not exercised. |
| 4 | Replay- and tamper-resistant channel | ✅ | N1.5d: a hostile relay that corrupts, duplicates, withholds or replays messages cannot make an order execute twice or unsigned — counted on the adapter's side, off the relay's path. The adapter host's line protocol and the order format are fuzzed (`fuzz/host_line`, `fuzz/exec_order`). Reordering reduces to replay or delay: the protocol is lockstep. |
| 5 | End-to-end flow | ✅ | N1.4: requests and intents drive the virtual devices through the adapter guest; receipts are verified and outcomes are checked against the observed state (spec 22); 14/14. |
| 6 | Latency and TCB measured | ✅ (relative, on QEMU) | N1.6: an order, boundary → channel → adapter → receipt, 0.70 ms median hosted against 41–50 ms on two guests. The code-size isolation TCB is about 486 KiB (Decision, condition 2). |
| 7 | Time isolation | ✅ **Temporal isolation demonstrated experimentally** | N1.6: with the adapter's guest spinning, and spinning under timer-interrupt pressure, the core is always scheduled and every stop completes; the median stop is 0.94–0.95× the unloaded baseline. The Hermit timer defect found during N1.6 was fixed by a backport of upstream's fix; that fix, not MCS, removed the long tail, which was gone after it with or without an MCS budget. Where partitions share a CPU, the MCS budget and period bound each one's CPU and give a lower-priority VM any CPU at all: N1 runs the adapter's VM one priority below the core's, and the core's VM at 80% of each 10 ms. The measurements are empirical and relative to QEMU, not a formal temporal guarantee. |

On the way, N1 found and fixed a timer bug in the Hermit kernel (a backport of upstream hermit-os/kernel#2585) and an idle guest's WFI trap storm (seL4 built with WFI not trapped). Neither is a property of the architecture; both are carried as patches (condition 6).

**What N1.7 showed on Bao** (bounded, the Project Lead's "mode C"). Bao v2.0.0 builds reproducibly with LLVM. Its isolation TCB is about 86 KiB of code, one thin layer with no formal verification claimed. Its standard model is static partitioning, one vCPU per physical CPU, with no scheduler. Bao's execution on `qemu-aarch64-virt` and Hermit-on-Bao were **not demonstrated** within the spike: Bao's supported QEMU boot path adds U-Boot firmware, which was outside the comparison's scope. This is a limitation of the spike, not a failure of Bao. DMA confinement is not demonstrated on N1/QEMU for Bao either: its Arm SMMUv3 stage‑2 support is an open upstream change, not in v2.0.0.

## Decision drivers

ADR 0001's drivers stand: isolation, assurance, the core running as it is, DMA control, effort, hardware reach, ecosystem, and the path to real I/O. N1 adds two:

1. **Evidence on Chitala's own workload.** An architecture is credited with what it was shown to do with Chitala on it — not with what it is capable of in principle.
2. **Honest limits.** Every claim this ADR makes must survive an auditor reading the evidence; what was not shown is stated as not shown.

## Options considered

- **A. seL4 + Microkit as a partitioning hypervisor, with Hermit guests** — the architecture N1 ran: the core and the adapter host in separate guests under libvmm VMMs, a byte-copying relay, and spec 19's signed, session-bound, single-use orders.
- **B. Bao as the partitioning hypervisor, with Hermit guests** — the fallback ADR 0001 named.
- **C. Defer the decision** until real hardware (H0) and a full Bao port exist.

Not reopened here: an own kernel (ruled out by ADR 0001 unless both candidates fail a gate that matters), and seL4-native protection domains with a `no_std` core (ADR 0001's long-term direction, decided in later ADRs).

## Evaluation

| | A. seL4 + Microkit | B. Bao | C. Defer |
|---|---|---|---|
| Chitala Native ran on it | ✅ N1.3–N1.6 | ❌ not demonstrated (N1.7) | — |
| Isolation shown on the workload | ✅ memory, crash, channel, time | ❌ not shown | — |
| Assurance evidence | 🟡 machine-checked proofs for specific seL4 configurations; the kernel N1 ran is not one of them, and the initialiser, loader, monitor and VMM are outside the kernel proof (condition 2) | 🟡 small and auditable; no formal verification claimed | — |
| Isolation TCB (code) | ~486 KiB: ~241 KiB the seL4 kernel, ~245 KiB the isolation machinery around it | ~86 KiB | — |
| Temporal model | shared CPU with MCS budgets and priorities: flexible, shown empirically under load | static 1:1 vCPU:pCPU, no scheduler: simple, rigid | — |
| DMA confinement on N1/QEMU | ❌ not demonstrated | ❌ not demonstrated | — |
| Effort to H0 | 🟡 move the shown system to hardware | ❌ boot harness, a Hermit port and the channel driver first | ❌ stalls Native |

What the table says: A is the only candidate that ran Chitala and was shown to isolate it; B buys simplicity and a smaller mechanism, but is unshown on Chitala's workload; C would trade evidence in hand for evidence not yet sought. Both candidates share the one open gate, DMA, so it does not separate them.

**Bao buys simplicity and a smaller mechanism; seL4 buys stronger assurance evidence, capability-based control, and flexibility.** The smaller TCB is not, by itself, the safer one.

## Decision

**N1 selects an architecture to carry forward, not a production assurance level. H0 decides whether that architecture is admissible on a concrete hardware platform.**

1. **The primary Native candidate is seL4 + Microkit, as a partitioning hypervisor with Hermit guests** — the architecture N1 demonstrated. The Native Hardware Gate H0 takes it to real hardware.
2. **Bao is the fallback and comparison candidate**, not a demonstrated Chitala Native platform. Bao is reconsidered if seL4 fails an H0 gate for which Bao has a credible path to satisfy the missing property, or if Bao later demonstrates a material architectural advantage worth the additional porting cost. A failure Bao would share does not reconsider it: if seL4 fails the DMA gate on a board with no SMMU, Bao has no path to DMA confinement on that board either. Reconsidering Bao starts with its U-Boot boot harness, Hermit-on-Bao, and an inter-guest channel driver.
3. **The choice is conditional. It is not a production or high-assurance certification.** These conditions and limits are part of the decision:
   1. **DMA is a mandatory H0 gate, for any platform.** Until it passes on supported hardware, a Native deployment assigns no DMA-capable device to an untrusted partition, and no deployment claims the DMA-isolation part of A2 or A3. The deployment reports this in evidence the node can check (PlatformIsolationEvidence today, attestation later), never as a constant.
   2. **No formal-verification claim for the N1 runtime.** seL4 has machine-checked verification results for specific supported configurations. **The exact N1 kernel binary and configuration used by Chitala is not one of those verified configurations, and this ADR makes no claim that the N1 runtime itself is formally verified.** The surrounding isolation stack — the initialiser, the loader, the monitor and libvmm — is also outside the seL4 kernel proof.

      ```text
      N1 code-size isolation TCB  ≈ 486 KiB
        ≈ 241 KiB  the seL4 kernel (the debug build N1 ran)
        ≈ 245 KiB  the surrounding isolation machinery: the CapDL initialiser (124.6),
                   the Microkit loader (16.5) and monitor (9.7), the core's VMM on libvmm (94.5)
      ```

      Where N1's kernel stands (checked 2026-10-08): N1 ran a debug build, with the MCS extensions and hypervisor support, on QEMU `virt`, without seL4's verification build options, and with WFI not trapped (a carried configuration change). seL4's AArch64 proofs cover the kernel in EL2 on a list of hardware platforms; the MCS proofs on AArch64 are in progress; no verified configuration covers an SMMU; QEMU `virt` is not a verified platform. H0 selects a platform and a release configuration, and states its distance from the nearest verified configuration.
   3. **Time isolation is demonstrated experimentally, not proven.** Where partitions share a CPU it rests on the MCS budget and period, and seL4's MCS proofs on AArch64 are in progress, so no formal temporal guarantee is claimed. The Hermit timer fix is a separate, carried correction: it, not MCS, removed N1.6's long tail. The budgets and priorities are part of the system description and of the evidence; a deployment that changes them re-measures.
   4. **The isolation machinery around the kernel is unverified code in the TCB**: the CapDL initialiser, the loader, the Microkit monitor and the core's VMM, about 245 KiB. It stays small, pinned and reviewed, and a fault in any of it is in scope for H0's isolation tests.
   5. **Crash containment was shown; guest reboot was not.** A guest restart policy (crash → VMM restarts the guest → new session → old order refused) is left to H0/N2 and is not claimed.
   6. **Carried patches are managed architectural debt.** Nine are carried: five to the Microkit and libvmm (the GICv3 board, the loader on a GICv3, WFI not trapped; the virtual GICv3 redistributor's address and registers) and four to the Hermit kernel (RNDR seeding, the virtual timer, the console as a channel, the timer deadline). Each is recorded in [the carried-patch register](../native/carried-patches.md) with its upstream reference and status, why it exists, its security and safety impact, the condition for dropping it, and the pin or release at which it is re-evaluated. They are not one kind, and are not judged as one: an upstream backport (the timer deadline) is reviewed against upstream's change, while a local change to the platform's behaviour (WFI not trapped, the console as a channel) is reviewed as Chitala's own code in the TCB. A patch that changes the kernel's configuration also counts toward the distance from a verified configuration (condition 2).
   7. **QEMU's numbers are relative.** Absolute latency, and the deadlines each profile requires, come from hardware.
4. **The Trusted Core stays as it is**: a Hermit guest with `std`, Cedar and Biscuit. Moving components into native protection domains, and the `no_std` question it raises, are decided in later ADRs.

## Consequences

- **Positive:**
  - Native goes to hardware with an architecture that was run and attacked with Chitala on it, not chosen on reputation.
  - The core did not change for N1; the untrusted-adapter model maps onto separate guests.
  - Every limit is written down, so later work closes named gaps rather than rediscovering them.
- **Negative:**
  - The isolation TCB is more than five times Bao's. About half of it lies outside the seL4 kernel proof altogether, and the kernel N1 ran is not a verified configuration either.
  - A VMM per guest is extra machinery, and the time-isolation result depends on an MCS configuration that must be maintained.
  - Nine carried patches until upstream releases catch up; the local ones may have no upstream path and stay Chitala's to maintain.
- **Risks:**
  - H0 may not show DMA confinement on the chosen board. Native then has no DMA-capable device in an untrusted partition, which bounds what A2/A3 deployments can attach.
  - The distance to a verified configuration may be larger on real hardware than on QEMU.
  - Hermit or the Microkit may move in ways that break the carried patches.

## Revisit when

- seL4 fails an H0 gate for which Bao has a credible path to the missing property — Bao's run then decides, starting with its boot harness and Hermit-on-Bao;
- Bao ships Arm SMMUv3 stage‑2 support in a release, or demonstrates Chitala Native;
- seL4's MCS proofs on AArch64 complete, or an SMMU enters a verified configuration;
- Hermit upstream stalls, or a release stops building for aarch64;
- a deployment needs A2/A3 with a DMA-capable device;
- a `no_std` path for Cedar and Biscuit appears (ADR 0001's long-term direction).

## Sources (checked 2026-10-08)

- seL4 verified configurations (AArch64 in EL2; MCS proofs in progress; no SMMU; listed platforms): <https://docs.sel4.systems/projects/sel4/verified-configurations.html>
- seL4 Microkit 2.3.1: <https://docs.sel4.systems/releases/microkit/2.3.1>; libvmm 0.2.0: <https://github.com/au-ts/libvmm/releases/tag/0.2.0>
- Bao v2.0.0: <https://github.com/bao-project/bao-hypervisor/releases>; its open Arm SMMUv3 work: <https://github.com/bao-project/bao-hypervisor/pulls>
- Hermit kernel fixes carried: <https://github.com/hermit-os/kernel/pull/2585> (the timer deadline), <https://github.com/hermit-os/kernel/pull/2528> (upstream's equivalent of the RNDR seeding patch); no Hermit release contains either yet (v0.13.2 is the latest)
- The N1 evidence: [`native/spike/README.md`](../../native/spike/README.md), [`native/spike/bao/README.md`](../../native/spike/bao/README.md); the carried patches: [`docs/native/carried-patches.md`](../native/carried-patches.md)
