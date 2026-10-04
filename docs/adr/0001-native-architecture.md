# ADR 0001 — Native architecture: Hermit, seL4, a hypervisor or an own kernel

Status: **Accepted with amendments** (2026-10-04, by the Project Lead). The amendments: seL4 is a candidate to be validated, not a decided direction; the spike's pass criteria include DMA isolation, crash containment, an authenticated replay-resistant channel and a latency baseline
Date: 2026-10-04
Context: Blueprint v20 §1, §2, §13, §19; decision D4 in [`docs/v20-alignment.md`](../v20-alignment.md); [spec 18](../../specs/18-platform.md) (PAL); [spec 20](../../specs/20-native-platform.md) (the Native spike); [spec 13, *Hosted and Native*](../../specs/13-threat-model.md#hosted-and-native-v02-step-6) (threats N1–N18 and the gates); v0.2 roadmap step 7.

## Context

Chitala's long-term goal is **Native**: booting on hardware with no Linux, Windows or macOS underneath (v20 §1). The Trusted Core already reaches the machine only through the PAL, and v0.2 step 5 booted the unchanged core as a **Hermit** unikernel on QEMU/aarch64. That spike runs in CI on every change.

Step 6 then showed what such a node is trusted for. Its decisions are as trustworthy as a hosted node's, and its attack surface is far smaller. But it stays a lab target until it meets these gates (spec 13):

| Gate | From | Needs |
|---|---|---|
| Isolation from the kernel | N1, N2 | a kernel the core can rely on, and memory isolation |
| Adapter isolation | N3 | adapters outside the core's memory |
| Hardware keys | N7 | non-exportable keys (D3) |
| Persistence and anti-rollback | N8, N9 | persistent, integrity-protected storage; a monotonic counter |
| Time across reboots | N6 | a persisted floor or authenticated time |
| Boot integrity | N10–N12 | verified or measured boot, anti-rollback of the image |
| DMA control | N13 | an IOMMU (SMMU) before the first DMA device |
| Production profile | N16 | no debug channels |

Two facts frame the options:

1. **The Trusted Core needs Rust `std` today.** Cedar (`cedar-policy` 4.13) and Biscuit (`biscuit-auth` 6) have no `no_std` support (checked 2026-10-04). The node uses `std` threads (six spawn sites). The rest of the core's dependencies support `no_std` (ed25519-dalek, sha2, ciborium, coset, serde_json), and so do the core's pure crates in principle.
2. **The team is small.** Native must not stall v0.2 to v0.3 (ExecutionLease, outcome verification, the Plan Engine, the Home reference implementation).

## Decision drivers

1. **Isolation**: the core's memory, the adapters, and the keys are separated by something stronger than Rust's type system (N1–N3).
2. **Assurance**: how much of what must be trusted is small, reviewed or proven.
3. **Fit with the core as it is**: `std`, Cedar, Biscuit, threads.
4. **Device and DMA control** (N13), and room for hardware keys (N7).
5. **Effort to the next useful milestone**, and to production.
6. **Hardware reach**: Arm boards first (edge, home), x86_64 servers, RISC-V later.
7. **Ecosystem**: maintenance, licence, and who else depends on it.
8. **The path to v0.3**: Matter and Home Assistant adapters need a full network stack and drivers.

Boot integrity (N10–N12) is mostly a firmware matter (Trusted Firmware-A, a verified boot loader, a signed image with an anti-rollback counter). Every option below must fit into such a chain, and none of them provides it alone.

## Options considered

### A. Hermit alone (today)

The core and a Rust library OS share one address space and one privilege level.

- **Strengths:**
  - It works now, with `std`.
  - The kernel is small (about 37,000 lines of Rust, 3,400 of them for aarch64) and memory-safe, and Chitala builds it without a network stack, PCI or a file system.
  - It is MIT/Apache-licensed and maintained upstream (RWTH Aachen and contributors), who are responsive: the aarch64 RNDR fix #2528 and the virtio-rng driver #2547 landed in 2026.
- **Limits:**
  - No memory isolation at all: kernel, core, adapters and keys are one domain (N1–N3).
  - No IOMMU policy.
  - No formal assurance.
  - Its entropy fallback had to be patched (spec 20; hermit-os/kernel#2736).

### B. seL4, natively

A formally verified, capability-based microkernel. Chitala components become protection domains, for example with the seL4 Microkit and the seL4 Device Driver Framework, as in UNSW's LionsOS. They are written in Rust with the seL4 project's `rust-sel4` crates.

- **Strengths:**
  - The strongest isolation available. The kernel is about ten thousand lines of C with machine-checked proofs. On AArch64 they cover C-level functional correctness, integrity and availability (access control), and confidentiality (information flow), for the kernel running in EL2 (hypervisor mode) on 18 platforms including the Raspberry Pi 4 and 5.
  - Its capability model matches Chitala's own: authority as unforgeable, delegable, revocable references.
  - Drivers run as user-level components; adapters, the key store and storage could each be a separate protection domain.
  - It has a foundation, industry users, and a GPLv2 kernel with BSD user-level libraries, so Chitala stays Apache-2.0 as separate components.
- **Limits:**
  - Rust on seL4 is essentially `no_std` with `alloc`, so the Trusted Core would have to drop `std`.
  - Cedar and Biscuit would have to be ported, replaced, or kept behind an interface with a `no_std` implementation.
  - Threads become components or event loops.
  - The guarantee is per configuration and per platform. No verified configuration covers device address translation (SMMU/IOMMU), multicore or (yet) the mixed-criticality extensions, and on AArch64 the proof stops at the C code: there is no binary verification.
  - It is the largest engineering investment short of option D.

### C. A partitioning hypervisor with Hermit guests

A small hypervisor partitions the machine. The Trusted Core keeps running as a Hermit guest (with `std`, unchanged). Adapters run in another guest: a second Hermit, or a small Linux "driver VM" with a full network stack for Matter and Home Assistant. Orders and receipts cross between guests over a narrow channel (shared-memory ring or virtio-vsock).

- **Candidates:**
  - **seL4 as a hypervisor**: on AArch64 the verified configuration *is* the kernel in hypervisor mode, so the kernel that separates the guests is the verified one. The virtual machine monitor runs at user level and is not verified.
  - **Bao**: a small static partitioning hypervisor for Arm and RISC-V (Apache-2.0). It runs on QEMU `virt` (aarch64) and the Raspberry Pi 4, and passes devices straight through to guests. Its documentation does not describe SMMU use, so DMA isolation must be checked in the spike.
  - **pKVM** (Android's protected KVM).
  - **Xen** (dom0less).
  - Xen and KVM-based monitors put a much larger code base in the trusted path.
- **Strengths:**
  - Memory isolation enforced by the hardware's second-stage translation, without changing the core.
  - A hypervisor that programs the SMMU keeps devices handed to the adapter guest away from the core (N13). Whether the candidates do this, and with what assurance, is a question for the spike: seL4's verified configurations exclude the SMMU.
  - The adapter guest can run anything (Linux, Matter SDKs) while being treated as untrusted, which is exactly Chitala's model.
  - It moves toward B: on seL4, components can later move out of guests into native protection domains one at a time.
- **Limits:**
  - The hypervisor joins the trusted base.
  - Hermit as a guest of seL4's or Bao's virtual machine monitor is **unproven**, so a spike must show it (device model, timers, entropy).
  - Inter-guest channels must be designed and fuzzed.
  - On Arm, confidential computing (CCA realms) would protect guests even from the hypervisor, but such hardware is not yet common.

### D. An own Chitala kernel

A minimal kernel written for Chitala: capability-native, Rust, `no_std`.

- **Strengths:**
  - Total control, and the smallest kernel that does exactly what Chitala needs.
- **Limits:**
  - Everything in B's limits (a `no_std` core, the Cedar and Biscuit question), plus writing and maintaining the kernel itself with `unsafe` code: boot, MMU, interrupts, timers, SMMU, drivers, scheduling.
  - No verification unless the project funds one.
  - It would reproduce, with less assurance, what seL4 already provides.
  - It would stop roadmap work for a long time.

## Evaluation

Legend: ✅ meets it · 🟡 partly or with work · ❌ does not.

| Driver | A. Hermit | B. seL4 native | C. Hypervisor + Hermit guests | D. Own kernel |
|---|---|---|---|---|
| Core vs adapters vs keys isolated (N2, N3) | ❌ one address space | ✅ separate protection domains | ✅ separate guests (stage-2 translation) | 🟡 as good as we make it |
| Assurance of the kernel or hypervisor (N1) | 🟡 small Rust, unverified | ✅ formal proofs (per configuration; C level on AArch64) | 🟡 seL4 hypervisor: the verified kernel itself, with an unverified user-level monitor; Bao: small, unverified | ❌ new, unverified |
| Core runs as it is (`std`, Cedar, Biscuit, threads) | ✅ | ❌ `no_std` port or replacements | ✅ the core stays in a Hermit guest | ❌ `no_std` port or replacements |
| DMA control (N13) | ❌ | 🟡 drivers at user level; the SMMU is outside the verified configurations | 🟡 depends on the candidate's SMMU use (to be checked in the spike) | ❌ must be written |
| Room for a hardware key store (N7) | 🟡 the driver shares the core's memory | ✅ its own protection domain | ✅ its own guest or service | 🟡 |
| Effort to the next useful milestone | ✅ done | ❌ large | 🟡 medium: hypervisor bring-up and a channel; core unchanged | ❌ very large |
| Hardware reach | 🟡 aarch64, x86_64, riscv64 under virtualisation; boards need work | ✅ many Arm, RISC-V and x86 platforms; 18 AArch64 platforms in verified configurations | 🟡 depends on the hypervisor (Bao: Arm, RISC-V, QEMU `virt`) | ❌ |
| Ecosystem and maintenance | 🟡 active, small team | ✅ foundation and industry | 🟡 varies by candidate | ❌ all on Chitala |
| Path to v0.3 (Matter, Home Assistant) | 🟡 Hermit's network stack, in the core's memory | 🟡 LionsOS networking; drivers to port | ✅ adapters in a driver guest with a full stack, isolated from the core | ❌ |

What the table says:

- **A** is the right lab baseline, but cannot meet the isolation gates.
- **D** loses on every driver except control.
- **B** is the strongest candidate destination but needs the core off `std` first, and much of what makes it attractive is still to be shown on Chitala's own workload.
- **C** gets memory isolation now and keeps the core unchanged. Device control depends on the candidate. Built on seL4, whose verified AArch64 configuration is the hypervisor configuration, it becomes a path to B rather than a detour.

## Decision

The path is **Hermit today → portability preparation → a partitioning spike → an evaluation of seL4 and Bao → only then a decision on the production Native architecture**, in a later ADR. This ADR decides the first three steps and the criteria for the fourth. It does not decide the production architecture ahead of the evidence.

1. **Keep Hermit as the lab target** (A) for v0.2 to v0.3, with the carried kernel patch (spec 20). No kernel work blocks the roadmap.
2. **Make the core portable now, as cheap insurance for B and C.** These steps help every option:
   - the pure core crates build as `no_std + alloc`, with a CI build for a bare-metal target;
   - the policy engine and the token format sit behind interfaces, so Cedar and Biscuit can be swapped without touching the rest;
   - the PAL offers tasks instead of `std` threads.
3. **Next Native milestone: a partitioning spike (C)** on QEMU/aarch64:
   - the Trusted Core in a Hermit guest, the virtual-device adapters in a second guest, and execution orders and receipts over an inter-guest channel;
   - candidates: **seL4 as a hypervisor** and **Bao**, chosen by the spike.
   - Pass criteria. Each is a test that can fail; a candidate that cannot meet one has failed that gate, and the spike records it:
     1. **Memory isolation:** the adapter guest cannot read or write the Trusted Core's memory.
     2. **DMA isolation:** a device assigned to the adapter guest that attempts DMA into the Trusted Core's memory is stopped. QEMU's `virt` board can model an SMMUv3 (`iommu=smmuv3`) for this.
     3. **Crash containment:** killing, panicking or rebooting the adapter guest leaves the Trusted Core running. Orders pending in that guest fail closed: nothing is believed without a receipt, the order expires, and the device's state becomes unknown, so `SAFE-3-STATE` applies.
     4. **An authenticated, replay-resistant channel:** an `ExecOrder` or `ExecutionReceipt` replayed or tampered with across the guest boundary is rejected. Spec 19 already makes orders signed, bound to an executor session and single-use; the test proves this still holds across guests, and the channel's framing is fuzzed.
     5. **Orders and receipts work** across the channel, and the CI boot test stays green.
     6. **Measurements:** the size of the trusted base, and a latency baseline for *Boundary → channel → adapter → receipt* (median and tail) against the hosted path. The aim is not early optimisation, but to avoid choosing an architecture whose overhead is unacceptable.
4. **Preferred long-term candidate: seL4 native (B), subject to the results of the partitioning spike and the later Native gates.** It is not chosen yet: SMMU support, Hermit as a guest, a `no_std` path for Cedar and Biscuit, the inter-guest channel and hardware coverage are all still unproven. If the evidence supports it, components move from guests into native protection domains once the core is `no_std` and the policy and token question has an answer: port Cedar and Biscuit, or compile policies to a small `no_std` evaluator. Both are decided in later ADRs.
5. **No own kernel (D).** It is reconsidered only if both B and C fail a gate that matters.

Independent of this ADR, the boot-integrity gates (N10–N12) are met in firmware (a verified boot chain with an anti-rollback counter), and hardware keys follow D3.

## Consequences

- **Positive:**
  - The roadmap continues (ExecutionLease next) while Native gains a credible route to isolation.
  - The core-portability work pays off whichever way B and C go.
  - Chitala's untrusted-adapter model maps directly onto separate guests or protection domains.
- **Negative:**
  - Two platforms to keep healthy for a while (hosted, Hermit), and a third in the spike.
  - The hypervisor adds trusted code.
  - The `no_std` direction will eventually force a hard choice about Cedar and Biscuit.
- **Risks:**
  - Hermit as a guest of seL4 or Bao may need upstream work. The spike surfaces it early, and the fallback is a different hypervisor or a Linux-free driver guest.
  - The spike may show that neither candidate meets DMA isolation (pass criterion 2) on available hardware. N13 then stays an open gate, and devices with DMA stay out of Native until it is met.

## Revisit when

- the partitioning spike fails on both candidates;
- Hermit upstream stalls, or a release stops building for aarch64;
- `std` support appears for seL4 (the core could then move with fewer changes), or Cedar or Biscuit gain `no_std` support;
- Arm CCA (or an equivalent) becomes common on target hardware;
- a gate in spec 13 turns out not to be reachable on the chosen path.

## Sources (checked 2026-10-04)

- seL4 verified configurations: <https://docs.sel4.systems/projects/sel4/verified-configurations.html>
- seL4 security proofs complete on AArch64: <https://sel4.discourse.group/t/sel4-security-proofs-now-complete-on-aarch64/1074>
- Rust on seL4 (`rust-sel4`, `no_std` with or without `alloc`): <https://docs.sel4.systems/projects/rust/tutorial/introduction.html>
- seL4 Microkit: <https://www.trustworthy.systems/projects/microkit>; LionsOS: <https://www.trustworthy.systems/projects/LionsOS>
- Bao hypervisor: <https://github.com/bao-project/bao-hypervisor>
- Hermit: aarch64 RNDR seeding <https://github.com/hermit-os/kernel/pull/2528>, virtio-rng <https://github.com/hermit-os/kernel/pull/2547>, the entropy fallback <https://github.com/hermit-os/kernel/issues/2736>
