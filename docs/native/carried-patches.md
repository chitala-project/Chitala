# Carried patches (Native)

The Native stack carries ten patches to its pinned upstream components: N1's nine, and H0.1's GICv2 for the Hermit kernel. [ADR 0002](../adr/0002-production-native-architecture.md) (condition 6) makes them managed architectural debt: each is recorded here with
- its upstream reference and status;
- why it exists;
- its security and safety impact;
- the condition for dropping it;
- the pin or release at which it is re-evaluated.

A patch is not added to a Native build without an entry here. The diagnostic `native/spike/diag/hermit-n16-trace.patch` is not carried: only the diagnostic scripts apply it, never a Native build.

**The kinds.** They are judged differently:
- **Upstream backport:** upstream's own fix, applied to the pin before a release contains it. It is reviewed against upstream's change.
- **Upstream-equivalent:** Chitala's own fix for a defect that upstream has since fixed in its own way.
- **Platform enablement:** makes a pinned component run on N1's platform: seL4 as a hypervisor, on QEMU `virt` with a GICv3.
- **Local behaviour:** changes how a component behaves, for Chitala. No upstream path is assumed. It stays Chitala's to maintain, and is reviewed as Chitala's own code in the TCB.

**When every entry is re-evaluated:** whenever its component's pin moves, and at H0, where the platform changes. Upstream status checked 2026-10-08.

**How they are kept honest:**
- Each applies to a pinned revision (`native/spike/tools.lock`, and the Hermit pin in each patch's header).
- It must apply cleanly, or the build stops.
- CI runs the systems that depend on it, on both architectures.

## Summary

| Patch | Component (pin) | Kind | Upstream | Touches |
|---|---|---|---|---|
| [`hermit-kernel-aarch64-wakeup-deadline`](../../native/patches/hermit-kernel-aarch64-wakeup-deadline.patch) | Hermit kernel (hermit-rs `hermit-0.13.0`, kernel `ef27b79`) | upstream backport | hermit-os/kernel#2585, merged 2026-08-11; in no release | timing in every Native guest |
| [`hermit-kernel-aarch64-rndr`](../../native/patches/hermit-kernel-aarch64-rndr.patch) | Hermit kernel | upstream-equivalent | hermit-os/kernel#2528, merged 2026-07-26; in no release | entropy in every Native guest |
| [`hermit-kernel-aarch64-virtual-timer`](../../native/patches/hermit-kernel-aarch64-virtual-timer.patch) | Hermit kernel | platform enablement | not proposed upstream as it is | the timer of every Native guest |
| [`hermit-kernel-chitala-channel`](../../native/patches/hermit-kernel-chitala-channel.patch) | Hermit kernel | local behaviour | not proposed upstream as it is | the core's end of the channel |
| [`hermit-kernel-gicv2`](../../native/patches/hermit-kernel-gicv2.patch) | Hermit kernel | platform enablement | not proposed upstream yet | the interrupt controller of every Native guest |
| [`microkit-0001-board-qemu-virt-aarch64-gicv3`](../../native/spike/sdk/microkit-0001-board-qemu-virt-aarch64-gicv3.patch) | Microkit SDK from the 2.3.1 sources (`ec86afd`) | platform enablement | not upstream at the pin; not proposed | the seL4 configuration for QEMU |
| [`microkit-0002-loader-no-gicc-on-gicv3`](../../native/spike/sdk/microkit-0002-loader-no-gicc-on-gicv3.patch) | Microkit SDK | platform enablement | not upstream at the pin; not proposed | the loader (isolation TCB) |
| [`microkit-0003-qemu-virt-aarch64-gicv3-no-wfi-traps`](../../native/spike/sdk/microkit-0003-qemu-virt-aarch64-gicv3-no-wfi-traps.patch) | Microkit SDK | local behaviour (a kernel configuration option) | not upstream; not proposed | the seL4 kernel's configuration |
| [`libvmm-0001-qemu-virt-gicv3-redistributor`](../../native/spike/sdk/libvmm-0001-qemu-virt-gicv3-redistributor.patch) | libvmm 0.2.0 (`7069ab9`) | platform enablement | not upstream at the pin; not proposed | every VMM (the core's is in the isolation TCB) |
| [`libvmm-0002-vgic-v3-redistributor-registers`](../../native/spike/sdk/libvmm-0002-vgic-v3-redistributor-registers.patch) | libvmm 0.2.0 | platform enablement | not upstream at the pin; not proposed | every VMM (the core's is in the isolation TCB) |

## The Hermit kernel

`native/run.sh` applies these to a copy of the pinned kernel, for every Native image, hosted on QEMU or as a guest on seL4.

### hermit-kernel-aarch64-wakeup-deadline

- **Kind:** upstream backport of hermit-os/kernel 8c28d804 and 14a98206, merged in #2585 on 2026-08-11. No release contains them; v0.13.2 is the latest.
- **Why:**
  - The kernel wrote a sleeping task's wakeup time to the timer's comparator without adding back `BOOT_COUNTER`, so the timer fired early.
  - Every timed sleep ended in a timer-interrupt storm.
  - Under seL4 the storm lasted up to 0.85 s. This was N1.6's long tail.
- **Security and safety impact:**
  - The core's availability and timing: a decision, a stop included, that met a storm waited for its end.
  - MCS did not fix it.
  - Without the patch, N1.6's stop latencies do not hold.
- **Drop when:** the pin moves to a Hermit release containing #2585.
- **Re-evaluate:** at each move of the Hermit pin.

### hermit-kernel-aarch64-rndr

- **Kind:** upstream-equivalent. Upstream merged its own fix, hermit-os/kernel#2528, on 2026-07-26. No release contains it.
- **Why:**
  - Upstream, `seed_entropy()` on aarch64 returns nothing.
  - The kernel's entropy then falls back to a 31-bit Park–Miller generator, and still reports success.
  - Rust `std` seeds each thread's HashMap from it, so those seeds are predictable ([spec 20](../../specs/20-native-platform.md), *Entropy*).
- **Security and safety impact:**
  - It is hardening only.
  - Chitala's own randomness never comes from the kernel, with or without the patch.
  - Without it, HashMap seeds are predictable.
  - On a CPU without FEAT_RNG nothing changes, and the Native image refuses to run there anyway.
- **Drop when:** the pin moves to a Hermit release containing #2528.
- **Re-evaluate:** at each move of the Hermit pin, and at H0, for the board's FEAT_RNG.

### hermit-kernel-aarch64-virtual-timer

- **Kind:** platform enablement. It is not proposed upstream as it is.
- **Why:**
  - Upstream programs the EL1 physical timer. That is one register set, which every guest on a CPU would program over the others'.
  - seL4 saves and restores the virtual timer for each vCPU, and injects its interrupt.
  - Without a hypervisor, the virtual timer is the physical one.
- **Security and safety impact:**
  - Time isolation: without the patch, two guests on one CPU would reprogram each other's timer, so one partition would interfere with another.
  - It is part of criterion 7's evidence.
- **Drop when:** a Hermit release runs on the virtual timer, or offers it.
- **Re-evaluate:** at each move of the Hermit pin, and at H0, for the board's timer under seL4.

### hermit-kernel-chitala-channel

- **Kind:** local behaviour. It is not proposed upstream as it is.
- **Why:**
  - The virtio console is the guests' byte channel, `/dev/chitala-channel`.
  - Upstream would make it the console: the kernel's log lines would reach the channel, and what it reads would be echoed.
  - With the patch, the log stays on the UART, reads hand over whole packets, and nothing is echoed.
- **Security and safety impact:** it is the core's end of the channel, in the core's guest kernel.
  - It keeps the core kernel's log off the channel, so the log does not reach the adapter's side that way, and it reflects nothing back.
  - The integrity of what crosses does not rest on it. Orders and receipts are signed and single-use ([spec 19](../../specs/19-execution-boundary.md)), and N1.5d showed that a hostile transport cannot make execution happen twice or unsigned.
  - A memory-safety defect in it would be a defect in the core's kernel.
- **Drop when:** the Native channel moves to a transport that does not need it.
- **Re-evaluate:** at each move of the Hermit pin, and at H0, for the channel on hardware.

### hermit-kernel-gicv2

- **Kind:** platform enablement (H0.1). It is not proposed upstream yet. Upstream main drives only a GICv3, as of 2026-10-08.
- **Why:**
  - Every candidate Arm board in the H0 survey has a GICv2: the ZynqMP (ZCU102, Kria K26, Ultra96-V2), the BCM2712 (Raspberry Pi 5) and the TX2.
  - Without this patch the kernel panics on any controller but a GICv3, so the Chitala image could not run as a guest on any of them.
- **What it does:**
  - The kernel reads the controller's kind from the device tree.
  - A GICv3 is driven as before: its CPU interface is system registers, reached without a lock.
  - A GICv2 is driven by a minimal driver that does what Linux's does. It leaves interrupt groups as they are, acknowledges through `GICC_IAR`, ends through `GICC_EOIR`, and routes a shared peripheral interrupt to the CPU that enables it.
  - That works on a GICv2 without the Security Extensions and on libvmm's virtual CPU interface; `arm-gic`'s own GICv2 driver works on neither.
- **Security and safety impact:**
  - It is the interrupt handling of the core's guest kernel, so it is in the core's TCB.
  - A defect could lose or misroute the core's own interrupts: its timer, its channel, its UART. A lost timer interrupt delays a timed wait, and the time-isolation measurements would show it.
  - It cannot reach another partition: the distributor a guest sees is libvmm's virtual one, and the CPU interface is the hardware's virtual one, both per guest.
  - On a GICv3 the acknowledge and end paths are unchanged. The controller's lock now masks interrupts while it is held, so an interrupt never waits for it on the same CPU.
- **Shown on:**
  - QEMU's GICv2 (`native/run.sh --gic=2`): 13/13, timer interrupts delivered;
  - the released Microkit SDK's GICv2 board on seL4, through libvmm's virtual GICv2 (N1.3 with `N1_BOARD=qemu_virt_aarch64`): 13/13, timer interrupts delivered;
  - the GICv3 runs, unchanged.
- **Drop when:** a Hermit release drives a GICv2.
- **Re-evaluate:** at each move of the Hermit pin, and on the first GICv2 board (H0.3).

## The Microkit SDK and libvmm

`native/spike/scripts/build-sdk.sh` builds the Microkit SDK from the sources 2.3.1 was released from, with the `microkit-*` patches. `native/spike/run-n1.3.sh` and `native/spike/scripts/two-guests.sh` apply the `libvmm-*` patches to the pinned libvmm.

### microkit-0001-board-qemu-virt-aarch64-gicv3

- **Kind:** platform enablement. It is not upstream at the pin, and not proposed.
- **Why:**
  - The Hermit kernel drives only a GICv3, and the released SDK's QEMU board has a GICv2.
  - The patch adds the board `qemu_virt_aarch64_gicv3`, which is `qemu_virt_aarch64` with `QEMU_GIC_VERSION=3`.
- **Security and safety impact:**
  - It sets the seL4 kernel's configuration for the QEMU board.
  - It is QEMU only, with no effect on a hardware board.
- **Drop when:** H0's board replaces QEMU `virt`, or a Microkit release ships a QEMU board with a GICv3.
- **Re-evaluate:** at each move of the Microkit pin, and at H0.

### microkit-0002-loader-no-gicc-on-gicv3

- **Kind:** platform enablement. It is not upstream at the pin, and not proposed.
- **Why:**
  - On QEMU `virt`, the loader writes the GICv2 CPU interface's priority mask.
  - A GICv3 has no memory-mapped CPU interface, so the write takes a data abort.
  - seL4's GICv3 driver sets the mask itself.
- **Security and safety impact:**
  - The loader runs before seL4 and is in the isolation TCB.
  - The patch removes one write, and only when the GICv3 is configured.
- **Drop when:** a Microkit release does the same, or H0's board does not take this path.
- **Re-evaluate:** at each move of the Microkit pin, and at H0.

### microkit-0003-qemu-virt-aarch64-gicv3-no-wfi-traps

- **Kind:** local behaviour, as a kernel configuration option (`KernelArmDisableWFIWFETraps`). It is not upstream, and not proposed.
- **Why:**
  - seL4 passes each WFI or WFE trap to the guest's VMM.
  - libvmm (0.2.0, and upstream as of 2026-10-07) answers by resuming the guest.
  - So an idle guest trapped without end through its VMM, at the VMM's priority: millions of traps in one N1.6 run.
- **Security and safety impact:**
  - **Scheduling and time isolation.** A guest waiting in WFI keeps the CPU until its budget or time slice ends.
    - This is why two guests at one priority take about twice as long as one.
    - It is also why N1's scheduling gives the core an MCS budget.
  - **Verification distance.** It changes the kernel's configuration, so it counts toward the distance from a verified configuration (ADR 0002, condition 2).
- **Drop when:** a libvmm release handles WFI by blocking the vCPU until its next interrupt.
- **Re-evaluate:** at each move of the Microkit or libvmm pin, and at H0, with the release configuration.

### libvmm-0001-qemu-virt-gicv3-redistributor

- **Kind:** platform enablement. It is not upstream at the pin, and not proposed.
- **Why:**
  - libvmm knows QEMU `virt`'s GIC distributor but not its GICv3 redistributor, because its QEMU board has a GICv2.
  - The patch adds the redistributor's address, `0x080A0000`.
- **Security and safety impact:**
  - It is a platform constant in every VMM, and the core's VMM is in the isolation TCB.
  - It has no effect on another board.
- **Drop when:** a libvmm release supports QEMU `virt` with a GICv3, or H0's board replaces QEMU `virt`.
- **Re-evaluate:** at each move of the libvmm pin, and at H0.

### libvmm-0002-vgic-v3-redistributor-registers

- **Kind:** platform enablement. It is not upstream at the pin, and not proposed.
- **Why:**
  - libvmm's virtual GICv3 redistributor emulates only some of the SGI and PPI registers.
  - Hermit's GIC driver changes them with read-modify-writes, so libvmm stops on its assertions.
- **What it adds:**
  - reads of the enable, pending, active and priority registers, from the state libvmm already keeps;
  - `GICR_ICFGR1` writes, which are kept;
  - `GICR_ICFGR0`, which reads as edge-triggered, and `GICR_IGRPMODR0`, which reads as zero; writes to both are ignored.
- **Security and safety impact:**
  - It is interrupt-controller emulation in every VMM, and the core's VMM is in the isolation TCB.
  - A defect could misdeliver interrupts to that VMM's own guest.
  - A VMM has no capability to another guest's memory: N1.5a's PlatformIsolationEvidence checks this, and N1.5b's hostile VMM faults.
- **Drop when:** a libvmm release emulates these registers.
- **Re-evaluate:** at each move of the libvmm pin, and at H0, for the board's GIC.
