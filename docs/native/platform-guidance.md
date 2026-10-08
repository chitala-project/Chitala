# Platform guidance for Chitala Native

Chitala runs **Hosted** on ordinary computers. **Native** asks more of the hardware. There, a partitioning hypervisor (seL4 with the Microkit, [ADR 0002](../adr/0002-production-native-architecture.md)) isolates the Trusted Core from the adapters that drive devices. Whether that isolation holds depends on what the hardware offers, beneath the software.

This page sums up what the partitioning spike (N1) and the first survey of the [Native Hardware Gate](h0-hardware-gate.md) found a platform needs. It is written for anyone who designs, selects or integrates hardware for Chitala Native.

It is guidance, not certification, endorsement or a ranking. Whether a platform has a property is established only by an H0 report run on that hardware ([spec 33](../../specs/33-hardware-qualification.md)). The Chitala Compatible and Chitala Certified programs are not open yet ([`CERTIFICATION.md`](../../CERTIFICATION.md)).

## What a platform needs

| Characteristic | What makes a platform straightforward to qualify | Why | H0 property |
|---|---|---|---|
| **CPU virtualization** | AArch64 with EL2 (Armv8-A or later), or x86-64 with VT-x and EPT | The core and each adapter run in separate partitions, isolated by stage-2 (or EPT) translation | `guest_vm`, `memory_isolation` |
| **Interrupt controller** | Arm: a GICv2 (GIC-400) or a GICv3 or later (GIC-600, GIC-700). x86: an x2APIC, with interrupt remapping | Each guest takes its interrupts through its own VMM. The Hermit kernel drives both GIC versions (GICv2 since H0.1) | `guest_timer` |
| **Timer** | Arm: the generic timer, with a virtual timer for each vCPU and a constant-frequency counter. x86: an invariant TSC | Time isolation between partitions, and timed waits that wake on time | `guest_timer`, `temporal_isolation` |
| **Hardware entropy** | An architectural RNG: Arm FEAT_RNG (`RNDR`, optional from Armv8.5-A) or x86 `RDSEED`. A documented on-chip TRNG, with health tests and failure reporting, can serve once it is qualified as a provider | Native draws its keys only from an admitted hardware entropy provider. With none, it refuses to start; it has no software fallback ([spec 20](../../specs/20-native-platform.md)) | `hardware_entropy` |
| **IOMMU** | Arm: an SMMUv3 with stage-2 translation, with every DMA-capable controller behind it under its own stream ID. x86: Intel VT-d with interrupt remapping, with each device in its own IOMMU group | A device given to an untrusted partition must not be able to read or write the core's memory by DMA | `dma_isolation` |
| **Memory** | 2 GiB or more; ECC for high-consequence deployments | Two guests and their VMMs; integrity of the core's state | — |
| **Real-time clock** | Battery-backed, so it is right at power-on | Native refuses a clock earlier than its image's floor ([spec 20](../../specs/20-native-platform.md)). The adapters' partition is never given the clock to set (N1.5a) | `device_isolation` |
| **Watchdog** | An independent hardware watchdog, which no untrusted partition can reach | High-consequence deployments need one | — |
| **Boot and keys** | A documented boot chain that can start a hypervisor at EL2, through U-Boot or UEFI. Then a hardware root of trust for secure boot, measured boot (TPM 2.0 or an equivalent), and hardware-protected key storage | Reproducible qualification today; attestation and hardware-held keys later | `repeated_boot` |
| **Debug and console** | A UART for the core's console. Debug access (JTAG) that can be locked in production | Evidence is read from the console during qualification, and a deployed device must not stay open | — |
| **Documentation and supply** | Public reference manuals for the CPU, the interrupt controller, the SMMU, the timer and the RNG; an upstream device tree; long availability | Qualification must be repeatable by anyone, and a platform must outlive its first deployment | — |

### What the assurance levels lean on

The assurance levels A0–A3 ([the direction](../architecture/direction.md)) are being specified, so this table shows a direction, not requirements:

| Level | For example | What the platform contributes |
|---|---|---|
| A0, A1 | lights, media, HVAC | Hosted on an ordinary computer is enough |
| A2 | a door, a pump, a robot | isolation (virtualization, an IOMMU for any DMA-capable device given to an untrusted partition), admitted hardware entropy, a watchdog |
| A3 | a vehicle, a medical device | all of A2, and hardware-held keys, measured boot, ECC memory |

## What the first survey found (2026-10-08)

The platform manifests in [`native/h0/platforms/`](../../native/h0/platforms/) cite their sources, and `native/h0/h0.py plan` shows the full matrix.

- **One combination is still uncommon on Arm boards.** It is FEAT_RNG and an SMMU that the stack drives. No Arm board in the survey has both:
  - their cores predate FEAT_RNG, which is optional from Armv8.5-A;
  - where they have an SMMU, seL4 and the Microkit do not drive it yet.

  Their GICv2 is no longer in the way: the Hermit kernel drives it since H0.1.
- **On the hardware side,** an Armv8.5-A or later core with FEAT_RNG and an SMMUv3 (MMU-600 or MMU-700) covers both. Driving an Arm SMMU from seL4 and the Microkit is work still to be done: H0-PX, with upstream.
- **x86 with VT-x and VT-d** is, today, the one platform where the stack configures an IOMMU for DMA confinement. It lies outside seL4's verified configurations.
- **Verified configurations.** A platform on seL4's list of verified configurations is closer to the configuration whose proofs apply ([ADR 0002](../adr/0002-production-native-architecture.md), condition 2).

## Bringing a platform to qualification

Anyone can bring a platform to H0. The steps are in [`native/h0/README.md`](../../native/h0/README.md):
1. Declare its capabilities in a manifest, each with its source.
2. Write a harness for the steps that test it.
3. Run the harness on the hardware, and publish the report.

A report binds its results to the exact images, kernel configuration and patches it tested. Only results of PASS on real hardware establish a property.
