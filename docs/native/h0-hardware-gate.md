# H0: the Native Hardware Gate

[ADR 0002](../adr/0002-production-native-architecture.md) chose seL4 + Microkit with Hermit guests as the architecture to carry forward. H0 decides whether that architecture is admissible on a concrete hardware platform. [Spec 33](../../specs/33-hardware-qualification.md) defines how: a **multi-platform hardware qualification framework**, not a script for one board. The framework has:
- one property catalogue;
- a manifest for each platform;
- a harness for each platform;
- one report for each run.

What a platform needs, for those who design or choose hardware, is in [the platform guidance](platform-guidance.md).

The goal is not "Chitala runs on board X". It is this: a new platform declares its capabilities, runs the same property tests, and gets evidence of which assurance it can support. Nothing here locks Chitala to one board, one CPU or one virtualization mechanism.

## Decisions (Project Lead, 2026-10-08)

| Question | Decision |
|---|---|
| H0.0 before any hardware? | **Yes, now.** It is a lasting product, not a temporary scaffold |
| H0.1, GICv2 for the Hermit kernel, on QEMU? | **Yes, high priority** |
| x86 before the Raspberry Pi 5? | **Yes, technically.** The Pi 5 adds portability, not a new property. x86 can give the one property N1 lacks, DMA isolation, but only on a real machine |
| Is the ZynqMP's SMMU part of H0? | **No.** It becomes **H0-PX**, platform enablement and upstream R&D, kept off H0's critical path |
| Buy a board now? | **No.** Finish the software first, then decide which board is worth it |
| The order of hardware | **Availability-driven:** the first Arm board available, then the first Intel machine with VT-x and VT-d, then more boards for portability |
| Assurance enforcement in the core? | **Not in H0.** H0 creates evidence. Typed Evidence → Safety Contracts → Assurance A0–A3 is where a node uses it |
| An emulator's evidence? | **A QEMU result of PASS is not a hardware property established.** The emulator's report establishes nothing for a hardware deployment. A property whose subject is the hardware is NOT_DEMONSTRATED on QEMU, whatever the emulator showed. These are entropy, DMA, absolute latency, interrupt and timer behaviour on silicon, and boot reliability. The reason says what the emulator observed, and no sixth status is added |
| Entropy | **An admitted hardware entropy provider, not `RNDR` only.** Spec 20 changes to: *Native Chitala must obtain boot entropy from an admitted hardware entropy provider. No deterministic, software-only, fixed, or silent fallback is permitted.* The admitted providers:<br>• `RNDR` on Arm with FEAT_RNG;<br>• `RDSEED` on x86, the CSPRNG's primary seed, with no step down to `RDRAND` just to boot;<br>• a board RNG, such as the Pi 5's `rng200`, only with a trusted driver, health and failure tests, and its provenance in H0 evidence;<br>• a TPM or an external TRNG, later, as a provider of its own, once its source and trust boundary are described.<br>With no admitted provider, Native fails closed, as now. The platform layer gets an `EntropyProvider` (id, class, hardware-backed, source, health, fill), and an H0 report names its `entropy_provider`. No enforcement in Authority or Safety |
| GICv2 and entropy | **Separate pull requests, tested separately.** GICv2 is interrupt-controller portability; entropy is security policy |
| The ZynqMP's entropy | **UNSUPPORTED** until a TPM, a TRNG or another real provider exists. No RNG is made up for the sake of it |

Two rules for every property used for assurance, from spec 33:
- a manifest is a declaration, never proof;
- only PASS establishes a property, and anything else means the property is unavailable.

## The steps

| Step | What | Needs hardware |
|---|---|---|
| H0.0 | **The framework**: spec 33, the catalogue, manifests for the QEMU boards and the candidate boards, harnesses for QEMU, the report and its validation. QEMU `virt` is Platform 0: N1's evidence, run through the framework, is the first report. CI runs every step through the harness and keeps the reports | no |
| H0.0e | **Entropy providers.** Spec 20 moves from `RNDR` only to an admitted hardware entropy provider, and the platform layer gets an `EntropyProvider` with `arm-rndr` as its first provider. This is its own pull request | no |
| H0.1 | **GICv2 for the Hermit kernel**, on the released SDK's GICv2 QEMU board (`qemu_virt_aarch64`), with a CPU model that has FEAT_RNG so `arm-rndr` still serves. It removes one blocker shared by the ZCU102, the Kria K26, the Ultra96-V2 and the Pi 5 | no |
| H0.1x | **x86 Native feasibility**: Hermit x86_64 → libvmm's x86 VMM on seL4 → the Chitala Native image boots, on QEMU. It needs the `x86-rdseed` provider first. No VT-d yet | no |
| H0.1e | **Board entropy**: the Pi 5's `rng200` as a provider (a trusted driver, health and failure tests, provenance). The ZynqMP stays UNSUPPORTED until a TPM, a TRNG or another real provider exists | no, until it is tested on the board |
| H0.2 | **A CI build matrix** for the target boards (`zcu102`, `kria_k26`, `ultra96v2`, `rpi5b_2gb`, `x86_64_generic_vtx`), with static PlatformIsolationEvidence for each | no |
| — | **Wait for, borrow, or get access to hardware**: a university or embedded group, a used board, a contributor who runs the harness on a board they have, or later a donation or sponsorship | — |
| H0.3 | **The first Arm hardware qualification** (layers A, B, C, E) | an Arm board |
| H0.4 | **The first x86 DMA qualification** through VT-d (layer D). The machine's BIOS, its IOMMU and real device passthrough are checked first | an Intel machine with VT-x and VT-d |
| H0.5 | **The H0 report** | — |

H0-PX, the ZynqMP's SMMU, stands apart. It means porting seL4's SMMUv2 driver from the TX2 to the ZynqMP, then integrating it with the Microkit and plumbing it through libvmm. It is a platform project of its own, worth doing with upstream, and H0 does not wait for it. Until it exists, a ZCU102 or a Kria reports `dma_isolation` as UNSUPPORTED: not "H0 blocked".

## What the boards need first (checked 2026-10-08)

The sources are:
- the pinned Microkit and its IOMMU code;
- the seL4 kernel's configuration;
- the seL4 hardware pages;
- libvmm 0.2.0;
- the Hermit kernel's main branch.

The manifests in [`native/h0/platforms/`](../../native/h0/platforms/) record each source.

- **The interrupt controller.** The ZynqMP (ZCU102, Kria, Ultra96), the BCM2712 (Pi 5) and the TX2 all have a GICv2. The Hermit kernel drives only a GICv3, so the Chitala image cannot run as a guest on any of them before H0.1. The `arm-gic` crate the kernel uses supports a GICv2.
- **DMA.**
  - seL4's SMMU driver (`KernelArmSMMU`) exists only for the TX2, and every AArch64 verified configuration turns it off.
  - The Microkit's IOMMU support (2.3.0 and later) covers x86_64 alone.
  - On x86, `KernelVTX` and `KernelIOMMU` both require the verification build to be off. So x86 with VT-x and VT-d is always outside a verified configuration.
- **Entropy.** The Chitala Native image draws its keys only from `RNDR` (Armv8.5 FEAT_RNG), and refuses to run without it ([spec 20](../../specs/20-native-platform.md)).
  - The Cortex-A53 (ZynqMP) and the Cortex-A76 (Pi 5) have no FEAT_RNG. CI already shows the image refusing to run on a Cortex-A76.
  - The Pi 5 has an RNG peripheral. The ZynqMP has none for its application processors in upstream Linux's device tree.
  - On x86_64 the image admits no source yet, and spec 20 names `RDSEED` as the candidate.
  - **Decided** (Project Lead, 2026-10-08, above): an admitted hardware entropy provider. The providers are `RNDR`, `RDSEED`, and a board RNG once it is qualified.
- **The VMM.** libvmm 0.2.0 knows the GICs of QEMU `virt`, the Odroid-C4, the MaaXBoard and the ZynqMP. The Pi 5 needs a libvmm patch.
- **The verified configurations.** seL4 has AArch64 verified configurations for the ZynqMP (ZCU102), the Ultra96-V2, the Pi 5 (bcm2712) and the TX2. None of them has MCS, and none has the SMMU.
