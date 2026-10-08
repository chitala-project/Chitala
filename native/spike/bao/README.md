# N1.7: a bounded Bao comparison

ADR 0001's decision 3 is **seL4 first, Bao as the comparison and the fallback**. N1.7's job, at this point, is a comparison good enough to inform the production-architecture decision (ADR 0002) — **not** to turn Bao into a second complete Chitala Native platform. The Project Lead scoped it as "mode C" (2026-10-08): pin and build Bao, measure it, compare it, and attempt a minimal boot; stop at the boundary where getting Bao to run would start pulling the scope from a comparison into a port.

Run it on the canonical N1 Linux host: `native/spike/env/vm.sh run native/spike/bao/run-n1.7.sh`. It is not part of the CI gate (the seL4 Native N1 workflow is); it is run on demand and fetches Bao from GitHub, verifying the pin.

## Status

| Step | | |
|---|---|---|
| N1.7a | ✅ | Bao v2.0.0 reproducible build (LLVM, no GCC) |
| N1.7b | ⚠️ | Bao execution on qemu-aarch64-virt: the build succeeds and entry reaches EL2, but the official boot path requires U-Boot firmware. A direct bare-QEMU boot did not reach the Bao banner within the N1.7-C time-box. |
| N1.7c | ⚠️ | Hermit-on-Bao **not demonstrated** — not attempted beyond the Bao boot boundary. |
| N1.7e | ✅ | code-size / TCB comparison (below) |
| N1.7f | ✅ | structured architectural comparison (below) |
| N1.7g | ✅ | sufficient evidence for ADR 0002 |

N1.7b and N1.7c are **not** a failure of Bao. The precise reading:

> **Not demonstrated within the bounded N1.7-C spike. The supported Bao/QEMU boot harness introduces U-Boot firmware, which was outside the selected comparison scope.**

Nothing here implies "Bao cannot run Hermit"; only that **Chitala has not demonstrated it**.

## The pins

`run-n1.7.sh` verifies them before building.

| | |
|---|---|
| Bao tag | `v2.0.0` (released 2026-03-04) |
| commit | `0af4a1ab558ad60c9658af4f43756c4536dd3141` |
| source archive sha256 | `645cb16921d1fef23a0fda35adf6a8622438603cdbdf81526e1c75b4387cb021` |
| platform | `qemu-aarch64-virt` (present in v2.0.0; the README's checkbox is stale) |
| toolchain | clang / ld.lld / llvm-\* 18.1.3 (the host's existing LLVM; no `aarch64-none-elf-gcc` needed) |
| QEMU | 8.2.2 |

Bao selects the LLVM tools when `CROSS_COMPILE`'s basename contains `clang`. A one-partition config (`config/chitala/config.c`) runs a minimal bare-metal guest (`guest/guest.S`); it builds `bao.elf`/`bao.bin` that embed the guest.

## N1.7b: the boot attempts, and why they stop at U-Boot

Bao's entry (`_reset_handler`/`_el2_entry`) expects EL2 and is position-independent: it reads `MPIDR_EL1` for the CPU id, computes its own load address, and ignores `x0`/the DTB (it uses the compiled-in platform description). So it can run at any load address, as bao-demos runs it at `0x50000000`.

bao-demos boots it with a **U-Boot firmware**: `-bios flash.bin`, then `go 0x50000000`. Tried here without that firmware, on qemu-aarch64-virt with `virtualization=on,gic-version=3`:

- `-kernel bao.bin` (enters EL2, `x0`=DTB, loads at the arm64 offset);
- `-device loader,file=bao.bin,addr=0x50000000,force-raw=on,cpu-num=0` (enters EL2 at `0x50000000`);
- the same with all four CPUs' PCs set, and with `-smp 1`, and with `-cpu max`.

None reached Bao's `"Bao Hypervisor"` banner within the time-box. The **boot method itself is sound**: the same `-device loader,addr=0x50000000` boots `guest/guest.S` to its UART line, so the loader, the EL2 entry, the PL011 and the serial routing all work. The gap is Bao's firmware expectation on this platform, and building U-Boot to cross it is the step that would push mode C toward a port. It is recorded, not pursued.

## N1.7e: the code-size TCB

Measured by `run-n1.7.sh` (`llvm-size` on `bao.elf`, source lines over the aarch64 build):

```text
Bao:
  ~86 KiB hypervisor .text
  small static isolation substrate
  no formal verification claimed

seL4 N1 stack:
  ~486 KiB code-size isolation TCB
  of which ~241 KiB is the seL4 kernel
    with formal verification evidence for applicable configurations
  the remaining VMM / initialiser / monitor are not formally verified
```

The ~86 KiB vs ~486 KiB figure is **not** "Bao is safer because it is smaller". It is one clear trade-off:

> **Bao buys simplicity and a smaller mechanism; seL4 buys stronger assurance evidence, capability-based control, and flexibility.**

## N1.7f: the structured comparison

| | Bao v2.0.0 | seL4 + Microkit (the N1 stack) |
|---|---|---|
| Model | static partitioning, 1:1 vCPU:pCPU, **no scheduler** in the standard model | shared CPU possible; MCS budget/period and priorities |
| Isolation | stage-2 translation over static partitions; devices passed through | capability model + stage-2 through a per-guest VMM (libvmm) |
| Resource sharing | fixed at build time, less flexible | dynamic, capability-mediated |
| Machinery per guest | thin: Bao itself | a VMM per guest |
| Isolation TCB (code) | ~86 KiB, one layer, unverified | ~486 KiB, of which the ~241 KiB kernel is formally verified |
| Chitala Native ran? | **not demonstrated** in N1.7-C | **yes**: N1.3 (go/no-go), N1.4 (two guests + relay), N1.5a–d (isolation), N1.6 (latency/time isolation) |
| DMA confinement on N1/QEMU | **NOT DEMONSTRATED** (Arm SMMUv3 stage-2 is an open upstream PR, not in v2.0.0) | **NOT DEMONSTRATED** (seL4's `qemu-arm-virt` has no SMMU driver) |

Because Bao re-runs nothing of N1.3–N1.6 here, the comparison is architectural, not a re-measurement. In particular, Bao's static, scheduler-less temporal model means N1.6 is **not** re-run as-is: there is no shared-CPU budget to measure.

## DMA

```text
seL4 N1/QEMU: NOT DEMONSTRATED
Bao  N1/QEMU: NOT DEMONSTRATED
            → mandatory H0 gate
```

Neither is made to "win" with a fixture that does not represent production. DMA/SMMU isolation is carried to H0 for both; no platform may claim the A2/A3 DMA-isolation assurance on N1/QEMU.

## N1.7g: input for ADR 0002

```text
Primary Native candidate:  seL4 + Microkit
Fallback / comparison:     Bao
Reason:
  - seL4 actually ran Chitala Native
  - two-guest isolation/execution was demonstrated
  - hostile transport / crash / time-isolation properties were exercised
  - Bao is substantially smaller and simpler
  - but Chitala-on-Bao was not demonstrated in N1.7-C
  - DMA remains unresolved for both until H0
```

**N1.7 is complete with a documented limitation; Bao remains a fallback candidate, not a demonstrated Chitala Native platform.**
