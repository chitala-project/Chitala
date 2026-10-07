# Native N1 — the partitioning spike: plan

**Status:** a plan, for the Project Lead's review (2026-10-07). It carries out decision 3 of [ADR 0001](../adr/0001-native-architecture.md): seL4 first, Bao as the comparison and the fallback. The Lead's order after v0.4 puts N1 second, after the history anchoring.

**Why N1, in Chitala's position** (Project Lead, 2026-10-07). Chitala does not try to become QNX, ROS, AUTOSAR and Home Assistant at once. It is the Authority and Safety layer, and it runs on those systems or connects to them:

```text
            Chitala
   ┌───────────┼───────────┐
 Matter      ROS 2      AUTOSAR
Smart Home   Robot      Vehicle
```

Native Chitala on a strongly isolating kernel gives that layer a foundation fit for high-consequence systems. N1 tests whether that foundation holds.

N1 is not about booting: the Hermit spike boots already, in CI, on every change (spec 20). N1 must show whether the Trusted Core can live in a strongly isolated environment, with the adapters in another domain, and at what cost. Every criterion below is a test that can fail. A candidate that fails one is recorded as failing that gate, and seL4 is not chosen on faith.

## What N1 must prove

| # | Criterion | How it is shown on QEMU `virt` (aarch64) |
|---|---|---|
| 1 | An adapter cannot read or modify the Trusted Core's memory | from the adapter guest, read and write an address of the core guest's memory: a stage-2 fault, and the core runs on |
| 2 | DMA from an adapter cannot reach the core's memory | a DMA-capable device assigned to the adapter guest, behind QEMU's SMMUv3 (`iommu=smmuv3`), is told to write into the core's memory: the transaction is stopped |
| 3 | An adapter guest crashes or reboots and the core lives on | panic, kill and reboot the adapter guest mid-order: the core keeps serving, the order fails closed (no receipt, it expires), and the device's state becomes unknown (`SAFE-3-STATE`) |
| 4 | Orders and receipts across the channel resist replay and tampering | a relay that replays, reorders, truncates or flips bytes: every such order or receipt is rejected (spec 19 binds them to a session, signs them and makes them single-use), and the relay's framing is fuzzed |
| 5 | The execution flow runs end to end | a person's request and an AI's intent drive the virtual lock through the adapter guest; the outcome is verified (spec 22) |
| 6 | Latency and TCB size are measured | *boundary → channel → adapter → receipt*, median and tail, against the hosted path; the trusted base counted (kernel, VMM, relay) |

## Not in N1

These come only after the partitioning architecture is shown (Project Lead):
- an own kernel;
- porting all of Chitala to `no_std`;
- production secure boot;
- full TPM/HSM;
- a driver framework;
- x86_64 bare metal;
- a package manager or UI.

The core stays exactly as it is: a Hermit guest, with `std`, Cedar and Biscuit.

## The shape, on seL4

```text
QEMU virt, aarch64 (virtualization=on, GICv3, iommu=smmuv3)
└─ seL4 in hypervisor mode, with the Microkit
   ├─ VMM "core"     ── guest: Hermit + the Chitala node, as today
   ├─ VMM "adapters" ── guest: Hermit + the adapter host (virtual devices)
   └─ PD "relay"     ── joins the two guests' console ports: it copies bytes and parses nothing
```

**The channel.** The adapter host protocol is already a byte stream: JSON Lines over a component's input and output (spec 19). Today, on Native, the adapter host is an in-process component of `MemoryExec`.
- **In N1, it moves to the second guest.** Each guest gets a virtio console port, which libvmm emulates over virtio-mmio, and a relay protection domain joins the two ports.
- **On the node's side,** the change is a Native execution host whose component is in another domain. Starting it opens the port, and the protocol is unchanged.
- **Nothing in the Trusted Core changes.** Orders are already signed by the boundary, bound to an executor session and single-use, so a channel that lies can only make execution fail, never make it happen twice.

**Then the history evaluator** (the Lead's step 3) becomes a third guest over the same channel model, once the adapter channel is shown.

## Unknowns, tested first

Each can stop the seL4 path early, and the steps below meet them first.

1. **Hermit as a libvmm guest.**
   - libvmm documents Linux guests only: a Linux arm64 `Image` with a DTB and an initrd.
   - Hermit's aarch64 loader takes a DTB, but may lack the Linux `Image` header libvmm looks for. If so, the first try is to wrap the loader in a 64-byte arm64 `Image` header, a small patch to carry or to propose upstream.
   - Nobody has reported booting Hermit under an seL4 VMM; a 2023 question on the seL4 list went unanswered.
2. **Hermit's virtio drivers against libvmm's devices.** Hermit's virtio-console, or virtio-vsock, must work over virtio-mmio as libvmm emulates it.
3. **The SMMU.** seL4's verified configurations exclude the SMMU. Whether seL4 and the Microkit program QEMU's SMMUv3 for a device passed to a guest is to be shown. If they do not, criterion 2 fails for seL4 in N1, and it is recorded (ADR 0001, *Risks*).
4. **Time and entropy inside the guest.** The virtual timer, and `RNDR` on a CPU model that has it. Today's spike refuses to run without a hardware RNG (spec 20).
5. **The build host.** The Microkit SDK has a macOS aarch64 release, and libvmm's examples build on macOS. libvmm advises Linux for anything custom.

## Steps

Each step ends in a script and a check.

| Step | What | Shows |
|---|---|---|
| N1.0 | Tools, pinned: the Microkit SDK, the libvmm commit, QEMU 11; scripts to fetch and verify them | a reproducible setup |
| N1.1 | Microkit "hello": two protection domains and a channel, on `qemu_virt_aarch64` | the toolchain works |
| N1.2 | libvmm's Linux guest example boots | the VMM works on this setup |
| N1.3 | **The Chitala Native image boots as a libvmm guest** | unknowns 1 and 4; the go/no-go of the seL4 path |
| N1.4 | Two guests and the relay; the node drives the adapter host in the second guest | criterion 5, and unknown 2 |
| N1.5 | The isolation tests: memory, crash and reboot, a lying relay, then DMA through the SMMUv3 | criteria 1, 3, 4 and 2, and unknown 3 |
| N1.6 | The measurements: TCB size, latency median and tail against hosted | criterion 6 |
| N1.7 | The same on Bao: static partitions; its shared-memory IPC needs a small Hermit driver, or virtio through its I/O dispatcher | the comparison, or the fallback |
| N1.8 | A report, and ADR 0002: the direction for the production Native architecture | the decision, on evidence |

## Where it lives

- **The spike's code:** `native/spike/`, outside the main workspace, like `native/` and `fuzz/`.
  - `sel4/`: the Microkit system description, the relay, the build and boot scripts;
  - `bao/`: the same for Bao;
  - `tests/`: the attacks.
- **The protection domains:** Rust, with the seL4 project's `rust-sel4` crates, where they fit; C where the VMM requires it.
- **CI:** a job boots the seL4 system on QEMU once N1.4 passes, as the Hermit spike does today.

## Exit

Each of the six criteria is recorded as passed or failed, with its evidence.
- **seL4 fails a gate that matters:** Bao's run decides.
- **Both fail:** ADR 0001 is revisited, as it says.

## Questions for the Project Lead

1. **A Linux build host.** Is a Linux machine (or a Linux VM on the Mac) available for the seL4 and Bao tooling, beyond libvmm's examples?
2. **Order.** Run steps N1.1 to N1.6 on seL4 before any Bao work, as decided? Or probe "Hermit as a guest" on both early, since that is the riskiest unknown?
3. **The relay's language.** Rust (`rust-sel4`'s Microkit crate) from the start, or C first and Rust after N1.4?
4. **Time isolation, a seventh criterion?** The six criteria isolate memory, DMA and faults, but not CPU time. Separation kernels for avionics (ARINC 653 partitions, as in INTEGRITY-178) also guarantee each partition its time budget. For Chitala, the threat is an adapter guest that spins and delays the core, and with it a stop. seL4's MCS configuration gives each protection domain a budget and a period, and the Microkit exposes them. Should N1 add: *an adapter guest that spins cannot delay the core beyond a stated bound*? Or should it wait for N2?

## Sources (checked 2026-10-07)

- Microkit 1.3.0: SDK for macOS aarch64, `qemu_virt_aarch64`, virtual machines: <https://docs.sel4.systems/releases/microkit/1.3.0>
- libvmm (Linux guests; virtio-mmio console, net and block; macOS builds for its examples): <https://github.com/au-ts/libvmm>
- seL4 list, booting Hermit under the CAmkES VMM (an unanswered question, 2023): <https://lists.sel4.systems/hyperkitty/list/devel@sel4.systems/message/NJCENN6YTTKPN52VXJLQZHOCDD6VZFER/>
- Hermit loader (aarch64, DTB): <https://github.com/hermitcore/loader>
- Bao: <https://bao-project.readthedocs.io/en/stable/bao_hyp/index.html>; its Linux IPC shared-memory driver (2025–26 patches): <https://lkml.iu.edu/2601.0/07701.html>
