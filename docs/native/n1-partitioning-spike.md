# Native N1 — the partitioning spike: plan

**Status:** approved by the Project Lead on 2026-10-07, with a seventh criterion (time isolation) added. It carries out decision 3 of [ADR 0001](../adr/0001-native-architecture.md): seL4 first, Bao as the comparison and the fallback. The Lead's order after v0.4 puts N1 second, after the history anchoring.

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
| 2 | DMA from an adapter cannot reach the core's memory — **FAIL on the N1 QEMU platform** (N1.5e): seL4's `qemu-arm-virt` has no SMMU driver, so DMA confinement cannot be programmed or shown; carried to H0 | a DMA-capable device assigned to the adapter guest, behind an SMMU, told to write into the core's memory: the transaction is stopped |
| 3 | An adapter guest crashes or reboots and the core lives on | panic, kill and reboot the adapter guest mid-order: the core keeps serving, the order fails closed (no receipt, it expires), and the device's state becomes unknown (`SAFE-3-STATE`) |
| 4 | Orders and receipts across the channel resist replay and tampering | a relay that replays, reorders, truncates or flips bytes: every such order or receipt is rejected (spec 19 binds them to a session, signs them and makes them single-use), and the relay's framing is fuzzed |
| 5 | The execution flow runs end to end | a person's request and an AI's intent drive the virtual lock through the adapter guest; the outcome is verified (spec 22) |
| 6 | Latency and TCB size are measured | *boundary → channel → adapter → receipt*, median and tail, against the hosted path; the trusted base counted (kernel, VMM, relay) |
| 7 | An adapter cannot delay the core (time isolation) | the adapter guest spins at 100% CPU, under interrupt and workload pressure: the core is still scheduled, and the time to judge and send a stop is measured against the unloaded baseline |

**Time isolation.** Memory isolation can be perfect and the system still unsafe, if an adapter that runs `while (true) {}` keeps the core from sending a stop in time.
- **On seL4:** each protection domain gets an MCS scheduling context, a budget and a period, set in the Microkit system description.
- **No deadline is set in N1.** N1 measures first and records a baseline; each profile states its required deadline later. A smart lock and a vehicle cannot share one.
- **On QEMU, times are relative.** QEMU emulates the CPU here, so the baseline and the loaded run are compared on the same host. Absolute figures wait for real hardware (the Native Hardware Gate H0, after N1.8). This holds for criterion 6 as well.

**Where each property comes from.** Chitala uses public architectures and an independent implementation; it copies no proprietary design.

| Property | Source |
|---|---|
| Space and time partitioning | ARINC 653 and the separation-kernel architecture |
| Strong isolation | seL4, with its proofs for its verified configurations |
| DMA isolation | an IOMMU (SMMU), configured by the hypervisor or microkernel |
| Health monitoring (later than N1) | ARINC 653-style partition health management: a policy to restart the adapter guest |

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

**Static system topology, bounded dynamic application state.** The trusted infrastructure is laid out statically:
- the core;
- the adapters;
- later the evaluator, a key service and storage.

Each part has its memory and its channels fixed in the system description. Inside the core, Chitala's semantic objects stay dynamic but bounded: intents, leases, plans, delegations and history rules. N1 does not make Chitala allocation-free.

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
2. **Hermit's virtio drivers against libvmm's devices.** Hermit's virtio-console, or virtio-vsock, must work over virtio-mmio as libvmm emulates it. *N1.4: virtio-console works, with a carried patch that makes it a channel rather than the console.*
3. **The SMMU.** seL4's verified configurations exclude the SMMU. Whether seL4 and the Microkit program QEMU's SMMUv3 for a device passed to a guest is to be shown. If they do not, criterion 2 fails for seL4 in N1, and it is recorded (ADR 0001, *Risks*).
4. **Time and entropy inside the guest.** The virtual timer, and `RNDR` on a CPU model that has it. Today's spike refuses to run without a hardware RNG (spec 20).
5. **The build host.** Linux is the canonical build host (decision 1): an Ubuntu 24.04 VM on the developer's machine, where N1 is developed, and CI on both architectures, which checks that the build reproduces ([`native/spike/`](../../native/spike/README.md)). The Microkit SDK also has a macOS aarch64 release, for convenience only.

## Steps

Each step ends in a script and a check.

| Step | What | Shows |
|---|---|---|
| N1.0 | ✅ Tools, pinned: the Microkit SDK (2.3.1, by sha256 and signature), libvmm (0.2.0, by commit), the host's compiler, QEMU and dtc; scripts to fetch and verify them; the local VM and CI on both architectures | a reproducible setup |
| N1.1 | ✅ Microkit: two protection domains, a channel and a shared page (read-only for the core), on `qemu_virt_aarch64` | the toolchain works |
| N1.2 | ✅ libvmm's Linux guest example boots, and takes a login over the VMM's console | the VMM works on this setup (and libvmm 0.2.0 with Microkit 2.3.1) |
| N1.3 | ✅ **The Chitala Native image runs as a guest on seL4: GO, and seL4 stays the primary candidate**, not yet chosen (13/13 decisions, the audit chain, hardware entropy and timer interrupts each checked). It took a GICv3 board for the SDK built from source, a Neoverse-N2 for the RNG, a VMM that loads the Hermit loader's ELF, and four small patches to Microkit and libvmm ([`native/spike/`](../../native/spike/README.md#n13-the-gono-go)) | unknowns 1 and 4; the go/no-go of the seL4 path |
| N1.4 | ✅ **Two guests and the relay**: the node drives the adapter host in the second guest, through a relay of 65 lines of C that copies bytes and parses nothing. The node's crates did not change; three orders execute and their receipts come back; an adapter guest that takes an order and disappears leaves its fate unknown, never "not sent" (R1); 14/14 decisions. Hermit's virtio console works over libvmm's, with two carried kernel patches (the virtual timer, the console as a channel). The boundaries and an order's fate: [`native/spike/`](../../native/spike/README.md#n14-two-guests-and-the-relay) | criterion 5, and unknown 2 |
| N1.5 | The isolation tests, in this order (Project Lead, 2026-10-07): **a** ✅ the adapter's guest loses the UART and the RTC it shares with the core's guest (its VMM emulates a UART that writes behind its prefix and a read-only RTC; the system description is checked; a forged core verdict does not count, [`native/spike/`](../../native/spike/README.md#n15a-no-device-shared-with-the-adapters-guest)); **b** ✅ the adapter's guest, given a device tree claiming more RAM than seL4 granted it, reaches past the grant and faults at seL4's stage-2, on its own VMM, while the core's state stays intact (its audit chain verifies); the VMM-capability layer (no cap to the core's RAM) is PlatformIsolationEvidence's ([`native/spike/`](../../native/spike/README.md#n15b-memory-isolation-shown)); **c** ✅ the adapter's guest crashes before an order (the core finds it unavailable and lives on) and after taking one (that order's fate is unknown, never not-sent, R1); a stale order or session is refused by the session gate (boundary unit tests). Actual guest reboot/reload is not exercised ([`native/spike/`](../../native/spike/README.md#n15c-the-adapter-crashes-and-the-core-lives-on)); **d** ✅ a hostile relay that corrupts, duplicates, withholds or replays cannot make execution happen twice or unsigned, shown with the device's own execution count (off the relay's path) and the core's audit ([`native/spike/`](../../native/spike/README.md#n15d-a-hostile-relay-cannot-make-execution-happen-twice-or-unsigned)); **e** DMA through an SMMU is **not demonstrated** on this platform (seL4's qemu-arm-virt has no SMMU driver): **criterion 2 FAILS for this N1 platform**, carried to H0, not worked around | criteria 1, 3, 4 and 2, and unknown 3 |
| N1.6 | ✅ **The measurements** (QEMU, so relative; [`native/spike/`](../../native/spike/README.md#n16-the-measurements)):<br>• An order, boundary → channel → adapter → receipt, against hosted: 0.70 ms hosted, 41–50 ms median on two guests.<br>• A stop with the adapter's guest spinning, and spinning under timer-interrupt pressure, against the unloaded baseline: medians ×0.94–0.95. The core is always scheduled, and every stop completes.<br>• The isolation TCB: about 486 KiB of code.<br>• The long tail found on the way was a timer bug in the Hermit kernel, fixed upstream and carried as a patch. | criteria 6 and 7 |
| N1.7 | ⚠️ **A bounded Bao comparison** (Project Lead, mode C). Bao v2.0.0 builds reproducibly with LLVM and its isolation TCB is ~86 KiB (one thin, unverified layer) against seL4's ~486 KiB (~241 KiB the kernel, which N1 did not run in a verified configuration, and ~245 KiB of isolation machinery outside the kernel proof); the static, scheduler-less temporal model and the trade-off are recorded for ADR 0002. Bao's execution on qemu-aarch64-virt and Hermit-on-Bao are **not demonstrated** within the spike — Bao's supported boot path adds U-Boot firmware, outside this scope (not a failure of Bao). DMA is not demonstrated for either and goes to H0 ([`native/spike/bao/`](../../native/spike/bao/README.md)) | the comparison, or the fallback |
| N1.8 | ✅ **[ADR 0002](../adr/0002-production-native-architecture.md), accepted (Project Lead, 2026-10-08)**: seL4 + Microkit is the primary Native candidate, Bao the fallback and comparison; DMA is a mandatory H0 gate for any platform. The choice is conditional, not a production or high-assurance certification: N1 selects an architecture to carry forward, not a production assurance level, and H0 decides whether it is admissible on a concrete hardware platform. The carried patches are tracked in [the register](carried-patches.md) | the decision, on evidence |

## Where it lives

- **The spike's code:** `native/spike/`, outside the main workspace, like `native/` and `fuzz/`.
  - `sel4/`: the Microkit system description, the relay, the build and boot scripts;
  - `bao/`: the same for Bao;
  - `tests/`: the attacks.
- **The protection domains:** Rust, with the seL4 project's `rust-sel4` crates, where they fit; C where the VMM requires it.
- **CI:** the Native N1 workflow boots each step's seL4 system on QEMU, N1.4's two guests included, on both architectures.

## Exit

Each of the seven criteria is recorded as passed or failed, with its evidence. After N1.8 comes the **Native Hardware Gate H0**: the same architecture on real silicon, for what QEMU can hide (the GIC, virtualization, the timer, entropy, the SMMU where the board has one, boot reliability, basic latency, isolation in practice). See [the direction](../architecture/direction.md).
- **seL4 fails a gate that matters:** Bao's run decides.
- **Both fail:** ADR 0001 is revisited, as it says.

## Decisions (Project Lead, 2026-10-07)

| Question | Decision |
|---|---|
| A Linux build host? | **Yes.** Linux (x86_64 or arm64) is the canonical N1 build host; macOS is a developer convenience only. |
| The order of the work? | **N1.0 to N1.8 as planned**, failing fast at N1.3. |
| The relay's language? | **Rust, `no_std`, where practical.** A minimal C relay is acceptable if the Microkit Rust crates bring too much friction. |
| Time isolation? | **Yes: criterion 7.** |

**The relay stays as small as it can be.** It copies bytes. It does not parse, authorize, or interpret an `ExecOrder`. If 200 lines of C are easier to audit than a Rust runtime pulled into the Microkit, the relay is C. The security property lives in the signed protocol, not in a clever relay.

## Sources (checked 2026-10-07)

- Microkit 2.3.1 (the pinned SDK; earlier drafts of this plan cited 1.3.0): <https://docs.sel4.systems/releases/microkit/2.3.1>; its manual, for `qemu_virt_aarch64`, channels, and a protection domain's budget and period: <https://github.com/seL4/microkit/blob/2.3.1/docs/manual.md>
- libvmm 0.2.0 (declares Microkit 2.3.0): <https://github.com/au-ts/libvmm/releases/tag/0.2.0>
- libvmm (Linux guests; virtio-mmio console, net and block; macOS builds for its examples): <https://github.com/au-ts/libvmm>
- seL4 list, booting Hermit under the CAmkES VMM (an unanswered question, 2023): <https://lists.sel4.systems/hyperkitty/list/devel@sel4.systems/message/NJCENN6YTTKPN52VXJLQZHOCDD6VZFER/>
- Hermit loader (aarch64, DTB): <https://github.com/hermitcore/loader>
- Bao: <https://bao-project.readthedocs.io/en/stable/bao_hyp/index.html>; its Linux IPC shared-memory driver (2025–26 patches): <https://lkml.iu.edu/2601.0/07701.html>
