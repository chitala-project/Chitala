# Native N1: the partitioning spike

This directory is the code of [the N1 plan](../../docs/native/n1-partitioning-spike.md): seL4 first, Bao as the comparison and the fallback. Each step ends in a script and a check. The Trusted Core is not touched here.

| Step | Status | Run |
|---|---|---|
| N1.0 Tools, pinned: the Microkit SDK, libvmm, the build host | ✅ | `scripts/fetch.sh`, `scripts/check-env.sh` |
| N1.1 Microkit: two protection domains and a channel, on `qemu_virt_aarch64` | ✅ | `run-n1.1.sh` |
| N1.2 libvmm's Linux guest example, under a VMM on seL4 | ✅ | `run-n1.2.sh` |
| N1.3 The Chitala Native image as a guest on seL4: the go/no-go | ✅ **go** | `run-n1.3.sh` |
| N1.4 Two guests and the relay: the node drives the adapter host in the second guest | ✅ | `run-n1.4.sh` |
| N1.5 The isolation tests: a. no shared UART or RTC for the adapter's guest; b. memory; c. crash and reboot; d. a hostile relay; e. DMA | next | |

## The build host

**Linux is the canonical build host** (Project Lead, 2026-10-07): Ubuntu 24.04, arm64 or x86_64, with the packages of [`env/provision.sh`](env/provision.sh). There are two of them:
- **The local VM, where N1 is developed.** Bring-up needs a loop of seconds, not one CI run per guess.
- **CI, which checks independently that the build reproduces.** [`.github/workflows/native-n1.yml`](../../.github/workflows/native-n1.yml) runs on both architectures, and on every change here.

On a Mac, the VM is [Lima](https://lima-vm.io) (`brew install lima`):

```bash
native/spike/env/vm.sh start              # create, mount this repository, provision (once)
native/spike/env/vm.sh run native/spike/run-n1.1.sh
native/spike/env/vm.sh shell              # work inside it; the repository is at the same path
```

`$LIMA_HOME` (default `~/.lima`) decides where the VM's disk lives.

On Apple silicon, the VM is arm64 on Virtualization.framework. The M1 and M2 have no nested virtualization, so QEMU emulates the board inside the VM. That is enough for N1, but times measured there are relative (criteria 6 and 7).

## The pins

[`tools.lock`](tools.lock) pins everything N1 builds with:
- **the Microkit SDK**, by version and by the sha256 of each host's tarball. With `N1_VERIFY_GPG=1` (as CI runs it) the signature is checked too, against the release key's fingerprint;
- **the SDK built from source (N1.3):**
  - its Microkit and seL4 commits, and the Rust version;
  - its Python packages, by version and sha256 (`env/sdk-*requirements.txt`), installed with `--require-hashes`;
- **libvmm**, by tag and commit;
- **the host's compiler, QEMU and dtc**, by version.

`scripts/fetch.sh` downloads into `$N1_CACHE` (default `~/.cache/chitala-n1`) and refuses anything that does not match. `scripts/check-env.sh` checks the host.

The Microkit SDK is 2.3.1, which restricts the rights of endpoint and notification capabilities. libvmm 0.2.0 declares 2.3.0; N1.2 shows it works with 2.3.1.

The guest images libvmm's examples boot (a Linux kernel and a buildroot initrd) come from the publisher, and are not signed. They are pinned by the sha256 of their first download. `fetch.sh` resumes a broken transfer: the publisher's server is far away, and slow from here.

## N1.1

[`sel4/channel`](sel4/channel) is the smallest system with the shape N1 needs:
- **two protection domains:** `core`, at the higher priority, and `adapter`;
- **one channel** between them;
- **one shared page,** which the adapter maps read-write and the core read-only.

The adapter writes a line and notifies; the core reads it and answers; the adapter hears the answer. `run-n1.1.sh` builds it with clang and `ld.lld` and boots it on QEMU `virt` (aarch64, EL2, Cortex-A53), as the Microkit manual runs `qemu_virt_aarch64`. It passes when all of that shows on the console.

## N1.2

`run-n1.2.sh` builds libvmm's own example, `examples/simple`: a VMM protection domain on seL4 that runs a Linux guest, with its console. It builds with the pinned SDK and libvmm, from the pinned guest images, and boots on QEMU `virt`. It passes when the guest's Linux:
1. reaches its login prompt;
2. takes a login over the VMM's virtual console;
3. runs a command.

```
[    0.000000] Linux version 7.1.0 …
buildroot login: root
# echo N1.2 guest says: $(uname -sm)
N1.2 guest says: Linux aarch64
N1.2: passed
```

This is the VMM and the guest console the Chitala image needs next, in N1.3.

## N1.3: the go/no-go

`run-n1.3.sh` runs **the Chitala Native image as it is** (`native/run.sh --build-only`, spec 20) in a virtual machine, under a VMM protection domain on seL4. It passes when the image says what it says under QEMU alone, and each claim of N1.3 shows on its own, so that no single line can stand for all of them:
- entropy from the CPU's RNG;
- the audit chain verified;
- 13 of 13 decisions;
- the image's verdict;
- a clean exit;
- timer interrupts delivered.

```
VMM|INFO: Hermit loader: segment at 0x40400000 …
[LOADER] Parsing kernel from ELF at 0x48000000 …
hermit    ] Welcome to Hermit 0.13.0
interrupts] Found GIC v3 with 1 cpus
[boot]      platform native-hermit · entropy: CPU RNDR (FEAT_RNG) · clock 2026-10-07 06:26 UTC (floor …)
 …
[audit]     29 records · hash chain ✓ · signed by the node through seq 29
[halt]      13/13 decisions as expected · CHITALA NATIVE OK
ok    entropy from the CPU's RNG (RNDR), through the VM
ok    the audit log's hash chain verifies
ok    13 of 13 Authority and Safety decisions as expected
ok    the image's verdict
ok    the image exits with status 0
ok    timer interrupts delivered to the guest: 57
N1.3: passed
```

**What GO means.** The Chitala Native image runs on seL4, so **seL4 stays the primary candidate**. It is not chosen yet. N1.4 to N1.6 answer the harder questions:
- can an adapter guest reach the core's memory, by itself or by DMA?
- does the core survive an adapter's crash?
- are a lying relay's orders refused?
- does an adapter that burns the CPU delay a stop?
- what does all this cost?

N1 isolates guests from each other, not the parts of one guest. The guest's RAM is mapped `rwx` because the guest is a whole unikernel, and enforcing W^X inside it is not N1's question.

**What it took.** The image itself did not change.
- **A GICv3.** The Hermit kernel drives only a GICv3, and the released SDK's QEMU board has a GICv2. `scripts/build-sdk.sh` builds the Microkit SDK from the sources 2.3.1 was released from, with two patches in `sdk/`:
  - `microkit-0001` adds the board `qemu_virt_aarch64_gicv3` (`QEMU_GIC_VERSION=3`);
  - `microkit-0002` stops Microkit's loader writing the GICv2 CPU interface, which a GICv3 does not have.
- **libvmm's virtual GICv3, completed for QEMU.**
  - `libvmm-0001` adds the redistributor's address.
  - `libvmm-0002` adds the redistributor registers Hermit's GIC driver reads and writes.
- **A Neoverse-N2.** The image refuses to run without a hardware RNG, and the seL4 built for the board runs on it, as on a Cortex-A53.
- **A VMM of its own** (`sel4/hermit-guest`). The Hermit loader is not a Linux image:
  - the VMM loads the loader's ELF segments at their addresses;
  - it puts the device tree at the start of RAM, where the loader reads it;
  - it passes the image as the initrd the device tree names.
- **A board for the guest** (`hermit.dts`): RAM, one CPU, the GICv3, the architected timer, the UART and the RTC, both passed through. There is no PCI and no virtio, so the guest touches nothing else. The guest runs on the virtual timer, which seL4 keeps for each vCPU and libvmm delivers (a carried Hermit patch since N1.4; N1.3 first ran on the physical timer, passed through).

**Carried platform patches.** The four patches are small, and each says why it exists. Until Microkit and libvmm take them upstream, they are carried, which means:
- each is pinned to an upstream revision (`tools.lock`);
- it must apply cleanly, or the build stops;
- a regression test covers it: N1.1 on the GICv3 board, and N1.3, in CI on both architectures.

N1 goes on without waiting for upstream.

## N1.4: two guests and the relay

`run-n1.4.sh` runs two guests on seL4 and a relay between them (`sel4/two-guests/`):
- **the core's guest:** the Chitala Native image, as in N1.3;
- **the adapter host's guest:** `chitala-native-adapter` ([`native/src/bin/`](../src/bin/chitala-native-adapter.rs)), the adapter host alone in a Hermit image of its own, with the same virtual devices;
- **the relay:** a protection domain of 65 lines of C ([`relay.c`](sel4/two-guests/relay.c)).

```text
QEMU virt, aarch64 (virtualization=on, GICv3, Neoverse-N2)
└─ seL4, with the Microkit
   ├─ VMM "core_vmm"    ── guest, 512 MiB: Hermit + the Chitala node
   │                       its virtio console ⇄ two serial queues ──┐
   ├─ PD  "relay"       ── copies bytes from one guest's queue to the other's
   │                       its virtio console ⇄ two serial queues ──┘
   └─ VMM "adapter_vmm" ── guest, 256 MiB: Hermit + the adapter host
```

Each guest's channel is a virtio console that its VMM emulates (libvmm, over virtio-mmio). The VMM moves bytes between the guest and two serial queues it shares with the relay, one each way, and reads none of them. Each guest's RAM is mapped only into that guest and its VMM. The relay maps the four queues of each side and no guest's RAM.

It passes when each claim shows on its own:

```
RELAY|INFO: up: copying bytes between the two guests' channels
[node]      adapter host in another guest, over the channel
[adapter]   channel up: the core's guest is on the other side
 1  person:alice   request  light.turn_on @ device:living-room-light
    identity ✓  request ✓  authority ✓  safety ✓   → ALLOW  executed, device reports brightness_pct=100 on=true
 …
[adapter]   took order #4 off the channel; disappearing before any answer (N1.4, R1)
14  person:alice   request  light.turn_on @ device:living-room-light
    identity ✓  request ✓  authority ✓  safety ✓   → UNKNOWN  X_EXECUTION_UNKNOWN: execution unknown: the adapter host took the order, then: …
[audit]     31 records · hash chain ✓ · signed by the node through seq 31
[halt]      14/14 decisions as expected · CHITALA NATIVE OK
ok    the relay is up
ok    the adapter host runs in the other guest, not in the core's
ok    the adapter's guest has the channel up
ok    orders crossed to the other guest and receipts came back: 3
ok    R1: the adapter's guest took an order and disappeared
ok    R1: the core classifies its fate as unknown, not as not sent
ok    14 of 14 decisions as expected
ok    the image's verdict
ok    the audit log's hash chain verifies
ok    entropy from the CPU's RNG (RNDR), through the VM
ok    the core's image exits with status 0
N1.4: passed
```

**What it shows** (the Project Lead's five points):
1. **The core does not know where its adapter host is.** No crate of the node or the Trusted Core changed. The Native platform gives the node an execution host, `ChannelExec` ([`platform.rs`](../src/platform.rs)), whose adapter host is at the other end of the channel: starting it opens the channel and shakes hands. Under QEMU alone, with no channel, the same image runs its adapter host in-process, as before (13/13).
2. **The adapter protocol's semantics are unchanged.** The adapter host's guest runs `chitala_adapters::host::run`, the same protocol loop, on the channel: the same JSON Lines (spec 19).
3. **Each `ExecOrder` keeps its signature, its session and its single use.** The core's boundary signs it and binds it to the executor's session, and the adapter host in the other guest admits it as it did in-process. Neither the relay nor the VMMs hold a key.
4. **Receipts come back through the same trust model.** They cross the relay, and the node handles them as before: a receipt is the adapter host's report, and the outcome is verified against what the device is then observed to be (spec 22). Three orders execute, and their devices report.
5. **An adapter host that disappears leaves the order's fate unknown (R1).** The adapter's guest takes the 4th order off the channel and goes silent before it answers (`--disappear-on-execute 4`). The core classifies the order as `X_EXECUTION_UNKNOWN`, never as not sent. This is the 14th decision, which only runs when there is a channel.

### The boundaries, and an order's fate

| | Between | Crossed when |
|---|---|---|
| **A** | the core's guest → the relay | the node's write of the order returns: its bytes have left the core's guest through its virtio console |
| **B** | the relay → the adapter host's guest | the relay has put the bytes in the other guest's queue, and its VMM has passed them into the guest |
| **C** | the adapter host → the device | the adapter host has admitted the order and driven the device |

The core sees only A. So:
- **Not sent** (`unavailable`): the order did not cross A. The channel could not be opened, the handshake failed, the write failed, or the order's executor session had ended before it was sent. The device did not act on it.
- **Unknown** (`X_EXECUTION_UNKNOWN`): the order crossed A, and then no answer came within the timeout, or the channel failed, or the answer was outside the protocol. Whether B or C happened cannot be told from the core's side: the device may have acted. The node then watches the order's outcome with its execution unknown, and what the device is observed to be decides: `applied`, `not_applied`, or `unconfirmed`, which puts a resource at medium risk or more in recovery (spec 22).
- **The order is never sent twice.** After an unknown, the executor stops the adapter host and starts a new session. The adapter's guest cannot be restarted from the core's, so the next start fails and later orders are not sent. Restarting the adapter's guest is the system's job (N1.5, crash and reboot), and an order of the old session is not valid in the new one.

### The relay is hostile transport

- It copies bytes. It parses nothing, authorises nothing, holds no key, and does not know what an `ExecOrder` is.
- Nothing trusts it. If it drops, duplicates, reorders, truncates, changes or delays bytes, execution can fail, but it cannot happen twice or without the boundary's signature. A relay that lies can do no more than an adapter host that lies, and the adapter host is already outside the Trusted Core. N1.5 runs a relay that lies.
- It can read what passes. Orders are signed, not encrypted, and the channel's confidentiality is not one of N1's seven criteria.
- **The handshake.** The VMM drops bytes that arrive before a guest's virtio console is up. So before the protocol, the two guests exchange lines of their own ([`channel.rs`](../src/channel.rs)): HELLO until START, then READY. These lines are not trusted either. A forged handshake can only start the protocol before the other side is there: then the adapter host does not start, and no order is sent.

### What it took

- **Two Hermit kernel patches,** carried in [`native/patches/`](../patches/) and applied by `native/run.sh` after the `RNDR` one:
  - `hermit-kernel-aarch64-virtual-timer.patch`: the kernel runs on the virtual timer. Upstream it programs the physical timer, which seL4 does not keep for each vCPU, so two guests on one CPU would program each other's. Without a hypervisor the virtual timer is the physical one, and N1.3 and the QEMU job pass with it.
  - `hermit-kernel-chitala-channel.patch`: the virtio console becomes the file `/dev/chitala-channel` instead of the console. The kernel's log stays on the UART, nothing is echoed, and reads hand over whole packets through a buffer.

  Both are spike-only and are not proposed upstream as they are.
- **The image** gains the kernel's `virtio-console` feature and a second binary, `chitala-native-adapter`. With no virtio console, as under QEMU alone, nothing changes.
- **The VMM** (`sel4/hermit-guest/vmm.c`) gains libvmm's virtio console over two serial queues (`GUEST_CHANNEL`). Only the core's guest takes the UART's interrupt (`GUEST_SERIAL_IRQ`).
- **The system** (`two-guests.system`): two VMMs and the relay, and the eight queue regions. The relay runs at priority 254, the core's VMM at 253, the adapter's VMM at 252, and both guests at 100. Whether the adapter's guest can delay the core's is N1.6's question.

### Not shown yet: N1.5 and N1.6

- **The adapter's guest is not hostile here.** It shares the UART with the core's guest, for its log, and the RTC. A hostile one could print lines that look like the core's, and set the clock the core reads. That is a trust boundary crossed, not only a test contaminated, so N1.5a takes both away from it first.
- **N1.5,** in this order:
  - a. no shared UART or RTC;
  - b. the adapter's guest reads and writes the core's RAM, and must fault;
  - c. it crashes and reboots, and the core lives on;
  - d. a relay that lies: nothing executes twice or unsigned;
  - e. DMA through the SMMUv3. If it cannot be shown, the gate fails; it is not worked around.
- **`isolated()`.** `ChannelExec` reports that its component is isolated because of the topology. N1.5 is what shows it. After N1, such a property comes from the platform's validated configuration or from attestation, never from a hard-coded claim.
- **N1.6:** latency, normal and saturated; a stop with the adapter's guest spinning.
