# Native N1: the partitioning spike

This directory is the code of [the N1 plan](../../docs/native/n1-partitioning-spike.md): seL4 first, Bao as the comparison and the fallback. Each step ends in a script and a check. The Trusted Core is not touched here.

| Step | Status | Run |
|---|---|---|
| N1.0 Tools, pinned: the Microkit SDK, libvmm, the build host | ✅ | `scripts/fetch.sh`, `scripts/check-env.sh` |
| N1.1 Microkit: two protection domains and a channel, on `qemu_virt_aarch64` | ✅ | `run-n1.1.sh` |
| N1.2 libvmm's Linux guest example, under a VMM on seL4 | ✅ | `run-n1.2.sh` |
| N1.3 The Chitala Native image as a guest on seL4: the go/no-go | ✅ **go** | `run-n1.3.sh` |
| N1.4 Two guests and the relay: the node drives the adapter host in the second guest | ✅ | `run-n1.4.sh` |
| N1.5 The isolation tests: a. no shared UART or RTC for the adapter's guest; b. memory; c. crash and reboot; d. a hostile relay; e. DMA | a ✅, b next | `run-n1.5.sh` |

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
ADAPTER| [adapter]   channel up: the core's guest is on the other side
 1  person:alice   request  light.turn_on @ device:living-room-light
    identity ✓  request ✓  authority ✓  safety ✓   → ALLOW  executed, device reports brightness_pct=100 on=true
 …
ADAPTER| [adapter]   took order #4 off the channel; disappearing before any answer (N1.4, R1)
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
ok    14 of 14 decisions as expected, and the image's verdict
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

- **The adapter's guest is not hostile here.** As N1.4 first ran, it shared the UART with the core's guest, for its log, and the RTC. A hostile one could have printed lines that look like the core's, and set the clock the core reads. That is a trust boundary crossed, not only a test contaminated, so N1.5a took both away from it first.
- **N1.5,** in this order:
  - a. ✅ no shared UART or RTC (below);
  - b. the adapter's guest reads and writes the core's RAM, and must fault;
  - c. it crashes and reboots, and the core lives on;
  - d. a relay that lies: nothing executes twice or unsigned;
  - e. DMA through the SMMUv3. If it cannot be shown, the gate fails; it is not worked around.
- **`isolated()`.** `ChannelExec` reports that its component is isolated because of the topology. N1.5 is what shows it. After N1, such a property comes from the platform's validated configuration or from attestation, never from a hard-coded claim.
- **N1.6:** latency, normal and saturated; a stop with the adapter's guest spinning.

## N1.5a: no device shared with the adapter's guest

The Project Lead's first step of N1.5. In N1.4 both guests mapped the board's UART and RTC. The adapter's guest could print lines that look like the core's, the very lines the checks read, and it could set the clock the core reads. Now **only the core's guest maps devices of the board**:
- **The adapter's guest maps its own RAM and nothing else.** Its VMM (`vmm.c`, built with `GUEST_DEVICES_EMULATED`) shows it a UART and an RTC where its device tree says they are, and handles every access.
- **Its UART is for output only.** The VMM writes each line to the system's debug console behind `ADAPTER| `. The prefix comes from the VMM, so the guest cannot leave it out. Only printable ASCII passes; every other byte, from a control character or an escape sequence to a C1 control such as `0x9b` or UTF-8, is written as `\xNN`. No byte of the guest's is a control byte on a terminal, so the guest cannot move the cursor back over its prefix either, nor mislead someone reading the log. A log's safety comes before its looks (the Project Lead's review).
- **Its RTC is read-only.** The VMM reads the board's RTC through a read-only mapping of its own, so the guest learns the time, which its order gate needs, and cannot set it. A write is refused and logged.

**The checks.** `run-n1.5.sh` builds the system and checks what the build gives each partition before anything boots ([PlatformIsolationEvidence](#platformisolationevidence), below). Then it boots the system with an adapter that forges the core's lines as it disappears (`--forge-core-lines`):

```
N1.5a: what the built system gives each partition (PlatformIsolationEvidence)
ok    R1 every kernel object has a physical address, and the spec agrees with the report
 …    (ten claims, and eight breaks caught: below)
N1.5a: the adapter's guest forges the core's lines as it disappears
ok    the adapter's VMM emulates its devices
ok    nothing the adapter's guest writes comes out without its prefix
ok    the adapter's lines come out behind its prefix
ok    the adapter's guest forged the core's verdict
ok    a byte that is not printable ASCII comes out as \xNN
ok    the adapter's lines carry printable ASCII only
ok    the adapter's guest forged the end of the boot
ok    the core's verdict, its own and only once: 1
ok    the core's exit, its own and only once: 1
ok    the adapter's guest boots at the board's date, from its read-only RTC
ok    its order gate admits the core's orders, so its clock agrees: 3
ok    R1 still holds
ok    the audit log's hash chain verifies
N1.5a: passed
```

In the log, the forgery is plain:

```
ADAPTER| [adapter]   took order #4 off the channel; disappearing before any answer (N1.4, R1)
ADAPTER| [audit]     31 records \xc2\xb7 hash chain \xe2\x9c\x93 \xc2\xb7 signed by the node through seq 31
ADAPTER| [halt]      14/14 decisions as expected \xc2\xb7 CHITALA NATIVE OK
ADAPTER| exit status 0
ADAPTER| [   13.175748][0][INFO  processor ] Shutting down system
 …
[halt]      14/14 decisions as expected · CHITALA NATIVE OK
exit status 0
```

- **The checks match the core's lines from the start of a line** (`scripts/two-guests.sh`), and the run ends only on the core's own "Shutting down system". The two guests share one UART, so a line of the adapter's can land in the middle of one of the core's. That can only make a check fail, never pass.
- **Not yet exercised: a write to the RTC.** The adapter host is safe Rust on Hermit and cannot reach a device's registers. N1.5b writes it, and checks the outcome, not the VMM's word: the RTC's value before and after, and the core's clock unaffected. A log line is not an outcome.

### Open: an intermittent fault in the core's guest early in its boot

N1.4 failed three times in CI on 2026-10-07. They are two different problems.

**A fault in the core's guest, twice on the arm64 runner** (runs 37590736217, on main after #72, and 37591400619, on #73).
- **What happened.** Early in the core's boot, before its first `[boot]` line, its VMM could not handle a fault of the core's guest. The VMM dumped the guest's registers, and seL4 then reported `Reply object already has unexecuted reply!` for the VMM. That warning is a consequence, not the cause.
- **The same fault both times.** The two dumps match (`spsr 0x600003c4`, `x17 0x5bee1000`, `x18 0x5bee4000`).
- **The cause is still unknown.** Both logs kept only their tail, so the fault's own line, with its address and syndrome, is missing.
- **Not reproduced.** A rerun passed. 141 boots in the local VM did not reproduce it, on both topologies, one at a time and four at once under load. Nor did 30 boots on the arm64 runner (the stress run).

**A check that failed on a line cut in two, once on the x86_64 runner** (run 37605171845, on main after #75).
- The core completed its scenario: 14/14, its verdict, the audit chain and exit 0.
- But a line of the adapter's landed in the middle of the core's entropy line, and the check, anchored at the start of the line, found it cut.
- **Fixed:** `scripts/core-lines.py` moves such a line apart and joins the core's line again, before any check reads the log. Everything from `ADAPTER| ` to the end of its line is the adapter's, and nothing else is, so a joined line holds only the core's bytes, in their order. On that run's log, the entropy line is whole again.

**Every boot ends** with the core's kernel reporting `Unsupported exception class: 0x0` after its exit status, passing runs included. That is how the kernel stops under the VMM, after the image has said what it checked, and it is not the fault above.

The fault in the core's guest stays open until it is explained, because a fault in the core's guest is what N1.5 is about. It is never hidden by an automatic retry, which would hide the very kind of fault N1 looks for.
- **On every failed step,** the scripts print every VMM error with its first lines, and CI keeps the boot logs.
- **A stress run,** `run-n1-stress.sh`, boots the two-guests system many times in a row and keeps the log of every boot that fails. The workflow *Native N1 stress* runs it on the arm64 runner weekly and on demand (30 boots by default), and never blocks a pull request.
- **What matters is the first fault:** its address and syndrome, the guest's PC and registers, and which handler of the VMM failed.

## After N1.5a: the Project Lead's review (2026-10-07)

N1.5a is complete. The review adds the following to the rest of N1.5.

**The system checker becomes evidence, before N1.8 and H0.** Done: [PlatformIsolationEvidence](#platformisolationevidence), below. The first checker, `check-system.py`, compared memory regions by name, so two regions of different names over the same physical range would have passed it. It is replaced.

**N1.5b proves two layers of isolation, in this order:**
1. A hostile adapter guest uses its own RAM: that works.
2. It reads outside its assigned memory: a fault.
3. It writes outside its assigned memory: a fault.
4. It targets the physical range where the core's RAM really is, taken from the Microkit build's report: a fault. Both guests see their own RAM at the same guest-physical address, so reading that address would only reach the guest's own RAM, and is not the test.
5. It writes the RTC: no effect, shown by the RTC's value and the core's clock, not by a log line.
6. A hostile build of the adapter's VMM tries to reach the core's RAM: seL4 faults that protection domain. This shows containment by seL4 itself, beyond the guest's address translation.
7. Through all of this, the core completes its scenario, and its audit log verifies. The attacker failing is not enough; the Trusted Core must have lived on.

**N1.5c, crash and reboot,** at three moments:
- before an order;
- after the adapter received one;
- a reboot that brings back an old order or session, which must be refused.

**N1.5d, a hostile relay:**
- drops, duplicates, reorders, flips bits and truncates;
- replays an old valid order or an old receipt;
- delays past an order's lifetime.

Then **N1.5e**, DMA through the SMMUv3.

### N1.5b: memory isolation, shown

N1.5b holds, in two layers. The first is shown at run time; the second from the built system.

**The guest cannot reach past the RAM seL4 granted it (steps 1–3, 7).** `run-n1.5.sh` builds the adapter's guest a device tree that claims more RAM than seL4 mapped into its VM (`ADAPTER_DTB_RAM`, the grant plus 64 MiB), and boots it. The adapter's own Hermit, believing it has 312 MiB where seL4 gave 256, uses a frame above the grant, and the write has no stage‑2 translation:

```
ADAPTER| … Total memory size: 312 MiB
adapter_vmm|ERROR … unexpected memory fault on address: 0x51496000, FSR: 0x92000046, is_write: true
```

- The faulting address, `0x51496000`, is past the grant's top (`0x40000000 + 0x10000000`). seL4 reports a stage‑2 translation fault (FSR `0x92…`, DFSC `0x06`, level 2).
- The fault is delivered to the **adapter's** VMM, which handles its VM's faults. **No such fault reaches the core's VMM.**
- The core, on its own frames, runs its decisions, and its audit log's hash chain still verifies: its state is intact. (The now-dead adapter means the core's device orders fail — liveness, not isolation — so the demo's verdict is not clean in this run; N1.5b checks the core's integrity, not the adapter's liveness.)

This models a guest that claims, or uses, more memory than it was granted. A deliberate probe from inside the guest would take a mapping past the grant, which only the guest's kernel can make; to add that reach to the core's kernel too (one image builds both) would widen the very surface N1 measures, so it is not done. The guest's own kernel exceeding the grant is contained all the same, which is the claim.

**The adapter's VMM holds no capability to the core's RAM (steps 4, 6).** From the built system, [PlatformIsolationEvidence](#platformisolationevidence) reads every object's physical range and every capability from the Microkit CapDL spec, and its self-test breaks the system to prove each check catches its break — including the core's RAM mapped, or aliased, into the adapter's guest, and a capability to the core's objects held by the adapter's VMM. On seL4 a protection domain cannot forge a capability, so a VMM confined to caps that exclude `core_ram` cannot reach it.

`run-n1.5.sh` also shows this at run time. A hostile build of the adapter's VMM (`N15B_HOSTILE_VMM`) reads the physical address the Microkit report gives the core's RAM:

```
adapter_vmm| … N1.5b: this VMM reaches for the core's RAM at 0x71200000; it holds no capability to it
MON|ERROR: faulting PD: adapter_vmm
MON|ERROR: VMFault: ip=… fault_addr=0x0000000071200000 fsr=0x…93130006 (data fault)
MON|ERROR:   dfsc = translation fault, level 2 (0x00000006)
```

The address is mapped nowhere in the VMM's own VSpace, so seL4 faults the VMM on the read — a stage‑2 translation fault at exactly the core's RAM — and Microkit's monitor names the faulting domain as the adapter's VMM. The `UNREACHED` line that would follow a successful read never prints, and the core's audit chain still verifies.

**The read-only RTC (step 5)** is N1.5a's: the adapter's VMM maps the RTC read-only, so a write has no effect on the time the core reads. **A hostile relay** is N1.5d.

## PlatformIsolationEvidence

The Project Lead's request after N1.5a, made before N1.8 and H0: isolation as evidence taken from what was built, not a claim about how the system description looks.

```text
two-guests.system ──► the Microkit tool ──► CapDL spec (--capdl-json) + report (-r)
                                                         │
isolation-policy.json ──────────────────────► scripts/isolation-evidence.py
                                                         │
                                       platform-isolation-evidence.json
                                       ten claims · five properties · PASS or FAIL
```

**What it reads:**
- **The CapDL spec** the Microkit tool writes (`--capdl-json`). It holds every mapping with its rights (read, write, execute), every capability with its rights, and every interrupt with the notification that receives it.
- **The build report**, with the physical address of every kernel object, RAM frames included.
- **The system description**, for which protection domains and virtual machines make up each partition.
- **A policy, [`isolation-policy.json`](sel4/two-guests/isolation-policy.json).** It declares the partitions (core, adapter, relay), the trusted Microkit monitor, each partition's private RAM, the shared regions with each side's rights (the eight channel queues), the devices with who may reach them and whether they can do DMA, and each partition's interrupts.

**What it checks.** Everything is checked on physical ranges, not names. Any physical range reachable by two partitions that the policy does not declare fails, whatever it is called.

| Claim | |
|---|---|
| R1 | every kernel object has a physical address, and the spec agrees with the report |
| M1 | no two kernel objects overlap physically |
| M2 | each partition's private RAM is reachable by that partition only |
| S1 | memory reachable by more than one partition is only what the policy declares, with no more rights |
| S2 | no memory shared between partitions is executable |
| D1 | each device is reachable only by the partitions the policy names, with no more rights |
| D2 | no DMA-capable device is given to a partition (none is: the SMMU is N1.5e) |
| C1 | no partition holds a capability to another's objects, beyond signalling a notification and reporting faults to the monitor |
| I1 | each interrupt has one owner, which also receives it |
| I2 | interrupts are owned as the policy declares |

**What it writes.** The evidence groups the Lead asked for: memory ranges per partition, private memory, overlaps, shared regions, devices, capabilities (holder → object → rights), interrupts, DMA, the claims and a verdict. It also states five properties, so that an assurance requirement can consume them later rather than repeat the logic:

```
      core_ram: physical [0x71200000, 0x91200000), reachable by core
      adapter_ram: physical [0x61200000, 0x71200000), reachable by adapter
      properties: memory_isolation verified, device_isolation verified, dma_isolation verified, capability_isolation verified, irq_isolation verified
```

**The checks are checked.** `--self-test` breaks the built system in memory, one way at a time, and each break must fail its claims:

```
ok    caught: the core's RAM mapped into the adapter's guest → fails M2, S1
ok    caught: an alias of the core's RAM, under another name, in the adapter's guest → fails M1, M2, S1
ok    caught: a capability to the core's vCPU thread for the adapter's VMM → fails C1
ok    caught: the core's interrupt handed to the adapter's VMM → fails I1, I2
ok    caught: the RTC writable for the adapter's VMM → fails D1, S1
ok    caught: a channel queue executable in the relay → fails S2
ok    caught: a right to receive on the core's notification for the adapter's VMM → fails C1
ok    caught: a frame of the core VMM's code mapped into the relay → fails S1
self-test: 8 of 8 breaks caught
```

On N1.4's system description, where both guests mapped the UART and the RTC, it fails S1 and D1, and `memory_isolation` and `device_isolation` are `violated`.

**Limits.**
- **The physical addresses are those the Microkit tool assigns and reports.** The CapDL initialiser allocates by the same spec at boot.
- **What the running system does is tested at run time,** from N1.5b on.
- **The evidence is about this build of the spike.** It is not yet produced for, or consumed by, a deployment.

CI keeps the JSON of every run (`n1-isolation-evidence-<arch>`).

## N1.6: the measurements

Criteria 6 and 7 of the [spike](../../docs/native/n1-partitioning-spike.md). Measure first, and set no deadline (the Project Lead, 2026-10-07).

**N1.6 passes, on the Project Lead's terms (2026-10-08).**
- Both criteria are measured against their baselines.
- Under the adapter's load and its interrupt pressure, the core is always scheduled, and every stop completes.
- On QEMU the numbers are relative. N1 sets no thresholds; the profiles set deadlines later.

**What is measured.** `run-n1.6.sh` boots the core with `--latency 4`. After its scenario, the core runs:
- **4 rounds of orders** (criterion 6), a minute apart. Safety lets a resource be actuated 6 times a minute (SAFE-6-RATE), and the rule is not relaxed for a benchmark. So each round sends 12 orders, 6 to the light and 6 to the thermostat, 48 in all. Each order is timed twice:
  - from its submission to the node's answer, executed, with its receipt verified;
  - from its line going out to the adapter host to the receipt's line coming back, on the core's side of the channel (`TimedExec` in `native/src/platform.rs`).
- **4 rounds of decisions,** 10.1 s apart for the Reference Monitor's rate limit. Each has 25 decisions through the node's IPC, refused by a safety hold. Even rounds add 25 decisions submitted directly on the core's thread; odd rounds add 12 stops through the node's IPC (a safety hold placed, criterion 7).

Each answer is checked, and counts in the core's verdict. `--latency` leaves R1, an adapter that disappears with an order, to N1.4.

**The runs.** Hosted ran on the Mac mini itself; the others on QEMU 8.2.2 (the pinned emulator, TCG), in the Linux VM on the same Mac mini.
- **Hosted:** the same program, with no VM.
- **Two guests at the same priority,** the adapter's guest idle.
- **The scheduling chosen for N1:** the adapter's VM one priority below the core's, and the core's VM at 80% of each 10 ms (an MCS budget). Under it the adapter's guest is:
  - idle: the baseline;
  - spinning (`--spin`);
  - spinning, while it also wakes on a timer 1000 times a second (`--timer-pressure 1000`). Each wakeup is a timer interrupt through seL4 and the adapter's VMM, which runs at priority 252, above both guests.

### Criterion 6: an order, boundary → channel → adapter → receipt

| Run | To a verified receipt, ms: median / p99 / max | On the channel, ms: median / p99 / max |
|---|---|---|
| Hosted | 0.70 / 1.02 / 1.11 | 0.11 / 0.14 / 0.16 |
| Two guests at the same priority, the adapter idle | 40.9 / 74.2 / 82.3 | 12.5 / 20.4 / 22.4 |
| The chosen scheduling, the adapter spinning | 49.5 / 70.2 / 72.3 | 21.4 / 31.3 / 34.0 |
| *For comparison:* the chosen scheduling, the adapter idle | 47.8 / 83.2 / 99.8 | 20.9 / 32.3 / 53.0 |

- **The criterion's span lies between the two clocks.** It runs from just before the boundary mints the order to a valid receipt back in the core.
  - The first clock also holds the request's way in, its decision, and the receipt's check and audit.
  - The second leaves out the minting and the check.
- **The scheduling sets the adapter's pace, not its spinning.** Under the chosen scheduling, the adapter's guest runs only in the 20% of each 10 ms that the core's budget leaves.
  - An order spends about 21 ms on the channel there, with the adapter idle or spinning, against 12.5 ms at the same priority.
  - That cost falls on the adapter's own orders. The core's stops do not slow down (below).

### Criterion 7: a stop, under load and interrupt pressure

All three runs use the chosen scheduling; n = 24 stops each.

| The adapter's guest | Stop, ms: median / p99 / max | Against the baseline: median / p99 / max |
|---|---|---|
| Idle (the baseline) | 8.50 / 10.41 / 15.75 | ×1.00 / ×1.00 / ×1.00 |
| Spinning | 8.04 / 18.82 / 42.62 | ×0.95 / ×1.81 / ×2.71 |
| Spinning, and 1000 timer wakeups a second asked (209 got) | 7.96 / 8.68 / 9.04 | ×0.94 / ×0.83 / ×0.57 |

- **The core is always scheduled.** In every run it completed its scenario and every measurement, each answer as expected (13/13).
- **Every stop completed:** 24 of 24 in each run, each checked.
- **No starvation.** The slowest stop took 42.6 ms, with the adapter spinning. The median does not move: 8.0–8.5 ms in each run.
- **The core's other decisions behave the same.** Through its IPC, the median is 7.6–8.0 ms in each run. The maxima are 13.0 ms idle, 8.7 spinning, and 29.5 under interrupt pressure.
- **The tail moves from run to run.** With 24 stops a run, one slow stop sets the maximum: here 42.6 ms with the adapter spinning, and 9.0 ms with it spinning under interrupt pressure.
- **An adapter's interrupts stay within its own share of the CPU.** The adapter's guest asked for 1000 timer wakeups a second and got 209. Its virtual timer fires only while its vCPU runs, inside the 20% of each 10 ms the core's budget leaves.
- **A guest that never yields starves its own adapter host on Hermit.** Hermit's scheduler is tickless, and it wakes the channel's reader when it runs. In a first run, a spinner that never yielded kept the adapter host from answering. The core then marked its devices unavailable and failed closed. The spinner now yields about every half millisecond, and the guest still never idles.

### The decision's latency, across schedulings

From the sweep that found the tail's cause (`diag/sweep.sh`, after the fix): QEMU 11.1.2, two rounds (n = 50, 25 and 12). The hosted row ran on the Mac mini.

| Run | IPC, ms: median / p99 / max | Direct: median / max | Stop: median / max |
|---|---|---|---|
| Hosted, no VM | 0.24 / 0.42 / 0.43 | 0.13 / 0.21 | 0.27 / 0.36 |
| seL4, the core alone (N1.3's system) | 6.0 / 6.8 / 8.3 | 2.0 / 2.4 | 6.3 / 7.3 |
| seL4, two guests, the adapter idle | 13.1 / 15.2 / 15.7 | 5.0 / 7.2 | 14.2 / 16.8 |
| seL4, two guests, the adapter spinning, at the core's priority | 14.2 / 18.9 / 23.1 | 5.0 / 7.2 | 14.6 / 19.1 |
| seL4, two guests, the adapter spinning one priority below; the core's VM at 80% of each 10 ms | 8.4 / 9.0 / 9.1 | 2.2 / 5.0 | 8.6 / 9.3 |

- **A spinning adapter at the core's priority costs the core about what an idle one does.** The IPC median goes from 13.1 to 14.2 ms, and the stop's maximum from 16.8 to 19.1 ms.
- **Why two guests take twice as long as the core alone.** At the same priority, seL4 gives each guest the CPU in turn, idle or not. A guest waiting in WFI keeps the CPU, because WFI is not trapped (below). So the core has the CPU about half of the time: 6 ms of its work takes about 13. With an 80% budget, it takes about 8.
- **The adapter one priority below, with no budget, never runs.** The core's idle guest waits in its own WFI and keeps the CPU. The adapter's guest never answers the handshake, and after 20 s the core carries on without it (#78). A guest below another runs only when that one's MCS budget runs out. That is why N1's chosen scheduling gives the core 80%.
- **The emulator's wake-ups are not in these numbers.** With the QEMU monitor reading the CPU's registers 20 times a second, each row comes out within 5 ms of the table. On QEMU 8.2.2, the core alone: an IPC median of 5.7–5.8 ms and a maximum of 8.0 ms or less, in 3 runs.

**The TCB** (`scripts/tcb-size.py`; code bytes, an estimate of size, not of assurance): the core's isolation rests on about 486 KiB of code. That is seL4 (241 KiB, the debug build the spike runs), the CapDL initialiser (125), the Microkit loader (17) and monitor (10), and the core's VMM (94). The core's image is 7.4 MiB, and what is outside the core's TCB (the relay, the adapter's VMM and image) is 1.2 MiB.

### The long tail: a timer bug in the Hermit kernel (B2)

Before the fix, the core's latency had a long tail of 0.4–0.85 s, on the IPC path and on the direct path, with one guest or two. It was causally tied to timed sleeping in the core's guest under seL4 and libvmm: changing the node's refresh period shifted the latency to match, and disabling the refresh removed the stall, although the refresh pass itself takes under 1.4 ms. **The cause is in the Hermit kernel, and upstream has fixed it.**

- **The bug.** The kernel counts time from its own boot. A sleeping task's wakeup time W is in microseconds since then: `get_timer_ticks()` is the counter minus `BOOT_COUNTER`, the counter's value at boot. On aarch64, `__set_oneshot_timer` wrote W to the timer's comparator without adding `BOOT_COUNTER` back.
- **What it did.** The timer fired `BOOT_COUNTER` early. The interrupt found no task due, because W had not passed in the kernel's own time, and set the same comparator, now in the past, again. The timer fired again at once: an interrupt storm, until W passed.
- **Why seL4 showed it and QEMU alone did not.** On QEMU alone, the kernel boots a few milliseconds after the counter starts, so the storms are short. Under seL4, the core's guest boots 0.4–0.85 s after it, varying from boot to boot. Each 1 s sleep of the refresh thread then ended in a storm of that length, and a decision that met one waited for its end. The stall matched each boot's offset: a stall of 835 ms with a gap of 169 ms between two timer interrupts, and one of 396 ms with a gap of 609.

**The trace** (`diag/`, the Hermit kernel and the core's VMM, in the one counter both read). The core is alone on seL4, and the refresh period is 200 ms.

| Step | What happened |
|---|---|
| T0: a task sleeps | The refresh thread blocks for 200 ms, until W. |
| T1: the comparator is set | It is set to W, read as the whole counter: about 0.7 s in the past. |
| T2: the timer's interrupt reaches the VMM | At once, and again every 0.43 ms (median). |
| T3: the VMM injects it | 34 µs after T2 (median). |
| T4: the guest acknowledges it | 87 µs after T3 (median). |
| T5: the guest's handler | Finds nothing due, and sets the same comparator again. |
| T6: a ready task runs | The IPC's server thread is the current task, but runs no instruction. There are 1030–1097 timer interrupts in 200 ms, and all 32 of the guest's PC samples during the IPC rounds are in its interrupt path. |

When W passes, the storm stops, and the server thread finishes in 1.5 ms. A decision through the IPC has two such hops, so every one took 2 × 200 ms (406 ms). The first of each round took one hop, 204 ms. No task waited more than 20 ms between being made ready and being scheduled. The delay was the storm, not the scheduler.

The bug accounts for each earlier observation:
- **In a diagnostic build with no refresh thread,** there is no timed sleep, so no storm and no stall.
- **With a refresh period of 200 ms,** shorter than the boot offset, every sleep is a storm from start to end, and every decision through the IPC takes 2 × 200 ms.
- **A diagnostic thread that only slept 10 ms at a time** did not help, because each of its sleeps was a storm too.
- **An 80% MCS budget, or the monitor's 20 Hz reads, made the stalls disappear in the sweep.** How they let the guest out of a storm is not explained. With the storm gone, it no longer matters.

**The fix:** `native/patches/hermit-kernel-aarch64-wakeup-deadline.patch` sets the deadline to `BOOT_COUNTER + W × frequency`. It backports upstream's 8c28d804 and 14a98206 (hermit-os/kernel#2585, merged on 2026-08-11). No release contains them yet; v0.13.2 is the latest.

A/B, on seL4 with the core alone, on QEMU 11.1.2:

| | Without the fix | With it |
|---|---|---|
| Refresh every 200 ms: IPC median | 406 ms | 6.0 ms |
| Refresh every 200 ms: timer interrupts in a run | 262,144 or more | under 128 |
| Refresh every 200 ms: the refresh thread wakes late by, at most | 656 ms | 17 ms |
| Refresh every 1 s, as shipped: maximum, IPC / direct | up to 0.84 s | 8.3 / 2.4 ms |

**MCS at 80% is not the fix for the tail** (the Project Lead). It stays a candidate for another purpose: giving any CPU at all to a guest below the core's priority, the last row of the results.

### B1: behavior that depended on the QEMU version

QEMU-version-dependent behavior was observed during diagnosis, but the minimal EL2 wakeup reproducer did not reproduce a QEMU timer fault. No QEMU bug is claimed.
- **Before the fix,** the core alone stalled in 3 of 7 runs on QEMU 8.2.2, and in 0 of 8 on 11.1.2.
- **With the fix,** it stalled in 0 of 3 runs on 8.2.2.
- **A likely reading, not proven:** the storms' length and timing depend on when the guest boots, and that differs with the emulator.

### Found on the way

- **An idle guest stormed WFI traps.** seL4 traps a guest's WFI and WFE, and libvmm handles the trap by resuming the guest at once. So an idle guest trapped through its VMM over and over: 2.1 million times or more for the adapter's. `sdk/microkit-0003` builds seL4 with `KernelArmDisableWFIWFETraps`. The cost: a guest waiting in WFI keeps the CPU (above).
- **The handshake with the adapter's guest is bounded.** `ChannelExec` waits 20 s, then the adapter host is unavailable, and the node starts degraded (#78).
- **The tools** are in [`diag/`](diag/README.md).

### Open

- **QEMU's times are relative.** The real numbers, and the deadlines a profile sets against them, come with H0.
- **A second oddity in the Hermit kernel, not carried.** When a task blocks with a later wakeup than the first one waiting, the kernel sets the timer to the later one, and the first task wakes only at the next interrupt. Upstream has since reworked this code. With the fix, the refresh thread woke at most 17 ms late.
- **The intermittent fault in the core's guest early in its boot** ([above](#open-an-intermittent-fault-in-the-cores-guest-early-in-its-boot)) is still unexplained. The bug made storms during the core's boot too. Whether that is connected is not known, and a stress run with the fix would say more.
