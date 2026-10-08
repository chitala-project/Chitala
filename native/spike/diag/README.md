# N1.6 diagnosis tools

The tools that found the cause of N1.6's long tail (the [N1.6 report](../README.md#n16-the-measurements)). They are for diagnosis only: nothing in CI runs them, and nothing they patch is committed. Each boot gets a build directory of its own under `~/.cache/chitala-n1/build/diag-*`, and none is deleted: give each run a new name.

They run in the Linux VM (`native/spike/env/vm.sh run …`), where the repository is mounted at the same path.

## Boots

| Tool | What it boots |
|---|---|
| `run.sh NAME [ADAPTER_ARGS] [ADAPTER_VM_PRIORITY] [SECONDS]` | The two-guests system, with `--latency 2` for the core and the instrumented libvmm. `CORE_VM_BUDGET`/`CORE_VM_PERIOD` (µs) give the core's VM an MCS budget; `EXTRA_CORE_ARGS` adds the core's arguments. |
| `core-alone.sh NAME [ROUNDS]` | The core's guest alone on seL4 (the N1.3 system), with `--latency ROUNDS`. |
| `sweep.sh` | `run.sh` over rows of adapter, priority and budget, each twice: plain, and with the QEMU monitor reading the CPU's registers at 20 Hz (the control for an emulator's wake-up artifact). Prints one table. |

All three take `QEMU_BIN` (the directory of another `qemu-system-aarch64`), `IMG` (a directory with both Hermit images; default the last `native/run.sh --build-only`) and `PC_SAMPLE=1` (sample the PC, below).

## Instruments

- **`instrument.py`** patches the boot's copy of libvmm. It counts WFx traps, VPPIs, maintenance interrupts and SGIs, and the vGIC's dropped or deduplicated interrupts (a line at each power of two). For the virtual timer it logs gaps of more than 100 ms between two VPPIs, and the timer's path in the counter the guest reads (CNTVOFF is 0): when a VPPI reaches the VMM (T2) against the deadline the guest set, when the VMM has injected it (T3), and when the guest's EOI acknowledges it (T4). It writes a `diag seg` line when any of those segments is longer than 20 ms.
- **`hermit-n16-trace.patch`** is a Hermit kernel patch: a ring of 16384 events with the virtual counter. It records the timer being set (SET), an interrupt taken (IRQ, with the comparator's value), a task blocking (BLK, with its wakeup time), woken (WAKE), made ready by its time (RDY) and scheduled (RUN).
- **`mark-diag.py`** patches `native/src/main.rs` in the working tree so that each decision through the node's IPC marks the ring before it starts. When a decision takes more than 100 ms, the kernel prints the events since that mark (`N16MARK`), with a run of timer interrupts on the same comparator counted as one line. Undo it with `git checkout -- native/src/main.rs`.
- **`refresh-diag.py TICK_MS`** patches `crates/chitala-node/src/ipc.rs` in the working tree: the refresh thread's period, and the time of each phase of its pass. Undo it with `git checkout -- crates/chitala-node/src/ipc.rs`.
- **`pc-sample.py`** reads the emulated CPU's PC and exception level through the QEMU monitor. `pc-symbols.py`, `pc-window.py` and `pc-profile.py` name the samples (seL4, a VMM, or a guest's image, which the Hermit loader puts at `0x40600000`).

## B2's evidence, again

```sh
# the traced image: the Hermit trace patch, the marks and a 200 ms refresh period
cp native/spike/diag/hermit-n16-trace.patch native/patches/hermit-kernel-zz-diag.patch
mv native/patches/hermit-kernel-aarch64-wakeup-deadline.patch /tmp/   # to see the bug, take the fix out
python3 native/spike/diag/refresh-diag.py 200
python3 native/spike/diag/mark-diag.py
native/run.sh --build-only
mkdir -p native/target/diag-images/trace && cp native/target/aarch64-unknown-hermit/release/chitala-native* native/target/diag-images/trace/
# undo, and build the normal image again
rm native/patches/hermit-kernel-zz-diag.patch
mv /tmp/hermit-kernel-aarch64-wakeup-deadline.patch native/patches/
git checkout -- crates/chitala-node/src/ipc.rs native/src/main.rs
native/run.sh --build-only

# boot it on seL4, the core alone (in the VM)
IMG=$PWD/native/target/diag-images/trace native/spike/diag/core-alone.sh trace-1 2
grep -a "N16MARK\|diag seg" ~/.cache/chitala-n1/build/diag-core-alone-trace-1/boot.txt
```

`native/run.sh` applies every `native/patches/*.patch` in order, so the trace patch, named `zz`, comes last. It is made against the kernel without the fix, so the fix comes out first.

## A minimal reproducer that did not reproduce

`qemu-wfi/` is a bare-metal program for QEMU's `virt` board: EL2 arms its timer, then an EL1 guest waits in WFI or spins, and the program prints how late each interrupt came. It looked for an emulator that wakes a halted CPU late. On QEMU 8.2.2 the worst lateness was 11–13 ms, and on 11.1.2 it printed nothing. It did not reproduce a QEMU timer fault, and no QEMU bug is claimed. `build-qemu.sh` builds QEMU 11.1.2 for the comparison.
