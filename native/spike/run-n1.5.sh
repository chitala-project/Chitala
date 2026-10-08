#!/usr/bin/env bash
# N1.5: the isolation tests, in the Project Lead's order (docs/native/
# n1-partitioning-spike.md). Each step checks its claims on its own.
#
# N1.5a, the adapter's guest shares no device with the core's:
# - the built system gives each partition what its policy allows, and
#   nothing more: scripts/isolation-evidence.py reads the Microkit's CapDL
#   spec and report (physical ranges, mappings, capabilities, interrupts,
#   devices) before anything boots, writes PlatformIsolationEvidence, and
#   breaks the system in memory to show that each check catches its break;
# - at run time, everything the adapter's guest writes comes out behind
#   "ADAPTER| ", in printable ASCII (any other byte as \xNN), including lines
#   forged to look like the core's verdict (--forge-core-lines). The core's
#   own verdict is there once, and a forged end of boot does not end the run;
# - the adapter's guest tells the time from its read-only RTC: it boots at
#   the board's date, and its order gate admits the core's orders.
#
# N1.5c, crash containment: the adapter crashes before an order (the core
# finds it unavailable and lives on) and after taking one (the order's fate is
# unknown, never not-sent); a stale order or session after a disconnect is
# refused by the session gate. Actual guest reboot/reload is not exercised.
#
# N1.5d, a hostile relay: a hostile build of the byte relay corrupts,
# duplicates, withholds or replays messages. Signed, session-bound, single-use
# orders and order-bound receipts mean it can only make execution fail, never
# happen twice or unsigned; the count of real executions is read from the
# adapter's side (its UART), off the relay's path.
#
# N1.5b, memory isolation: the adapter's guest, given a device tree that
# claims more RAM than seL4 granted it, reaches past the grant; seL4 faults it
# at stage-2, on the adapter's VMM, and the core's state stays intact (its
# audit chain still verifies). The second layer — the adapter's VMM holds no
# capability to the core's RAM — is PlatformIsolationEvidence's, checked from
# the built system in N1.5a.
#
# The images: what native/run.sh --build-only last built (both binaries).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
. "$HERE/tools.lock"
env_out="$("$HERE/scripts/fetch.sh")"
eval "$env_out"
"$HERE/scripts/check-env.sh"
# the GICv3 board needs the SDK built from source; the released SDK's GICv2
# board (H0.1: N1_BOARD=qemu_virt_aarch64) is fetch.sh's
if [ "${N1_BOARD:-qemu_virt_aarch64_gicv3}" = qemu_virt_aarch64_gicv3 ]; then
    env_out="$("$HERE/scripts/build-sdk.sh")"
    eval "$env_out"
fi
# shellcheck source-path=SCRIPTDIR source=scripts/two-guests.sh
. "$HERE/scripts/two-guests.sh"

two_guests_build n1.5a "--disappear-on-execute 4 --forge-core-lines"
echo "N1.5a: what the built system gives each partition (PlatformIsolationEvidence)"
if ! python3 "$HERE/scripts/isolation-evidence.py" --system "$BUILD/out/two-guests.system" \
    --capdl "$BUILD/out/capdl.json" --report "$BUILD/out/report.txt" \
    --policy "$TWO_GUESTS_POLICY" \
    --out "$BUILD/platform-isolation-evidence.json" --self-test; then
    echo "N1.5a FAILED: the platform's isolation evidence"
    exit 1
fi

echo "N1.5a: the adapter's guest forges the core's lines as it disappears"
two_guests_run
expect "the adapter's VMM emulates its devices" '^adapter_vmm\|INFO: no device of the board in the guest'
reject "nothing the adapter's guest writes comes out without its prefix" '^(\[adapter\]|Chitala Native spike: the adapter)'
expect "the adapter's lines come out behind its prefix" 'ADAPTER\| \[adapter\] +channel up'
expect "the adapter's guest forged the core's verdict" 'ADAPTER\| \[halt\] +14/14 decisions as expected \\xc2\\xb7 CHITALA NATIVE OK'
expect "a byte that is not printable ASCII comes out as \\xNN" 'ADAPTER\| \[audit\] .*hash chain \\xe2\\x9c\\x93'
if LC_ALL=C grep -aq 'ADAPTER| .*[^ -~]' "$clean"; then
    echo "FAIL  the adapter's lines carry printable ASCII only"
    fail=1
else
    echo "ok    the adapter's lines carry printable ASCII only"
fi
expect "the adapter's guest forged the end of the boot" 'ADAPTER\| .*Shutting down system'
count "the core's verdict, its own and only once" "$CORE_VERDICT" 1
count "the core's exit, its own and only once" "$CORE_EXIT" 1
expect "the adapter's guest boots at the board's date, from its read-only RTC" 'ADAPTER\| .*Hermit booted on 20[2-9][0-9]-'
count "its order gate admits the core's orders, so its clock agrees" "$CORE_RECEIPT" 3
expect "R1 still holds" "$CORE_UNKNOWN"
expect "the audit log's hash chain verifies" "$CORE_AUDIT"
two_guests_finish N1.5a

# N1.5b, memory isolation (the Project Lead's order). Its first layer, that
# the guest cannot reach past the RAM seL4 granted it, is shown at run time
# here. Its second layer, that the adapter's VMM holds no capability to the
# core's RAM, is shown from the built system by PlatformIsolationEvidence
# (above, N1.5a): the evidence lists every physical range and capability, and
# its self-test breaks the system to prove each check catches its break. The
# read-only RTC (a write has no effect) is N1.5a's; a hostile relay is N1.5d.
#
# The attack: the adapter's guest is given a device tree claiming more RAM
# than seL4 mapped into its VM (ADAPTER_DTB_RAM), so its first access beyond
# the grant has no stage-2 translation. seL4 must fault it — on the adapter's
# VMM, which handles its VM's faults — and the core, on its own frames, must
# be untouched. The adapter's guest then cannot serve, so the core's device
# orders fail: that is liveness, not isolation, and the core's demo verdict is
# not clean here. What N1.5b checks is the core's integrity under the attack.
echo "N1.5b: a hostile adapter guest reaches past the RAM seL4 granted it"
echo "N1.5b: step 1 (the adapter uses its own RAM: it serves) is N1.5a, above"
export ADAPTER_DTB_RAM=0x14000000 # the grant is 0x10000000; claim 0x04000000 more
two_guests_build n1.5b-oob ""
unset ADAPTER_DTB_RAM
two_guests_run
expect "the adapter's guest believes it has more RAM than the grant" \
    'ADAPTER\| .*Total memory size: (29[0-9]|[3-9][0-9][0-9]|[0-9]{4}) MiB'
expect "seL4 faults the write past the grant, on the adapter's VMM (stage-2)" \
    '^adapter_vmm\|ERROR.*unexpected memory fault on address: 0x5[0-9a-f]+, FSR: 0x92'
reject "no such fault reaches the core's VMM" '^core_vmm\|ERROR.*(memory fault|Failed to handle)'
expect "the core still ran its decisions" '^\[identity\]  domain:home'
expect "the core's audit log's hash chain still verifies (its state is intact)" "$CORE_AUDIT"
two_guests_finish N1.5b

# N1.5b, step 6: a hostile build of the adapter's VMM — not its guest, the VMM
# itself — reaches for the core's RAM, at the physical address the Microkit
# report gives it. The VMM holds no capability to those frames, so that
# address is mapped nowhere in its own VSpace, and seL4's monitor faults the
# adapter's VMM, naming it; the core is untouched. (PlatformIsolationEvidence,
# N1.5a, shows the same from the built system: the VMM is given no such cap.)
core_paddr=$(grep -m1 frame_mr_core_ram "$BUILD/out/report.txt" | grep -oE '0x[0-9a-f]+' | tail -1)
core_paddr_sig=0x$(printf '%x' "$core_paddr") # the report's zero-padded hex, as the monitor prints it
echo "N1.5b: a hostile adapter VMM reaches for the core's RAM at $core_paddr (step 6)"
export ADAPTER_VMM_EXTRA_CFLAGS="-DN15B_HOSTILE_VMM -DN15B_CORE_PADDR=$core_paddr"
two_guests_build n1.5b-vmm ""
unset ADAPTER_VMM_EXTRA_CFLAGS
two_guests_run
expect "the hostile VMM reaches for the core's RAM, holding no capability to it" \
    "^adapter_vmm\\|INFO: N1.5b: this VMM reaches for the core's RAM"
reject "it never reads a byte of the core's RAM" 'N1.5b: UNREACHED'
expect "seL4's monitor faults the adapter's VMM" '^MON\|ERROR: faulting PD: adapter_vmm'
expect "the fault is at the core's RAM, a stage-2 translation fault" \
    "^MON\\|ERROR: VMFault:.*fault_addr=0x0*${core_paddr_sig#0x} "
expect "the fault is stage-2, level 2 (seL4's stage-2 translation)" \
    '^MON\|ERROR: +dfsc = translation fault, level 2'
reject "no fault reaches the core's VMM" '^core_vmm\|ERROR'
expect "the core's audit log's hash chain still verifies (its state is intact)" "$CORE_AUDIT"
two_guests_finish N1.5b-vmm

# N1.5c, crash containment (the Project Lead's c-light). The adapter crashes;
# the core must live on. A true guest reboot/reload is NOT built here: that
# would be a VM lifecycle manager, and the property to show is fault
# containment, not recovery. Three facts:
#  C1 crash before any order     → the core finds the adapter unavailable, lives on
#  C2 crash after taking an order → that order's fate is unknown, never not-sent (R1)
#  C3 a stale order or session after a disconnect → refused by the session gate,
#     shown by the boundary's unit tests (execution_boundary.rs
#     a_stale_order_reaching_a_restarted_host_is_refused; node.rs
#     replay_after_restart_is_refused), not by a boot here.
echo "N1.5c: the adapter crashes and the core lives on (crash containment)"
echo "N1.5c: actual guest reboot/reload is NOT exercised; fault containment and stale-session semantics are shown separately"

two_guests_build n1.5c-c1 "--crash-after 0"
two_guests_run
expect "C1: the adapter crashes before serving any order" 'ADAPTER\| \[adapter\] +crashing before serving any order'
expect "C1: the core ran its decisions" '^\[identity\]  domain:home'
expect "C1: the core's audit chain still verifies (it lived on)" "$CORE_AUDIT"

two_guests_build n1.5c-c2 "--crash-after 1"
two_guests_run
expect "C2: the adapter crashes after taking an order" 'ADAPTER\| \[adapter\] +crashing after taking order'
expect "C2: that order's fate is unknown, never not-sent (R1)" "$CORE_UNKNOWN"
expect "C2: the core's audit chain still verifies (it lived on)" "$CORE_AUDIT"

echo "ok    C3: a stale order or session after a disconnect is refused by the session gate (boundary unit tests; see the note above)"
two_guests_finish N1.5c

# N1.5d, a hostile relay. The relay copies bytes between the two guests; a
# hostile build corrupts, duplicates, withholds or replays them. Orders are
# signed, session-bound and single-use, and receipts are bound to their order
# (spec 19), so a lying relay can only make execution fail — never happen twice
# or unsigned. How many times the device actually executed is read from the
# adapter's own side, on its emulated UART ("ADAPTER| … device executed
# order=… count=…"), a path that does not cross the relay; the core's audit
# chain shows its state is intact. Each class is a separate boot.
# (D3, reordering whole messages, is not a boot: the order protocol is lockstep
# — one order and its reply at a time — so there is never a second message in
# flight to reorder, and each order is validated on its own regardless of
# arrival order. It reduces to D2/D4.)
echo "N1.5d: a hostile relay cannot make execution happen twice or unsigned"
executed_ids() { grep -aoE 'device executed order=[0-9a-f]+' "$clean" | sed 's/.*=//' || true; }
no_double() { # what
    if [ -n "$(executed_ids | sort | uniq -d)" ]; then
        echo "FAIL  $1: an order executed more than once"
        fail=1
    else
        echo "ok    $1: no order executed more than once ($(executed_ids | sort -u | grep -c . || true) executed, each once)"
    fi
}
hostile_relay() { # mode
    export RELAY_EXTRA_CFLAGS="-DRELAY_HOSTILE -DRELAY_MODE=$1"
    two_guests_build "n1.5d-m$1" ""
    unset RELAY_EXTRA_CFLAGS
    two_guests_run
}

hostile_relay 1 # D1: flip a bit in every order → signature/parse fails
reject "D1 corruption: nothing executes" 'device executed order='
expect "D1 corruption: the core's audit still verifies" "$CORE_AUDIT"

hostile_relay 2 # D2: send every order twice → the gate's single use admits each once
expect "D2 duplicate: the device executed an order" 'device executed order='
no_double "D2 duplicate"
expect "D2 duplicate: the core's audit still verifies" "$CORE_AUDIT"

hostile_relay 4 # D4: withhold every order → it never reaches the adapter
reject "D4 withholding: nothing executes" 'device executed order='
expect "D4 withholding: the core calls it unknown, never not-sent (R1)" "$CORE_UNKNOWN"
expect "D4 withholding: the core's audit still verifies" "$CORE_AUDIT"

hostile_relay 5 # D5: replay each receipt to the core → the core rejects the stale one
expect "D5 receipt replay: the device executed an order" 'device executed order='
no_double "D5 receipt replay"
expect "D5 receipt replay: the core rejects a receipt not bound to the order" 'X_RECEIPT_INVALID'
expect "D5 receipt replay: the core's audit still verifies" "$CORE_AUDIT"

two_guests_finish N1.5d
