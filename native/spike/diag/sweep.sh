#!/usr/bin/env bash
# N1.6 diagnosis: the core's latency on seL4 across MCS budgets and periods, with
# the instrumented libvmm (diag/instrument.py), the SDK as the repository
# builds it (WFI/WFE not trapped, sdk/microkit-0003) and QEMU_BIN's QEMU.
# Each row runs twice: plain, and with the QEMU monitor poking the vCPU at
# 20 Hz (diag/pc-sample.py), the control for emulator wake-up artifacts.
#   row: name | adapter args | adapter VM priority | core VM budget µs | core VM period µs
# Each run has a build directory of its own; none is deleted.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${TAG:-$(date +%H%M%S)}"
ROWS="${ROWS:-idle-eq||100||
spin-eq|--spin|100||
spin-below|--spin|99||
spin-below-c50-p2|--spin|99|1000|2000
spin-below-c80-p2|--spin|99|1600|2000
spin-below-c50-p10|--spin|99|5000|10000
spin-below-c80-p10|--spin|99|8000|10000
idle-below-c50-p2||99|1000|2000}"
runs=()
while IFS='|' read -r name args prio budget period; do
    [ -z "$name" ] && continue
    for mode in plain poke; do
        run="sw-$TAG-$name-$mode"
        if [ "$mode" = poke ]; then
            CORE_VM_BUDGET="$budget" CORE_VM_PERIOD="$period" PC_SAMPLE=1 PC_INTERVAL=0.05 \
                "$HERE/diag/run.sh" "$run" "$args" "$prio" 300 >/dev/null 2>&1
        else
            CORE_VM_BUDGET="$budget" CORE_VM_PERIOD="$period" \
                "$HERE/diag/run.sh" "$run" "$args" "$prio" 300 >/dev/null 2>&1
        fi
        runs+=("$run")
        echo "done: $run" >&2
    done
done <<<"$ROWS"
python3 - "${runs[@]}" <<'EOF'
import os, re, sys
lat = re.compile(r"^\[latency\] +(decision through|decision submitted|stop through).* · n=\d+ · median (\d+) µs · p99 (\d+) µs · max (\d+) µs")
print(f"{'configuration':<22} {'mode':<6} {'ipc med/p99/max ms':<20} {'direct med/max':<15} {'stop med/max':<15} {'adapter':>8} note")
for run in sys.argv[1:]:
    path = os.path.expanduser(f"~/.cache/chitala-n1/build/diag-{run}/boot.txt")
    text = open(path, errors="replace").read() if os.path.exists(path) else ""
    got = {}
    for line in text.splitlines():
        m = lat.match(line)
        if m:
            got[m.group(1)] = [int(x) / 1000 for x in m.group(2, 3, 4)]
    spun = re.findall(r"ADAPTER\| \[adapter\]   spun (\d+)", text)
    note = "handshake timed out" if "adapter host unavailable" in text else ""
    if "CHITALA NATIVE OK" not in text:
        note += (" · " if note else "") + "no verdict OK"
    ipc, di, st = got.get("decision through"), got.get("decision submitted"), got.get("stop through")
    f = lambda v, k: "/".join(f"{v[i]:.1f}" for i in k) if v else "-"
    _, _, name, mode = run.split("-", 2)[0], None, run.split("-", 2)[2].rsplit("-", 1)[0], run.rsplit("-", 1)[1]
    print(f"{name:<22} {mode:<6} {f(ipc,(0,1,2)):<20} {f(di,(0,2)):<15} {f(st,(0,2)):<15} {spun[-1] if spun else '-':>8} {note}")
EOF
