#!/usr/bin/env bash
# N1.6 (WIP): the core's latency on seL4 across MCS budgets and periods, with
# the instrumented libvmm (diag/instrument.py) and the SDK as the repository
# builds it (WFI/WFE not trapped, sdk/microkit-0003). One boot per row:
#   name | adapter args | adapter VM priority | core VM budget µs | core VM period µs
set -uo pipefail
HERE=/Users/quantran/ChitalaOS/native/spike
ROWS="${ROWS:-idle-eq|--disappear-on-execute 4|100||
spin-eq|--disappear-on-execute 4 --spin|100||
spin-below|--disappear-on-execute 4 --spin|99||
spin-below-c50-p2|--disappear-on-execute 4 --spin|99|1000|2000
spin-below-c80-p2|--disappear-on-execute 4 --spin|99|1600|2000
spin-below-c50-p10|--disappear-on-execute 4 --spin|99|5000|10000
spin-below-c80-p10|--disappear-on-execute 4 --spin|99|8000|10000
idle-below-c50-p2|--disappear-on-execute 4|99|1000|2000}"
while IFS='|' read -r name args prio budget period; do
    [ -z "$name" ] && continue
    echo "=== $name (adapter VM priority $prio${budget:+, core VM budget $budget µs per $period µs})"
    CORE_VM_BUDGET="$budget" CORE_VM_PERIOD="$period" "$HERE/diag/run.sh" "$name" "$args" "$prio" 300 2>&1 |
        grep -E "^\[latency\] |^\[halt\]|adapter host unavailable|diag (wfx|vppi|maint|nolr|disabled|vtimer)|Timer\]|Resched" |
        grep -v "samples µs"
    B="$HOME/.cache/chitala-n1/build/diag-$name/boot.txt"
    spun=$(grep -ac "spun [0-9]* × 2^24" "$B" || true)
    last=$(grep -a "spun [0-9]* × 2^24" "$B" | tail -1 | sed 's/.*spun //')
    echo "adapter progress: $spun lines${last:+, last: $last}"
    grep -a "diag vppi gap" "$B" | sort -t' ' -k5 -n | tail -3
done <<<"$ROWS"
