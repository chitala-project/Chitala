#!/usr/bin/env bash
# N1.6: the measurements (docs/native/n1-partitioning-spike.md, criteria 6
# and 7). Measure first, set no deadline (Project Lead, 2026-10-07): this
# reports numbers and checks only that each run is sound.
#
# The core's latency: after its scenario, the core runs N1_LATENCY_ROUNDS (2)
# rounds of measurements (native/src/main.rs, --latency). Each round waits
# 10.1 s for the Reference Monitor's rate limit, then times
# - 25 decisions through the node's IPC (Identity, Authority, Safety; refused
#   by a safety hold), as an adapter or a client meets the core;
# - in even rounds, 25 decisions submitted directly on the core's thread (no
#   IPC, no thread switch): the decision's own cost on the platform;
# - in odd rounds, 12 stops through the node's IPC (a safety hold placed).
# Each answer is checked and counts in the core's verdict. Measured:
# - hosted: the same program on this machine, with no VM (if cargo is here);
# - on seL4, the adapter's guest idle: the baseline;
# - on seL4, the adapter's guest spinning, at the core's priority;
# - on seL4, the adapter's guest spinning one priority below the core's, with
#   the core's VM given 80% of each 10 ms (an MCS budget): with WFI not
#   trapped, an idle core's guest keeps the CPU, so a guest below it runs only
#   when the core's budget runs out.
# On QEMU the times are relative: the runs compare on the same host.
#
# The TCB: the code of what the core's isolation rests on (scripts/tcb-size.py).
#
# Results: $N1_BUILD/n1.6-results.json. The images: what native/run.sh
# --build-only last built (both binaries).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
. "$HERE/tools.lock"
env_out="$("$HERE/scripts/fetch.sh")"
eval "$env_out"
"$HERE/scripts/check-env.sh"
env_out="$("$HERE/scripts/build-sdk.sh")"
eval "$env_out"
# shellcheck source-path=SCRIPTDIR source=scripts/two-guests.sh
. "$HERE/scripts/two-guests.sh"

rounds="${N1_LATENCY_ROUNDS:-2}"
results="${N1_BUILD:-$HOME/.cache/chitala-n1/build}/n1.6-results.json"
# what: ipc, direct or stop; the label the core prints for it
KINDS=(
    "ipc|decision through the node's IPC"
    "direct|decision submitted directly on this thread"
    "stop|stop through the node's IPC"
)
rows=()

record() { # label, file with the latency lines
    local kind what line row="$1"
    for k in "${KINDS[@]}"; do
        kind="${k%%|*}"
        what="${k#*|}"
        line=$(grep -E "^\[latency\] +$what [^·]*· n=[0-9]+ · median [0-9]+ µs" "$2" | head -1 || true)
        if [ -z "$line" ]; then
            echo "FAIL  $1: no latency line for $kind"
            fail=1
            return
        fi
        row+="|$kind $(echo "$line" | sed -E 's/.* · n=([0-9]+) · median ([0-9]+) µs · p99 ([0-9]+) µs · max ([0-9]+) µs$/\1 \2 \3 \4/')"
    done
    rows+=("$row")
    echo "ok    $1: measured"
}

echo "N1.6: hosted, the same program with no VM"
if command -v cargo >/dev/null; then
    hosted="$(mktemp)"
    if (cd "$REPO/native" && cargo run --release --locked -q -- --latency "$rounds") >"$hosted" 2>&1 &&
        grep -q "CHITALA NATIVE OK" "$hosted"; then
        record "hosted" "$hosted"
    else
        echo "--    hosted: not measured here (the native toolchain did not run)"
    fi
else
    echo "--    hosted: not measured here (no cargo)"
fi

measure() { # name, label, adapter's VM priority, core's VM budget µs, its period µs, adapter args
    echo "N1.6: on seL4, $2"
    ADAPTER_VM_PRIORITY="$3" CORE_VM_BUDGET="$4" CORE_VM_PERIOD="$5" \
        two_guests_build "n1.6-$1" "$6" "--latency $rounds"
    two_guests_run
    expect "the core completes its scenario: 14/14 and its verdict" "$CORE_VERDICT"
    expect "the audit log's hash chain verifies" "$CORE_AUDIT"
    expect "the core exits with status 0" "$CORE_EXIT"
    case "$6" in *--spin*) expect "the adapter's guest spins" 'ADAPTER\| \[adapter\] +spinning' ;; esac
    record "$2" "$clean"
}
measure idle "the adapter's guest idle" 100 "" "" "--disappear-on-execute 4"
measure spin "the adapter's guest spinning, at the core's priority" 100 "" "" "--disappear-on-execute 4 --spin"
measure spin-below-c80 "the adapter's guest spinning below, the core at 80% of 10 ms" 99 8000 10000 \
    "--disappear-on-execute 4 --spin"

echo "N1.6: the TCB"
tcb="$(mktemp)"
python3 "$HERE/scripts/tcb-size.py" \
    --sdk-elf "$MICROKIT_SDK/board/qemu_virt_aarch64_gicv3/debug/elf" --build "$BUILD/out" \
    --images "${CARGO_TARGET_DIR:-$REPO/native/target}/aarch64-unknown-hermit/release" \
    --sources "$HERE/sel4" --out "$tcb" || fail=1

echo "N1.6: the core's latency (ms: median / p99 / max; $rounds rounds)"
python3 - "$results" "$tcb" "$rounds" ${rows[@]+"${rows[@]}"} <<'EOF'
import json, sys
out, tcb, rounds, rows = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4:]
with open(tcb, encoding="utf-8") as f:
    tcb = json.load(f)
runs = []
print(f"{'':<62} {'IPC':>20} {'direct':>20} {'stop':>20}")
for row in rows:
    label, *kinds = row.split("|")
    run = {"run": label}
    for k in kinds:
        kind, n, median, p99, mx = k.split()
        run[kind] = {"n": int(n), "median_us": int(median), "p99_us": int(p99), "max_us": int(mx)}
    runs.append(run)
    cell = lambda k: "/".join(f"{run[k][x] / 1000:.1f}" for x in ("median_us", "p99_us", "max_us")) if k in run else "-"
    print(f"{label:<62} {cell('ipc'):>20} {cell('direct'):>20} {cell('stop'):>20}")
with open(out, "w", encoding="utf-8") as f:
    json.dump({"rounds": rounds, "latency": runs, "tcb": tcb,
               "note": "QEMU times are relative: compare runs on the same host"}, f, indent=1)
    f.write("\n")
EOF
echo "results: $results"
two_guests_finish N1.6
