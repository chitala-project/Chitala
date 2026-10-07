#!/usr/bin/env bash
# N1.6: the measurements (docs/native/n1-partitioning-spike.md, criteria 6
# and 7). Measure first, set no deadline (Project Lead, 2026-10-07): this
# reports numbers and checks only that each run is sound.
#
# The core's decision latency: after its scenario, the core times
# N1_LATENCY_SAMPLES (200) decisions through Identity, Authority and Safety,
# all in the core, each checked (native/src/main.rs, --latency). Measured:
# - hosted: the same program on this machine, with no VM (if cargo is here);
# - on seL4, the adapter's guest idle: the baseline;
# - on seL4, the adapter's guest spinning (--spin), at the core's priority;
# - on seL4, the adapter's guest spinning, one priority below the core's.
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

samples="${N1_LATENCY_SAMPLES:-200}"
results="${N1_BUILD:-$HOME/.cache/chitala-n1/build}/n1.6-results.json"
LATENCY='^\[latency\] +decision through Identity, Authority and Safety \(refused by the hold\) · n=([0-9]+) · median ([0-9]+) µs · p99 ([0-9]+) µs · max ([0-9]+) µs$'
rows=()

record() { # label, file with the latency line
    local line
    line=$(grep -E "$LATENCY" "$2" | head -1 || true)
    if [ -z "$line" ]; then
        echo "FAIL  $1: no latency line"
        fail=1
        return
    fi
    rows+=("$1|$(echo "$line" | sed -E "s/$LATENCY/\\2 \\3 \\4/")")
    echo "ok    $1: $(echo "$line" | sed -E "s/$LATENCY/median \\2 µs · p99 \\3 µs · max \\4 µs/")"
}

echo "N1.6: hosted, the same program with no VM"
if command -v cargo >/dev/null; then
    hosted="$(mktemp)"
    if (cd "$REPO/native" && cargo run --release --locked -q -- --latency "$samples") >"$hosted" 2>&1 &&
        grep -q "CHITALA NATIVE OK" "$hosted"; then
        record "hosted" "$hosted"
    else
        echo "--    hosted: not measured here (the native toolchain did not run)"
    fi
else
    echo "--    hosted: not measured here (no cargo)"
fi

measure() { # name, label, adapter's VM priority, adapter args
    echo "N1.6: on seL4, $2"
    ADAPTER_VM_PRIORITY="$3" two_guests_build "n1.6-$1" "$4" "--latency $samples"
    two_guests_run
    expect "the core completes its scenario: 14/14 and its verdict" "$CORE_VERDICT"
    expect "the audit log's hash chain verifies" "$CORE_AUDIT"
    expect "the core exits with status 0" "$CORE_EXIT"
    case "$4" in *--spin*) expect "the adapter's guest spins" 'ADAPTER\| \[adapter\] +spinning' ;; esac
    record "$2" "$clean"
}
measure idle "the adapter's guest idle" 100 "--disappear-on-execute 4"
measure spin "the adapter's guest spinning, at the core's priority" 100 "--disappear-on-execute 4 --spin"
measure spin-below "the adapter's guest spinning, one priority below the core's" 99 "--disappear-on-execute 4 --spin"

echo "N1.6: the TCB"
tcb="$(mktemp)"
python3 "$HERE/scripts/tcb-size.py" \
    --sdk-elf "$MICROKIT_SDK/board/qemu_virt_aarch64_gicv3/debug/elf" --build "$BUILD/out" \
    --images "${CARGO_TARGET_DIR:-$REPO/native/target}/aarch64-unknown-hermit/release" \
    --sources "$HERE/sel4" --out "$tcb" || fail=1

echo "N1.6: the core's decision latency (n=$samples each)"
base=""
printf '%-62s %10s %10s %10s %8s\n' "" "median µs" "p99 µs" "max µs" "median×"
json="["
for row in "${rows[@]}"; do
    label="${row%%|*}"
    read -r median p99 max <<<"${row#*|}"
    [ "$label" = "the adapter's guest idle" ] && base="$median"
    ratio="-"
    [ -n "$base" ] && [ "$label" != "hosted" ] && ratio=$(awk -v m="$median" -v b="$base" 'BEGIN { printf "%.2f", m / b }')
    printf '%-62s %10s %10s %10s %8s\n' "$label" "$median" "$p99" "$max" "$ratio"
    json+="{\"run\": \"$label\", \"median_us\": $median, \"p99_us\": $p99, \"max_us\": $max},"
done
json="${json%,}]"
python3 - "$results" "$tcb" "$samples" "$json" <<'EOF'
import json, sys
out, tcb, samples, latency = sys.argv[1], sys.argv[2], int(sys.argv[3]), json.loads(sys.argv[4])
with open(tcb, encoding="utf-8") as f:
    tcb = json.load(f)
with open(out, "w", encoding="utf-8") as f:
    json.dump({"samples": samples, "latency": latency, "tcb": tcb,
               "note": "QEMU times are relative: compare runs on the same host"}, f, indent=1)
    f.write("\n")
EOF
echo "results: $results"
two_guests_finish N1.6
