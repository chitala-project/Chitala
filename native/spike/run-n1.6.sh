#!/usr/bin/env bash
# N1.6: the measurements (docs/native/n1-partitioning-spike.md, criteria 6
# and 7). Measure first, set no deadline (Project Lead, 2026-10-07): this
# reports numbers and ratios, and checks that each run is sound.
#
# The core runs its scenario, then N1_LATENCY_ROUNDS (4) rounds of
# measurements (native/src/main.rs, --latency); each answer is checked and
# counts in the core's verdict:
# - orders (criterion 6), a minute apart as Safety's rate rule allows: 12 per
#   round to the light and the thermostat, each timed from submission to the
#   node's answer, executed with its receipt verified (boundary → channel →
#   adapter → receipt), and on the channel from the order's line going out to
#   the receipt's line coming back;
# - decisions, 10.1 s apart for the Reference Monitor's rate limit: 25 per
#   round through the node's IPC (refused by a safety hold); in even rounds,
#   25 submitted directly on the core's thread; in odd rounds, 12 stops
#   through the node's IPC (a safety hold placed, criterion 7).
#
# The runs:
# - hosted: the same program on this machine, with no VM (if cargo is here);
# - on seL4, the adapter's guest idle, both guests at the same priority;
# - on seL4 with the scheduling chosen for N1 (the adapter's guest one
#   priority below the core's, the core's VM at 80% of each 10 ms: with WFI
#   not trapped, a guest below another runs only when that one's budget runs
#   out), the adapter's guest
#   - idle: criterion 7's baseline;
#   - spinning (--spin), while its adapter host serves;
#   - spinning, and waking on a timeout 1000 times a second (--timer-pressure),
#     each wakeup a timer interrupt through seL4 and its VMM.
# Criterion 6 compares the orders: hosted, idle, spinning. Criterion 7 the
# stops: spinning, and spinning under interrupt pressure, against the
# baseline. On QEMU the times are relative: the runs compare on one host.
#
# The TCB: the code of what the core's isolation rests on (scripts/tcb-size.py).
#
# The board: the GICv3 board of the SDK built from source, or the released
# SDK's GICv2 board (H0.1: N1_BOARD=qemu_virt_aarch64), whose kernel traps a
# guest's WFI to its VMM. Each run keeps every sample (the distribution), how
# many answers were wrong, how many of those were time-outs, and the
# decisions slower than 100 ms; the results keep the kernel's configuration
# (MCS, WFI). On QEMU the times are relative, and say nothing of deadlines
# on silicon.
#
# Results: $N1_BUILD/n1.6-results.json (n1.6-results-gicv2.json on the GICv2
# board). The images: what native/run.sh --build-only last built (both
# binaries).
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

rounds="${N1_LATENCY_ROUNDS:-4}"
results="${N1_BUILD:-$HOME/.cache/chitala-n1/build}/n1.6-results$TWO_GUESTS_SUFFIX.json"
# --latency leaves R1 to N1.4: the adapter host answers every order
VERDICT='^\[halt\] +13/13 decisions as expected · CHITALA NATIVE OK$'
# what: the label the core prints for it
KINDS=(
    "order|order through the node's IPC to a verified receipt"
    "channel|order on the channel, out to its receipt back"
    "ipc|decision through the node's IPC"
    "direct|decision submitted directly on this thread"
    "stop|stop through the node's IPC"
)
rows=()

record() { # name, label, file with the latency lines
    local kind what line row="$1|$2"
    for k in "${KINDS[@]}"; do
        kind="${k%%|*}"
        what="${k#*|}"
        line=$(grep -E "^\[latency\] +$what [^·]*· n=[0-9]+ · median [0-9]+ µs" "$3" | head -1 || true)
        if [ -z "$line" ]; then
            echo "FAIL  $2: no latency line for $kind"
            fail=1
            return
        fi
        row+="|$kind $(echo "$line" | sed -E 's/.* · n=([0-9]+) · median ([0-9]+) µs · p99 ([0-9]+) µs · max ([0-9]+) µs$/\1 \2 \3 \4/')"
    done
    # the load the adapter's guest put on: its last progress lines
    row+="|load $(grep -Eo 'spun [0-9]+ x 2\^24 at \+[0-9]+ ms' "$3" | tail -1 | sed -E 's/spun ([0-9]+) .* \+([0-9]+) ms/\1 \2/' || true)"
    row+="|timer $(grep -Eo 'timer pressure: [0-9]+ wakeups at \+[0-9]+ ms' "$3" | tail -1 | sed -E 's/.*: ([0-9]+) wakeups at \+([0-9]+) ms/\1 \2/' || true)"
    # the log itself: the samples, and the wrong answers, time-outs and slow decisions in it
    row+="|log $3"
    rows+=("$row")
    echo "ok    $2: measured"
}

echo "N1.6: hosted, the same program with no VM"
if command -v cargo >/dev/null; then
    hosted="$(mktemp)"
    if (cd "$REPO/native" && cargo run --release --locked -q -- --latency "$rounds") >"$hosted" 2>&1 &&
        grep -q "CHITALA NATIVE OK" "$hosted"; then
        record hosted "hosted" "$hosted"
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
    expect "the core completes its scenario and every measurement, each answer as expected" "$VERDICT"
    expect "the audit log's hash chain verifies" "$CORE_AUDIT"
    expect "the core exits with status 0" "$CORE_EXIT"
    case "$6" in *--spin*) expect "the adapter's guest spins" 'ADAPTER\| \[adapter\] +spun [0-9]+ x 2\^24' ;; esac
    case "$6" in *--timer-pressure*) expect "the adapter's guest wakes on its timer" 'ADAPTER\| \[adapter\] +timer pressure: [0-9]+ wakeups' ;; esac
    record "$1" "$2" "$clean"
}
measure idle "the adapter's guest idle, the same priority" 100 "" "" ""
measure mcs-idle "chosen scheduling, the adapter's guest idle" 99 8000 10000 ""
measure mcs-spin "chosen scheduling, the adapter's guest spinning" 99 8000 10000 "--spin"
measure mcs-spin-irq "chosen scheduling, spinning and 1000 timer wakeups a second" 99 8000 10000 \
    "--spin --timer-pressure 1000"

echo "N1.6: the TCB"
tcb="$(mktemp)"
python3 "$HERE/scripts/tcb-size.py" \
    --sdk-elf "$MICROKIT_SDK/board/$TWO_GUESTS_BOARD/debug/elf" --build "$BUILD/out" \
    --images "${CARGO_TARGET_DIR:-$REPO/native/target}/aarch64-unknown-hermit/release" \
    --sources "$HERE/sel4" --out "$tcb" || fail=1

python3 - "$results" "$tcb" "$rounds" "$TWO_GUESTS_BOARD" "$MICROKIT_SDK/board/$TWO_GUESTS_BOARD/debug/include/kernel/gen_config.json" \
    ${rows[@]+"${rows[@]}"} <<'EOF'
import json, re, sys
out, tcb, rounds, board, config_path, rows = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6:]
with open(config_path, encoding="utf-8") as f:
    config = json.load(f)
configuration = {"board": board, **{k: config.get(k) for k in ("KERNEL_MCS", "DISABLE_WFI_WFE_TRAPS", "ARM_GIC_V3_SUPPORT")}}
LABELS = {
    "order": "order through the node's IPC to a verified receipt",
    "channel": "order on the channel, out to its receipt back",
    "ipc": "decision through the node's IPC",
    "direct": "decision submitted directly on this thread",
    "stop": "stop through the node's IPC",
}
def from_log(path):
    # every sample, by kind; the wrong answers, the time-outs among them, the slow decisions
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    samples = {}
    for kind, what in LABELS.items():
        m = re.search(r"^\[latency\] +samples µs, " + re.escape(what) + r"[^:]*: ([0-9 ]+)$", text, re.M)
        if m:
            samples[kind] = [int(x) for x in m.group(1).split()]
    # the core counts every answer that was not the expected one; an order
    # the adapter host did not answer in time is X_EXECUTION_UNKNOWN (its
    # outcome is unknown), printed on its own line
    m = re.search(r"^\[latency\] +✗ ([0-9]+) answers were not the expected ones$", text, re.M)
    wrong = int(m.group(1)) if m else 0
    failed = re.findall(r"^\[latency\] +✗ (\S+ @ \S+: .*)$", text, re.M)
    timeouts = sum("X_EXECUTION_UNKNOWN" in f for f in failed)
    slow = [int(x) for x in re.findall(r"^\[latency\] +slow: ([0-9]+) ms", text, re.M)]
    return samples, wrong, timeouts, failed, slow
with open(tcb, encoding="utf-8") as f:
    tcb = json.load(f)
runs = {}
for row in rows:
    name, label, *parts = row.split("|")
    run = {"run": label}
    for p in parts:
        kind, *v = p.split()
        if kind == "log":
            samples, wrong, timeouts, failed, slow = from_log(v[0])
            run.update(samples_us=samples, wrong_answers=wrong, order_timeouts=timeouts, failed_orders=failed,
                       slow_over_100ms_ms=slow)
            continue
        if kind in ("load", "timer"):
            if len(v) == 2:
                run["adapter_" + ("spun_2pow24" if kind == "load" else "timer_wakeups")] = int(v[0])
                run["adapter_" + kind + "_at_ms"] = int(v[1])
            continue
        n, median, p99, mx = map(int, v)
        run[kind] = {"n": n, "median_us": median, "p99_us": p99, "max_us": mx}
    runs[name] = run
ms = lambda r, k: "/".join(f"{r[k][x] / 1000:.2f}" for x in ("median_us", "p99_us", "max_us")) if k in r else "-"
print("N1.6, criterion 6: an order, boundary → channel → adapter → receipt (ms: median / p99 / max)")
print(f"{'':<62} {'to a verified receipt':>24} {'on the channel':>22}")
for name in ("hosted", "idle", "mcs-spin"):
    if name in runs:
        r = runs[name]
        print(f"{r['run']:<62} {ms(r, 'order'):>24} {ms(r, 'channel'):>22}")
print("N1.6, criterion 7: a stop through the node's IPC, against the baseline (ms: median / p99 / max; ratios)")
base = runs.get("mcs-idle")
for name in ("mcs-idle", "mcs-spin", "mcs-spin-irq"):
    if name not in runs:
        continue
    r = runs[name]
    ratio = ""
    if base and "stop" in base and "stop" in r:
        ratio = " · ×" + " / ×".join(f"{r['stop'][x] / base['stop'][x]:.2f}" for x in ("median_us", "p99_us", "max_us"))
        r["stop_ratio_to_baseline"] = {x: round(r["stop"][x] / base["stop"][x], 3) for x in ("median_us", "p99_us", "max_us")}
    load = ""
    if "adapter_timer_wakeups" in r:
        load = f" · adapter timer {r['adapter_timer_wakeups'] * 1000 // max(r['adapter_timer_at_ms'], 1)}/s"
    n = r["stop"]["n"] if "stop" in r else 0
    print(f"{r['run']:<62} {ms(r, 'stop'):>22} (n={n}){ratio}{load}")
print(f"N1.6 on {board} (MCS {configuration['KERNEL_MCS']}, WFI/WFE traps disabled {configuration['DISABLE_WFI_WFE_TRAPS']}): "
      "wrong answers, orders timed out, decisions slower than 100 ms")
for r in runs.values():
    print(f"{r['run']:<62} {r.get('wrong_answers', '-'):>3} {r.get('order_timeouts', '-'):>3} {len(r.get('slow_over_100ms_ms', [])):>3}")
with open(out, "w", encoding="utf-8") as f:
    json.dump({"rounds": rounds, "configuration": configuration, "runs": list(runs.values()), "tcb": tcb,
               "note": "QEMU evidence only: times are relative, compare runs on the same host; "
                       "not a deadline guarantee on silicon"}, f, indent=1)
    f.write("\n")
EOF
echo "results: $results"
two_guests_finish N1.6
