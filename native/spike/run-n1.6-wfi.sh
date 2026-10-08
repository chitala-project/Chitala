#!/usr/bin/env bash
# H0.1: N1.6 on the GICv2 board, before and after one change to WFI. The
# Project Lead (2026-10-08): if WFI is changed, keep the results before and
# after, and record exactly what changed.
#
# Both kernels are built from the same sources, with the same toolchain
# (scripts/build-sdk.sh), for the same board, qemu_virt_aarch64:
# - before (N1_SDK_VARIANT=gicv2-wfi-traps): the board as upstream defines it,
#   which traps a guest's WFI and WFE to its VMM, as the released SDK's does;
# - after (N1_SDK_VARIANT=gicv2-no-wfi-traps): the same board with
#   KernelArmDisableWFIWFETraps (sdk/wfi/), as the GICv3 board has
#   (sdk/microkit-0003).
# The images, the system, the scheduling and the rounds are the same. The two
# kernels' configurations are compared key by key: the comparison fails
# unless DISABLE_WFI_WFE_TRAPS is the one key that differs.
#
# QEMU evidence only: the times are relative, so compare them on one host.
# Nothing here is a deadline on silicon. Whether a board's WFI configuration
# holds up is a risk to check on H0.3's hardware configuration.
#
# Results: $N1_BUILD/n1.6-wfi/comparison.json, and each side's N1.6 results
# and logs in $N1_BUILD/n1.6-wfi/<side>/.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
base="${N1_BUILD:-$HOME/.cache/chitala-n1/build}/n1.6-wfi"
mkdir -p "$base"
for side in wfi-traps no-wfi-traps; do
    echo "N1.6 WFI: $side"
    N1_BOARD=qemu_virt_aarch64 N1_SDK_VARIANT="gicv2-$side" N1_BUILD="$base/$side" N1_HOSTED=no "$HERE/run-n1.6.sh"
done

python3 - "$base" <<'EOF'
import json, sys
base = sys.argv[1]
side = {}
for name in ("wfi-traps", "no-wfi-traps"):
    with open(f"{base}/{name}/n1.6-results-gicv2.json", encoding="utf-8") as f:
        side[name] = json.load(f)
before, after = side["wfi-traps"], side["no-wfi-traps"]
kb, ka = before["kernel_config"], after["kernel_config"]
changed = {k: {"before": kb.get(k), "after": ka.get(k)} for k in sorted(set(kb) | set(ka)) if kb.get(k) != ka.get(k)}
print("N1.6 WFI: the kernels' configurations differ in:")
for k, v in changed.items():
    print(f"  {k}: {v['before']} → {v['after']}")
ok = list(changed) == ["DISABLE_WFI_WFE_TRAPS"] and changed["DISABLE_WFI_WFE_TRAPS"] == {"before": False, "after": True}

KINDS = ("order", "channel", "ipc", "direct", "stop")
STATS = ("median_us", "p99_us", "max_us")
runs = []
print("N1.6 WFI: before → after (ms: median / p99 / max), wrong answers, orders timed out, decisions over 100 ms")
for rb, ra in zip(before["runs"], after["runs"]):
    assert rb["run"] == ra["run"], (rb["run"], ra["run"])
    row = {"run": rb["run"]}
    print(rb["run"])
    for kind in KINDS:
        if kind in rb and kind in ra:
            row[kind] = {
                "before": {s: rb[kind][s] for s in STATS},
                "after": {s: ra[kind][s] for s in STATS},
                "ratio_after_to_before": {s: round(ra[kind][s] / rb[kind][s], 3) for s in STATS},
            }
            fmt = lambda r: "/".join(f"{r[kind][s] / 1000:.2f}" for s in STATS)
            print(f"  {kind:<8} {fmt(rb):>24} → {fmt(ra):<24}")
    for count in ("wrong_answers", "order_timeouts"):
        row[count] = {"before": rb.get(count), "after": ra.get(count)}
    row["slow_over_100ms"] = {"before": len(rb.get("slow_over_100ms_ms", [])), "after": len(ra.get("slow_over_100ms_ms", []))}
    print(f"  wrong {row['wrong_answers']['before']} → {row['wrong_answers']['after']} · "
          f"timed out {row['order_timeouts']['before']} → {row['order_timeouts']['after']} · "
          f"over 100 ms {row['slow_over_100ms']['before']} → {row['slow_over_100ms']['after']}")
    runs.append(row)
with open(f"{base}/comparison.json", "w", encoding="utf-8") as f:
    json.dump({
        "step": "H0.1, N1.6 on the GICv2 board: WFI before and after",
        "board": "qemu_virt_aarch64",
        "before": {"sdk_variant": "gicv2-wfi-traps", "configuration": before["configuration"]},
        "after": {"sdk_variant": "gicv2-no-wfi-traps", "configuration": after["configuration"]},
        "kernel_config_changed": changed,
        "runs": runs,
        "note": "QEMU evidence only: times are relative, compare runs on the same host; "
                "not a deadline guarantee on silicon",
    }, f, indent=1)
    f.write("\n")
print(f"results: {base}/comparison.json")
if not ok:
    print("N1.6 WFI FAILED: the kernels must differ in DISABLE_WFI_WFE_TRAPS alone (False → True)")
    sys.exit(1)
print("N1.6 WFI: passed")
EOF
