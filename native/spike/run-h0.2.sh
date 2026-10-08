#!/usr/bin/env bash
# H0.2 (docs/native/h0-hardware-gate.md): the target boards of the H0 survey,
# built without hardware, with the released Microkit SDK. For each board:
# - N1.1's system (two protection domains and a channel): the SDK and the
#   Microkit tool build a system for it;
# - N1.4's two-guests system, with the board's addresses, and its
#   PlatformIsolationEvidence (scripts/isolation-evidence.py --self-test), on
#   a board libvmm knows: the ZynqMP boards. On the others the build is tried,
#   and what stops it is recorded.
#
# This is static evidence of the configuration, and nothing more (Project
# Lead, 2026-10-08):
# - nothing here boots;
# - it is not a test of isolation at run time;
# - it is not evidence about DMA on silicon.
#
# Results: $N1_BUILD/h0.2/summary.json, and each board's evidence and logs.
# The images: what native/run.sh --build-only last built (both binaries).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
. "$HERE/tools.lock"
env_out="$("$HERE/scripts/fetch.sh")"
eval "$env_out"
"$HERE/scripts/check-env.sh"

BOARDS=(zcu102 kria_k26 ultra96v2 rpi5b_2gb x86_64_generic_vtx)
IMAGES="${CARGO_TARGET_DIR:-$REPO/native/target}/aarch64-unknown-hermit/release"
for image in chitala-native chitala-native-adapter; do
    [ -f "$IMAGES/$image" ] || { echo "H0.2: no $image in $IMAGES: build both with native/run.sh --build-only" >&2; exit 1; }
done
OUT="${N1_BUILD:-$HOME/.cache/chitala-n1/build}/h0.2"
rm -rf "$OUT" && mkdir -p "$OUT"
cp -R "$LIBVMM" "$OUT/libvmm"
for p in "$HERE"/sdk/libvmm-*.patch; do
    git -C "$OUT/libvmm" apply "$p"
done

fail=0
rows=()
for board in "${BOARDS[@]}"; do
    echo "H0.2: $board"
    d="$OUT/$board"
    mkdir -p "$d/channel"
    if make -s -C "$HERE/sel4/channel" BUILD_DIR="$d/channel" MICROKIT_SDK="$MICROKIT_SDK" MICROKIT_BOARD="$board" \
        >"$d/channel.log" 2>&1; then
        echo "ok    the Microkit builds N1.1's system for $board ($(stat -c %s "$d/channel/loader.img") bytes)"
        channel=built
    else
        echo "FAIL  N1.1's system does not build for $board (log: $d/channel.log)"
        tail -5 "$d/channel.log"
        channel=failed
        fail=1
    fi

    case "$board" in
        x86_64_*)
            echo "--    two guests: not built: this VMM is Arm's; a guest on x86 waits for an Intel host with VT-x (H0.1x-b)"
            two=not-built
            ;;
        *)
            if make -s -C "$HERE/sel4/two-guests" BOARD="$board" BUILD_DIR="$d/two-guests" MICROKIT_SDK="$MICROKIT_SDK" \
                LIBVMM="$OUT/libvmm" LOADER_ELF="$HERMIT_LOADER" CORE_ELF="$IMAGES/chitala-native" \
                ADAPTER_ELF="$IMAGES/chitala-native-adapter" >"$d/two-guests.log" 2>&1; then
                if python3 "$HERE/scripts/isolation-evidence.py" --system "$d/two-guests/two-guests.system" \
                    --capdl "$d/two-guests/capdl.json" --report "$d/two-guests/report.txt" \
                    --policy "$HERE/sel4/two-guests/isolation-policy-zynqmp.json" \
                    --out "$d/platform-isolation-evidence.json" --self-test >"$d/evidence.log" 2>&1; then
                    echo "ok    the two-guests system builds for $board, and its PlatformIsolationEvidence holds (static)"
                    grep -E "^      properties:|^self-test:" "$d/evidence.log" | sed 's/^ */      /'
                    two=evidence
                else
                    echo "FAIL  the two-guests system's PlatformIsolationEvidence for $board (log: $d/evidence.log)"
                    grep -E "^FAIL|^ *✗" "$d/evidence.log" | head -10 || true
                    two=failed
                    fail=1
                fi
            elif grep -q "Need to define GIC addresses" "$d/two-guests.log"; then
                # a declared gap (the platform manifest): libvmm does not know the board's GIC
                echo "--    two guests: not built: libvmm 0.2.0 stops on '#error Need to define GIC addresses' for $board"
                two=unsupported-libvmm-gic
            else
                echo "FAIL  the two-guests system does not build for $board (log: $d/two-guests.log)"
                grep -E "error|Error" "$d/two-guests.log" | head -10 || true
                two=failed
                fail=1
            fi
            ;;
    esac
    rows+=("$board|$channel|$two")
done

python3 - "$OUT/summary.json" ${rows[@]+"${rows[@]}"} <<'EOF'
import json, sys
out, rows = sys.argv[1], sys.argv[2:]
boards = {}
for row in rows:
    board, channel, two = row.split("|")
    boards[board] = {"n1_1_system": channel, "two_guests": two}
with open(out, "w", encoding="utf-8") as f:
    json.dump({
        "step": "H0.2",
        "boards": boards,
        "limits": "Static evidence of the configuration only: nothing booted; not a test of isolation at run time; "
                  "not evidence about DMA on silicon (Project Lead, 2026-10-08).",
    }, f, indent=1)
    f.write("\n")
EOF
echo "H0.2: static evidence of the configuration only: nothing booted, isolation not tested at run time, nothing shown about DMA on silicon"
echo "results: $OUT/summary.json"
if [ "$fail" != 0 ]; then
    echo "H0.2 FAILED"
    exit 1
fi
echo "H0.2: passed"
