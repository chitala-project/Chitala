#!/usr/bin/env bash
# N1.6 diagnosis: build the two-guests system with an instrumented libvmm and boot it once
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/tools.lock"; env_out="$("$HERE/scripts/fetch.sh")"; eval "$env_out"
env_out="$("$HERE/scripts/build-sdk.sh")"; eval "$env_out"
B="$HOME/.cache/chitala-n1/build/diag-${1:-idle}"; [ -e "$B" ] && { echo "$B exists: give the run another name" >&2; exit 1; }; mkdir -p "$B"
cp -R "$LIBVMM" "$B/libvmm"; for p in "$HERE"/sdk/libvmm-*.patch; do git -C "$B/libvmm" apply "$p"; done
python3 "$HERE/diag/instrument.py" "$B/libvmm"
IMG="${IMG:-${CARGO_TARGET_DIR:-$HERE/../target}/aarch64-unknown-hermit/release}"
make -s -C "$HERE/sel4/two-guests" BUILD_DIR="$B/out" MICROKIT_SDK="$MICROKIT_SDK" LIBVMM="$B/libvmm" \
  LOADER_ELF="$HERMIT_LOADER" CORE_ELF="$IMG/chitala-native" ADAPTER_ELF="$IMG/chitala-native-adapter" \
  ADAPTER_ARGS="${2:---disappear-on-execute 4}" CORE_ARGS="--latency 2${EXTRA_CORE_ARGS:+ $EXTRA_CORE_ARGS}" CORE_VM_BUDGET="${CORE_VM_BUDGET:-}" CORE_VM_PERIOD="${CORE_VM_PERIOD:-}" ADAPTER_VM_PRIORITY="${3:-100}"
log="$B/boot.log"
"${QEMU_BIN:+$QEMU_BIN/}qemu-system-aarch64" -machine virt,virtualization=on,gic-version=3 -cpu neoverse-n2 -m size=2G \
  -display none -serial stdio -monitor unix:"$B/monitor.sock",server,nowait -nic none \
  -device loader,file="$B/out/loader.img",addr=0x70000000,cpu-num=0 </dev/null >"$log" 2>&1 &
q=$!; deadline=$((SECONDS + ${4:-300}))
[ -n "${PC_SAMPLE:-}" ] && { python3 "$HERE/diag/pc-sample.py" "$B/monitor.sock" "$B/pc.txt" "${PC_INTERVAL:-0.05}" & }
# stop when the core's kernel shuts down (an adapter's line saying so is behind its prefix)
while kill -0 $q 2>/dev/null && [ $SECONDS -lt $deadline ] && ! grep -a "Shutting down system" "$log" | grep -qv "^ADAPTER|"; do sleep 0.5; done
kill $q 2>/dev/null; wait $q 2>/dev/null || true
tr -d '\r' <"$log" | sed 's/\x1b\[[0-9;]*m//g' >"$B/boot.txt"
grep -a "diag \|adapter host unavailable\|^\[latency\]\|^\[halt\]\|Reschedule\]\|Timer\]" "$B/boot.txt" | awk '{k=$1" "$2" "$3; last[k]=$0; if(!(k in seen)){order[++n]=k; seen[k]=1}} END{for(i=1;i<=n;i++) print last[order[i]]}'
