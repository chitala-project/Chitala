#!/usr/bin/env bash
# temporary: build the two-guests system with an instrumented libvmm and boot it once
set -euo pipefail
HERE=/Users/quantran/ChitalaOS/native/spike
. "$HERE/tools.lock"; env_out="$("$HERE/scripts/fetch.sh")"; eval "$env_out"
env_out="$("$HERE/scripts/build-sdk.sh")"; eval "$env_out"
[ -n "${DIAG_SDK:-}" ] && MICROKIT_SDK="$DIAG_SDK"
B="$HOME/.cache/chitala-n1/build/diag-${1:-idle}"; rm -rf "$B"; mkdir -p "$B"
cp -R "$LIBVMM" "$B/libvmm"; for p in "$HERE"/sdk/libvmm-*.patch; do git -C "$B/libvmm" apply "$p"; done
python3 "$HERE/.diag/instrument.py" "$B/libvmm"
IMG=/Users/quantran/ChitalaOS/native/target/aarch64-unknown-hermit/release
make -s -C "$HERE/sel4/two-guests" BUILD_DIR="$B/out" MICROKIT_SDK="$MICROKIT_SDK" LIBVMM="$B/libvmm" \
  LOADER_ELF="$HERMIT_LOADER" CORE_ELF="$IMG/chitala-native" ADAPTER_ELF="$IMG/chitala-native-adapter" \
  ADAPTER_ARGS="${2:---disappear-on-execute 4}" CORE_ARGS="--latency 50" ADAPTER_VM_PRIORITY="${3:-100}"
log="$B/boot.log"
timeout "${4:-240}" qemu-system-aarch64 -machine virt,virtualization=on,gic-version=3 -cpu neoverse-n2 -m size=2G \
  -nographic -serial mon:stdio -nic none -device loader,file="$B/out/loader.img",addr=0x70000000,cpu-num=0 </dev/null >"$log" 2>&1 || true
tr -d '\r' <"$log" | sed 's/\x1b\[[0-9;]*m//g' >"$B/boot.txt"
grep -a "diag \|^\[latency\]\|^\[halt\]\|Reschedule\]\|Timer\]" "$B/boot.txt" | awk '{k=$1" "$2" "$3; last[k]=$0; if(!(k in seen)){order[++n]=k; seen[k]=1}} END{for(i=1;i<=n;i++) print last[order[i]]}'
