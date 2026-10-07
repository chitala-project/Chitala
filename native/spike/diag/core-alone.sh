#!/usr/bin/env bash
# N1.6 diagnosis: the core's guest alone on seL4 (the N1.3 system), with
# --latency, the instrumented libvmm and the SDK as the repository builds it:
# does the tail of 0.5-0.85 s show without a second guest?
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/tools.lock"; env_out="$("$HERE/scripts/fetch.sh")"; eval "$env_out"
env_out="$("$HERE/scripts/build-sdk.sh")"; eval "$env_out"
B="$HOME/.cache/chitala-n1/build/diag-core-alone-${1:-1}"; [ -e "$B" ] && { echo "$B exists: give the run another name" >&2; exit 1; }; mkdir -p "$B"
cp -R "$LIBVMM" "$B/libvmm"; for p in "$HERE"/sdk/libvmm-*.patch; do git -C "$B/libvmm" apply "$p"; done
python3 "$HERE/diag/instrument.py" "$B/libvmm" >/dev/null
# the guest's board, with boot arguments for the image
cp -R "$HERE/sel4/hermit-guest" "$B/guest"
sed -i 's|stdout-path = "/pl011@9000000";|stdout-path = "/pl011@9000000";\n\t\tbootargs = "-- --latency '"${2:-2}"'";|' "$B/guest/hermit.dts"
grep -q 'bootargs = "-- --latency' "$B/guest/hermit.dts"
IMG="${IMG:-${CARGO_TARGET_DIR:-$HERE/../target}/aarch64-unknown-hermit/release}/chitala-native"
make -s -C "$B/guest" BUILD_DIR="$B/out" MICROKIT_SDK="$MICROKIT_SDK" LIBVMM="$B/libvmm" LOADER_ELF="$HERMIT_LOADER" IMAGE_ELF="$IMG"
log="$B/boot.log"
mon="$B/monitor.sock"
"${QEMU_BIN:+$QEMU_BIN/}qemu-system-aarch64" -machine virt,virtualization=on,gic-version=3 -cpu neoverse-n2 -m size=2G \
  -display none -serial stdio -monitor unix:"$mon",server,nowait -nic none \
  -device loader,file="$B/out/loader.img",addr=0x70000000,cpu-num=0 </dev/null >"$log" 2>&1 &
q=$!; deadline=$((SECONDS + 300))
[ -n "${PC_SAMPLE:-}" ] && { python3 "$HERE/diag/pc-sample.py" "$mon" "$B/pc.txt" 0.05 & }
while kill -0 $q 2>/dev/null && [ $SECONDS -lt $deadline ] && ! grep -q "Shutting down system" "$log"; do sleep 0.5; done
kill $q 2>/dev/null; wait $q 2>/dev/null || true
tr -d '\r' <"$log" | sed 's/\x1b\[[0-9;]*m//g' >"$B/boot.txt"
grep -aE "^\[latency\] +(decision|stop)|^\[halt\]|diag (wfx|vppi gap|vtimer)" "$B/boot.txt" | sed 's/ (Identity, Authority, Safety; refused by the hold)//; s/ (no IPC, no thread switch)//; s/ (a safety hold placed)//'
