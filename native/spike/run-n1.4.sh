#!/usr/bin/env bash
# N1.4: two guests on seL4 and a relay. The core's guest runs the Chitala
# Native image; the adapter host runs alone in the other guest
# (chitala-native-adapter); the relay copies bytes between their channels.
# The node does not know where its adapter host is: the Native platform
# (native/src/platform.rs) gives it one that is reached over the channel.
#
# Passes when each of N1.4's claims shows on its own:
# - the adapter host is in the other guest, and the channel is up through the relay;
# - orders cross to it and their receipts come back (the devices report);
# - 14 of 14 decisions are as expected, the 14th of them R1: the adapter's
#   guest takes an order off the channel and disappears before it answers,
#   and the core classifies the order's fate as UNKNOWN, never as not sent;
# - the audit log verifies; entropy from the CPU's RNG; a clean exit.
#
# The images: what native/run.sh --build-only last built (both binaries).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
. "$HERE/tools.lock"
env_out="$("$HERE/scripts/fetch.sh")"
eval "$env_out"
"$HERE/scripts/check-env.sh"
env_out="$("$HERE/scripts/build-sdk.sh")"
eval "$env_out"
IMAGES="${CARGO_TARGET_DIR:-$REPO/native/target}/aarch64-unknown-hermit/release"
for image in chitala-native chitala-native-adapter; do
    if [ ! -f "$IMAGES/$image" ]; then
        echo "N1.4: no $image in $IMAGES: build both with native/run.sh --build-only" >&2
        exit 1
    fi
done
BUILD="${N1_BUILD:-$HOME/.cache/chitala-n1/build}/two-guests"
rm -rf "$BUILD" && mkdir -p "$BUILD"
cp -R "$LIBVMM" "$BUILD/libvmm"
for p in "$HERE"/sdk/libvmm-*.patch; do
    git -C "$BUILD/libvmm" apply "$p"
done
# the adapter's guest takes the 4th order (the first three are the scenario's) and disappears
make -s -C "$HERE/sel4/two-guests" BUILD_DIR="$BUILD/out" MICROKIT_SDK="$MICROKIT_SDK" LIBVMM="$BUILD/libvmm" \
    LOADER_ELF="$HERMIT_LOADER" CORE_ELF="$IMAGES/chitala-native" ADAPTER_ELF="$IMAGES/chitala-native-adapter" \
    ADAPTER_ARGS="--disappear-on-execute 4"

log="$BUILD/boot.log"
qemu-system-aarch64 \
    -machine virt,virtualization=on,gic-version=3 -cpu neoverse-n2 -m size=2G \
    -nographic -serial mon:stdio -nic none \
    -device loader,file="$BUILD/out/loader.img",addr=0x70000000,cpu-num=0 </dev/null >"$log" 2>&1 &
qemu=$!
# the core runs its scenario, says what it checked, and stops; the adapter's guest stays silent
deadline=$((SECONDS + ${N1_BOOT_SECONDS:-900}))
while kill -0 "$qemu" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ] && ! grep -q "Shutting down system" "$log"; do
    sleep 0.5
done
kill "$qemu" 2>/dev/null || true
wait "$qemu" 2>/dev/null || true

clean="$BUILD/boot.txt"
tr -d '\r' <"$log" | sed 's/\x1b\[[0-9;]*m//g' >"$clean"
fail=0
expect() { # what, extended regular expression
    if grep -Eq "$2" "$clean"; then echo "ok    $1"; else echo "FAIL  $1: no /$2/"; fail=1; fi
}
expect "the relay is up" 'RELAY\|INFO: up'
expect "the adapter host runs in the other guest, not in the core's" 'adapter host in another guest, over the channel'
expect "the adapter's guest has the channel up" '\[adapter\] +channel up'
receipts=$(grep -Ec 'ALLOW +executed, device reports' "$clean" || true)
if [ "${receipts:-0}" -ge 3 ]; then
    echo "ok    orders crossed to the other guest and receipts came back: $receipts"
else
    echo "FAIL  orders crossed to the other guest and receipts came back: ${receipts:-0} of 3"
    fail=1
fi
expect "R1: the adapter's guest took an order and disappeared" 'took order #4 off the channel; disappearing'
expect "R1: the core classifies its fate as unknown, not as not sent" '→ UNKNOWN +X_EXECUTION_UNKNOWN'
expect "14 of 14 decisions as expected" '14/14 decisions as expected'
expect "the image's verdict" 'CHITALA NATIVE OK'
expect "the audit log's hash chain verifies" '\[audit\] +[0-9]+ records · hash chain ✓'
expect "entropy from the CPU's RNG (RNDR), through the VM" 'entropy: CPU RNDR \(FEAT_RNG\)'
expect "the core's image exits with status 0" 'exit status 0'
if [ "$fail" != 0 ]; then
    echo "N1.4 FAILED (boot log: $log)"
    grep -v "^LDR|INFO: region\|copying region" "$clean" | tail -60
    exit 1
fi
echo "N1.4: passed"
