#!/usr/bin/env bash
# N1.3, the go/no-go of the seL4 path: the Chitala Native image (the node's
# core as a Hermit unikernel, spec 20) in a virtual machine, under a VMM
# protection domain on seL4. The board is qemu_virt_aarch64_gicv3 (the SDK
# built from source: the Hermit kernel needs a GICv3) on a Neoverse-N2 (the
# image refuses to run without a hardware RNG). Passes when the image says
# CHITALA NATIVE OK, as it does under QEMU alone (native/run.sh), and each of
# N1.3's claims shows on its own: hardware entropy, the audit chain, 13/13
# decisions, a clean exit, timer interrupts delivered.
#
# The image: N1_CHITALA_IMAGE, or what native/run.sh last built.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
. "$HERE/tools.lock"
env_out="$("$HERE/scripts/fetch.sh")"
eval "$env_out"
"$HERE/scripts/check-env.sh"
# the GICv3 board of the SDK built from source (N1.3), or the released SDK's
# GICv2 board (H0.1: N1_BOARD=qemu_virt_aarch64), which fetch.sh gave
BOARD="${N1_BOARD:-qemu_virt_aarch64_gicv3}"
case "$BOARD" in
    qemu_virt_aarch64_gicv3)
        env_out="$("$HERE/scripts/build-sdk.sh")"
        eval "$env_out"
        GIC=3 NAME=hermit-guest
        ;;
    qemu_virt_aarch64) GIC=2 NAME=hermit-guest-gicv2 ;;
    *) echo "N1.3: no board $BOARD" >&2; exit 2 ;;
esac
IMAGE="${N1_CHITALA_IMAGE:-${CARGO_TARGET_DIR:-$REPO/native/target}/aarch64-unknown-hermit/release/chitala-native}"
if [ ! -f "$IMAGE" ]; then
    echo "N1.3: no Chitala image at $IMAGE: build it with native/run.sh, or set N1_CHITALA_IMAGE" >&2
    exit 1
fi
BUILD="${N1_BUILD:-$HOME/.cache/chitala-n1/build}/$NAME"
rm -rf "$BUILD" && mkdir -p "$BUILD"
# libvmm, with its patches, in a copy of its own
cp -R "$LIBVMM" "$BUILD/libvmm"
for p in "$HERE"/sdk/libvmm-*.patch; do
    git -C "$BUILD/libvmm" apply "$p"
done
make -s -C "$HERE/sel4/hermit-guest" BUILD_DIR="$BUILD/out" MICROKIT_SDK="$MICROKIT_SDK" BOARD="$BOARD" \
    LIBVMM="$BUILD/libvmm" LOADER_ELF="$HERMIT_LOADER" IMAGE_ELF="$IMAGE"

log="$BUILD/boot.log"
qemu-system-aarch64 \
    -machine "virt,virtualization=on,gic-version=$GIC" -cpu neoverse-n2 -m size=2G \
    -nographic -serial mon:stdio -nic none \
    -device loader,file="$BUILD/out/loader.img",addr=0x70000000,cpu-num=0 </dev/null >"$log" 2>&1 &
qemu=$!
# the image runs its scenario and says what it checked; then Hermit counts the
# interrupts it took and stops. Wait for the stop
deadline=$((SECONDS + ${N1_BOOT_SECONDS:-600}))
while kill -0 "$qemu" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ] && ! grep -q "Shutting down system" "$log"; do
    sleep 0.5
done
kill "$qemu" 2>/dev/null || true
wait "$qemu" 2>/dev/null || true

# each claim of N1.3 on its own, so that no single line can stand for them all
clean="$BUILD/boot.txt"
tr -d '\r' <"$log" | sed 's/\x1b\[[0-9;]*m//g' >"$clean"
fail=0
expect() { # what, extended regular expression
    if grep -Eq "$2" "$clean"; then echo "ok    $1"; else echo "FAIL  $1: no /$2/"; fail=1; fi
}
expect "entropy from the CPU's RNG (RNDR), through the VM" 'entropy: arm-rndr, .*, health ✓'
expect "the core's evidence names its admitted entropy provider" '^\[evidence\] +\{.*"provider_id":"arm-rndr".*"hardware_backed":true'
grep -m1 -E '^\[evidence\] +\{' "$clean" | sed -E 's/^\[evidence\] +/evidence  /' || true
expect "the audit log's hash chain verifies" '\[audit\] +[0-9]+ records · hash chain ✓'
expect "13 of 13 Authority and Safety decisions as expected" '13/13 decisions as expected'
expect "the image's verdict" 'CHITALA NATIVE OK'
expect "the image exits with status 0" 'exit status 0'
timer=$(grep -Eo '\[Timer\]: [0-9]+' "$clean" | grep -Eo '[0-9]+$' | tail -1)
if [ "${timer:-0}" -gt 0 ]; then
    echo "ok    timer interrupts delivered to the guest: $timer"
else
    echo "FAIL  timer interrupts delivered to the guest: none counted"
    fail=1
fi
if [ "$fail" != 0 ]; then
    echo "N1.3 FAILED (boot log: $log)"
    grep -v "^LDR|INFO: region\|copying region" "$clean" | tail -40
    exit 1
fi
echo "N1.3: passed ($BOARD)"
