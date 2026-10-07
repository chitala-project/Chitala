#!/usr/bin/env bash
# N1.3, the go/no-go of the seL4 path: the Chitala Native image (the node's
# core as a Hermit unikernel, spec 20) in a virtual machine, under a VMM
# protection domain on seL4. The board is qemu_virt_aarch64_gicv3 (the SDK
# built from source: the Hermit kernel needs a GICv3) on a Neoverse-N2 (the
# image refuses to run without a hardware RNG). Passes when the image says
# CHITALA NATIVE OK, as it does under QEMU alone (native/run.sh).
#
# The image: N1_CHITALA_IMAGE, or what native/run.sh last built.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
. "$HERE/tools.lock"
eval "$("$HERE/scripts/fetch.sh")"
"$HERE/scripts/check-env.sh"
eval "$("$HERE/scripts/build-sdk.sh")"
IMAGE="${N1_CHITALA_IMAGE:-${CARGO_TARGET_DIR:-$REPO/native/target}/aarch64-unknown-hermit/release/chitala-native}"
if [ ! -f "$IMAGE" ]; then
    echo "N1.3: no Chitala image at $IMAGE: build it with native/run.sh, or set N1_CHITALA_IMAGE" >&2
    exit 1
fi
BUILD="${N1_BUILD:-$HOME/.cache/chitala-n1/build}/hermit-guest"
rm -rf "$BUILD" && mkdir -p "$BUILD"
# libvmm, with its patches, in a copy of its own
cp -R "$LIBVMM" "$BUILD/libvmm"
for p in "$HERE"/sdk/libvmm-*.patch; do
    git -C "$BUILD/libvmm" apply "$p"
done
make -s -C "$HERE/sel4/hermit-guest" BUILD_DIR="$BUILD/out" MICROKIT_SDK="$MICROKIT_SDK" \
    LIBVMM="$BUILD/libvmm" LOADER_ELF="$HERMIT_LOADER" IMAGE_ELF="$IMAGE"

log="$BUILD/boot.log"
qemu-system-aarch64 \
    -machine virt,virtualization=on,gic-version=3 -cpu neoverse-n2 -m size=2G \
    -nographic -serial mon:stdio -nic none \
    -device loader,file="$BUILD/out/loader.img",addr=0x70000000,cpu-num=0 </dev/null >"$log" 2>&1 &
qemu=$!
deadline=$((SECONDS + ${N1_BOOT_SECONDS:-600}))
while kill -0 "$qemu" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ] && ! grep -q "CHITALA NATIVE OK" "$log"; do
    sleep 0.5
done
kill "$qemu" 2>/dev/null || true
wait "$qemu" 2>/dev/null || true
if ! grep -q "CHITALA NATIVE OK" "$log"; then
    echo "N1.3 FAILED: no CHITALA NATIVE OK (boot log: $log)"
    tr -d '\r' <"$log" | grep -v "^LDR|INFO: region\|copying region" | tail -40
    exit 1
fi
tr -d '\r' <"$log" | grep -a "VMM\|CHITALA" | head -20
echo "N1.3: passed"
