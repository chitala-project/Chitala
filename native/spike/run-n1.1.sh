#!/usr/bin/env bash
# N1.1: build the two-PD system (sel4/channel) and boot it on QEMU virt
# (aarch64, EL2), as the Microkit manual runs qemu_virt_aarch64. Passes when
# both domains report and the adapter hears the core's answer.
#
# N1_BOARD=qemu_virt_aarch64_gicv3 runs it on the board N1.3 needs instead: the
# SDK built from source (scripts/build-sdk.sh), a GICv3, and a Neoverse-N2,
# whose hardware RNG the Chitala image requires.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/tools.lock"
eval "$("$HERE/scripts/fetch.sh")"
"$HERE/scripts/check-env.sh"
BOARD="${N1_BOARD:-qemu_virt_aarch64}"
case "$BOARD" in
    qemu_virt_aarch64) MACHINE=virt,virtualization=on CPU=cortex-a53 ;;
    qemu_virt_aarch64_gicv3)
        eval "$("$HERE/scripts/build-sdk.sh")"
        MACHINE=virt,virtualization=on,gic-version=3 CPU=neoverse-n2
        ;;
    *) echo "N1.1: no board $BOARD" >&2; exit 2 ;;
esac
export MICROKIT_SDK
BUILD="${N1_BUILD:-$HOME/.cache/chitala-n1/build}/channel-$BOARD"
rm -rf "$BUILD" && mkdir -p "$BUILD"
make -s -C "$HERE/sel4/channel" BUILD_DIR="$BUILD" MICROKIT_SDK="$MICROKIT_SDK" MICROKIT_BOARD="$BOARD"
log="$BUILD/boot.log"
# seL4 does not power the board off: the boot ends when the system has said
# what it should, or at the time limit. No network card: N1.1 needs none.
qemu-system-aarch64 \
    -machine "$MACHINE" -cpu "$CPU" -m size=2G -nographic -serial mon:stdio -nic none \
    -device loader,file="$BUILD/loader.img",addr=0x70000000,cpu-num=0 </dev/null >"$log" 2>&1 &
qemu=$!
deadline=$((SECONDS + ${N1_BOOT_SECONDS:-60}))
while kill -0 "$qemu" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ] && ! grep -q "N1.1 PASS" "$log"; do
    sleep 0.2
done
kill "$qemu" 2>/dev/null || true
wait "$qemu" 2>/dev/null || true
sed -n '/core: up\|adapter: \|core: from/p' "$log"
for line in "core: up" "adapter: up" "core: from the adapter: receipt 1" "adapter: the core answered" "N1.1 PASS"; do
    grep -qF "$line" "$log" || { echo "N1.1 FAILED: no \"$line\" (boot log: $log)"; tail -30 "$log"; exit 1; }
done
echo "N1.1: passed ($BOARD)"
