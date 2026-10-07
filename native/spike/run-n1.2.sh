#!/usr/bin/env bash
# N1.2: libvmm's own example, examples/simple: a Linux guest under a VMM
# protection domain on seL4, built with the pinned SDK and libvmm from the
# pinned, verified guest images, and booted on QEMU virt (aarch64, EL2).
# Passes when the guest's Linux reaches its login prompt, takes a login over
# the VMM's console, and runs a command.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/tools.lock"
eval "$("$HERE/scripts/fetch.sh")"
export MICROKIT_SDK
"$HERE/scripts/check-env.sh"
BUILD="${N1_BUILD:-$HOME/.cache/chitala-n1/build}/simple"
rm -rf "$BUILD" && mkdir -p "$BUILD"
# the kernel and the initrd where the example's Makefile expects them: it
# finds them, and downloads nothing itself
tar -xzf "$GUESTS/$LIBVMM_LINUX.tar.gz" -O "$LIBVMM_LINUX/Image" >"$BUILD/$LIBVMM_LINUX"
tar -xzf "$GUESTS/$LIBVMM_INITRD.tar.gz" -O "$LIBVMM_INITRD/rootfs.cpio.gz" >"$BUILD/$LIBVMM_INITRD"
make -s -C "$LIBVMM/examples/simple" BUILD_DIR="$BUILD" MICROKIT_BOARD=qemu_virt_aarch64 \
    MICROKIT_CONFIG=debug MICROKIT_SDK="$MICROKIT_SDK" LINUX="$LIBVMM_LINUX" INITRD="$LIBVMM_INITRD"

log="$BUILD/boot.log"
console="$BUILD/console"
rm -f "$console" && mkfifo "$console"
qemu-system-aarch64 \
    -machine virt,virtualization=on -cpu cortex-a53 -m size=2G -nographic -serial mon:stdio -nic none \
    -device loader,file="$BUILD/loader.img",addr=0x70000000,cpu-num=0 <"$console" >"$log" 2>&1 &
qemu=$!
exec 3>"$console"
stop() { kill "$qemu" 2>/dev/null || true; wait "$qemu" 2>/dev/null || true; }
trap stop EXIT
# wait until `$1` shows in the log, for at most `$2` seconds
until_seen() {
    local deadline=$((SECONDS + $2))
    while ! grep -q "$1" "$log"; do
        if ! kill -0 "$qemu" 2>/dev/null || [ "$SECONDS" -ge "$deadline" ]; then
            echo "N1.2 FAILED: no \"$1\" (boot log: $log)"; tail -30 "$log"; exit 1
        fi
        sleep 0.5
    done
}
until_seen "login:" "${N1_BOOT_SECONDS:-600}"
printf 'root\n' >&3
until_seen "^# \|# $" 60
printf 'echo N1.2 guest says: $(uname -sm)\n' >&3
until_seen "N1.2 guest says: Linux aarch64" 60
grep -a "Linux version\|login:\|N1.2 guest says" "$log" | tr -d '\r' | head -5
echo "N1.2: passed"
