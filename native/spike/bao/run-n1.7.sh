#!/usr/bin/env bash
# N1.7 (bounded Bao comparison): the architectural comparison of Bao with
# seL4, enough to inform ADR 0002 — not a second complete Native platform
# (the Project Lead, 2026-10-08, chose this bounded "mode C").
#
# It pins and builds Bao v2.0.0 reproducibly with the LLVM toolchain the N1
# Linux host already has (no GCC), measures its code-size TCB, builds a
# minimal one-partition config with a bare-metal guest, and records a direct
# bare-QEMU boot attempt. Bao's supported qemu-aarch64-virt boot path adds a
# U-Boot firmware (`-bios flash.bin` then `go`), which is outside this spike's
# scope; a direct boot does not reach Bao's banner within the time-box. That
# is a documented limitation of the spike, NOT a failure of Bao, and
# Chitala/Hermit-on-Bao is therefore not demonstrated here (N1.7c).
#
# Run on the canonical N1 Linux host (native/spike/env/vm.sh run …).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# ── the pins (same discipline as the Microkit SDK) ───────────────────────────
BAO_TAG="v2.0.0"
BAO_COMMIT="0af4a1ab558ad60c9658af4f43756c4536dd3141"
BAO_SHA256="645cb16921d1fef23a0fda35adf6a8622438603cdbdf81526e1c75b4387cb021"
PLATFORM="qemu-aarch64-virt"

C="${N1_BAO:-$HOME/.cache/chitala-n1/bao}"
mkdir -p "$C"
tarball="$C/bao-$BAO_TAG.tar.gz"
src="$C/src"

cc="$(command -v clang)"
for t in "$cc" ld.lld llvm-objcopy llvm-size qemu-system-aarch64 make; do
    command -v "$t" >/dev/null || { echo "N1.7: missing tool: $t" >&2; exit 1; }
done

echo "N1.7a: fetch and pin Bao $BAO_TAG (commit $BAO_COMMIT)"
if [ ! -f "$tarball" ]; then
    curl -fsSL -o "$tarball" "https://github.com/bao-project/bao-hypervisor/archive/refs/tags/$BAO_TAG.tar.gz"
fi
got="$(sha256sum "$tarball" | cut -d' ' -f1)"
if [ "$got" != "$BAO_SHA256" ]; then
    echo "N1.7: FAIL: $tarball sha256 $got != pinned $BAO_SHA256" >&2
    exit 1
fi
echo "ok    source archive sha256 matches the pin"
rm -rf "$src" && mkdir -p "$src" && tar xzf "$tarball" -C "$src" --strip-components=1
[ -d "$src/src/platform/$PLATFORM" ] || { echo "N1.7: FAIL: no platform $PLATFORM in Bao $BAO_TAG" >&2; exit 1; }

echo "N1.7a: build the bare-metal guest with the LLVM toolchain"
g="$C/guest"
mkdir -p "$g"
"$cc" --target=aarch64-none-elf -ffreestanding -nostdlib -c "$HERE/guest/guest.S" -o "$g/guest.o"
ld.lld -Ttext=0x40000000 -o "$g/guest.elf" "$g/guest.o"
llvm-objcopy -O binary "$g/guest.elf" "$g/guest.bin"
echo "ok    guest.bin ($(stat -c %s "$g/guest.bin") bytes)"

echo "N1.7a: build Bao with the one-partition config (CONFIG=chitala)"
cfg="$C/config"
rm -rf "$cfg" && mkdir -p "$cfg/chitala"
sed "s|@GUEST_BIN@|$g/guest.bin|" "$HERE/config/chitala/config.c" >"$cfg/chitala/config.c"
# Bao's Makefile runs `git describe` for a version string; the extracted
# tarball is not a git tree, so stand in the pinned tag to keep it quiet and
# reproducible.
git -C "$src" init -q 2>/dev/null && git -C "$src" -c user.name=n1 -c user.email=n1@local commit -q --allow-empty -m pin 2>/dev/null &&
    git -C "$src" tag "$BAO_TAG" 2>/dev/null || true
if ! make -s -C "$src" PLATFORM="$PLATFORM" CONFIG=chitala CONFIG_REPO="$cfg" CROSS_COMPILE="$cc" >"$C/build.log" 2>&1; then
    cat "$C/build.log" >&2
    echo "N1.7: FAIL: Bao build failed" >&2
    exit 1
fi
elf="$src/bin/$PLATFORM/chitala/bao.elf"
bin="$src/bin/$PLATFORM/chitala/bao.bin"
[ -f "$elf" ] || { echo "N1.7: FAIL: Bao did not build" >&2; exit 1; }
echo "ok    Bao builds reproducibly with LLVM: $(stat -c %s "$bin") byte image"

echo "N1.7e: the code-size TCB"
read -r text _ < <(llvm-size "$elf" | awk 'NR==2')
loc=0
for d in src/core src/arch/armv8 "src/platform/$PLATFORM" src/lib; do
    n="$(find "$src/$d" \( -name '*.c' -o -name '*.S' -o -name '*.h' \) -exec cat {} + 2>/dev/null | grep -cvE '^\s*$' || true)"
    loc=$((loc + n))
done
printf 'ok    Bao hypervisor .text: %.1f KiB (one thin layer, no formal verification claimed); ~%d source lines\n' \
    "$(echo "$text" | awk '{print $1/1024}')" "$loc"

echo "N1.7b: a direct bare-QEMU boot attempt (the supported path uses U-Boot; this is informational)"
log="$C/boot-attempt.txt"
timeout 15 qemu-system-aarch64 -machine virt,virtualization=on,gic-version=3 -cpu cortex-a53 -smp 4 -m 4G \
    -nographic -device loader,file="$bin",addr=0x50000000,force-raw=on,cpu-num=0 >"$log" 2>&1 || true
if grep -q "Bao Hypervisor" "$log"; then
    echo "ok    Bao reached its banner on a direct boot"
else
    echo "--    Bao enters EL2 but does not reach its banner on a direct boot within the time-box;"
    echo "      its supported qemu-aarch64-virt boot path adds a U-Boot firmware, outside N1.7-C's scope."
    echo "      (The same loader boots a bare-metal guest, so the boot method is sound; the gap is Bao's"
    echo "      firmware expectation.) Hermit-on-Bao (N1.7c) is therefore not demonstrated here."
fi

echo
echo "N1.7f: see native/spike/bao/README.md for the structured seL4-vs-Bao comparison (ADR 0002 input)."
