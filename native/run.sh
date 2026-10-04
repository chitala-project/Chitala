#!/usr/bin/env bash
# Build the Chitala Native spike as a Hermit unikernel and boot it in QEMU
# (aarch64 `virt` board). No Linux, Windows or macOS runs inside the VM.
#
#   native/run.sh                 # build (release) and boot on a CPU with a hardware RNG
#   native/run.sh --no-rng        # boot on Cortex-A76 (no RNG): must refuse to run (exit 3)
#   native/run.sh --no-build      # boot the last build
#
# Needs: rustup (the toolchain in native/rust-toolchain.toml is installed on
# first use), clang (and llvm-ar on Linux), qemu-system-aarch64, curl. Environment:
#   CARGO_TARGET_DIR   build directory (default native/target)
#   HERMIT_LOADER      the Hermit loader (default: downloaded and verified)
#   HERMIT_MANIFEST_DIR a Hermit kernel source tree to use as is (default: the
#                      pinned kernel with native/patches/*.patch applied)
#   QEMU_TIMEOUT       seconds before the VM is killed (default 120)
#   QEMU_CPU           CPU model (default neoverse-n2, or max without FEAT_LPA2,
#                      which Hermit 0.13's page-table setup misreads)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET=aarch64-unknown-hermit
LOADER_VERSION=v0.5.7
LOADER_SHA256=1b6faeb93cf1a0a240641e2286f0db5fecd19a6b7fb5625496e089a34fd3e5d8
CPU="${QEMU_CPU:-}"
BUILD=1
for arg in "$@"; do
    case "$arg" in
        --no-rng) CPU=cortex-a76 ;;
        --no-build) BUILD=0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HERE/target}"
# the rustup proxies must win over any other Rust on PATH: the Hermit kernel is
# built by a nested cargo that relies on its own rust-toolchain.toml
export PATH="$HOME/.cargo/bin:$PATH"
IMAGE="$CARGO_TARGET_DIR/$TARGET/release/chitala-native"
# C and assembly inside dependencies (e.g. psm, under Cedar) must be built for
# the target: clang cross-compiles by itself, a host GCC does not
if [ -z "${CC_aarch64_unknown_hermit:-}" ] && command -v clang >/dev/null; then
    export CC_aarch64_unknown_hermit=clang
fi
if [ -z "${AR_aarch64_unknown_hermit:-}" ] && command -v llvm-ar >/dev/null; then
    export AR_aarch64_unknown_hermit=llvm-ar
fi

sha256() {
    if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

# The pinned Hermit kernel with Chitala's patches applied, in a copy under the
# build directory (rebuilt only when the kernel or a patch changes). A patch
# that no longer applies stops the build.
patch_kernel() {
    (cd "$HERE" && cargo fetch --locked >/dev/null)
    local manifest src dest stamp p
    manifest=$(cd "$HERE" && cargo metadata --locked --format-version 1 --filter-platform "$TARGET" |
        python3 -c 'import json, sys; print(next(p["manifest_path"] for p in json.load(sys.stdin)["packages"] if p["name"] == "hermit"))')
    src="$(dirname "$(dirname "$manifest")")/kernel"
    dest="$CARGO_TARGET_DIR/hermit-kernel-patched"
    stamp="$src $(cat "$HERE"/patches/*.patch | sha256)"
    if [ "$(cat "$dest/.chitala-patches" 2>/dev/null)" != "$stamp" ]; then
        rm -rf "$dest"
        mkdir -p "$dest"
        cp -R "$src/." "$dest/"
        for p in "$HERE"/patches/*.patch; do
            patch -d "$dest" -p1 --forward --silent < "$p"
        done
        echo "$stamp" > "$dest/.chitala-patches"
    fi
    export HERMIT_MANIFEST_DIR="$dest"
}

if [ "$BUILD" = 1 ]; then
    if [ -z "${HERMIT_MANIFEST_DIR:-}" ]; then patch_kernel; fi
    echo "hermit kernel: $HERMIT_MANIFEST_DIR" >&2
    (cd "$HERE" && cargo build --locked -Zbuild-std=std,panic_abort --target "$TARGET" --release)
fi

LOADER="${HERMIT_LOADER:-$CARGO_TARGET_DIR/hermit-loader-aarch64-elf-$LOADER_VERSION}"
if [ ! -f "$LOADER" ]; then
    curl -sSfL -o "$LOADER.part" \
        "https://github.com/hermit-os/loader/releases/download/$LOADER_VERSION/hermit-loader-aarch64-elf"
    mv "$LOADER.part" "$LOADER"
fi
actual=$(sha256 < "$LOADER")
if [ "$actual" != "$LOADER_SHA256" ]; then
    echo "the Hermit loader does not match its pinned SHA-256 ($actual)" >&2
    exit 1
fi

if [ -z "$CPU" ]; then
    if qemu-system-aarch64 -cpu help | grep -qw neoverse-n2; then CPU=neoverse-n2; else CPU="max,lpa2=off"; fi
fi
echo "qemu: $(qemu-system-aarch64 --version | head -1) · cpu $CPU" >&2

# `-semihosting` lets the unikernel hand its exit code back to QEMU; no
# network device: the spike has no network stack (spec 20)
qemu-system-aarch64 \
    -machine virt,gic-version=3 -cpu "$CPU" -smp 1 -m 512M \
    -semihosting -display none -serial stdio -no-reboot -nic none \
    -kernel "$LOADER" \
    -device "guest-loader,addr=0x48000000,initrd=$IMAGE" &
qemu=$!
# the sleep must not hold our output open once QEMU is done (a pipe would wait for it)
( sleep "${QEMU_TIMEOUT:-120}" </dev/null >/dev/null 2>&1; kill "$qemu" 2>/dev/null && echo "QEMU timed out" >&2 ) &
watchdog=$!
status=0
wait "$qemu" || status=$?
kill "$watchdog" 2>/dev/null || true
exit "$status"
