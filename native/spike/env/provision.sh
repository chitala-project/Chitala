#!/usr/bin/env bash
# The N1 build host's packages (Ubuntu 24.04, arm64 or x86_64): the same in the
# local VM (env/n1-vm.yaml) and in CI. Run as root.
set -euo pipefail
. "$(dirname "$0")/../tools.lock"
. /etc/os-release
if [ "${VERSION_ID:-}" != "$UBUNTU_VERSION" ]; then
    echo "provision: Ubuntu $UBUNTU_VERSION expected, found ${PRETTY_NAME:-unknown}" >&2
    exit 1
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends \
    ca-certificates curl git gnupg make python3 xz-utils \
    "clang-$CLANG_MAJOR" "lld-$CLANG_MAJOR" "llvm-$CLANG_MAJOR" \
    device-tree-compiler qemu-system-arm
# the unversioned names the Microkit and libvmm Makefiles call
for tool in clang ld.lld llvm-ar llvm-objcopy; do
    ln -sf "$(command -v "$tool-$CLANG_MAJOR")" "/usr/local/bin/$tool"
done
