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
    clang lld llvm device-tree-compiler qemu-system-arm ipxe-qemu
# Ubuntu's unversioned clang, lld and llvm give the tool names the Microkit
# and libvmm Makefiles call (clang, ld.lld, llvm-ar, llvm-ranlib, …); on
# 24.04 they are LLVM 18, which scripts/check-env.sh checks. ipxe-qemu holds
# the boot ROM of QEMU's default network card: seL4's build boots QEMU to dump
# the board's device tree
