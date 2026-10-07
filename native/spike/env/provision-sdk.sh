#!/usr/bin/env bash
# What building the Microkit SDK from source needs (N1.3, scripts/build-sdk.sh),
# beyond env/provision.sh: build tools from Ubuntu, and Rust (tools.lock), with
# the bare-metal target Microkit's initialiser is built for, for the invoking
# user through rustup. Run as root, with sudo.
set -euo pipefail
. "$(dirname "$0")/../tools.lock"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -q --no-install-recommends build-essential cmake ninja-build libxml2-utils python3-venv
# Microkit's loader preprocesses its linker script with clang-cpp, which
# Ubuntu ships only under LLVM's own directory
ln -sf "/usr/lib/llvm-$CLANG_MAJOR/bin/clang-cpp" /usr/local/bin/clang-cpp
user="${SUDO_USER:-$(id -un)}"
sudo -u "$user" -H sh -c "
    command -v rustup >/dev/null || curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
    \$HOME/.cargo/bin/rustup toolchain install $RUST_VERSION --profile minimal --component rust-src \
        --target aarch64-unknown-none
"
