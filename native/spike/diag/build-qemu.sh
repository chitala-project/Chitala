#!/usr/bin/env bash
# N1.6 diagnosis: a newer QEMU, built for aarch64 only, to compare with Ubuntu's 8.2.2
set -euo pipefail
V="${1:-v11.1.2}"; C="$HOME/.cache/chitala-n1"; D="$C/qemu-$V"
if [ ! -x "$D/bin/qemu-system-aarch64" ]; then
  sudo apt-get install -y -q libglib2.0-dev libpixman-1-dev meson ninja-build python3-venv flex bison >/dev/null
  rm -rf "$C/qemu-src"; git clone -q --depth 1 --branch "$V" https://gitlab.com/qemu-project/qemu.git "$C/qemu-src"
  cd "$C/qemu-src" && ./configure -q --prefix="$D" --target-list=aarch64-softmmu --disable-docs --disable-werror >/dev/null
  make -s -j"$(nproc)" >/dev/null && make -s install >/dev/null
fi
"$D/bin/qemu-system-aarch64" --version | head -1
echo "QEMU_BIN=$D/bin"
