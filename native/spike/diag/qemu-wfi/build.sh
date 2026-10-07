#!/usr/bin/env bash
# N1.6 (WIP): build the two reproducers (WFI, spin) with clang and lld
set -euo pipefail
cd "$(dirname "$0")"
out="${1:-$HOME/.cache/chitala-n1/qemu-wfi}"; mkdir -p "$out"
for mode in wfi spin; do
  def=""; [ "$mode" = spin ] && def="-DSPIN"
  clang --target=aarch64-none-elf -march=armv8-a -ffreestanding -fno-builtin -nostdlib -O2 $def \
    -Wl,-T,link.ld -fuse-ld=lld -o "$out/repro-$mode.elf" start.S main.c
done
ls "$out"
