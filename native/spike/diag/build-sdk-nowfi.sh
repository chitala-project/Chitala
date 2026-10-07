#!/usr/bin/env bash
# temporary: the pinned SDK, rebuilt with seL4's KernelArmDisableWFIWFETraps (N1.6 investigation)
set -euo pipefail
HERE=/Users/quantran/ChitalaOS/native/spike
. "$HERE/tools.lock"
CACHE="$HOME/.cache/chitala-n1"
env_out="$("$HERE/scripts/build-sdk.sh")"; eval "$env_out"   # makes sure sdk-src is prepared
src="$CACHE/sdk-src"; dst="$CACHE/sdk-src-nowfi"; SDK="$CACHE/microkit-sdk-nowfi"
if [ ! -f "$SDK/.built" ]; then
  rm -rf "$dst"; mkdir -p "$dst"; cp -R "$src/microkit" "$src/seL4" "$dst/"
  python3 - "$dst/microkit/build_sdk.py" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
o = '"QEMU_GIC_VERSION": 3,'
assert s.count(o) == 1
s = s.replace(o, o + '\n            "KernelArmDisableWFIWFETraps": True,')
open(p, "w").write(s)
PY
  rm -rf "$dst/microkit/release" "$dst/microkit/build"
  export PATH="$HOME/.cargo/bin:$PATH" RUSTUP_TOOLCHAIN="$RUST_VERSION"
  (cd "$dst/microkit" && "$src/pyenv/bin/python" build_sdk.py --sel4 ../seL4 --llvm \
    --boards qemu_virt_aarch64_gicv3 --configs debug --skip-docs --skip-tar \
    --tool-target-triple "$(uname -m)-unknown-linux-gnu" --version "$MICROKIT_VERSION-nowfi" >/dev/null 2>&1)
  rm -rf "$SDK"; cp -R "$dst/microkit/release/microkit-sdk-$MICROKIT_VERSION-nowfi" "$SDK"; touch "$SDK/.built"
fi
grep -c "DISABLE_WFI_WFE_TRAPS" "$SDK/board/qemu_virt_aarch64_gicv3/debug/include/kernel/gen_config.h" 2>/dev/null || grep -rl "DISABLE_WFI_WFE_TRAPS" "$SDK/board" | head -2
echo "SDK=$SDK"
