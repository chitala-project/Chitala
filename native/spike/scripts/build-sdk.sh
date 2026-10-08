#!/usr/bin/env bash
# N1.3: the Microkit SDK built from its pinned sources (tools.lock), with the
# board patches in sdk/: seL4 on QEMU virt with a GICv3, which the Hermit
# kernel needs (the released SDK's qemu_virt_aarch64 has a GICv2). Built with
# LLVM, for the debug configuration. Prints MICROKIT_SDK for the result.
#
# N1_SDK_VARIANT builds, instead, one of the two kernels of the WFI
# experiment on the GICv2 board (run-n1.6-wfi.sh), each in its own SDK:
# - gicv2-wfi-traps: qemu_virt_aarch64 as upstream defines it;
# - gicv2-no-wfi-traps: the same, with sdk/wfi/'s one change.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../tools.lock"
CACHE="${N1_CACHE:-$HOME/.cache/chitala-n1}"
variant="${N1_SDK_VARIANT:-}"
extra=()
case "$variant" in
    "") boards=qemu_virt_aarch64_gicv3 ;;
    gicv2-wfi-traps) boards=qemu_virt_aarch64 ;;
    gicv2-no-wfi-traps) boards=qemu_virt_aarch64; extra=("$HERE"/../sdk/wfi/microkit-*.patch) ;;
    *) echo "build-sdk: no SDK variant $variant" >&2; exit 2 ;;
esac
SDK="$CACHE/microkit-sdk-$MICROKIT_VERSION-chitala${variant:+-$variant}"
# (the default SDK's stamp is what it was before the variants)
stamp="$MICROKIT_COMMIT $SEL4_COMMIT ${variant:+$variant }$(cat "$HERE"/../sdk/microkit-*.patch ${extra[@]+"${extra[@]}"} "$HERE"/../env/sdk-*requirements.txt | sha256sum | cut -d' ' -f1)"
if [ "$(cat "$SDK/.built" 2>/dev/null)" = "$stamp" ]; then
    echo "MICROKIT_SDK=$SDK"
    exit 0
fi
src="$CACHE/sdk-src"
mkdir -p "$src"
at_commit() { # directory, repository, commit
    if [ "$(git -C "$1" rev-parse HEAD 2>/dev/null)" != "$3" ]; then
        rm -rf "$1"
        git init -q "$1"
        git -C "$1" fetch -q --depth 1 "$2" "$3"
        git -C "$1" checkout -q FETCH_HEAD
    fi
    git -C "$1" reset -q --hard "$3"
    git -C "$1" clean -qfdx
    [ "$(git -C "$1" rev-parse HEAD)" = "$3" ] || { echo "build-sdk: $1 is not at $3" >&2; exit 1; }
}
at_commit "$src/microkit" https://github.com/seL4/microkit "$MICROKIT_COMMIT"
at_commit "$src/seL4" https://github.com/seL4/seL4 "$SEL4_COMMIT"
for p in "$HERE"/../sdk/microkit-*.patch ${extra[@]+"${extra[@]}"}; do
    git -C "$src/microkit" apply "$p"
done
# the Python packages the build uses, in a fresh environment, each pinned by
# version and hash (env/sdk-*requirements.txt); pyfdt, which has no wheel, is
# built with the pinned setuptools and wheel, not ones fetched for the build
rm -rf "$src/pyenv"
python3 -m venv "$src/pyenv"
"$src/pyenv/bin/pip" install -q --require-hashes -r "$HERE/../env/sdk-bootstrap-requirements.txt"
"$src/pyenv/bin/pip" install -q --require-hashes --no-build-isolation -r "$HERE/../env/sdk-requirements.txt"
export PATH="$HOME/.cargo/bin:$PATH" RUSTUP_TOOLCHAIN="$RUST_VERSION"
(cd "$src/microkit" && "$src/pyenv/bin/python" build_sdk.py --sel4 ../seL4 --llvm \
    --boards "$boards" --configs debug --skip-docs --skip-tar \
    --tool-target-triple "$(uname -m)-unknown-linux-gnu" --version "$MICROKIT_VERSION-chitala" >&2)
rm -rf "$SDK"
cp -R "$src/microkit/release/microkit-sdk-$MICROKIT_VERSION-chitala" "$SDK"
echo "$stamp" > "$SDK/.built"
echo "MICROKIT_SDK=$SDK"
