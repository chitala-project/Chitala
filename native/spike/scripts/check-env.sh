#!/usr/bin/env bash
# Check that this build host matches tools.lock: the compilers, QEMU and dtc at
# the pinned versions, and a verified Microkit SDK. Prints what it found.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../tools.lock"
fail=0
check() { # name, version found, prefix expected
    if [[ "$2" == "$3"* ]]; then echo "ok    $1 $2"; else echo "FAIL  $1 ${2:-missing}: $3.* expected"; fail=1; fi
}
first_version() { grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1; }
check clang "$(clang --version 2>/dev/null | first_version)" "$CLANG_MAJOR."
check ld.lld "$(ld.lld --version 2>/dev/null | first_version)" "$CLANG_MAJOR."
check qemu-system-aarch64 "$(qemu-system-aarch64 --version 2>/dev/null | first_version)" "$QEMU_VERSION_PREFIX"
check dtc "$(dtc --version 2>/dev/null | first_version)" "$DTC_VERSION_PREFIX"
check make "$(make --version 2>/dev/null | first_version)" ""
sdk="${MICROKIT_SDK:-${N1_CACHE:-$HOME/.cache/chitala-n1}/microkit-sdk-$MICROKIT_VERSION}"
if [ -f "$sdk/.verified" ] && [ -x "$sdk/bin/microkit" ]; then
    echo "ok    microkit-sdk $MICROKIT_VERSION ($sdk)"
else
    echo "FAIL  microkit-sdk $MICROKIT_VERSION: not fetched (scripts/fetch.sh)"; fail=1
fi
exit $fail
