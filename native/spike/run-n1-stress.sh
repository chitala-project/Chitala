#!/usr/bin/env bash
# N1 stress: boot the two-guests system, as N1.4 builds it, COUNT times in a
# row (default 30), to catch what fails only now and then. It answers the one
# open failure of N1.4 on the arm64 CI runner (native/spike/README.md).
#
# Every boot counts. A boot that fails is reported and its log kept; nothing
# is retried, so an intermittent fault cannot turn green by chance. For each
# failure it prints the first error of a VMM with its next lines: the fault's
# address, its syndrome, the guest's registers. A reply-object warning from
# seL4 after it is a consequence, not the cause.
#
#   native/spike/run-n1-stress.sh [COUNT]
#
# The images: what native/run.sh --build-only last built (both binaries).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
. "$HERE/tools.lock"
env_out="$("$HERE/scripts/fetch.sh")"
eval "$env_out"
"$HERE/scripts/check-env.sh"
env_out="$("$HERE/scripts/build-sdk.sh")"
eval "$env_out"
# shellcheck source-path=SCRIPTDIR source=scripts/two-guests.sh
. "$HERE/scripts/two-guests.sh"

count="${1:-30}"
two_guests_build stress "--disappear-on-execute 4"
passed=0
for i in $(seq 1 "$count"); do
    start=$SECONDS
    two_guests_run "$BUILD/boot-$i.log"
    if grep -Eq "$CORE_VERDICT" "$clean" && grep -Eq "$CORE_EXIT" "$clean"; then
        passed=$((passed + 1))
        echo "boot $i of $count: ok in $((SECONDS - start)) s"
        rm -f "$log" "$clean"
    else
        echo "boot $i of $count: FAILED in $((SECONDS - start)) s (log: $log)"
        grep -a -m1 -A12 "|ERROR" "$clean" || echo "  (no error from a VMM; the log's tail:)"
        grep -a -v "^LDR|INFO: region\|copying region" "$clean" | tail -20
    fi
done
echo "N1 stress: $passed of $count boots passed"
[ "$passed" = "$count" ]
