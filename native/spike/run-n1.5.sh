#!/usr/bin/env bash
# N1.5: the isolation tests, in the Project Lead's order (docs/native/
# n1-partitioning-spike.md). Each step checks its claims on its own.
#
# N1.5a, the adapter's guest shares no device with the core's:
# - the system description gives the adapter's guest its own RAM and nothing
#   else, its VMM nothing of the board it could write, and its partition no
#   interrupt (scripts/check-system.py, before anything boots);
# - at run time, everything the adapter's guest writes comes out behind
#   "ADAPTER| ", in printable ASCII (any other byte as \xNN), including lines
#   forged to look like the core's verdict (--forge-core-lines). The core's
#   own verdict is there once, and a forged end of boot does not end the run;
# - the adapter's guest tells the time from its read-only RTC: it boots at
#   the board's date, and its order gate admits the core's orders.
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

echo "N1.5a: what the system description gives each partition"
if ! python3 "$HERE/scripts/check-system.py" "$HERE/sel4/two-guests/two-guests.system"; then
    echo "N1.5a FAILED: the system description"
    exit 1
fi

echo "N1.5a: the adapter's guest forges the core's lines as it disappears"
two_guests_boot n1.5a "--disappear-on-execute 4 --forge-core-lines"
expect "the adapter's VMM emulates its devices" '^adapter_vmm\|INFO: no device of the board in the guest'
reject "nothing the adapter's guest writes comes out without its prefix" '^(\[adapter\]|Chitala Native spike: the adapter)'
expect "the adapter's lines come out behind its prefix" 'ADAPTER\| \[adapter\] +channel up'
expect "the adapter's guest forged the core's verdict" 'ADAPTER\| \[halt\] +14/14 decisions as expected \\xc2\\xb7 CHITALA NATIVE OK'
expect "a byte that is not printable ASCII comes out as \\xNN" 'ADAPTER\| \[audit\] .*hash chain \\xe2\\x9c\\x93'
if LC_ALL=C grep -aq 'ADAPTER| .*[^ -~]' "$clean"; then
    echo "FAIL  the adapter's lines carry printable ASCII only"
    fail=1
else
    echo "ok    the adapter's lines carry printable ASCII only"
fi
expect "the adapter's guest forged the end of the boot" 'ADAPTER\| .*Shutting down system'
count "the core's verdict, its own and only once" "$CORE_VERDICT" 1
count "the core's exit, its own and only once" "$CORE_EXIT" 1
expect "the adapter's guest boots at the board's date, from its read-only RTC" 'ADAPTER\| .*Hermit booted on 20[2-9][0-9]-'
count "its order gate admits the core's orders, so its clock agrees" "$CORE_RECEIPT" 3
expect "R1 still holds" "$CORE_UNKNOWN"
expect "the audit log's hash chain verifies" "$CORE_AUDIT"
two_guests_finish N1.5a
