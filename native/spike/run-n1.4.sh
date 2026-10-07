#!/usr/bin/env bash
# N1.4: two guests on seL4 and a relay. The core's guest runs the Chitala
# Native image; the adapter host runs alone in the other guest
# (chitala-native-adapter); the relay copies bytes between their channels.
# The node does not know where its adapter host is: the Native platform
# (native/src/platform.rs) gives it one that is reached over the channel.
#
# Passes when each of N1.4's claims shows on its own:
# - the adapter host is in the other guest, and the channel is up through the relay;
# - orders cross to it and their receipts come back (the devices report);
# - 14 of 14 decisions are as expected, the 14th of them R1: the adapter's
#   guest takes an order off the channel and disappears before it answers,
#   and the core classifies the order's fate as UNKNOWN, never as not sent;
# - the audit log verifies; entropy from the CPU's RNG; a clean exit.
#
# The images: what native/run.sh --build-only last built (both binaries).
# Since N1.5a the adapter's guest has no UART: its lines are behind
# "ADAPTER| ", and the core's are matched from the start of the line
# (scripts/two-guests.sh).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
. "$HERE/tools.lock"
env_out="$("$HERE/scripts/fetch.sh")"
eval "$env_out"
"$HERE/scripts/check-env.sh"
env_out="$("$HERE/scripts/build-sdk.sh")"
eval "$env_out"
. "$HERE/scripts/two-guests.sh"
# the adapter's guest takes the 4th order (the first three are the scenario's) and disappears
two_guests_boot two-guests "--disappear-on-execute 4"

expect "the relay is up" '^RELAY\|INFO: up'
expect "the adapter host runs in the other guest, not in the core's" '^\[node\] +adapter host in another guest, over the channel'
expect "the adapter's guest has the channel up" 'ADAPTER\| \[adapter\] +channel up'
count "orders crossed to the other guest and receipts came back" "$CORE_RECEIPT" 3
expect "R1: the adapter's guest took an order and disappeared" 'ADAPTER\| \[adapter\] +took order #4 off the channel; disappearing'
expect "R1: the core classifies its fate as unknown, not as not sent" "$CORE_UNKNOWN"
expect "14 of 14 decisions as expected, and the image's verdict" "$CORE_VERDICT"
expect "the audit log's hash chain verifies" "$CORE_AUDIT"
expect "entropy from the CPU's RNG (RNDR), through the VM" "$CORE_ENTROPY"
expect "the core's image exits with status 0" "$CORE_EXIT"
two_guests_finish N1.4
