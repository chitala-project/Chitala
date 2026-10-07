#!/usr/bin/env bash
# The local N1 VM (env/n1-vm.yaml), with Lima (https://lima-vm.io):
#
#   native/spike/env/vm.sh start    # create or start it, mount this repository, provision it
#   native/spike/env/vm.sh shell    # a shell in the repository, inside the VM
#   native/spike/env/vm.sh run CMD  # run CMD in the repository, inside the VM
#   native/spike/env/vm.sh stop
#
# Lima keeps its VMs in $LIMA_HOME (default ~/.lima): set it to put the VM's
# disk elsewhere. The repository is mounted writable at the same path.
set -euo pipefail
NAME=chitala-n1
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
case "${1:-}" in
    start)
        if limactl list -q 2>/dev/null | grep -qx "$NAME"; then
            limactl start "$NAME"
        else
            limactl start --name="$NAME" --tty=false --mount="$REPO:w" "$HERE/n1-vm.yaml"
        fi
        limactl shell --workdir "$REPO" "$NAME" sudo bash native/spike/env/provision.sh
        ;;
    shell) limactl shell --workdir "$REPO" "$NAME" ;;
    run) shift; limactl shell --workdir "$REPO" "$NAME" "$@" ;;
    stop) limactl stop "$NAME" ;;
    *) sed -n '2,11p' "$0"; exit 2 ;;
esac
