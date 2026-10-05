#!/bin/bash
# Chitala v0.3 step ③A lab: three virtual Matter devices from the Matter SDK
# (connectedhomeip) on this host — a dimmable light, an on/off plug and a door
# lock. Each has its own port, discriminator and storage. The lock reads
# simulated events (door state, jammed alarm) from a named pipe.
#
#   SDK_OUT=<connectedhomeip>/out ./run_devices.sh start|stop|codes
set -euo pipefail
cd "$(dirname "$0")"
OUT=${SDK_OUT:-connectedhomeip/out}
mkdir -p state logs

start() {
  local name=$1; shift
  if [ -f "state/$name.pid" ] && kill -0 "$(cat "state/$name.pid")" 2>/dev/null; then return; fi
  "$@" > "logs/$name.log" 2>&1 &
  echo $! > "state/$name.pid"
}

case "${1:-start}" in
  start)
    start light "$OUT/darwin-arm64-light/chip-lighting-app" \
      --KVS "$PWD/state/light.kvs" --secured-device-port 5541 --discriminator 3841
    start plug "$OUT/darwin-arm64-all-devices/all-devices-app" --device on-off-plug-in-unit:1 \
      --KVS "$PWD/state/plug.kvs" --port 5542 --discriminator 3842
    start lock "$OUT/darwin-arm64-lock/chip-lock-app" \
      --KVS "$PWD/state/lock.kvs" --secured-device-port 5543 --discriminator 3843 --app-pipe "$PWD/state/lock.fifo"
    ;;
  stop)
    for name in light plug lock; do
      [ -f "state/$name.pid" ] && kill "$(cat "state/$name.pid")" 2>/dev/null || true
      rm -f "state/$name.pid"
    done
    ;;
  codes)
    # the QR setup code each device prints at start-up: it carries the full
    # discriminator (the manual code holds only its top 4 bits, the same here)
    for name in light plug lock; do
      echo "$name $(grep -o 'SetupQRCode: \[MT:[A-Z0-9.-]*\]' "logs/$name.log" | head -1 | sed 's/.*\[//; s/\]//')"
    done
    ;;
esac
