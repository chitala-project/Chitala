#!/bin/bash
# Lab supervisor: run Home Assistant and start it again when it asks for a
# restart (exit code 100), as the Supervisor or a container would.
cd "$(dirname "$0")"
while true; do
  venv/bin/hass -c config
  code=$?
  echo "$(date '+%F %T') hass exited with $code" >&2
  [ "$code" -eq 100 ] || exit "$code"
done
