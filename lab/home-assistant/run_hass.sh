#!/bin/bash
# Lab supervisor: run Home Assistant and start it again when it asks for a
# restart (exit code 100) or crashes, as the Supervisor or a container would.
# Home Assistant 2026.9 on Python 3.14 (macOS) can segfault while the
# interpreter exits after a restart request (exit code 139): that is restarted
# too. Killed on purpose (SIGKILL 137, SIGTERM 143) or a clean exit: it stops.
cd "$(dirname "$0")"
while true; do
  venv/bin/hass -c config
  code=$?
  echo "$(date '+%F %T') hass exited with $code" >&2
  case "$code" in
    100) ;;
    0|137|143) exit "$code" ;;
    *) [ "$code" -gt 128 ] || exit "$code" ;;
  esac
done
