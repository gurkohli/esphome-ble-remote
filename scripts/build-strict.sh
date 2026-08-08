#!/usr/bin/env bash

set -uo pipefail

build_log="$(mktemp "${TMPDIR:-/tmp}/esphome-build.XXXXXX")"
trap 'rm -f "$build_log"' EXIT

"$@" 2>&1 | tee "$build_log"
build_status=${PIPESTATUS[0]}

if ((build_status != 0)); then
  exit "$build_status"
fi

if grep -Ei 'components/ble_client_hid/.*warning:' "$build_log" >/dev/null; then
  echo "Build failed because ble_client_hid emitted compiler warnings." >&2
  grep -Ei 'components/ble_client_hid/.*warning:' "$build_log" >&2
  exit 1
fi
