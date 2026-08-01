#!/usr/bin/env bash
set -euo pipefail

exec "${RKA_TRACE_HOST_CLI:?}" trace-adb "$@"
