#!/usr/bin/env bash
set -euo pipefail

printf 'invoked\n' >> "$RKA_FAKE_INVOCATION_FILE"
[[ "${1-}" == -s && -n "${2-}" && "${3-}" == shell ]] || exit 90
serial=$2
shift 3

case "${RKA_FAKE_ADB_MODE:-capture}" in
    join)
        remote_command=$*
        PATH="$RKA_FAKE_SU_BIN:$PATH" /bin/sh -c "$remote_command"
        ;;
    capture)
        printf '%s\n' "$serial" > "$RKA_FAKE_SERIAL_FILE"
        printf '%s\0' "$@" > "$RKA_FAKE_ARGV_FILE"
        cat > "$RKA_FAKE_STDIN_FILE"
        printf '%s' "${RKA_FAKE_STDOUT:-}"
        printf '%s' "${RKA_FAKE_STDERR:-}" >&2
        exit "${RKA_FAKE_EXIT:-0}"
        ;;
    overflow-stdout)
        cat > "$RKA_FAKE_STDIN_FILE"
        head -c 1048577 /dev/zero | tr '\0' x
        ;;
    overflow-stderr)
        cat > "$RKA_FAKE_STDIN_FILE"
        head -c 1048577 /dev/zero | tr '\0' y >&2
        ;;
    overflow-both)
        cat > "$RKA_FAKE_STDIN_FILE"
        head -c 1048577 /dev/zero | tr '\0' x &
        stdout_pid=$!
        head -c 1048577 /dev/zero | tr '\0' y >&2 &
        stderr_pid=$!
        wait "$stdout_pid"
        wait "$stderr_pid"
        ;;
    *) exit 91 ;;
esac
