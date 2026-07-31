#!/usr/bin/env bash

readonly RKA_ADB_ROOT_INPUT_MAX_BYTES=65536
readonly RKA_ADB_ROOT_OUTPUT_MAX_BYTES=1048576
readonly RKA_ADB_ROOT_PAYLOAD_DELIMITER=RKA_ADB_ROOT_PAYLOAD_7D4C2A91

rka_adb_root_run() (
    set -uo pipefail
    set -f

    if (( $# < 4 )); then
        printf 'RKA_ADB_ROOT_INPUT_INVALID\n' >&2
        return 64
    fi
    local adb_command=$1 serial=$2 script=$3
    shift 3
    if [[ ! "$serial" =~ ^[A-Za-z0-9._:-]{1,255}$ || -z "$script" || "$script" != *$'\n' ]]; then
        printf 'RKA_ADB_ROOT_INPUT_INVALID\n' >&2
        return 64
    fi
    if [[ $'\n'"$script" == *$'\n'"$RKA_ADB_ROOT_PAYLOAD_DELIMITER"$'\n'* ]]; then
        printf 'RKA_ADB_ROOT_INPUT_INVALID\n' >&2
        return 64
    fi

    local argument input_bytes script_bytes
    script_bytes=$(printf '%s' "$script" | LC_ALL=C wc -c) || return 70
    input_bytes=$((7 + script_bytes))
    for argument in "$@"; do
        if [[ ! "$argument" =~ ^[A-Za-z0-9_./:-]{1,1024}$ ]]; then
            printf 'RKA_ADB_ROOT_INPUT_INVALID\n' >&2
            return 64
        fi
        input_bytes=$((input_bytes + 1 + ${#argument}))
    done
    if (( input_bytes > RKA_ADB_ROOT_INPUT_MAX_BYTES )); then
        printf 'RKA_ADB_ROOT_INPUT_INVALID\n' >&2
        return 64
    fi

    local temporary stdout_fifo stderr_fifo stdout_file stderr_file
    temporary=$(mktemp -d "${TMPDIR:-/tmp}/rka-adb-root.XXXXXX") || return 70
    stdout_fifo=$temporary/stdout.fifo
    stderr_fifo=$temporary/stderr.fifo
    stdout_file=$temporary/stdout
    stderr_file=$temporary/stderr
    local stdout_reader='' stderr_reader=''
    cleanup_rka_adb_root() {
        [[ -z "$stdout_reader" ]] || kill "$stdout_reader" 2>/dev/null || :
        [[ -z "$stderr_reader" ]] || kill "$stderr_reader" 2>/dev/null || :
        case "$temporary" in
            "${TMPDIR:-/tmp}"/rka-adb-root.*) find "$temporary" -depth -delete 2>/dev/null || : ;;
        esac
    }
    trap cleanup_rka_adb_root EXIT
    mkfifo "$stdout_fifo" "$stderr_fifo" || return 70

    head -c $((RKA_ADB_ROOT_OUTPUT_MAX_BYTES + 1)) < "$stdout_fifo" > "$stdout_file" &
    stdout_reader=$!
    head -c $((RKA_ADB_ROOT_OUTPUT_MAX_BYTES + 1)) < "$stderr_fifo" > "$stderr_file" &
    stderr_reader=$!

    local loader_prefix loader_suffix
    loader_prefix=$(cat <<'RKA_ADB_ROOT_LOADER'
set -eu
set -f
umask 077
rka_script=$(mktemp /data/local/tmp/rka-adb-root.XXXXXX)
trap 'rm -f "$rka_script"' 0 HUP INT TERM
cat > "$rka_script" <<'RKA_ADB_ROOT_PAYLOAD_7D4C2A91'
RKA_ADB_ROOT_LOADER
)
    loader_suffix=$(cat <<'RKA_ADB_ROOT_LOADER'
chmod 700 "$rka_script"
status=0
sh "$rka_script" </dev/null || status=$?
rm -f "$rka_script"
trap - 0 HUP INT TERM
exit "$status"
RKA_ADB_ROOT_LOADER
)
    {
        printf '%s\n' "$loader_prefix"
        printf 'set --'
        for argument in "$@"; do
            printf ' %s' "$argument"
        done
        printf '\n%s' "$script"
        printf '%s\n%s\n' "$RKA_ADB_ROOT_PAYLOAD_DELIMITER" "$loader_suffix"
    } | "$adb_command" -s "$serial" shell su 0 sh > "$stdout_fifo" 2> "$stderr_fifo"
    local -a transport_status=("${PIPESTATUS[@]}")
    wait "$stdout_reader" 2>/dev/null || :
    wait "$stderr_reader" 2>/dev/null || :
    stdout_reader=
    stderr_reader=

    local stdout_size stderr_size
    stdout_size=$(wc -c < "$stdout_file")
    stderr_size=$(wc -c < "$stderr_file")
    if (( stdout_size > RKA_ADB_ROOT_OUTPUT_MAX_BYTES || stderr_size > RKA_ADB_ROOT_OUTPUT_MAX_BYTES )); then
        head -c "$RKA_ADB_ROOT_OUTPUT_MAX_BYTES" "$stdout_file"
        head -c "$RKA_ADB_ROOT_OUTPUT_MAX_BYTES" "$stderr_file" >&2
        printf 'RKA_ADB_ROOT_OUTPUT_TRUNCATED\n' >&2
        cleanup_rka_adb_root
        trap - EXIT
        return 74
    fi

    cat "$stdout_file"
    cat "$stderr_file" >&2
    local result=0
    if (( transport_status[1] != 0 )); then
        result=${transport_status[1]}
    elif (( transport_status[0] != 0 )); then
        printf 'RKA_ADB_ROOT_STDIN_FAILED\n' >&2
        result=74
    fi
    cleanup_rka_adb_root
    trap - EXIT
    return "$result"
)
