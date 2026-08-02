#!/usr/bin/env bash

readonly RKA_ADB_ROOT_INPUT_MAX_BYTES=98304
readonly RKA_ADB_ROOT_OUTPUT_MAX_BYTES=1048576
readonly RKA_ADB_ROOT_PAYLOAD_DELIMITER=RKA_ADB_ROOT_PAYLOAD_7D4C2A91
readonly RKA_ADB_PROTECTED_UPLOAD_MAX_BYTES=134217728

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

rka_adb_protected_push() (
    set -uo pipefail
    set -f

    if (( $# != 8 )); then
        printf 'RKA_ADB_PROTECTED_UPLOAD_INVALID\n' >&2
        return 64
    fi
    local adb_command=$1 serial=$2 local_path=$3 target=$4 expected_sha=$5 mode=$6 transfer_id=$7 label=$8
    if [[ ! "$serial" =~ ^[A-Za-z0-9._:-]{1,255}$ || ! -f "$local_path" || -L "$local_path" ||
        ! "$expected_sha" =~ ^[0-9a-f]{64}$ || ! "$mode" =~ ^[0-7]{3}$ ||
        ! "$transfer_id" =~ ^[A-Za-z0-9._-]{1,160}$ || ! "$label" =~ ^[A-Za-z0-9._-]{1,48}$ ]]; then
        printf 'RKA_ADB_PROTECTED_UPLOAD_INVALID\n' >&2
        return 64
    fi

    case "$target" in
        /data/adb/teesimulator-rka/probes/*.manager-appid) ;;
        /data/adb/teesimulator-rka/upload/role-neutral-release.zip|\
        /data/adb/teesimulator-rka/upload/role-neutral-release.zip.source-sha) ;;
        *) printf 'RKA_ADB_PROTECTED_UPLOAD_INVALID\n' >&2; return 64 ;;
    esac

    local local_size local_sha
    local_size=$(LC_ALL=C wc -c < "$local_path") || return 70
    if (( local_size > RKA_ADB_PROTECTED_UPLOAD_MAX_BYTES )); then
        printf 'RKA_ADB_PROTECTED_UPLOAD_INVALID\n' >&2
        return 64
    fi
    local_sha=$(sha256sum -- "$local_path" | awk '{print $1}') || return 70
    if [[ "$local_sha" != "$expected_sha" ]]; then
        printf 'RKA_ADB_PROTECTED_UPLOAD_HASH_MISMATCH\n' >&2
        return 65
    fi

    local staging_path="/data/local/tmp/rka-adb-upload-$transfer_id-$label"
    if (( ${#staging_path} > 240 )); then
        printf 'RKA_ADB_PROTECTED_UPLOAD_INVALID\n' >&2
        return 64
    fi
    local materialize_script cleanup_script
    materialize_script=$(cat <<'RKA_ADB_PROTECTED_UPLOAD'
set -eu
set -f
stage=$1
target=$2
expected_sha=$3
mode=$4
case "$stage" in /data/local/tmp/rka-adb-upload-*) ;; *) exit 2 ;; esac
case "$target" in
    /data/adb/teesimulator-rka/probes/*.manager-appid) parent=/data/adb/teesimulator-rka/probes ;;
    /data/adb/teesimulator-rka/upload/role-neutral-release.zip|\
    /data/adb/teesimulator-rka/upload/role-neutral-release.zip.source-sha) parent=/data/adb/teesimulator-rka/upload ;;
    *) exit 2 ;;
esac
case "$expected_sha" in *[!0-9a-f]*|'') exit 2 ;; esac
[ "$(printf %s "$expected_sha" | wc -c)" -eq 64 ] || exit 2
case "$mode" in 600|700) ;; *) exit 2 ;; esac
for directory in /data /data/adb /data/adb/teesimulator-rka "$parent"; do
    [ ! -L "$directory" ] || exit 1
    if [ ! -e "$directory" ]; then mkdir "$directory"; fi
    [ -d "$directory" ] && [ ! -L "$directory" ] || exit 1
done
chmod 700 /data/adb/teesimulator-rka "$parent"
[ -f "$stage" ] && [ ! -L "$stage" ] || exit 1
[ ! -L "$target" ] || exit 1
temporary=$(mktemp "$parent/.rka-adb-upload.XXXXXX")
cleanup() { rm -f -- "$temporary" "$stage"; }
trap cleanup EXIT HUP INT TERM
cat -- "$stage" > "$temporary"
[ "$(sha256sum "$temporary" | awk '{print $1}')" = "$expected_sha" ] || exit 1
chown 0:0 "$temporary"
chmod "$mode" "$temporary"
mv -f -- "$temporary" "$target"
temporary=
[ -f "$target" ] && [ ! -L "$target" ] || exit 1
[ "$(sha256sum "$target" | awk '{print $1}')" = "$expected_sha" ] || exit 1
rm -f -- "$stage"
trap - EXIT HUP INT TERM
RKA_ADB_PROTECTED_UPLOAD
)
    materialize_script+=$'\n'
    cleanup_script=$(cat <<'RKA_ADB_PROTECTED_UPLOAD_CLEANUP'
set -eu
set -f
stage=$1
case "$stage" in /data/local/tmp/rka-adb-upload-*) ;; *) exit 2 ;; esac
rm -f -- "$stage"
[ ! -e "$stage" ] && [ ! -L "$stage" ]
RKA_ADB_PROTECTED_UPLOAD_CLEANUP
)
    cleanup_script+=$'\n'

    local result=0
    "$adb_command" -s "$serial" push "$local_path" "$staging_path" >/dev/null || result=$?
    if (( result == 0 )); then
        rka_adb_root_run "$adb_command" "$serial" "$materialize_script" \
            "$staging_path" "$target" "$expected_sha" "$mode" || result=$?
    fi
    if (( result != 0 )); then
        rka_adb_root_run "$adb_command" "$serial" "$cleanup_script" "$staging_path" >/dev/null 2>&1 || :
        return "$result"
    fi
)
