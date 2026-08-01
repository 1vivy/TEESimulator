set -eu
set -f
umask 077

action=${1-}
sentinel_id=${2-}
nonce_hash=${3-}
role=${4-}
sampler_hash=${5-}
max_samples=${6-}
max_duration_seconds=${7-}
max_frame_bytes=${8-}
max_total_bytes=${9-}
max_state_files=${10-}
max_field_bytes=${11-}
root=${RKA_SENTINEL_ROOT:-/data/adb/teesimulator-rka/task25-sentinel}
control=${RKA_SENTINEL_CONTROL:-/data/adb/modules/tricky_store/rka-control.sh}
state_root=${RKA_SENTINEL_STATE_ROOT:-/data/adb/teesimulator-rka}

case $action in start|sample|assert-live|stop) ;; *) exit 2 ;; esac
case $sentinel_id in *[!0-9a-f]*|'') exit 2 ;; esac
[ "$(printf %s "$sentinel_id" | wc -c)" -eq 64 ] || exit 2
case $nonce_hash:$sampler_hash in *[!0-9a-f:]*|:*) exit 2 ;; esac
[ "$(printf %s "$nonce_hash" | wc -c)" -eq 64 ] || exit 2
[ "$(printf %s "$sampler_hash" | wc -c)" -eq 64 ] || exit 2
case $role in DONOR|CANDIDATE) ;; *) exit 2 ;; esac
for value in "$max_samples" "$max_duration_seconds" "$max_frame_bytes" "$max_total_bytes" "$max_state_files" "$max_field_bytes"; do
    case $value in ''|*[!0-9]*) exit 2 ;; esac
done
[ "$max_samples" -ge 2 ] && [ "$max_samples" -le 1024 ] || exit 2
[ "$max_duration_seconds" -ge 1 ] && [ "$max_duration_seconds" -le 2048 ] || exit 2
[ "$max_frame_bytes" -ge 512 ] && [ "$max_frame_bytes" -le 4096 ] || exit 2
[ "$max_total_bytes" -eq $((max_samples * max_frame_bytes + 8192)) ] || exit 2
[ "$max_state_files" -eq $((max_samples + 6)) ] || exit 2
[ "$max_field_bytes" -ge 64 ] && [ "$max_field_bytes" -le 256 ] || exit 2
sentinel=$root/$sentinel_id

safe_directory() {
    [ -d "$1" ] && [ ! -L "$1" ] &&
        [ "$(stat -c %u "$1")" = "$(id -u)" ] &&
        [ "$(stat -c %a "$1")" = 700 ]
}

safe_regular_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    parent=${1%/*}
    while [ "$parent" != / ] && [ -n "$parent" ]; do
        [ -d "$parent" ] && [ ! -L "$parent" ] || return 1
        parent=${parent%/*}
        [ -n "$parent" ] || parent=/
    done
}

bounded_text_file() {
    safe_regular_file "$1" &&
        [ "$(wc -c < "$1")" -le "$2" ] &&
        awk -v maximum="$max_field_bytes" 'length($0) > maximum { bad=1 } END { exit bad }' "$1"
}

state_total_bytes() {
    find "$sentinel" -type f |
        while IFS= read -r state_path; do wc -c < "$state_path"; done |
        awk '{total += $1} END {print total + 0}'
}

publish_terminal() {
    terminal_code=$1
    if [ -e "$sentinel/terminal" ] || [ -L "$sentinel/terminal" ]; then
        bounded_text_file "$sentinel/terminal" 128 || return 1
        [ "$(sed -n '1p' "$sentinel/terminal")" = version=1 ] || return 1
        [ "$(sed -n '2s/^result=//p' "$sentinel/terminal")" = "$terminal_code" ] || return 1
        return 0
    fi
    terminal_tmp=$sentinel/.terminal.tmp
    [ ! -e "$terminal_tmp" ] && [ ! -L "$terminal_tmp" ] || return 1
    {
        printf 'version=1\n'
        printf 'result=%s\n' "$terminal_code"
    } > "$terminal_tmp"
    chmod 600 "$terminal_tmp"
    mv "$terminal_tmp" "$sentinel/terminal"
}

process_identity() {
    name=$1 expected=$2
    matches=
    for pid in $(pidof "$name" 2>/dev/null || :); do
        case $pid in ''|*[!0-9]*) return 1 ;; esac
        executable=$(readlink "/proc/$pid/exe" 2>/dev/null || :)
        [ "$executable" = "$expected" ] || continue
        [ -z "$matches" ] || return 1
        stat_line=$(cat "/proc/$pid/stat" 2>/dev/null) || return 1
        stat_tail=${stat_line##*) }
        # shellcheck disable=SC2086
        set -- $stat_tail
        start_time=${20-}
        case $start_time in ''|*[!0-9]*) return 1 ;; esac
        executable_hash=$(printf %s "$executable" | sha256sum | awk '{print $1}') || return 1
        matches=$pid:$start_time:$executable_hash
    done
    printf %s "${matches:-ABSENT}"
}

property_hash() {
    properties_file=$sentinel/private-properties
    bounded_text_file "$properties_file" 2048 || return 1
    if [ "$role" = CANDIDATE ]; then
        [ ! -s "$properties_file" ] || return 1
        printf NONE
        return
    fi
    [ -s "$properties_file" ] || return 1
    while IFS= read -r name; do
        case $name in ''|*[!A-Za-z0-9_.-]*) return 1 ;; esac
        [ "$(printf %s "$name" | wc -c)" -le 128 ] || return 1
        printf '%s=' "$name"
        getprop "$name"
    done < "$properties_file" | sha256sum | awk '{print $1}'
}

runtime_phase() {
    phase=PRE_INSTALL
    runtime_hash=ABSENT
    module_directory=${control%/*}
    manifest=$module_directory/META-INF/rka-artifacts.sha256
    if [ -e "$module_directory" ] || [ -L "$module_directory" ]; then
        [ -d "$module_directory" ] && [ ! -L "$module_directory" ] || return 1
        control_present=false
        manifest_present=false
        [ ! -e "$control" ] && [ ! -L "$control" ] || control_present=true
        [ ! -e "$manifest" ] && [ ! -L "$manifest" ] || manifest_present=true
        [ "$control_present" = "$manifest_present" ] || return 1
        if [ "$control_present" = true ]; then
            safe_regular_file "$control" && safe_regular_file "$manifest" || return 1
            expected=$(awk '$2 == "rka-control.sh" {print $1}' "$manifest") || return 1
            case $expected in *[!0-9a-f]*|'') return 1 ;; esac
            [ "$(printf %s "$expected" | wc -c)" -eq 64 ] || return 1
            runtime_hash=$(sha256sum "$control" | awk '{print $1}') || return 1
            [ "$runtime_hash" = "$expected" ] || return 1
            phase=STAGED
            continuity=$state_root/run/boot-continuity.state
            if [ -e "$continuity" ] || [ -L "$continuity" ]; then
                safe_regular_file "$continuity" || return 1
                recorded_boot=$(sed -n '3s/^boot_id=//p' "$continuity") || return 1
                recorded_hash=$(printf %s "$recorded_boot" | sha256sum | awk '{print $1}') || return 1
                current_hash=$(cat /proc/sys/kernel/random/boot_id | tr -d '\n' | sha256sum | awk '{print $1}') || return 1
                [ "$recorded_hash" = "$current_hash" ] || return 1
                phase=INSTALLED
            fi
        fi
    fi
    printf '%s|%s' "$phase" "$runtime_hash"
}

take_sample_locked() {
    [ ! -e "$sentinel/terminal" ] && [ ! -L "$sentinel/terminal" ] || return 3
    count=$(cat "$sentinel/count" 2>/dev/null) || return 1
    case $count in ''|*[!0-9]*) return 1 ;; esac
    [ "$count" -le "$max_samples" ] || return 1
    if [ "$count" -eq "$max_samples" ]; then
        publish_terminal SENTINEL_SAMPLE_LIMIT || return 1
        return 3
    fi
    next=$((count + 1))
    boot_hash=$(cat /proc/sys/kernel/random/boot_id | tr -d '\n' | sha256sum | awk '{print $1}') || return 1
    uptime_ms=$(awk '{printf "%d", $1 * 1000}' /proc/uptime) || return 1
    case $uptime_ms in ''|*[!0-9]*) return 1 ;; esac
    started_uptime=$(sed -n '6s/^started_uptime_ms=//p' "$sentinel/metadata") || return 1
    case $started_uptime in ''|*[!0-9]*) return 1 ;; esac
    if [ $((uptime_ms - started_uptime)) -gt $((max_duration_seconds * 1000)) ]; then
        publish_terminal SENTINEL_DURATION_LIMIT || return 1
        return 3
    fi
    keystore2=$(process_identity keystore2 /system/bin/keystore2) || return 1
    rkpd=$(process_identity rkpd /system/bin/rkpd) || return 1
    forbidden=$(for name in reboot shutdown recovery; do pidof "$name" 2>/dev/null || :; done | tr ' ' '\n' | sed '/^$/d' | sort -n -u)
    [ -z "$forbidden" ] || return 1
    properties=$(property_hash) || return 1
    runtime=$(runtime_phase) || return 1
    phase=${runtime%%|*}
    runtime_hash=${runtime#*|}
    temporary=$sentinel/samples/.sample-$next.tmp
    [ ! -e "$temporary" ] && [ ! -L "$temporary" ] || return 1
    {
        printf 'version=3\n'
        printf 'sentinel_id=%s\n' "$sentinel_id"
        printf 'nonce_sha256=%s\n' "$nonce_hash"
        printf 'role=%s\n' "$role"
        printf 'sequence=%s\n' "$next"
        printf 'phase=%s\n' "$phase"
        printf 'boot_sha256=%s\n' "$boot_hash"
        printf 'uptime_ms=%s\n' "$uptime_ms"
        printf 'keystore2=%s\n' "$keystore2"
        printf 'rkpd=%s\n' "$rkpd"
        printf 'forbidden_pids=NONE\n'
        printf 'property_sha256=%s\n' "$properties"
        printf 'runtime_sha256=%s\n' "$runtime_hash"
        printf 'complete=1\n'
    } > "$temporary"
    bounded_text_file "$temporary" "$max_frame_bytes" || return 1
    current_total=$(state_total_bytes) || return 1
    frame_bytes=$(wc -c < "$temporary") || return 1
    [ $((current_total + frame_bytes)) -le "$max_total_bytes" ] || return 1
    chmod 600 "$temporary"
    mv "$temporary" "$sentinel/samples/$next"
    count_tmp=$sentinel/.count.tmp
    printf '%s\n' "$next" > "$count_tmp"
    chmod 600 "$count_tmp"
    mv "$count_tmp" "$sentinel/count"
}

take_sample() {
    safe_directory "$sentinel" && safe_directory "$sentinel/samples" || return 1
    mkdir "$sentinel/.lock" 2>/dev/null || return 1
    sample_result=0
    take_sample_locked || sample_result=$?
    rmdir "$sentinel/.lock" || return 1
    return "$sample_result"
}

validate_metadata() {
    metadata=$sentinel/metadata
    bounded_text_file "$metadata" 2048 && [ "$(wc -l < "$metadata")" -eq 12 ] || return 1
    [ "$(sed -n '1p' "$metadata")" = version=3 ] || return 1
    [ "$(sed -n '2s/^sentinel_id=//p' "$metadata")" = "$sentinel_id" ] || return 1
    [ "$(sed -n '3s/^nonce_sha256=//p' "$metadata")" = "$nonce_hash" ] || return 1
    [ "$(sed -n '4s/^role=//p' "$metadata")" = "$role" ] || return 1
    [ "$(sed -n '5s/^sampler_sha256=//p' "$metadata")" = "$sampler_hash" ] || return 1
    started_uptime=$(sed -n '6s/^started_uptime_ms=//p' "$metadata")
    case $started_uptime in ''|*[!0-9]*) return 1 ;; esac
    [ "$(sed -n '7s/^max_samples=//p' "$metadata")" = "$max_samples" ] || return 1
    [ "$(sed -n '8s/^max_duration_seconds=//p' "$metadata")" = "$max_duration_seconds" ] || return 1
    [ "$(sed -n '9s/^max_frame_bytes=//p' "$metadata")" = "$max_frame_bytes" ] || return 1
    [ "$(sed -n '10s/^max_total_bytes=//p' "$metadata")" = "$max_total_bytes" ] || return 1
    [ "$(sed -n '11s/^max_state_files=//p' "$metadata")" = "$max_state_files" ] || return 1
    [ "$(sed -n '12s/^max_field_bytes=//p' "$metadata")" = "$max_field_bytes" ] || return 1
}

validate_samples_locked() {
    validate_metadata || return 1
    bounded_text_file "$sentinel/count" 16 || return 1
    count=$(cat "$sentinel/count") || return 1
    case $count in ''|*[!0-9]*) return 1 ;; esac
    [ "$count" -ge 1 ] && [ "$count" -le "$max_samples" ] || return 1
    [ -z "$(find "$sentinel" -type l -print -quit)" ] || return 1
    directory_count=$(find "$sentinel" -mindepth 1 -type d | wc -l)
    [ "$directory_count" -eq 2 ] || return 1
    sample_entries=$(find "$sentinel/samples" -mindepth 1 -maxdepth 1 | wc -l)
    [ "$sample_entries" -eq "$count" ] || return 1
    terminal_extra=0
    if [ -e "$sentinel/terminal" ] || [ -L "$sentinel/terminal" ]; then terminal_extra=1; fi
    if [ "$terminal_extra" -eq 0 ]; then [ "$count" -ge 2 ] || return 1; fi
    state_files=$(find "$sentinel" -type f | wc -l)
    [ "$state_files" -eq $((count + 5 + terminal_extra)) ] || return 1
    [ "$state_files" -le "$max_state_files" ] || return 1
    total_bytes=$(state_total_bytes) || return 1
    [ "$total_bytes" -le "$max_total_bytes" ] || return 1
    previous_uptime=
    previous_phase=PRE_INSTALL
    baseline_boot=
    baseline_keystore=
    baseline_rkpd=
    baseline_forbidden=
    baseline_property=
    installed_seen=false
    sequence=1
    while [ "$sequence" -le "$count" ]; do
        sample=$sentinel/samples/$sequence
        bounded_text_file "$sample" "$max_frame_bytes" && [ "$(wc -l < "$sample")" -eq 14 ] || return 1
        [ "$(sed -n '1p' "$sample")" = version=3 ] || return 1
        [ "$(sed -n '2s/^sentinel_id=//p' "$sample")" = "$sentinel_id" ] || return 1
        [ "$(sed -n '3s/^nonce_sha256=//p' "$sample")" = "$nonce_hash" ] || return 1
        [ "$(sed -n '4s/^role=//p' "$sample")" = "$role" ] || return 1
        [ "$(sed -n '5s/^sequence=//p' "$sample")" = "$sequence" ] || return 1
        phase=$(sed -n '6s/^phase=//p' "$sample")
        boot=$(sed -n '7s/^boot_sha256=//p' "$sample")
        uptime=$(sed -n '8s/^uptime_ms=//p' "$sample")
        keystore=$(sed -n '9s/^keystore2=//p' "$sample")
        rkpd_value=$(sed -n '10s/^rkpd=//p' "$sample")
        forbidden_value=$(sed -n '11s/^forbidden_pids=//p' "$sample")
        property=$(sed -n '12s/^property_sha256=//p' "$sample")
        runtime_hash=$(sed -n '13s/^runtime_sha256=//p' "$sample")
        [ "$(sed -n '14s/^complete=//p' "$sample")" = 1 ] || return 1
        case $boot in *[!0-9a-f]*|'') return 1 ;; esac
        [ "$(printf %s "$boot" | wc -c)" -eq 64 ] || return 1
        [ "$forbidden_value" = NONE ] || return 1
        case $uptime in ''|*[!0-9]*) return 1 ;; esac
        case $keystore:$rkpd_value in *[!A-Z0-9a-f:]*|:) return 1 ;; esac
        case $property in NONE) [ "$role" = CANDIDATE ] || return 1 ;; *[!0-9a-f]*|'') return 1 ;; esac
        case $runtime_hash in ABSENT) ;; *[!0-9a-f]*|'') return 1 ;; esac
        case $phase in PRE_INSTALL) [ "$previous_phase" = PRE_INSTALL ] || return 1 ;; STAGED) [ "$previous_phase" != INSTALLED ] || return 1 ;; INSTALLED) installed_seen=true ;; *) return 1 ;; esac
        if [ -z "$baseline_boot" ]; then
            baseline_boot=$boot
            baseline_keystore=$keystore
            baseline_rkpd=$rkpd_value
            baseline_forbidden=$forbidden_value
            baseline_property=$property
        else
            [ "$boot" = "$baseline_boot" ] || return 1
            [ "$uptime" -gt "$previous_uptime" ] || return 1
            [ $((uptime - previous_uptime)) -le 2000 ] || return 1
            [ "$keystore" = "$baseline_keystore" ] || return 1
            [ "$rkpd_value" = "$baseline_rkpd" ] || return 1
            [ "$forbidden_value" = "$baseline_forbidden" ] || return 1
            [ "$property" = "$baseline_property" ] || return 1
        fi
        previous_uptime=$uptime
        previous_phase=$phase
        sequence=$((sequence + 1))
    done
    if [ "$terminal_extra" -eq 1 ]; then
        bounded_text_file "$sentinel/terminal" 128 && [ "$(wc -l < "$sentinel/terminal")" -eq 2 ] || return 1
        [ "$(sed -n '1p' "$sentinel/terminal")" = version=1 ] || return 1
        terminal_code=$(sed -n '2s/^result=//p' "$sentinel/terminal")
        case $terminal_code in SENTINEL_SAMPLE_LIMIT|SENTINEL_DURATION_LIMIT) ;; *) return 1 ;; esac
        printf 'sentinel_id=%s action=%s phase=LIMIT_REACHED samples=%s result=%s\n' "$sentinel_id" "$action" "$count" "$terminal_code"
        return 3
    fi
    last_uptime=$(awk '{printf "%d", $1 * 1000}' /proc/uptime) || return 1
    [ $((last_uptime - previous_uptime)) -le 2000 ] || return 1
    bounded_text_file "$sentinel/pid" 32 && bounded_text_file "$sentinel/pid_start" 32 || return 1
    pid=$(cat "$sentinel/pid") || return 1
    case $pid in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$pid" 2>/dev/null || return 1
    expected_start=$(cat "$sentinel/pid_start") || return 1
    pid_stat=$(cat "/proc/$pid/stat" 2>/dev/null) || return 1
    pid_tail=${pid_stat##*) }
    # shellcheck disable=SC2086
    set -- $pid_tail
    [ "${20-}" = "$expected_start" ] || return 1
    phase=ROOT_AUTHORITATIVE
    [ "$installed_seen" = false ] || phase=INSTALLED_OBSERVED
    printf 'sentinel_id=%s action=%s phase=%s samples=%s\n' "$sentinel_id" "$action" "$phase" "$count"
}

validate_samples() {
    safe_directory "$sentinel" && safe_directory "$sentinel/samples" || return 1
    lock_attempt=0
    while ! mkdir "$sentinel/.lock" 2>/dev/null; do
        lock_attempt=$((lock_attempt + 1))
        [ "$lock_attempt" -le 100 ] || return 1
        sleep 0.01
    done
    validation_result=0
    validate_samples_locked || validation_result=$?
    rmdir "$sentinel/.lock" || return 1
    return "$validation_result"
}

case $action in
    start)
        if [ -n "${RKA_SENTINEL_ROOT-}" ]; then
            safe_directory "$root" || exit 1
        else
            for directory in /data /data/adb /data/adb/teesimulator-rka "$root"; do
                [ ! -L "$directory" ] || exit 1
                if [ ! -e "$directory" ]; then mkdir "$directory"; chmod 700 "$directory"; fi
                [ -d "$directory" ] && [ ! -L "$directory" ] || exit 1
            done
        fi
        safe_directory "$root" || exit 1
        [ ! -e "$sentinel" ] && [ ! -L "$sentinel" ] || exit 1
        mkdir "$sentinel"
        started=false
        cleanup_incomplete_start() {
            if [ "$started" = false ] && safe_directory "$sentinel"; then
                find "$sentinel" -depth -delete 2>/dev/null || :
                rmdir "$root" 2>/dev/null || :
            fi
        }
        trap cleanup_incomplete_start EXIT HUP INT TERM
        mkdir "$sentinel/samples"
        property_tmp=$sentinel/.private-properties.tmp
        : > "$property_tmp"
        property_count=0
        while IFS= read -r property_name <&3; do
            case $property_name in ''|*[!A-Za-z0-9_.-]*) exit 1 ;; esac
            [ "$(printf %s "$property_name" | wc -c)" -le 128 ] || exit 1
            ! grep -Fqx "$property_name" "$property_tmp" 2>/dev/null || exit 1
            printf '%s\n' "$property_name" >> "$property_tmp"
            property_count=$((property_count + 1))
            [ "$property_count" -le 16 ] || exit 1
        done
        if [ "$role" = DONOR ]; then [ "$property_count" -ge 1 ] || exit 1; else [ "$property_count" -eq 0 ] || exit 1; fi
        [ "$(wc -c < "$property_tmp")" -le 2048 ] || exit 1
        chmod 600 "$property_tmp"
        mv "$property_tmp" "$sentinel/private-properties"
        exec 3<&-
        started_uptime=$(awk '{printf "%d", $1 * 1000}' /proc/uptime) || exit 1
        {
            printf 'version=3\n'
            printf 'sentinel_id=%s\n' "$sentinel_id"
            printf 'nonce_sha256=%s\n' "$nonce_hash"
            printf 'role=%s\n' "$role"
            printf 'sampler_sha256=%s\n' "$sampler_hash"
            printf 'started_uptime_ms=%s\n' "$started_uptime"
            printf 'max_samples=%s\n' "$max_samples"
            printf 'max_duration_seconds=%s\n' "$max_duration_seconds"
            printf 'max_frame_bytes=%s\n' "$max_frame_bytes"
            printf 'max_total_bytes=%s\n' "$max_total_bytes"
            printf 'max_state_files=%s\n' "$max_state_files"
            printf 'max_field_bytes=%s\n' "$max_field_bytes"
        } > "$sentinel/metadata"
        printf '0\n' > "$sentinel/count"
        chmod 600 "$sentinel/metadata" "$sentinel/count"
        take_sample || exit 1
        (
            set +f
            set -- /proc/self/fd/*
            set -f
            for inherited_fd_path do
                inherited_fd=${inherited_fd_path##*/}
                case $inherited_fd in ''|*[!0-9]*|0|1|2) continue ;; esac
                eval "exec $inherited_fd<&-" || exit 1
            done
            trap 'exit 0' HUP INT TERM
            while sleep 1; do take_sample || exit $?; done
        ) </dev/null >/dev/null 2>&1 &
        pid=$!
        printf '%s\n' "$pid" > "$sentinel/pid"
        pid_stat=$(cat "/proc/$pid/stat") || exit 1
        pid_tail=${pid_stat##*) }
        # shellcheck disable=SC2086
        set -- $pid_tail
        pid_start=${20-}
        case $pid_start in ''|*[!0-9]*) exit 1 ;; esac
        printf '%s\n' "$pid_start" > "$sentinel/pid_start"
        chmod 600 "$sentinel/pid" "$sentinel/pid_start"
        started=true
        trap - EXIT HUP INT TERM
        printf 'sentinel_id=%s action=start phase=ROOT_AUTHORITATIVE samples=1\n' "$sentinel_id"
        ;;
    sample|assert-live)
        validate_samples
        ;;
    stop)
        if [ ! -e "$sentinel" ] && [ ! -L "$sentinel" ]; then
            printf 'sentinel_id=%s action=stop phase=STOPPED samples=0\n' "$sentinel_id"
            exit 0
        fi
        safe_directory "$sentinel" || exit 1
        bounded_text_file "$sentinel/pid" 32 && bounded_text_file "$sentinel/pid_start" 32 || exit 1
        pid=$(cat "$sentinel/pid")
        expected_start=$(cat "$sentinel/pid_start")
        case $pid:$expected_start in *[!0-9:]*) exit 1 ;; esac
        pid_stat=$(cat "/proc/$pid/stat" 2>/dev/null || :)
        if [ -n "$pid_stat" ]; then
            pid_tail=${pid_stat##*) }
            # shellcheck disable=SC2086
            set -- $pid_tail
            [ "${20-}" = "$expected_start" ] || exit 1
            kill "$pid" 2>/dev/null || :
        fi
        count=$(cat "$sentinel/count" 2>/dev/null || printf 0)
        find "$sentinel" -depth -delete
        rmdir "$root" 2>/dev/null || :
        printf 'sentinel_id=%s action=stop phase=STOPPED samples=%s\n' "$sentinel_id" "$count"
        ;;
esac
