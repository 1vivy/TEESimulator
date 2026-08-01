set -eu
set -f
umask 077

action=${1-}
sentinel_id=${2-}
nonce_hash=${3-}
role=${4-}
sampler_hash=${5-}
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
sentinel=$root/$sentinel_id

safe_directory() {
    [ -d "$1" ] && [ ! -L "$1" ] &&
        [ "$(stat -c %u "$1")" = "$(id -u)" ] &&
        [ "$(stat -c %a "$1")" = 700 ]
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
    if [ "$role" = CANDIDATE ]; then
        printf NONE
        return
    fi
    {
        for name in \
            ro.build.fingerprint \
            ro.build.version.release \
            ro.build.version.incremental \
            ro.vendor.build.fingerprint
        do
            printf '%s=' "$name"
            getprop "$name"
        done
    } | sha256sum | awk '{print $1}'
}

runtime_phase() {
    phase=PRE_INSTALL
    runtime_hash=ABSENT
    manifest=${control%/*}/META-INF/rka-artifacts.sha256
    if [ -e "$control" ] || [ -e "$manifest" ]; then
        [ -f "$control" ] && [ ! -L "$control" ] && [ -f "$manifest" ] && [ ! -L "$manifest" ] || return 1
        expected=$(awk '$2 == "rka-control.sh" {print $1}' "$manifest") || return 1
        case $expected in *[!0-9a-f]*|'') return 1 ;; esac
        [ "$(printf %s "$expected" | wc -c)" -eq 64 ] || return 1
        runtime_hash=$(sha256sum "$control" | awk '{print $1}') || return 1
        [ "$runtime_hash" = "$expected" ] || return 1
        phase=STAGED
        continuity=$state_root/run/boot-continuity.state
        if [ -f "$continuity" ] && [ ! -L "$continuity" ]; then
            recorded_boot=$(sed -n '3s/^boot_id=//p' "$continuity") || return 1
            recorded_hash=$(printf %s "$recorded_boot" | sha256sum | awk '{print $1}') || return 1
            current_hash=$(cat /proc/sys/kernel/random/boot_id | tr -d '\n' | sha256sum | awk '{print $1}') || return 1
            [ "$recorded_hash" = "$current_hash" ] || return 1
            phase=INSTALLED
        fi
    fi
    printf '%s|%s' "$phase" "$runtime_hash"
}

take_sample() {
    safe_directory "$sentinel" || return 1
    count=$(cat "$sentinel/count" 2>/dev/null) || return 1
    case $count in ''|*[!0-9]*) return 1 ;; esac
    next=$((count + 1))
    boot_hash=$(cat /proc/sys/kernel/random/boot_id | tr -d '\n' | sha256sum | awk '{print $1}') || return 1
    uptime_ms=$(awk '{printf "%d", $1 * 1000}' /proc/uptime) || return 1
    case $uptime_ms in ''|*[!0-9]*) return 1 ;; esac
    keystore2=$(process_identity keystore2 /system/bin/keystore2) || return 1
    rkpd=$(process_identity rkpd /system/bin/rkpd) || return 1
    forbidden=$(for name in reboot shutdown recovery; do pidof "$name" 2>/dev/null || :; done | tr ' ' '\n' | sed '/^$/d' | sort -n -u)
    [ -z "$forbidden" ] || return 1
    properties=$(property_hash) || return 1
    runtime=$(runtime_phase) || return 1
    phase=${runtime%%|*}
    runtime_hash=${runtime#*|}
    trace=CLEAN
    started_epoch=$(sed -n '6s/^started_epoch=//p' "$sentinel/metadata") || return 1
    if logcat -b all -v epoch -d 2>/dev/null |
        awk -v started="$started_epoch" '$1 + 0 >= started' |
        grep -Eiq 'sys[.]powerctl|reboot|Restarting.*(keystore2|rkpd)'; then
        trace=FORBIDDEN
    fi
    temporary=$sentinel/.sample-$next.tmp
    {
        printf 'version=1\n'
        printf 'sentinel_id=%s\n' "$sentinel_id"
        printf 'sequence=%s\n' "$next"
        printf 'phase=%s\n' "$phase"
        printf 'boot_sha256=%s\n' "$boot_hash"
        printf 'uptime_ms=%s\n' "$uptime_ms"
        printf 'keystore2=%s\n' "$keystore2"
        printf 'rkpd=%s\n' "$rkpd"
        printf 'forbidden_pids=NONE\n'
        printf 'property_sha256=%s\n' "$properties"
        printf 'runtime_sha256=%s\n' "$runtime_hash"
        printf 'trace=%s\n' "$trace"
    } > "$temporary"
    chmod 600 "$temporary"
    mv -f "$temporary" "$sentinel/samples/$next"
    printf '%s\n' "$next" > "$sentinel/count"
    chmod 600 "$sentinel/count"
}

validate_samples() {
    safe_directory "$sentinel" || return 1
    metadata=$sentinel/metadata
    [ -f "$metadata" ] && [ ! -L "$metadata" ] || return 1
    [ "$(sed -n '1p' "$metadata")" = version=1 ] || return 1
    [ "$(sed -n '2s/^sentinel_id=//p' "$metadata")" = "$sentinel_id" ] || return 1
    [ "$(sed -n '3s/^nonce_sha256=//p' "$metadata")" = "$nonce_hash" ] || return 1
    [ "$(sed -n '4s/^role=//p' "$metadata")" = "$role" ] || return 1
    [ "$(sed -n '5s/^sampler_sha256=//p' "$metadata")" = "$sampler_hash" ] || return 1
    started_epoch=$(sed -n '6s/^started_epoch=//p' "$metadata")
    case $started_epoch in ''|*[!0-9]*) return 1 ;; esac
    count=$(cat "$sentinel/count") || return 1
    case $count in ''|*[!0-9]*) return 1 ;; esac
    [ "$count" -ge 2 ] || return 1
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
        [ -f "$sample" ] && [ ! -L "$sample" ] && [ "$(wc -l < "$sample")" -eq 12 ] || return 1
        [ "$(sed -n '1p' "$sample")" = version=1 ] || return 1
        [ "$(sed -n '2s/^sentinel_id=//p' "$sample")" = "$sentinel_id" ] || return 1
        [ "$(sed -n '3s/^sequence=//p' "$sample")" = "$sequence" ] || return 1
        phase=$(sed -n '4s/^phase=//p' "$sample")
        boot=$(sed -n '5s/^boot_sha256=//p' "$sample")
        uptime=$(sed -n '6s/^uptime_ms=//p' "$sample")
        keystore=$(sed -n '7s/^keystore2=//p' "$sample")
        rkpd_value=$(sed -n '8s/^rkpd=//p' "$sample")
        forbidden_value=$(sed -n '9s/^forbidden_pids=//p' "$sample")
        property=$(sed -n '10s/^property_sha256=//p' "$sample")
        runtime_hash=$(sed -n '11s/^runtime_sha256=//p' "$sample")
        trace=$(sed -n '12s/^trace=//p' "$sample")
        case $boot in *[!0-9a-f]*|'') return 1 ;; esac
        [ "$(printf %s "$boot" | wc -c)" -eq 64 ] || return 1
        [ "$forbidden_value" = NONE ] || return 1
        case $uptime in ''|*[!0-9]*) return 1 ;; esac
        case $keystore:$rkpd_value in *[!A-Z0-9a-f:]*|:) return 1 ;; esac
        case $property in NONE) [ "$role" = CANDIDATE ] || return 1 ;; *[!0-9a-f]*|'') return 1 ;; esac
        case $runtime_hash in ABSENT) ;; *[!0-9a-f]*|'') return 1 ;; esac
        [ "$trace" = CLEAN ] || return 1
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
    last_uptime=$(awk '{printf "%d", $1 * 1000}' /proc/uptime) || return 1
    [ $((last_uptime - previous_uptime)) -le 2000 ] || return 1
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
    printf 'sentinel_id=%s action=assert-live phase=%s samples=%s\n' "$sentinel_id" "$phase" "$count"
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
        {
            printf 'version=1\n'
            printf 'sentinel_id=%s\n' "$sentinel_id"
            printf 'nonce_sha256=%s\n' "$nonce_hash"
            printf 'role=%s\n' "$role"
            printf 'sampler_sha256=%s\n' "$sampler_hash"
            printf 'started_epoch=%s\n' "$(date +%s)"
        } > "$sentinel/metadata"
        printf '0\n' > "$sentinel/count"
        chmod 600 "$sentinel/metadata" "$sentinel/count"
        take_sample || exit 1
        RKA_SENTINEL_ID=$sentinel_id
        export RKA_SENTINEL_ID
        (
            trap 'exit 0' HUP INT TERM
            while sleep 1; do take_sample || exit 1; done
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
    sample)
        validate_samples
        ;;
    assert-live)
        validate_samples
        ;;
    stop)
        if [ ! -e "$sentinel" ] && [ ! -L "$sentinel" ]; then
            printf 'sentinel_id=%s action=stop phase=STOPPED samples=0\n' "$sentinel_id"
            exit 0
        fi
        safe_directory "$sentinel" || exit 1
        pid=$(cat "$sentinel/pid" 2>/dev/null || :)
        case $pid in ''|*[!0-9]*) exit 1 ;; esac
        expected_start=$(cat "$sentinel/pid_start" 2>/dev/null || :)
        pid_stat=$(cat "/proc/$pid/stat" 2>/dev/null || :)
        if [ -n "$pid_stat" ]; then
            pid_tail=${pid_stat##*) }
            # shellcheck disable=SC2086
            set -- $pid_tail
            [ -n "$expected_start" ] && [ "${20-}" = "$expected_start" ] || exit 1
            kill "$pid" 2>/dev/null || :
        fi
        count=$(cat "$sentinel/count" 2>/dev/null || printf 0)
        find "$sentinel" -depth -delete
        rmdir "$root" 2>/dev/null || :
        printf 'sentinel_id=%s action=stop phase=STOPPED samples=%s\n' "$sentinel_id" "$count"
        ;;
esac
