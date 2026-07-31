#!/system/bin/sh

set -f

readonly DEFAULT_ROOT=/data/adb/tricky_store
readonly DEFAULT_STATE=/data/adb/teesimulator-rka
readonly MAX_CRASHES=3

root=$DEFAULT_ROOT
state=$DEFAULT_STATE
control=${RKA_CONTROL:-${0%/*}/rka-control.sh}
daemon=${RKA_DAEMON:-${0%/*}/daemon}
sidecar=${RKA_SIDECAR:-${0%/*}/rka-sidecar}
backoff=${RKA_BACKOFF_BASE:-1}
stable_seconds=${RKA_STABLE_SECONDS:-30}

usage() { printf '%s\n' 'usage: rka-supervisor.sh [--root PATH] [--state-root PATH] {start|stop|status}' >&2; }

while [ $# -gt 0 ]; do
    case $1 in
        --root) root=$2; shift 2 ;;
        --state-root) state=$2; shift 2 ;;
        start|stop|status) command=$1; shift ;;
        *) usage; exit 2 ;;
    esac
done
[ -n "$command" ] || { usage; exit 2; }

run=$state/run
pids=$run/pids
state_file=$run/supervisor.state

proc_stamp() {
    [ -r "/proc/$1/stat" ] || return 1
    awk '{print $1 " " $5 " " $22}' "/proc/$1/stat"
}

record_live() {
    [ -f "$1" ] || return 1
    IFS=' ' read -r pid pgid start < "$1" || return 1
    [ "$(proc_stamp "$pid")" = "$pid $pgid $start" ] || return 1
}

profile_valid() {
    profile=$state/profiles/active.conf
    [ -f "$profile" ] && [ ! -L "$profile" ] || return 1
    [ "$(stat -c '%u:%a' "$profile")" = "$(id -u):600" ] || return 1
    [ "$(sed -n '1p' "$profile")" = version=1 ] || return 1
    [ "$(sed -n '2p' "$profile")" = "role=$1" ] || return 1
    epoch_line=$(sed -n '3p' "$profile")
    case $epoch_line in profile_epoch=*) ;; *) return 1 ;; esac
    active_epoch=${epoch_line#profile_epoch=}
    case $active_epoch in ''|*[!0-9]*) return 1 ;; esac
    [ "$(wc -l < "$profile")" -eq 3 ]
}

direct_profile_valid() {
    profile=$state/profiles/direct.conf
    [ -f "$profile" ] && [ ! -L "$profile" ] || return 1
    [ "$(stat -c '%u:%a' "$profile")" = "$(id -u):600" ] || return 1
    [ "$(sed -n '1p' "$profile")" = version=1 ] || return 1
    [ "$(sed -n '2p' "$profile")" = "role=$1" ] || return 1
    [ "$(sed -n '3p' "$profile")" = "profile_epoch=$2" ] || return 1
    endpoint_line=$(sed -n '4p' "$profile")
    case $endpoint_line in peer_endpoint=*) ;; *) return 1 ;; esac
    endpoint=${endpoint_line#peer_endpoint=}
    case $endpoint in ''|*[!0-9.]*) return 1 ;; esac
    pin_line=$(sed -n '5p' "$profile")
    case $pin_line in peer_spki_sha256=*) ;; *) return 1 ;; esac
    pin=${pin_line#peer_spki_sha256=}
    case $pin in *[!0-9a-f]*) return 1 ;; esac
    [ "$(printf %s "$pin" | wc -c)" -eq 64 ] || return 1
    [ "$(sed -n '6p' "$profile")" = transport=DIRECT ] || return 1
    [ "$(wc -l < "$profile")" -eq 6 ]
}

direct_ready() {
    request=$state/profiles/pair.request
    key=$state/secrets/transport.key
    trust=$state/trust/transport-trust.pem
    identity_commit=$state/trust/transport-identity.commit
    [ -f "$request" ] && [ ! -L "$request" ] &&
        [ "$(cat "$request")" = "version=1
action=PAIR_DIRECT" ] || return 1
    [ -f "$key" ] && [ ! -L "$key" ] && [ "$(stat -c '%u:%a' "$key")" = "$(id -u):600" ] ||
        return 1
    [ "$(wc -c < "$key")" -ge 16 ] && [ "$(wc -c < "$key")" -le 16384 ] || return 1
    [ -f "$identity_commit" ] && [ ! -L "$identity_commit" ] &&
        [ "$(stat -c '%u:%a' "$identity_commit")" = "$(id -u):600" ] || return 1
    grep -Eq '^version=1$' "$identity_commit" &&
        sed -n '2p' "$identity_commit" | grep -Eq '^spki_sha256=[0-9a-f]{64}$' &&
        [ "$(wc -l < "$identity_commit")" -eq 2 ] || return 1
    [ -f "$trust" ] && [ ! -L "$trust" ] &&
        [ "$(stat -c '%u:%a' "$trust")" = "$(id -u):600" ] || return 1
    [ "$(sed -n '1p' "$trust")" = '-----BEGIN CERTIFICATE-----' ] &&
        [ "$(tail -n 1 "$trust")" = '-----END CERTIFICATE-----' ]
}

write_record() {
    name=$1 child=$2
    child_stamp=$(proc_stamp "$child") || return 1
    # shellcheck disable=SC2086
    set -- $child_stamp
    printf '%s %s %s\n' "$child" "$2" "$3" > "$pids/$name.pid"
    chmod 600 "$pids/$name.pid"
}

child_loop() {
    name=$1
    shift
    crashes=0
    while :; do
        started=$(date +%s)
        setsid "$@" &
        child=$!
        write_record "$name" "$child" || :
        wait "$child"
        [ "$(cat "$state_file" 2>/dev/null)" = RUNNING ] || exit 0
        if restart_blocked; then
            printf '%s\n' QUARANTINED_AMBIGUOUS_MUTATION > "$state_file"
            rm -f "$pids/$name.pid"
            exit 1
        fi
        finished=$(date +%s)
        if [ $((finished - started)) -ge "$stable_seconds" ]; then
            crashes=0
        else
            crashes=$((crashes + 1))
        fi
        if [ "$crashes" -gt "$MAX_CRASHES" ]; then
            printf '%s\n' FAILED_CRASH_CAP > "$state_file"
            rm -f "$pids/$name.pid"
            exit 1
        fi
        sleep "$backoff"
    done
}

restart_blocked() {
    marker=$state/journal/mutation.state
    [ ! -e "$marker" ] && [ ! -L "$marker" ] && return 1
    [ -f "$marker" ] && [ ! -L "$marker" ] && [ -r "$marker" ] || return 0
    marker_state=$(cat "$marker") || return 0
    case $marker_state in
        POST_AMBIGUOUS|RKP_KEY_GENERATING|APP_KEY_GENERATING) return 0 ;;
        RKP_KEY_RECORDED|CSR_PREPARED|CSR_POSTING|RKP_CERTIFIED|APP_KEY_RECORDED|EXPOSED|TERMINAL|DELETE|IDLE|COMPLETED) return 1 ;;
        *) return 0 ;;
    esac
}

start_one() {
    name=$1
    shift
    if record_live "$pids/$name.pid"; then return 0; fi
    rm -f "$pids/$name.pid"
    child_loop "$name" "$@" </dev/null >/dev/null 2>&1 &
    attempts=0
    while [ ! -f "$pids/$name.pid" ] && [ "$attempts" -lt 5 ]; do
        sleep 1
        attempts=$((attempts + 1))
    done
    [ -f "$pids/$name.pid" ]
}

profile_receipt_valid() {
    receipt=$state/run/direct-profile.receipt
    [ -f "$receipt" ] && [ ! -L "$receipt" ] || return 1
    [ "$(stat -c '%u:%a' "$receipt")" = "$(id -u):600" ] || return 1
    [ "$(sed -n '1p' "$receipt")" = version=1 ] || return 1
    [ "$(sed -n '2p' "$receipt")" = "profile_sha256=$1" ] || return 1
    [ "$(sed -n '3p' "$receipt")" = "profile_epoch=$2" ] || return 1
    pin_receipt=$(sed -n '4p' "$receipt")
    case $pin_receipt in peer_pin_sha256=*) ;; *) return 1 ;; esac
    pin_hash=${pin_receipt#peer_pin_sha256=}
    case $pin_hash in *[!0-9a-f]*) return 1 ;; esac
    [ "$(printf %s "$pin_hash" | wc -c)" -eq 64 ] || return 1
    [ "$(sed -n '5p' "$receipt")" = transport=DIRECT ] || return 1
    [ "$(wc -l < "$receipt")" -eq 5 ]
}

start_sidecar() {
    selected_role=$1
    selected_epoch=$2
    profile_hash=$(sha256sum "$state/profiles/direct.conf" | awk '{print $1}') || return 1
    rm -f "$state/run/direct-profile.receipt"
    start_one sidecar env RKA_STATE_ROOT="$state" \
        RKA_PROFILE_PATH="$state/profiles/direct.conf" \
        RKA_EXPECTED_PROFILE_EPOCH="$selected_epoch" \
        RKA_PROFILE_RECEIPT_PATH="$state/run/direct-profile.receipt" \
        "$sidecar" "$selected_role" || return 1
    attempts=0
    while ! profile_receipt_valid "$profile_hash" "$selected_epoch" && [ "$attempts" -lt 5 ]; do
        record_live "$pids/sidecar.pid" || return 1
        sleep 1
        attempts=$((attempts + 1))
    done
    profile_receipt_valid "$profile_hash" "$selected_epoch"
}

start() {
    role=$($control --root "$root" --state-root "$state" boot-decision) || return 1
    case $role in
        DISABLED) return 1 ;;
        DONOR|CANDIDATE)
            profile_valid "$role" || return 1
            direct_profile_valid "$role" "$active_epoch" || return 1
            if [ "${RKA_REQUIRE_DIRECT_READY:-false}" = true ]; then
                direct_ready || return 1
            fi
            ;;
        LOCAL) ;;
        *) return 1 ;;
    esac
    umask 077
    mkdir -p "$pids" || return 1
    chmod 700 "$run" "$pids" || return 1
    [ "$(cat "$state_file" 2>/dev/null)" = FAILED_CRASH_CAP ] && return 1
    printf '%s\n' RUNNING > "$state_file"
    case $role in
        LOCAL) start_one legacy "$daemon" legacy ;;
        DONOR)
            start_one broker "$daemon" broker --rka-role DONOR --rka-no-candidate || { stop; return 1; }
            start_sidecar donor "$active_epoch" || { stop; return 1; }
            ;;
        CANDIDATE)
            start_one broker "$daemon" broker --rka-role CANDIDATE --rka-candidate || { stop; return 1; }
            start_sidecar candidate "$active_epoch" || { stop; return 1; }
            ;;
    esac
}

stop() {
    mkdir -p "$pids" || return 1
    printf '%s\n' STOPPED > "$state_file"
    for name in legacy broker sidecar; do
        record=$pids/$name.pid
        [ -f "$record" ] || continue
        if record_live "$record"; then
            IFS=' ' read -r pid pgid start < "$record"
            kill -TERM "$pid" 2>/dev/null
            kill -TERM "-$pgid" 2>/dev/null
            attempts=0
            while record_live "$record" && [ "$attempts" -lt 3 ]; do
                sleep 1
                attempts=$((attempts + 1))
            done
            if record_live "$record"; then
                IFS=' ' read -r pid pgid start < "$record"
                kill -KILL "$pid" 2>/dev/null
            fi
        fi
        rm -f "$record"
    done
}

status() {
    printf 'state=%s\n' "$(cat "$state_file" 2>/dev/null || printf STOPPED)"
    for name in legacy broker sidecar; do
        if record_live "$pids/$name.pid"; then printf '%s=RUNNING\n' "$name"; else printf '%s=STOPPED\n' "$name"; fi
    done
}

case $command in
    start) start ;;
    stop) stop ;;
    status) status ;;
esac
