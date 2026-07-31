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
    case $(sed -n '3p' "$profile") in profile_epoch=[0-9]*) ;; *) return 1 ;; esac
    [ "$(wc -l < "$profile")" -eq 3 ]
}

write_record() {
    name=$1 child=$2
    child_stamp=$(proc_stamp "$child") || return 1
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
        write_record "$name" "$child" || exit 1
        wait "$child"
        [ "$(cat "$state_file" 2>/dev/null)" = RUNNING ] || exit 0
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

start() {
    role=$($control --root "$root" --state-root "$state" boot-decision) || return 1
    case $role in
        DISABLED) return 1 ;;
        DONOR|CANDIDATE) profile_valid "$role" || return 1 ;;
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
            start_one sidecar "$sidecar" donor || { stop; return 1; }
            ;;
        CANDIDATE)
            start_one broker "$daemon" broker --rka-role CANDIDATE --rka-candidate || { stop; return 1; }
            start_one sidecar "$sidecar" candidate || { stop; return 1; }
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
