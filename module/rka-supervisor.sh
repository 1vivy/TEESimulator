#!/system/bin/sh

set -f

readonly DEFAULT_ROOT=/data/adb/tricky_store
readonly DEFAULT_STATE=/data/adb/teesimulator-rka
readonly MAX_CRASHES=3

root=$DEFAULT_ROOT
state=$DEFAULT_STATE
module_directory=${0%/*}
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
runtime_sidecar=$state/bin/rka-sidecar

proc_stamp() {
    [ -r "/proc/$1/stat" ] || return 1
    awk '{print $1 " " $5 " " $22}' "/proc/$1/stat"
}

identity_contract_required() {
    [ "$daemon" = "$module_directory/daemon" ] && [ "$sidecar" = "$module_directory/rka-sidecar" ]
}

private_directory() {
    [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = "$(id -u):700" ]
}

materialize_sidecar() {
    [ -f "$sidecar" ] && [ ! -L "$sidecar" ] || return 1
    if record_live "$pids/broker.pid" || record_live "$pids/sidecar.pid"; then
        [ -f "$runtime_sidecar" ] && [ ! -L "$runtime_sidecar" ] || return 1
        return 0
    fi
    if identity_contract_required; then
        [ "$(stat -c '%u:%a' "$sidecar")" = "$(id -u):755" ] || return 1
    fi
    bin=$state/bin
    if [ ! -e "$bin" ] && [ ! -L "$bin" ]; then
        mkdir "$bin" || return 1
        chmod 700 "$bin" || return 1
    fi
    private_directory "$bin" || return 1
    temporary=$(mktemp "$bin/.rka-sidecar.XXXXXX") || return 1
    trap 'rm -f "$temporary"' EXIT HUP INT TERM
    cp "$sidecar" "$temporary" || return 1
    chmod 700 "$temporary" || return 1
    sync -f "$temporary" || return 1
    mv -f "$temporary" "$runtime_sidecar" || return 1
    sync -f "$bin" || return 1
    trap - EXIT HUP INT TERM
}

identity_nonce() {
    dd if=/dev/urandom bs=32 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n'
}

process_identity_matches() {
    child=$1
    executable=$2
    expected_cmdline=$3
    [ "$(readlink "/proc/$child/exe")" = "$executable" ] || return 1
    observed_cmdline=$(tr '\000' '\n' < "/proc/$child/cmdline") || return 1
    [ "$observed_cmdline" = "$expected_cmdline" ]
}

publish_identity() {
    name=$1
    selected_role=$2
    child=$3
    identity_contract_required || return 0
    child_stamp=$(proc_stamp "$child") || return 1
    IFS=' ' read -r _ _ start_time <<EOF
$child_stamp
EOF
    case $name in
        broker)
            executable=/system/bin/app_process64
            expected_cmdline="/system/bin/app_process64
/system/bin
org.matrix.TEESimulator.App
--rka-role
$selected_role"
            ;;
        sidecar)
            executable=$runtime_sidecar
            expected_cmdline="$runtime_sidecar
--role
$selected_role"
            ;;
        *) return 0 ;;
    esac
    attempts=0
    while ! process_identity_matches "$child" "$executable" "$expected_cmdline" && [ "$attempts" -lt 5 ]; do
        [ -d "/proc/$child" ] || return 1
        sleep 1
        attempts=$((attempts + 1))
    done
    process_identity_matches "$child" "$executable" "$expected_cmdline" || return 1
    executable_inode=$(stat -c '%i' "$executable") || return 1
    [ "$(stat -Lc '%i' "/proc/$child/exe")" = "$executable_inode" ] || return 1
    nonce=$(identity_nonce) || return 1
    [ "$(printf %s "$nonce" | wc -c)" -eq 64 ] || return 1
    case $nonce in *[!0-9a-f]*) return 1 ;; esac
    temporary=$(mktemp "$pids/.${name}.identity.XXXXXX") || return 1
    trap 'rm -f "$temporary"' EXIT HUP INT TERM
    printf 'version=1\ngeneration=%s\nlaunch_nonce=%s\nuid=%s\ngid=%s\npid=%s\nstart_time_ticks=%s\nexecutable_inode=%s\nexecutable_path=%s\nrole=%s\n' \
        "$(date +%s)" "$nonce" "$(id -u)" "$(id -g)" "$child" "$start_time" \
        "$executable_inode" "$executable" "$(printf %s "$selected_role" | tr '[:lower:]' '[:upper:]')" > "$temporary" || return 1
    chmod 600 "$temporary" || return 1
    sync -f "$temporary" || return 1
    mv -f "$temporary" "$pids/$name.identity" || return 1
    sync -f "$pids" || return 1
    trap - EXIT HUP INT TERM
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
    [ "$(sed -n '1p' "$profile")" = version=2 ] || return 1
    [ "$(sed -n '2p' "$profile")" = "role=$1" ] || return 1
    [ "$(sed -n '3p' "$profile")" = "profile_epoch=$2" ] || return 1
    [ "$(sed -n '4p' "$profile")" = dial_mode=DONOR_DIALS ] || return 1
    endpoint_line=$(sed -n '5p' "$profile")
    case $endpoint_line in dial_endpoint=*) ;; *) return 1 ;; esac
    endpoint=${endpoint_line#dial_endpoint=}
    case $endpoint in ''|*[!0-9.]*) return 1 ;; esac
    listen_line=$(sed -n '6p' "$profile")
    case $listen_line in listen_interface=*) ;; *) return 1 ;; esac
    listen=${listen_line#listen_interface=}
    case $listen in ''|*[!0-9.]*) return 1 ;; esac
    pin_line=$(sed -n '7p' "$profile")
    case $pin_line in peer_spki_sha256=*) ;; *) return 1 ;; esac
    pin=${pin_line#peer_spki_sha256=}
    case $pin in *[!0-9a-f]*) return 1 ;; esac
    [ "$(printf %s "$pin" | wc -c)" -eq 64 ] || return 1
    [ "$(sed -n '8p' "$profile")" = transport=DIRECT ] || return 1
    [ "$(wc -l < "$profile")" -eq 8 ]
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
    selected_role=$2
    shift 2
    crashes=0
    while :; do
        started=$(date +%s)
        setsid "$@" &
        child=$!
        if ! publish_identity "$name" "$selected_role" "$child"; then
            kill -TERM "$child" 2>/dev/null
            wait "$child" 2>/dev/null
            rm -f "$pids/$name.pid" "$pids/$name.identity"
        else
            write_record "$name" "$child" || :
            wait "$child"
        fi
        rm -f "$pids/$name.identity"
        [ "$(cat "$state_file" 2>/dev/null)" = RUNNING ] || exit 0
        if restart_blocked; then
            printf '%s\n' QUARANTINED_AMBIGUOUS_MUTATION > "$state_file"
            rm -f "$pids/$name.pid" "$pids/$name.identity"
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
            rm -f "$pids/$name.pid" "$pids/$name.identity"
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
    selected_role=$2
    shift 2
    if record_live "$pids/$name.pid"; then return 0; fi
    rm -f "$pids/$name.pid" "$pids/$name.identity"
    child_loop "$name" "$selected_role" "$@" </dev/null >/dev/null 2>&1 &
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
    [ "$(sed -n '5p' "$receipt")" = dial_mode=DONOR_DIALS ] || return 1
    [ "$(sed -n '6p' "$receipt")" = transport=DIRECT ] || return 1
    [ "$(wc -l < "$receipt")" -eq 6 ]
}

start_sidecar() {
    selected_role=$1
    selected_epoch=$2
    profile_hash=$(sha256sum "$state/profiles/direct.conf" | awk '{print $1}') || return 1
    if record_live "$pids/sidecar.pid" && profile_receipt_valid "$profile_hash" "$selected_epoch"; then
        return 0
    fi
    rm -f "$state/run/direct-profile.receipt"
    start_one sidecar "$selected_role" env RKA_STATE_ROOT="$state" \
        RKA_PROFILE_PATH="$state/profiles/direct.conf" \
        RKA_EXPECTED_PROFILE_EPOCH="$selected_epoch" \
        RKA_PROFILE_RECEIPT_PATH="$state/run/direct-profile.receipt" \
        "$runtime_sidecar" --role "$selected_role" || return 1
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
        LOCAL) start_one legacy '' "$daemon" legacy ;;
        DONOR)
            materialize_sidecar || { stop; return 1; }
            start_sidecar donor "$active_epoch" || { stop; return 1; }
            start_one broker donor "$daemon" "$module_directory" --rka-role donor || { stop; return 1; }
            ;;
        CANDIDATE)
            materialize_sidecar || { stop; return 1; }
            start_sidecar candidate "$active_epoch" || { stop; return 1; }
            start_one broker candidate "$daemon" "$module_directory" --rka-role candidate || { stop; return 1; }
            ;;
    esac
}

stop() {
    mkdir -p "$pids" || return 1
    printf '%s\n' STOPPED > "$state_file"
    for name in legacy broker sidecar; do
        record=$pids/$name.pid
        [ -f "$record" ] || {
            rm -f "$pids/$name.identity"
            continue
        }
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
        rm -f "$record" "$pids/$name.identity"
    done
    remove_runtime_socket
}

remove_runtime_socket() {
    socket_directory=$run/sockets
    socket_path=$socket_directory/broker.sock
    [ ! -e "$socket_directory" ] && [ ! -L "$socket_directory" ] && return 0
    private_directory "$socket_directory" || return 1
    [ ! -e "$socket_path" ] && [ ! -L "$socket_path" ] && return 0
    [ -S "$socket_path" ] && [ ! -L "$socket_path" ] || return 1
    [ "$(stat -c '%u:%g:%a' "$socket_path")" = "$(id -u):$(id -g):600" ] || return 1
    rm -f "$socket_path" || return 1
    sync -f "$socket_directory"
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
