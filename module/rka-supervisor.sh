#!/system/bin/sh

set -f

readonly DEFAULT_ROOT=/data/adb/tricky_store
readonly DEFAULT_STATE=/data/adb/teesimulator-rka
readonly MAX_CRASHES=3

root=$DEFAULT_ROOT
state=$DEFAULT_STATE
module_directory=$(CDPATH='' cd -- "${0%/*}" && pwd)
control=${RKA_CONTROL:-${0%/*}/rka-control.sh}
daemon=${RKA_DAEMON:-${0%/*}/daemon}
sidecar=${RKA_SIDECAR:-${0%/*}/rka-sidecar}
native_supervisor=${RKA_NATIVE_SUPERVISOR:-${0%/*}/supervisor}
backoff=${RKA_BACKOFF_BASE:-1}
stable_seconds=${RKA_STABLE_SECONDS:-30}
socket_directory_context=${RKA_SOCKET_DIRECTORY_CONTEXT:-u:object_r:teesimulator_rka_socket_dir:s0}
socket_context=${RKA_SOCKET_CONTEXT:-u:object_r:teesimulator_rka_socket:s0}
internal_name=
internal_role=
internal_candidate=
candidate_selector=

usage() { printf '%s\n' 'usage: rka-supervisor.sh [--root PATH] [--state-root PATH] {start|stop|status} [CANDIDATE]' >&2; }

while [ $# -gt 0 ]; do
    case $1 in
        --root) root=$2; shift 2 ;;
        --state-root) state=$2; shift 2 ;;
        start|stop|status) command=$1; shift ;;
        __child-loop)
            [ "$#" -ge 4 ] || { usage; exit 2; }
            command=$1
            internal_name=$2
            internal_role=$3
            internal_candidate=$4
            shift 4
            break
            ;;
        *)
            [ -n "${command:-}" ] && [ -z "$candidate_selector" ] || { usage; exit 2; }
            candidate_selector=$1
            shift
            ;;
    esac
done
[ -n "$command" ] || { usage; exit 2; }

run=$state/run
pids=$run/pids
state_file=$run/supervisor.state
runtime_sidecar=$state/bin/rka-sidecar

candidate_is_valid() {
    [ -n "$1" ] && [ "$(printf %s "$1" | wc -c)" -le 64 ] || return 1
    case $1 in *[!A-Za-z0-9_-]*) return 1 ;; esac
}

donor_candidates() {
    candidate_directory=$state/profiles/direct.d
    if [ ! -e "$candidate_directory" ] && [ ! -L "$candidate_directory" ]; then
        return 0
    fi
    [ -d "$candidate_directory" ] && [ ! -L "$candidate_directory" ] || return 1
    candidate_profiles=$(find "$candidate_directory" -mindepth 1 -maxdepth 1 -name '*.conf' -print | LC_ALL=C sort) || return 1
    while IFS= read -r candidate_profile; do
        [ -n "$candidate_profile" ] || continue
        candidate_name=${candidate_profile##*/}
        candidate_name=${candidate_name%.conf}
        candidate_is_valid "$candidate_name" || return 1
        printf '%s\n' "$candidate_name"
    done <<EOF
$candidate_profiles
EOF
}

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

path_context() {
    ls -Zd "$1" 2>/dev/null | awk '{print $1}'
}

ensure_socket_directory_context() {
    observed_context=$(path_context "$1") || return 1
    [ "$observed_context" = "$socket_directory_context" ] && return 0
    [ "$observed_context" = u:object_r:adb_data_file:s0 ] || return 1
    toybox chcon "$socket_directory_context" "$1" || return 1
    [ "$(path_context "$1")" = "$socket_directory_context" ]
}

ensure_socket_context() {
    observed_context=$(path_context "$1") || return 1
    [ "$observed_context" = "$socket_context" ] && return 0
    case $observed_context in
        u:object_r:unlabeled:s0|u:object_r:adb_data_file:s0|u:object_r:teesimulator_rka_socket_dir:s0) ;;
        *) return 1 ;;
    esac
    toybox chcon "$socket_context" "$1" || return 1
    [ "$(path_context "$1")" = "$socket_context" ]
}

prepare_candidate_child_socket() {
    [ "$1:$2" = sidecar:candidate ] || return 0
    identity_contract_required || return 0
    remove_runtime_socket
}

secure_candidate_child_socket() {
    [ "$1:$2" = sidecar:candidate ] || return 0
    identity_contract_required || return 0
    child=$3
    candidate_socket=$run/sockets/broker.sock
    attempts=0
    while [ "$attempts" -lt 5 ]; do
        proc_stamp "$child" >/dev/null || return 1
        if [ -S "$candidate_socket" ] && [ ! -L "$candidate_socket" ] &&
            [ "$(stat -c '%u:%g:%a' "$candidate_socket")" = "$(id -u):$(id -g):600" ] &&
            ensure_socket_context "$candidate_socket"; then
            return 0
        fi
        sleep 1
        attempts=$((attempts + 1))
    done
    return 1
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
        broker|broker-*)
            executable=/system/bin/app_process64
            expected_cmdline="/system/bin/app_process64
/system/bin
org.matrix.TEESimulator.App
--rka-role
$selected_role"
            ;;
        sidecar|sidecar-*)
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

record_generation_live() {
    [ -f "$1" ] || return 1
    IFS=' ' read -r pid pgid start < "$1" || return 1
    [ "$(proc_stamp "$pid")" = "$pid $pgid $start" ] || return 1
}

record_live() {
    record_generation_live "$1" || return 1
    record_name=${1##*/}
    record_name=${record_name%.pid}
    case $record_name in legacy) return 0 ;; esac
    identity_contract_required || return 0
    identity=$pids/$record_name.identity
    [ -f "$identity" ] && [ ! -L "$identity" ] || return 1
    [ "$(stat -c '%u:%a' "$identity")" = "$(id -u):600" ] || return 1
    [ "$(wc -l < "$identity")" -eq 10 ] || return 1
    [ "$(sed -n '1p' "$identity")" = version=1 ] || return 1
    [ "$(sed -n '4p' "$identity")" = "uid=$(id -u)" ] || return 1
    [ "$(sed -n '5p' "$identity")" = "gid=$(id -g)" ] || return 1
    [ "$(sed -n '6p' "$identity")" = "pid=$pid" ] || return 1
    [ "$(sed -n '7p' "$identity")" = "start_time_ticks=$start" ] || return 1
    identity_inode_line=$(sed -n '8p' "$identity") || return 1
    case $identity_inode_line in executable_inode=*) ;; *) return 1 ;; esac
    identity_inode=${identity_inode_line#executable_inode=}
    case $identity_inode in ''|*[!0-9]*) return 1 ;; esac
    identity_path_line=$(sed -n '9p' "$identity") || return 1
    case $identity_path_line in executable_path=*) ;; *) return 1 ;; esac
    identity_path=${identity_path_line#executable_path=}
    [ -n "$identity_path" ] || return 1
    [ "$(readlink "/proc/$pid/exe")" = "$identity_path" ] || return 1
    [ "$(stat -Lc '%i' "/proc/$pid/exe")" = "$identity_inode" ]
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
    profile=${3:-$state/profiles/direct.conf}
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

write_supervisor_state() {
    target_state_file=$1
    next_state=$2
    [ ! -L "$target_state_file" ] || return 1
    printf '%s\n' "$next_state" > "$target_state_file" || return 1
    chmod 600 "$target_state_file"
}

child_loop() {
    name=$1
    selected_role=$2
    shift 2
    crashes=0
    while :; do
        prepare_candidate_child_socket "$name" "$selected_role" || {
            printf '%s\n' FAILED_CRASH_CAP > "$state_file"
            rm -f "$pids/$name.pid" "$pids/$name.identity"
            exit 1
        }
        started=$(date +%s)
        setsid "$@" &
        child=$!
        if ! publish_identity "$name" "$selected_role" "$child" ||
            ! secure_candidate_child_socket "$name" "$selected_role" "$child"; then
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
    selected_candidate=$3
    shift 3
    if record_live "$pids/$name.pid"; then return 0; fi
    rm -f "$pids/$name.pid" "$pids/$name.identity"
    [ -x "$native_supervisor" ] || return 1
    "$native_supervisor" --detach "$module_directory/rka-supervisor.sh" \
        --root "$root" --state-root "$state" __child-loop "$name" "$selected_role" \
        "$selected_candidate" "$@" || return 1
    attempts=0
    while ! record_live "$pids/$name.pid" && [ "$attempts" -lt 100 ]; do
        sleep 0.1
        attempts=$((attempts + 1))
    done
    record_live "$pids/$name.pid"
}

profile_receipt_valid() {
    receipt=$1
    shift
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
    selected_candidate=${3:-}
    if [ -n "$selected_candidate" ]; then
        profile_path=$state/profiles/direct.d/$selected_candidate.conf
        receipt_path=$state/run/direct-profile-$selected_candidate.receipt
        process_name=sidecar-$selected_candidate
        socket_path=$state/run/sockets/broker-$selected_candidate.sock
    else
        profile_path=$state/profiles/direct.conf
        receipt_path=$state/run/direct-profile.receipt
        process_name=sidecar
        socket_path=$state/run/sockets/broker.sock
    fi
    profile_hash=$(sha256sum "$profile_path" | awk '{print $1}') || return 1
    if record_live "$pids/$process_name.pid" &&
        profile_receipt_valid "$receipt_path" "$profile_hash" "$selected_epoch"; then
        return 0
    fi
    rm -f "$receipt_path"
    start_one "$process_name" "$selected_role" "$selected_candidate" env RKA_STATE_ROOT="$state" \
        RKA_PROFILE_PATH="$profile_path" \
        RKA_EXPECTED_PROFILE_EPOCH="$selected_epoch" \
        RKA_PROFILE_RECEIPT_PATH="$receipt_path" \
        RKA_DONOR_SOCKET="$socket_path" \
        "$runtime_sidecar" --role "$selected_role" || return 1
    attempts=0
    while ! profile_receipt_valid "$receipt_path" "$profile_hash" "$selected_epoch" && [ "$attempts" -lt 5 ]; do
        record_live "$pids/$process_name.pid" || return 1
        sleep 1
        attempts=$((attempts + 1))
    done
    profile_receipt_valid "$receipt_path" "$profile_hash" "$selected_epoch"
}

wait_sidecar_socket() {
    selected_candidate=${1:-}
    if [ -n "$selected_candidate" ]; then
        process_name=sidecar-$selected_candidate
    else
        process_name=sidecar
    fi
    attempts=0
    while ! runtime_socket_ready "$selected_candidate" && [ "$attempts" -lt 5 ]; do
        record_live "$pids/$process_name.pid" || return 1
        sleep 1
        attempts=$((attempts + 1))
    done
    runtime_socket_ready "$selected_candidate"
}

start_donor_candidate() {
    selected_candidate=$1
    selected_state_file=$run/supervisor-$selected_candidate.state
    write_supervisor_state "$selected_state_file" STARTING || return 1
    profile_path=$state/profiles/direct.d/$selected_candidate.conf
    direct_profile_valid DONOR "$active_epoch" "$profile_path" || return 1
    start_sidecar donor "$active_epoch" "$selected_candidate" || return 1
    start_one "broker-$selected_candidate" donor "$selected_candidate" env \
        RKA_DONOR_SOCKET="$run/sockets/broker-$selected_candidate.sock" \
        "$daemon" "$module_directory" --rka-role donor || return 1
    wait_sidecar_socket "$selected_candidate" || return 1
    candidate_graph_ready "$selected_candidate" || return 1
    write_supervisor_state "$selected_state_file" RUNNING
}

runtime_socket_ready() {
    selected_candidate=${1:-}
    if [ -n "$selected_candidate" ]; then
        candidate_is_valid "$selected_candidate" || return 1
        selected_socket=$run/sockets/broker-$selected_candidate.sock
    else
        selected_socket=$run/sockets/broker.sock
    fi
    [ -S "$selected_socket" ] && [ ! -L "$selected_socket" ] &&
        [ "$(stat -c '%u:%g:%a' "$selected_socket")" = "$(id -u):$(id -g):600" ]
}

candidate_graph_ready() {
    selected_candidate=$1
    candidate_is_valid "$selected_candidate" || return 1
    profile_path=$state/profiles/direct.d/$selected_candidate.conf
    receipt_path=$run/direct-profile-$selected_candidate.receipt
    profile_hash=$(sha256sum "$profile_path" | awk '{print $1}') || return 1
    record_live "$pids/broker-$selected_candidate.pid" &&
        record_live "$pids/sidecar-$selected_candidate.pid" &&
        profile_receipt_valid "$receipt_path" "$profile_hash" "$active_epoch" &&
        runtime_socket_ready "$selected_candidate"
}

global_graph_ready() {
    selected_role=$1
    case $selected_role in
        LOCAL) record_live "$pids/legacy.pid" ;;
        DONOR|CANDIDATE)
            profile_path=$state/profiles/direct.conf
            receipt_path=$run/direct-profile.receipt
            profile_hash=$(sha256sum "$profile_path" | awk '{print $1}') || return 1
            record_live "$pids/broker.pid" &&
                record_live "$pids/sidecar.pid" &&
                profile_receipt_valid "$receipt_path" "$profile_hash" "$active_epoch" &&
                runtime_socket_ready
            ;;
        *) return 1 ;;
    esac
}

all_candidate_graphs_ready() {
    selected_candidates=$(donor_candidates) || return 1
    [ -n "$selected_candidates" ] || return 1
    while IFS= read -r selected_candidate; do
        [ -n "$selected_candidate" ] || continue
        candidate_graph_ready "$selected_candidate" || return 1
    done <<EOF
$selected_candidates
EOF
}

start() {
    if ! record_live "$pids/legacy.pid" &&
        ! record_live "$pids/broker.pid" &&
        ! record_live "$pids/sidecar.pid"; then
        remove_runtime_socket || return 1
    fi
    role=$($control --root "$root" --state-root "$state" boot-decision) || return 1
    case $role in
        DISABLED) return 1 ;;
        DONOR)
            profile_valid "$role" || return 1
            if [ "${RKA_REQUIRE_DIRECT_READY:-false}" = true ]; then
                direct_ready || return 1
            fi
            ;;
        CANDIDATE)
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
    socket_directory=$run/sockets
    mkdir -p "$pids" "$socket_directory" || return 1
    chmod 700 "$run" "$pids" "$socket_directory" || return 1
    private_directory "$socket_directory" || return 1
    ensure_socket_directory_context "$socket_directory" || return 1
    [ "$(cat "$state_file" 2>/dev/null)" = FAILED_CRASH_CAP ] && return 1
    write_supervisor_state "$state_file" STARTING || return 1
    case $role in
        LOCAL) start_one legacy '' '' "$daemon" "$module_directory" ;;
        DONOR)
            materialize_sidecar || { stop; return 1; }
            selected_candidates=$(donor_candidates) || { stop; return 1; }
            if [ -n "$selected_candidates" ]; then
                while IFS= read -r selected_candidate; do
                    [ -n "$selected_candidate" ] || continue
                    start_donor_candidate "$selected_candidate" || { stop; return 1; }
                done <<EOF
$selected_candidates
EOF
            else
                direct_profile_valid DONOR "$active_epoch" || { stop; return 1; }
                start_sidecar donor "$active_epoch" || { stop; return 1; }
                start_one broker donor '' "$daemon" "$module_directory" --rka-role donor || { stop; return 1; }
                wait_sidecar_socket || { stop; return 1; }
            fi
            ;;
        CANDIDATE)
            materialize_sidecar || { stop; return 1; }
            start_sidecar candidate "$active_epoch" || { stop; return 1; }
            wait_sidecar_socket || { stop; return 1; }
            start_one broker candidate '' "$daemon" "$module_directory" --rka-role candidate || { stop; return 1; }
            ;;
    esac
    case $role in
        DONOR)
            if [ -n "${selected_candidates:-}" ]; then
                write_supervisor_state "$state_file" RUNNING
            else
                global_graph_ready "$role" && write_supervisor_state "$state_file" RUNNING
            fi
            ;;
        LOCAL|CANDIDATE)
            global_graph_ready "$role" && write_supervisor_state "$state_file" RUNNING
            ;;
    esac
}

stop() {
    mkdir -p "$pids" || return 1
    if [ -n "$candidate_selector" ]; then
        candidate_is_valid "$candidate_selector" || return 1
        stop_names="broker-$candidate_selector sidecar-$candidate_selector"
        selected_state_file=$run/supervisor-$candidate_selector.state
    else
        stop_names="legacy broker sidecar"
        donor_pid_paths=$(find "$pids" -mindepth 1 -maxdepth 1 \( -name 'broker-*.pid' -o -name 'sidecar-*.pid' \) -print 2>/dev/null) || return 1
        while IFS= read -r donor_pid_path; do
            [ -n "$donor_pid_path" ] || continue
            donor_pid_name=${donor_pid_path##*/}
            stop_names="$stop_names ${donor_pid_name%.pid}"
        done <<EOF
$donor_pid_paths
EOF
        selected_state_file=$state_file
    fi
    stopping_state_files=$selected_state_file
    if [ -z "$candidate_selector" ]; then
        candidate_state_paths=$(find "$run" -mindepth 1 -maxdepth 1 -name 'supervisor-*.state' -print 2>/dev/null) || return 1
        while IFS= read -r candidate_state_path; do
            [ -n "$candidate_state_path" ] || continue
            candidate_state_name=${candidate_state_path##*/}
            stopping_candidate=${candidate_state_name#supervisor-}
            stopping_candidate=${stopping_candidate%.state}
            candidate_is_valid "$stopping_candidate" || return 1
            stopping_state_files="$stopping_state_files $candidate_state_path"
        done <<EOF
$candidate_state_paths
EOF
    fi
    for stopping_state_file in $stopping_state_files; do
        write_supervisor_state "$stopping_state_file" STOPPING || return 1
    done
    for name in $stop_names; do
        record=$pids/$name.pid
        [ -f "$record" ] || {
            rm -f "$pids/$name.identity"
            continue
        }
        if record_generation_live "$record" && ! record_live "$record"; then
            return 1
        fi
        if record_live "$record"; then
            IFS=' ' read -r pid pgid start < "$record"
            kill -TERM "$pid" 2>/dev/null
            kill -TERM "-$pgid" 2>/dev/null
            attempts=0
            while record_generation_live "$record" && [ "$attempts" -lt 3 ]; do
                sleep 1
                attempts=$((attempts + 1))
            done
            if record_generation_live "$record"; then
                IFS=' ' read -r pid pgid start < "$record"
                kill -KILL "$pid" 2>/dev/null
                attempts=0
                while record_generation_live "$record" && [ "$attempts" -lt 3 ]; do
                    sleep 1
                    attempts=$((attempts + 1))
                done
                record_generation_live "$record" && return 1
            fi
        fi
        rm -f "$record" "$pids/$name.identity"
    done
    remove_runtime_socket "$candidate_selector" || return 1
    if [ -z "$candidate_selector" ]; then
        stopped_candidates=$(donor_candidates) || return 1
        while IFS= read -r stopped_candidate; do
            [ -n "$stopped_candidate" ] || continue
            remove_runtime_socket "$stopped_candidate" || return 1
        done <<EOF
$stopped_candidates
EOF
    fi
    for stopping_state_file in $stopping_state_files; do
        write_supervisor_state "$stopping_state_file" STOPPED || return 1
    done
}

remove_runtime_socket() {
    selected_candidate=${1:-}
    socket_directory=$run/sockets
    if [ -n "$selected_candidate" ]; then
        candidate_is_valid "$selected_candidate" || return 1
        socket_name=broker-$selected_candidate.sock
    else
        socket_name=broker.sock
    fi
    socket_path=$socket_directory/$socket_name
    [ ! -e "$socket_directory" ] && [ ! -L "$socket_directory" ] && return 0
    private_directory "$socket_directory" || return 1
    ensure_socket_directory_context "$socket_directory" || return 1
    if [ -e "$socket_path" ] || [ -L "$socket_path" ]; then
        remove_owned_runtime_socket "$socket_path" || return 1
    fi
    runtime_tombstones=$(find "$socket_directory" -mindepth 1 -maxdepth 1 -name ".$socket_name.delete-*" -print) || return 1
    while IFS= read -r runtime_tombstone; do
        [ -n "$runtime_tombstone" ] || continue
        tombstone_name=${runtime_tombstone##*/}
        tombstone_token=${tombstone_name#.$socket_name.delete-}
        [ "$tombstone_name" = ".$socket_name.delete-$tombstone_token" ] || return 1
        [ "$(printf %s "$tombstone_token" | wc -c)" -eq 32 ] || return 1
        case $tombstone_token in *[!0-9a-f]*) return 1 ;; esac
        remove_owned_runtime_socket "$runtime_tombstone" || return 1
    done <<EOF
$runtime_tombstones
EOF
    sync -f "$socket_directory"
}

remove_owned_runtime_socket() {
    socket_path=$1
    [ -S "$socket_path" ] && [ ! -L "$socket_path" ] || return 1
    socket_owner=$(id -u):$(id -g)
    case $(stat -c '%u:%g:%a' "$socket_path") in
        "$socket_owner:600"|"$socket_owner:700") ;;
        *) return 1 ;;
    esac
    ensure_socket_context "$socket_path" || return 1
    rm -f "$socket_path" || return 1
}

component_status() {
    selected_record=$1
    if record_live "$selected_record"; then
        component_state=RUNNING
    elif record_generation_live "$selected_record"; then
        component_state=UNVERIFIABLE
    else
        component_state=STOPPED
    fi
}

status_state() {
    selected_marker=$1
    shift
    selected_state=$selected_marker
    case $selected_marker in
        RUNNING)
            for selected_component in "$@"; do
                [ "$selected_component" = RUNNING ] || selected_state=NOT_READY
            done
            ;;
        STOPPED)
            for selected_component in "$@"; do
                [ "$selected_component" = STOPPED ] || selected_state=NOT_READY
            done
            ;;
    esac
}

status() {
    if [ -n "$candidate_selector" ]; then
        candidate_is_valid "$candidate_selector" || return 1
        state_file=$run/supervisor-$candidate_selector.state
        component_status "$pids/broker-$candidate_selector.pid"
        broker_state=$component_state
        component_status "$pids/sidecar-$candidate_selector.pid"
        sidecar_state=$component_state
        status_state "$(cat "$state_file" 2>/dev/null || printf STOPPED)" \
            "$broker_state" "$sidecar_state"
        if [ "$selected_state" = RUNNING ]; then
            profile_valid DONOR && candidate_graph_ready "$candidate_selector" ||
                selected_state=NOT_READY
        fi
        printf 'state=%s\n' "$selected_state"
        for kind in broker sidecar; do
            name=$kind-$candidate_selector
            component_status "$pids/$name.pid"
            printf '%s=%s\n' "$kind" "$component_state"
        done
        return 0
    fi
    component_status "$pids/legacy.pid"
    legacy_state=$component_state
    component_status "$pids/broker.pid"
    broker_state=$component_state
    component_status "$pids/sidecar.pid"
    sidecar_state=$component_state
    status_role=$(sed -n '2s/^role=//p' "$state/profiles/active.conf" 2>/dev/null)
    status_marker=$(cat "$state_file" 2>/dev/null || printf STOPPED)
    case $status_role in
        LOCAL) status_state "$status_marker" "$legacy_state" ;;
        DONOR)
            status_candidates=$(donor_candidates) || return 1
            if [ "$status_marker" = RUNNING ] && [ -n "$status_candidates" ]; then
                selected_state=RUNNING
            else
                status_state "$status_marker" "$broker_state" "$sidecar_state"
            fi
            ;;
        CANDIDATE) status_state "$status_marker" "$broker_state" "$sidecar_state" ;;
        *) status_state "$status_marker" "$legacy_state" "$broker_state" "$sidecar_state" ;;
    esac
    if [ "$selected_state" = RUNNING ]; then
        case $status_role in
            LOCAL) global_graph_ready LOCAL || selected_state=NOT_READY ;;
            DONOR)
                profile_valid DONOR || selected_state=NOT_READY
                if [ "$selected_state" = RUNNING ]; then
                    if [ -n "${status_candidates:-}" ]; then
                        all_candidate_graphs_ready || selected_state=NOT_READY
                    else
                        global_graph_ready DONOR || selected_state=NOT_READY
                    fi
                fi
                ;;
            CANDIDATE)
                profile_valid CANDIDATE && global_graph_ready CANDIDATE ||
                    selected_state=NOT_READY
                ;;
            *) selected_state=NOT_READY ;;
        esac
    fi
    printf 'state=%s\n' "$selected_state"
    for name in legacy broker sidecar; do
        component_status "$pids/$name.pid"
        printf '%s=%s\n' "$name" "$component_state"
    done
}

case $command in
    start) start ;;
    stop) stop ;;
    status) status ;;
    __child-loop)
        [ "${RKA_INTERNAL_CHILD_LOOP:-}" = 1 ] || exit 2
        case $internal_name:$internal_role in
            legacy:|broker:donor|broker:candidate|sidecar:donor|sidecar:candidate) ;;
            broker-*:donor|sidecar-*:donor)
                candidate_is_valid "$internal_candidate" || exit 2
                [ "$internal_name" = "${internal_name%%-*}-$internal_candidate" ] || exit 2
                state_file=$run/supervisor-$internal_candidate.state
                ;;
            *) exit 2 ;;
        esac
        [ "$#" -gt 0 ] || exit 2
        child_loop "$internal_name" "$internal_role" "$@"
        ;;
esac
