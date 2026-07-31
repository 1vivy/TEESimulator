#!/bin/sh

set -f

readonly MAX_CONFIG_BYTES=4096
readonly DEFAULT_ROOT=/data/adb/tricky_store
readonly DEFAULT_STATE_ROOT=/data/adb/teesimulator-rka
readonly CONFIG_DIRECTORY=rka
readonly CONFIG_NAME=role.conf

root=$DEFAULT_ROOT
rka_state_root=$DEFAULT_STATE_ROOT

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$script_directory/rka-paths.sh"

print_inert() {
    printf '%s\n' INERT_INVALID_CONFIG
}

role_is_valid() {
    case $1 in
        LOCAL | DONOR | CANDIDATE | DISABLED) return 0 ;;
        *) return 1 ;;
    esac
}

root_is_trusted() {
    [ -d "$root" ] && [ ! -L "$root" ] || return 1
    [ "$(stat -c %u "$root")" = "$(id -u)" ]
}

config_directory_is_trusted() {
    [ -d "$config_directory" ] && [ ! -L "$config_directory" ] || return 1
    [ "$(stat -c %u "$config_directory")" = "$(id -u)" ]
}

config_is_valid() {
    config_path=$root/$CONFIG_DIRECTORY/$CONFIG_NAME
    [ -f "$config_path" ] && [ ! -L "$config_path" ] || return 1
    [ "$(stat -c '%u:%a' "$config_path")" = "$(id -u):600" ] || return 1
    config_size=$(wc -c < "$config_path") || return 1
    [ "$config_size" -le "$MAX_CONFIG_BYTES" ] || return 1

    version_seen=false
    role_seen=false
    parsed_role=
    while IFS= read -r config_line || [ -n "$config_line" ]; do
        config_key=${config_line%%=*}
        config_value=${config_line#*=}
        [ "$config_key" != "$config_line" ] || return 1
        case $config_key in
            version)
                [ "$version_seen" = false ] && [ "$config_value" = 1 ] || return 1
                version_seen=true
                ;;
            role)
                [ "$role_seen" = false ] && role_is_valid "$config_value" || return 1
                role_seen=true
                parsed_role=$config_value
                ;;
            *) return 1 ;;
        esac
    done < "$config_path"
    [ "$version_seen" = true ] && [ "$role_seen" = true ]
}

read_role() {
    [ ! -L "$root" ] || return 1
    if [ ! -e "$root" ]; then
        printf '%s\n' LOCAL
        return 0
    fi
    root_is_trusted || return 1
    config_directory=$root/$CONFIG_DIRECTORY
    [ ! -L "$config_directory" ] || return 1
    if [ ! -e "$config_directory" ]; then
        printf '%s\n' LOCAL
        return 0
    fi
    config_directory_is_trusted || return 1
    config_path=$config_directory/$CONFIG_NAME
    if [ ! -e "$config_path" ] && [ ! -L "$config_path" ]; then
        printf '%s\n' LOCAL
        return 0
    fi
    config_is_valid || return 1
    printf '%s\n' "$parsed_role"
}

set_role() {
    requested_role=$1
    role_is_valid "$requested_role" || return 1
    umask 077
    [ ! -L "$root" ] || return 1
    if [ ! -e "$root" ]; then
        mkdir -p "$root" || return 1
    fi
    root_is_trusted || return 1
    config_directory=$root/$CONFIG_DIRECTORY
    [ ! -L "$config_directory" ] || return 1
    if [ ! -e "$config_directory" ]; then
        mkdir "$config_directory" || return 1
    fi
    config_directory_is_trusted || return 1
    config_path=$config_directory/$CONFIG_NAME
    [ ! -e "$config_path" ] && [ ! -L "$config_path" ] || config_is_valid || return 1
    rka_atomic_replace "$config_directory" "$config_path" "version=1
role=$requested_role
"
}

usage() {
    printf '%s\n' 'usage: rka-control.sh [--root PATH] [--state-root PATH] {set-role ROLE|initialize|wipe|mutation-states|status|boot-decision|webui-open|webui ACTION NONCE}' >&2
}

webui_invalid_request() {
    printf '%s\n' WEBUI_INVALID_REQUEST
}

webui_nonce_is_valid() {
    case $1 in
        ????????????????????????????????) ;;
        *) return 1 ;;
    esac
    case $1 in
        *[!0123456789abcdef]*) return 1 ;;
        *) return 0 ;;
    esac
}

webui_issue_nonce() {
    webui_role=$(read_role) || return 1
    [ "$webui_role" != DISABLED ] || return 1
    rka_initialize_layout "$webui_role" || return 1
    webui_nonce=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n') || return 1
    webui_nonce_is_valid "$webui_nonce" || return 1
    rka_atomic_replace "$rka_state_root/run" "$rka_state_root/run/webui.nonce" "$webui_nonce
" || return 1
    printf 'nonce=%s\n' "$webui_nonce"
}

webui_nonce_matches() {
    webui_supplied_nonce=$1
    webui_nonce_is_valid "$webui_supplied_nonce" || return 1
    webui_nonce_path=$rka_state_root/run/webui.nonce
    rka_private_file_is_valid "$webui_nonce_path" || return 1
    IFS= read -r webui_stored_nonce < "$webui_nonce_path" || return 1
    webui_nonce_is_valid "$webui_stored_nonce" || return 1
    [ "$webui_supplied_nonce" = "$webui_stored_nonce" ]
}

webui_rotate_nonce() {
    webui_role=$(read_role) || return 1
    rka_layout_is_valid || rka_initialize_layout "$webui_role" || return 1
    webui_nonce=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n') || return 1
    webui_nonce_is_valid "$webui_nonce" || return 1
    rka_atomic_replace "$rka_state_root/run" "$rka_state_root/run/webui.nonce" "$webui_nonce
" || return 1
    printf 'next_nonce=%s\n' "$webui_nonce"
}

webui_phone_role() {
    case $1 in
        DONOR) printf '%s\n' PHONE_A_DONOR ;;
        CANDIDATE) printf '%s\n' PHONE_B_CANDIDATE ;;
        LOCAL) printf '%s\n' LOCAL_LEGACY ;;
        *) printf '%s\n' INERT ;;
    esac
}

webui_profile_epoch() {
    if rka_layout_is_valid && rka_profile_is_valid; then
        printf '%s\n' "$rka_profile_value"
    else
        printf '%s\n' 0
    fi
}

webui_sentinel_status() {
    webui_sentinel_path=$rka_state_root/run/boot-continuity.state
    if rka_private_file_is_valid "$webui_sentinel_path" && [ "$(cat "$webui_sentinel_path")" = LIVE ]; then
        printf '%s\n' LIVE
    else
        printf '%s\n' NOT_READY
    fi
}

webui_quarantine_count() {
    if rka_layout_is_valid; then
        find "$rka_state_root/quarantine" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' '
    else
        printf '%s\n' 0
    fi
}

webui_status() {
    webui_role=$(read_role) || return 1
    printf 'role=%s\n' "$webui_role"
    printf 'phone_role=%s\n' "$(webui_phone_role "$webui_role")"
    printf 'profile_epoch=%s\n' "$(webui_profile_epoch)"
    printf '%s\n' 'direct_profile=DIRECT_NETWORK'
    printf '%s\n' 'direct_readiness=NOT_READY'
    printf '%s\n' 'pairing=UNPAIRED'
    printf '%s\n' 'diagnostic=DIAGNOSTIC_ONLY'
    printf 'sentinel=%s\n' "$(webui_sentinel_status)"
    printf 'quarantine_count=%s\n' "$(webui_quarantine_count)"
}

webui_record_request() {
    webui_request_path=$1
    webui_request_body=$2
    rka_layout_is_valid || return 1
    rka_atomic_replace "$(dirname "$webui_request_path")" "$webui_request_path" "$webui_request_body"
}

webui_mutation_complete() {
    webui_status || return 1
    webui_rotate_nonce
}

webui_request() {
    webui_action=$1
    webui_nonce=$2
    webui_nonce_matches "$webui_nonce" || return 1
    case $webui_action in
        status) webui_status ;;
        role-donor) set_role DONOR && webui_mutation_complete ;;
        role-candidate) set_role CANDIDATE && webui_mutation_complete ;;
        pair-direct) webui_record_request "$rka_state_root/profiles/pair.request" "version=1
action=PAIR_DIRECT
" && webui_mutation_complete ;;
        rotate-pairing) webui_record_request "$rka_state_root/trust/rotate.request" "version=1
action=ROTATE_PAIRING
" && webui_mutation_complete ;;
        start) "$script_directory/rka-supervisor.sh" --root "$root" --state-root "$rka_state_root" start && webui_mutation_complete ;;
        stop) "$script_directory/rka-supervisor.sh" --root "$root" --state-root "$rka_state_root" stop && webui_mutation_complete ;;
        recover-keystore2) webui_record_request "$rka_state_root/journal/recovery.request" "version=1
target=KEYSTORE2
" && printf '%s\n' recovery_target=KEYSTORE2 && webui_mutation_complete ;;
        export-audit) webui_record_request "$rka_state_root/sidecar/audit/export.request" "version=1
action=EXPORT_AUDIT
" && webui_mutation_complete ;;
        cleanup) rka_wipe_runtime && webui_mutation_complete ;;
        quarantine) webui_status ;;
        *) return 1 ;;
    esac
}

while [ $# -gt 0 ]; do
    case $1 in
        --root)
            [ $# -ge 2 ] || exit 2
            root=$2
            shift 2
            ;;
        --state-root)
            [ $# -ge 2 ] || exit 2
            rka_state_root=$2
            shift 2
            ;;
        set-role)
            [ $# -eq 2 ] || exit 2
            set_role "$2" || {
                print_inert
                exit 1
            }
            exit 0
            ;;
        status)
            [ $# -eq 1 ] || exit 2
            role=$(read_role) || {
                print_inert
                exit 1
            }
            printf 'version=1\nrole=%s\n' "$role"
            exit 0
            ;;
        initialize)
            [ $# -eq 1 ] || exit 2
            role=$(read_role) || {
                print_inert
                exit 1
            }
            rka_initialize_layout "$role" || {
                print_inert
                exit 1
            }
            printf '%s\n' READY
            exit 0
            ;;
        wipe)
            [ $# -eq 1 ] || exit 2
            rka_wipe_runtime || {
                print_inert
                exit 1
            }
            printf '%s\n' WIPED
            exit 0
            ;;
        mutation-states)
            [ $# -eq 1 ] || exit 2
            rka_mutation_states
            exit 0
            ;;
        boot-decision)
            [ $# -eq 1 ] || exit 2
            role=$(read_role) || {
                print_inert
                exit 1
            }
            case $role in
                LOCAL | DONOR | CANDIDATE | DISABLED)
                    printf '%s\n' "$role"
                    exit 0
                    ;;
                *) print_inert; exit 1 ;;
            esac
            ;;
        webui-open)
            [ $# -eq 1 ] || exit 2
            webui_issue_nonce || {
                webui_invalid_request
                exit 1
            }
            exit 0
            ;;
        webui)
            [ $# -eq 3 ] || {
                webui_invalid_request
                exit 1
            }
            webui_request "$2" "$3" || {
                webui_invalid_request
                exit 1
            }
            exit 0
            ;;
        *) usage; exit 2 ;;
    esac
done

usage
exit 2
