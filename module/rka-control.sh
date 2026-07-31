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

webui_next_nonce() {
    webui_generated_nonce=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n') || return 1
    webui_nonce_is_valid "$webui_generated_nonce" || return 1
    printf '%s\n' "$webui_generated_nonce"
}

webui_release_mutation_lock() {
    [ "${webui_mutation_lock_held:-false}" = true ] || return 0
    rmdir "$rka_state_root/run/webui.mutation.lock" || return 1
    webui_mutation_lock_held=false
}

webui_consume_nonce() {
    webui_supplied_nonce=$1
    webui_nonce_is_valid "$webui_supplied_nonce" || return 1
    rka_layout_is_valid || return 1
    umask 077
    mkdir "$rka_state_root/run/webui.mutation.lock" || return 1
    chmod 700 "$rka_state_root/run/webui.mutation.lock" || {
        rmdir "$rka_state_root/run/webui.mutation.lock"
        return 1
    }
    webui_mutation_lock_held=true
    webui_nonce_matches "$webui_supplied_nonce" || {
        webui_release_mutation_lock
        return 1
    }
    webui_new_nonce=$(webui_next_nonce) || {
        webui_release_mutation_lock
        return 1
    }
    rka_atomic_replace "$rka_state_root/run" "$rka_state_root/run/webui.nonce" "$webui_new_nonce
" || {
        webui_release_mutation_lock
        return 1
    }
}

webui_phone_role() {
    case $1 in
        DONOR) printf '%s\n' PHONE_A_DONOR ;;
        CANDIDATE) printf '%s\n' PHONE_B_CANDIDATE ;;
        LOCAL) printf '%s\n' LOCAL_LEGACY ;;
        *) printf '%s\n' INERT ;;
    esac
}

webui_read_active_profile() {
    rka_layout_is_valid && rka_profile_is_valid || return 1
    webui_profile_role=
    webui_profile_epoch=
    while IFS= read -r webui_profile_line || [ -n "$webui_profile_line" ]; do
        case $webui_profile_line in
            role=*) webui_profile_role=${webui_profile_line#role=} ;;
            profile_epoch=*) webui_profile_epoch=${webui_profile_line#profile_epoch=} ;;
        esac
    done < "$rka_state_root/profiles/$RKA_PROFILE_NAME"
    role_is_valid "$webui_profile_role" || return 1
    case $webui_profile_epoch in '' | *[!0-9]*) return 1 ;; esac
}

webui_sentinel_status() {
    webui_sentinel_path=$rka_state_root/run/boot-continuity.state
    webui_sentinel=NOT_READY
    if rka_private_file_is_valid "$webui_sentinel_path" && [ "$(wc -c < "$webui_sentinel_path")" -le 16 ] && [ "$(cat "$webui_sentinel_path")" = LIVE ]; then
        webui_sentinel=LIVE
    fi
}

webui_quarantine_count() {
    if rka_layout_is_valid; then
        webui_quarantine_total=$(find "$rka_state_root/quarantine" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ') || return 1
        case $webui_quarantine_total in '' | *[!0-9]*) return 1 ;; esac
        [ "$webui_quarantine_total" -le 9999 ] || return 1
        printf '%s\n' "$webui_quarantine_total"
    else
        printf '%s\n' 0
    fi
}

webui_pair_request_is_valid() {
    webui_request_path=$rka_state_root/profiles/pair.request
    rka_private_file_is_valid "$webui_request_path" || return 1
    [ "$(wc -c < "$webui_request_path")" -le 64 ] || return 1
    [ "$(cat "$webui_request_path")" = "version=1
action=PAIR_DIRECT" ]
}

webui_runtime_state() {
    webui_runtime=STOPPED
    webui_runtime_path=$rka_state_root/run/supervisor.state
    if [ ! -e "$webui_runtime_path" ] && [ ! -L "$webui_runtime_path" ]; then
        return 0
    fi
    rka_private_file_is_valid "$webui_runtime_path" || return 1
    [ "$(wc -c < "$webui_runtime_path")" -le 64 ] || return 1
    webui_runtime=$(cat "$webui_runtime_path") || return 1
    case $webui_runtime in RUNNING|STOPPED|FAILED_CRASH_CAP|QUARANTINED_AMBIGUOUS_MUTATION) return 0 ;; *) return 1 ;; esac
}

webui_transport_key_is_valid() {
    webui_transport_key_path=$rka_state_root/secrets/transport.key
    rka_private_file_is_valid "$webui_transport_key_path" || return 1
    webui_transport_key_bytes=$(wc -c < "$webui_transport_key_path") || return 1
    case $webui_transport_key_bytes in '' | *[!0-9]*) return 1 ;; esac
    [ "$webui_transport_key_bytes" -ge 16 ] && [ "$webui_transport_key_bytes" -le 16384 ]
}

webui_transport_trust_is_valid() {
    webui_transport_trust_path=$rka_state_root/trust/transport-trust.pem
    rka_private_file_is_valid "$webui_transport_trust_path" || return 1
    webui_transport_trust_bytes=$(wc -c < "$webui_transport_trust_path") || return 1
    case $webui_transport_trust_bytes in '' | *[!0-9]*) return 1 ;; esac
    [ "$webui_transport_trust_bytes" -ge 64 ] && [ "$webui_transport_trust_bytes" -le 16384 ] || return 1
    webui_trust_phase=header
    webui_trust_payload_seen=false
    while IFS= read -r webui_trust_line || [ -n "$webui_trust_line" ]; do
        case $webui_trust_phase in
            header)
                [ "$webui_trust_line" = '-----BEGIN CERTIFICATE-----' ] || return 1
                webui_trust_phase=payload
                ;;
            payload)
                if [ "$webui_trust_line" = '-----END CERTIFICATE-----' ]; then
                    [ "$webui_trust_payload_seen" = true ] || return 1
                    webui_trust_phase=footer
                else
                    case $webui_trust_line in ''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]*) return 1 ;; esac
                    webui_trust_payload_seen=true
                fi
                ;;
            footer) return 1 ;;
        esac
    done < "$webui_transport_trust_path"
    [ "$webui_trust_phase" = footer ]
}

webui_status_state() {
    webui_pairing=UNPAIRED
    webui_direct_profile=UNAVAILABLE
    webui_direct_readiness=NOT_READY
    webui_diagnostic=DIAGNOSTIC_ONLY
    if [ ! -e "$rka_state_root/profiles/pair.request" ] && [ ! -L "$rka_state_root/profiles/pair.request" ]; then
        return 0
    fi
    webui_pair_request_is_valid || return 1
    webui_pairing=PENDING
    webui_direct_profile=DIRECT_NETWORK
    if webui_transport_key_is_valid && webui_transport_trust_is_valid; then
        webui_pairing=PAIRED
        if [ "$webui_runtime" = RUNNING ] && [ "$webui_sentinel" = LIVE ]; then
            webui_direct_readiness=READY
        fi
    fi
}

webui_status() {
    webui_role=$(read_role) || return 1
    webui_read_active_profile || return 1
    [ "$webui_role" = "$webui_profile_role" ] || return 1
    webui_runtime_state || return 1
    webui_sentinel_status
    webui_status_state || return 1
    printf 'role=%s\n' "$webui_role"
    printf 'phone_role=%s\n' "$(webui_phone_role "$webui_role")"
    printf 'profile_epoch=%s\n' "$webui_profile_epoch"
    printf 'direct_profile=%s\n' "$webui_direct_profile"
    printf 'direct_readiness=%s\n' "$webui_direct_readiness"
    printf 'pairing=%s\n' "$webui_pairing"
    printf 'diagnostic=%s\n' "$webui_diagnostic"
    printf 'runtime=%s\n' "$webui_runtime"
    printf 'sentinel=%s\n' "$webui_sentinel"
    printf 'quarantine_count=%s\n' "$(webui_quarantine_count)"
}

webui_record_request() {
    webui_request_path=$1
    webui_request_body=$2
    rka_layout_is_valid || return 1
    rka_atomic_replace "$(dirname "$webui_request_path")" "$webui_request_path" "$webui_request_body"
}

webui_set_role() {
    webui_requested_role=$1
    role_is_valid "$webui_requested_role" || return 1
    [ "$webui_requested_role" != DISABLED ] || return 1
    webui_read_active_profile || return 1
    webui_previous_role=$(read_role) || return 1
    webui_previous_profile=$(cat "$rka_state_root/profiles/$RKA_PROFILE_NAME") || return 1
    rka_atomic_replace "$rka_state_root/profiles" "$rka_state_root/profiles/$RKA_PROFILE_NAME" "version=1
role=$webui_requested_role
profile_epoch=$webui_profile_epoch
" || return 1
    set_role "$webui_requested_role" || {
        rka_atomic_replace "$rka_state_root/profiles" "$rka_state_root/profiles/$RKA_PROFILE_NAME" "$webui_previous_profile
"
        return 1
    }
    if webui_read_active_profile && [ "$webui_profile_role" = "$webui_requested_role" ] && [ "$(read_role)" = "$webui_requested_role" ]; then
        return 0
    fi
    set_role "$webui_previous_role" || return 1
    rka_atomic_replace "$rka_state_root/profiles" "$rka_state_root/profiles/$RKA_PROFILE_NAME" "$webui_previous_profile
"
}

webui_export_redacted() {
    webui_export_kind=$1
    case $webui_export_kind in audit|evidence) ;; *) return 1 ;; esac
    webui_export_snapshot=$(webui_status) || return 1
    [ "$(printf '%s' "$webui_export_snapshot" | wc -c)" -le 448 ] || return 1
    webui_export_path=$rka_state_root/sidecar/audit/$webui_export_kind-export.txt
    rka_atomic_replace "$rka_state_root/sidecar/audit" "$webui_export_path" "version=1
kind=$webui_export_kind
$webui_export_snapshot
" || return 1
    case $webui_export_kind in
        audit) printf '%s\n' audit_export=REDACTED_READY ;;
        evidence) printf '%s\n' evidence_export=REDACTED_READY ;;
    esac
}

webui_mutation_complete() {
    webui_status || return 1
    printf 'next_nonce=%s\n' "$webui_new_nonce"
}

webui_action_is_valid() {
    case $1 in
        status|role-donor|role-candidate|pair-direct|rotate-pairing|start|stop|recover-keystore2|export-audit|export-evidence|cleanup|quarantine) return 0 ;;
        *) return 1 ;;
    esac
}

webui_request() {
    webui_action=$1
    webui_nonce=$2
    webui_action_is_valid "$webui_action" || return 1
    case $webui_action in
        status|quarantine) webui_nonce_matches "$webui_nonce" && webui_status; return $? ;;
    esac
    webui_consume_nonce "$webui_nonce" || return 1
    webui_request_ok=false
    case $webui_action in
        role-donor) webui_set_role DONOR && webui_request_ok=true ;;
        role-candidate) webui_set_role CANDIDATE && webui_request_ok=true ;;
        pair-direct) webui_record_request "$rka_state_root/profiles/pair.request" "version=1
action=PAIR_DIRECT
" && webui_request_ok=true ;;
        rotate-pairing) webui_record_request "$rka_state_root/trust/rotate.request" "version=1
action=ROTATE_PAIRING
" && webui_request_ok=true ;;
        start) sh "$script_directory/rka-supervisor.sh" --root "$root" --state-root "$rka_state_root" start && webui_request_ok=true ;;
        stop) sh "$script_directory/rka-supervisor.sh" --root "$root" --state-root "$rka_state_root" stop && webui_request_ok=true ;;
        recover-keystore2) webui_record_request "$rka_state_root/journal/recovery.request" "version=1
target=KEYSTORE2
" && printf '%s\n' recovery_target=KEYSTORE2 && webui_request_ok=true ;;
        export-audit) webui_export_redacted audit && webui_request_ok=true ;;
        export-evidence) webui_export_redacted evidence && webui_request_ok=true ;;
        cleanup) rka_wipe_runtime && webui_request_ok=true ;;
    esac
    if [ "$webui_request_ok" = true ]; then
        webui_mutation_complete
        webui_result=$?
    else
        webui_result=1
    fi
    webui_release_mutation_lock || webui_result=1
    return "$webui_result"
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
