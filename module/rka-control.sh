#!/bin/sh

set -f

readonly MAX_CONFIG_BYTES=4096
readonly DEFAULT_ROOT=/data/adb/tricky_store
readonly DEFAULT_STATE_ROOT=/data/adb/teesimulator-rka
readonly CONFIG_DIRECTORY=rka
readonly CONFIG_NAME=role.conf
readonly OFFICIAL_ATTESTATION_ROOT_URL=https://android.googleapis.com/attestation/root

root=$DEFAULT_ROOT
rka_state_root=$DEFAULT_STATE_ROOT

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=module/rka-paths.sh
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
    printf '%s\n' 'usage: rka-control.sh [--root PATH] [--state-root PATH] {set-role ROLE|initialize|provision-rkp|wipe|mutation-states|status|boot-decision|recover-exact ACTION TARGET [ARGS]|webui-open|webui ACTION NONCE}' >&2
}

provision_getprop() {
    "${RKA_GETPROP:-getprop}" "$1"
}

provision_rkp_inputs() {
    provision_role=$(read_role) || return 1
    [ "$provision_role" = DONOR ] || return 1
    rka_layout_is_valid && rka_profile_is_valid || return 1
    provision_epoch=$(sed -n '3s/^profile_epoch=//p' "$rka_state_root/profiles/$RKA_PROFILE_NAME") || return 1
    case $provision_epoch in ''|*[!0-9]*) return 1 ;; esac
    provision_socket=$rka_state_root/run/sockets/broker.sock
    [ -S "$provision_socket" ] && [ ! -L "$provision_socket" ] || return 1
    [ "$(stat -c '%u:%g:%a' "$provision_socket")" = "$(id -u):$(id -g):600" ] || return 1
    [ "$(provision_getprop remote_provisioning.enable_rkpd)" = true ] || return 1
    provision_hostname=$(provision_getprop remote_provisioning.hostname) || return 1
    case $provision_hostname in ''|.*|*..*|*.|*[!a-z0-9.-]*) return 1 ;; esac
    [ "$(printf '%s' "$provision_hostname" | wc -c)" -le 253 ] || return 1
    provision_fingerprint=$(provision_getprop ro.build.fingerprint) || return 1
    case $provision_fingerprint in ''|*[!A-Za-z0-9._:/-]*) return 1 ;; esac
    [ "$(printf '%s' "$provision_fingerprint" | wc -c)" -le 4096 ] || return 1
}

provision_rkp() {
    provision_rkp_inputs || return 1
    provision_output=$(
        RKA_STATE_ROOT="$rka_state_root" \
        RKA_PROFILE_PATH="$rka_state_root/profiles/direct.conf" \
        RKA_PROFILE_RECEIPT_PATH="$rka_state_root/run/direct-profile.receipt" \
        RKA_EXPECTED_PROFILE_EPOCH="$provision_epoch" \
        RKA_DONOR_SOCKET="$provision_socket" \
        RKA_VALIDATOR_PKCS8="$rka_state_root/secrets/validator.pk8" \
        RKA_PROVISIONING_BASE="https://$provision_hostname/v1" \
        RKA_BUILD_FINGERPRINT="$provision_fingerprint" \
        RKA_PROFILE_EPOCH="$provision_epoch" \
        RKA_KEY_COUNT=1 \
            "${RKA_SIDECAR:-$script_directory/rka-sidecar}" provision
    ) || return 1
    [ "$provision_output" = "role=donor status=READY
RESULT=PROVISIONED" ] || return 1
    rka_atomic_replace "$rka_state_root/journal" \
        "$rka_state_root/journal/provisioning.state" "version=1
status=PROVISIONED
profile_epoch=$provision_epoch
key_count=1
" || return 1
    printf '%s\n' "$provision_output"
}

recovery_read_profile() {
    recovery_profile=$rka_state_root/profiles/recovery.conf
    rka_private_file_is_valid "$recovery_profile" || return 1
    [ "$(wc -l < "$recovery_profile")" -eq 9 ] || return 1
    recovery_keystore_name=
    recovery_keystore_executable=
    recovery_keystore_restart=
    recovery_rkpd_name=
    recovery_rkpd_executable=
    recovery_rkpd_restart=
    recovery_property_one=
    recovery_property_two=
    while IFS= read -r recovery_line || [ -n "$recovery_line" ]; do
        recovery_key=${recovery_line%%=*}
        recovery_value=${recovery_line#*=}
        [ "$recovery_key" != "$recovery_line" ] || return 1
        case $recovery_value in ''|*[!A-Za-z0-9._/-]*) return 1 ;; esac
        case $recovery_key in
            version) [ "$recovery_value" = 1 ] || return 1 ;;
            keystore2_name) [ -z "$recovery_keystore_name" ]; recovery_keystore_name=$recovery_value ;;
            keystore2_executable) [ -z "$recovery_keystore_executable" ]; recovery_keystore_executable=$recovery_value ;;
            keystore2_restart) [ -z "$recovery_keystore_restart" ]; recovery_keystore_restart=$recovery_value ;;
            rkpd_name) [ -z "$recovery_rkpd_name" ]; recovery_rkpd_name=$recovery_value ;;
            rkpd_executable) [ -z "$recovery_rkpd_executable" ]; recovery_rkpd_executable=$recovery_value ;;
            rkpd_restart) [ -z "$recovery_rkpd_restart" ]; recovery_rkpd_restart=$recovery_value ;;
            rkpd_property_one) [ -z "$recovery_property_one" ]; recovery_property_one=$recovery_value ;;
            rkpd_property_two) [ -z "$recovery_property_two" ]; recovery_property_two=$recovery_value ;;
            *) return 1 ;;
        esac
    done < "$recovery_profile"
    [ "$recovery_keystore_executable" = /system/bin/keystore2 ] &&
        [ "$recovery_rkpd_executable" = /system/bin/rkpd ] &&
        [ "$recovery_property_one" != "$recovery_property_two" ]
}

recovery_select_target() {
    case $1 in
        keystore2)
            recovery_name=$recovery_keystore_name
            recovery_executable=$recovery_keystore_executable
            recovery_restart=$recovery_keystore_restart
            ;;
        rkpd)
            recovery_name=$recovery_rkpd_name
            recovery_executable=$recovery_rkpd_executable
            recovery_restart=$recovery_rkpd_restart
            ;;
        *) return 1 ;;
    esac
}

recovery_getprop() {
    "${RKA_RECOVERY_GETPROP:-getprop}" "$1"
}

recovery_setprop() {
    "${RKA_RECOVERY_SETPROP:-setprop}" "$1" "$2"
}

recovery_find_service() {
    recovery_pids=$("${RKA_RECOVERY_PIDOF:-pidof}" "$recovery_name") || return 1
    case $recovery_pids in ''|*[!0-9]*) return 1 ;; esac
    recovery_pid=$recovery_pids
    recovery_proc_root=${RKA_RECOVERY_PROC_ROOT:-/proc}
    recovery_start=$(awk '{print $22}' "$recovery_proc_root/$recovery_pid/stat") || return 1
    case $recovery_start in ''|*[!0-9]*) return 1 ;; esac
    recovery_actual_executable=$(readlink "$recovery_proc_root/$recovery_pid/exe") || return 1
    [ "$recovery_actual_executable" = "$recovery_executable" ]
}

recovery_emit_snapshot() {
    recovery_boot=$(cat "${RKA_RECOVERY_BOOT_ID_PATH:-/proc/sys/kernel/random/boot_id}") || return 1
    case $recovery_boot in ''|*[!A-Za-z0-9._-]*) return 1 ;; esac
    recovery_uptime=$(awk '{printf "%d", $1 * 1000}' "${RKA_RECOVERY_UPTIME_PATH:-/proc/uptime}") || return 1
    recovery_find_service || return 1
    printf 'boot_id=%s\nuptime_ms=%s\nservice=%s|%s|%s|%s\n' \
        "$recovery_boot" "$recovery_uptime" "$1" "$recovery_pid" "$recovery_start" "$recovery_executable"
    if [ "$1" = rkpd ]; then
        if [ "${recovery_use_snapshot_values:-false}" != true ]; then
            recovery_value_one=$(recovery_getprop "$recovery_property_one") || return 1
            recovery_value_two=$(recovery_getprop "$recovery_property_two") || return 1
        fi
        recovery_hash_one=$(printf '%s' "$recovery_value_one" | sha256sum | awk '{print $1}')
        recovery_hash_two=$(printf '%s' "$recovery_value_two" | sha256sum | awk '{print $1}')
        [ -n "$recovery_value_one" ] || recovery_hash_one=
        [ -n "$recovery_value_two" ] || recovery_hash_two=
        printf 'property=%s|%s\n' "$recovery_property_one" "$(printf '%s' "$recovery_hash_one" | base64 | tr -d '\n')"
        printf 'property=%s|%s\n' "$recovery_property_two" "$(printf '%s' "$recovery_hash_two" | base64 | tr -d '\n')"
    fi
    recovery_sentinel=$rka_state_root/run/boot-continuity.state
    rka_private_file_is_valid "$recovery_sentinel" || return 1
    [ "$(wc -l < "$recovery_sentinel")" -eq 4 ] || return 1
    [ "$(sed -n '1p' "$recovery_sentinel")" = version=1 ] || return 1
    recovery_sentinel_id=$(sed -n '2s/^sentinel_id=//p' "$recovery_sentinel")
    recovery_sentinel_boot=$(sed -n '3s/^boot_id=//p' "$recovery_sentinel")
    recovery_sentinel_sample=$(sed -n '4s/^sample_ms=//p' "$recovery_sentinel")
    case $recovery_sentinel_id in ????????????????????????????????) ;; *) return 1 ;; esac
    case $recovery_sentinel_id in *[!0123456789abcdef]*) return 1 ;; esac
    [ "$recovery_sentinel_boot" = "$recovery_boot" ] || return 1
    case $recovery_sentinel_sample in ''|*[!0-9]*) return 1 ;; esac
    [ "$recovery_sentinel_sample" -le "$recovery_uptime" ] || return 1
    recovery_sentinel_hash=$(sha256sum "$recovery_sentinel" | awk '{print $1}') || return 1
    printf 'sentinel_hash=%s\n' "$recovery_sentinel_hash"

    recovery_quarantine=$rka_state_root/quarantine
    rka_path_is_private_directory "$recovery_quarantine" || return 1
    recovery_manifest=
    recovery_count=0
    recovery_entries=$(find "$recovery_quarantine" -mindepth 1 -maxdepth 1 -print | LC_ALL=C sort) || return 1
    while IFS= read -r recovery_entry; do
        [ -n "$recovery_entry" ] || continue
        recovery_name=${recovery_entry##*/}
        case $recovery_name in ''|*[!A-Za-z0-9._-]*) return 1 ;; esac
        rka_private_file_is_valid "$recovery_entry" || return 1
        recovery_size=$(wc -c < "$recovery_entry") || return 1
        [ "$recovery_size" -gt 0 ] && [ "$recovery_size" -le 131072 ] || return 1
        recovery_count=$((recovery_count + 1))
        [ "$recovery_count" -le 20 ] || return 1
        recovery_digest=$(sha256sum "$recovery_entry" | awk '{print $1}') || return 1
        recovery_manifest=$recovery_manifest$recovery_name'|'$recovery_size'|'$recovery_digest'
'
    done <<EOF
$recovery_entries
EOF
    [ "$recovery_count" -gt 0 ] || return 1
    recovery_quarantine_hash=$(printf '%s' "$recovery_manifest" | sha256sum | awk '{print $1}')
    printf 'quarantine_count=%s\nquarantine_hash=%s\n' \
        "$recovery_count" "$recovery_quarantine_hash"
}

ensure_boot_sentinel() {
    recovery_boot=$(cat "${RKA_RECOVERY_BOOT_ID_PATH:-/proc/sys/kernel/random/boot_id}") || return 1
    recovery_uptime=$(awk '{printf "%d", $1 * 1000}' "${RKA_RECOVERY_UPTIME_PATH:-/proc/uptime}") || return 1
    recovery_sentinel=$rka_state_root/run/boot-continuity.state
    if rka_private_file_is_valid "$recovery_sentinel" &&
        [ "$(sed -n '3p' "$recovery_sentinel")" = "boot_id=$recovery_boot" ]; then
        return 0
    fi
    recovery_sentinel_id=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n') || return 1
    rka_atomic_replace "$rka_state_root/run" "$recovery_sentinel" "version=1
sentinel_id=$recovery_sentinel_id
boot_id=$recovery_boot
sample_ms=$recovery_uptime
"
}

recovery_snapshot() {
    if [ "$1" = rkpd ]; then
        recovery_value_one=$(recovery_getprop "$recovery_property_one") || return 1
        recovery_value_two=$(recovery_getprop "$recovery_property_two") || return 1
        recovery_use_snapshot_values=true
    fi
    recovery_output=$(recovery_emit_snapshot "$1") || return 1
    recovery_state=$rka_state_root/journal/recovery-exact.state
    rka_atomic_replace "$rka_state_root/journal" "$recovery_state" "$recovery_output
" || return 1
    if [ "$1" = rkpd ]; then
        recovery_properties=$rka_state_root/journal/recovery-exact.properties
        rka_atomic_replace "$rka_state_root/journal" "$recovery_properties" "property=$recovery_property_one|$(printf '%s' "$recovery_value_one" | base64 | tr -d '\n')
property=$recovery_property_two|$(printf '%s' "$recovery_value_two" | base64 | tr -d '\n')
" || return 1
    fi
    printf '%s\n' "$recovery_output"
}

recovery_restart_exact() {
    [ "$#" -eq 3 ] || return 1
    recovery_find_service || return 1
    [ "$recovery_pid" = "$2" ] && [ "$recovery_start" = "$3" ] || return 1
    recovery_setprop ctl.restart "$recovery_restart" || return 1
    printf '%s\n' RESTARTED
}

recovery_ready() {
    case $2 in ''|*[!0-9]*) return 1 ;; esac
    [ "$2" -le 30000 ] || return 1
    recovery_attempts=$((($2 + 99) / 100))
    while [ "$recovery_attempts" -gt 0 ]; do
        if recovery_find_service; then
            printf '%s\n' READY
            return 0
        fi
        sleep 0.1
        recovery_attempts=$((recovery_attempts - 1))
    done
    return 1
}

recovery_reapply() {
    [ "$1" = rkpd ] || return 1
    case $2 in
        "$recovery_property_one"|"$recovery_property_two") ;;
        *) return 1 ;;
    esac
    [ -z "$(recovery_getprop "$2")" ] || return 1
    recovery_properties=$rka_state_root/journal/recovery-exact.properties
    rka_private_file_is_valid "$recovery_properties" || return 1
    recovery_encoded=
    while IFS= read -r recovery_property_line || [ -n "$recovery_property_line" ]; do
        recovery_property_key=${recovery_property_line%%|*}
        if [ "$recovery_property_key" = "property=$2" ]; then
            [ -z "$recovery_encoded" ] || return 1
            recovery_encoded=${recovery_property_line#*|}
        fi
    done < "$recovery_properties"
    [ -n "$recovery_encoded" ] || return 1
    recovery_value=$(printf '%s' "$recovery_encoded" | base64 -d) || return 1
    recovery_setprop "$2" "$recovery_value"
}

recover_exact() {
    [ "$#" -ge 2 ] || return 1
    recovery_read_profile || return 1
    recovery_select_target "$2" || return 1
    case $1 in
        snapshot) [ "$#" -eq 2 ] && recovery_snapshot "$2" ;;
        verify) [ "$#" -eq 2 ] && recovery_emit_snapshot "$2" ;;
        restart) [ "$#" -eq 4 ] && recovery_restart_exact "$2" "$3" "$4" ;;
        ready) [ "$#" -eq 3 ] && recovery_ready "$2" "$3" ;;
        reapply) [ "$#" -eq 3 ] && recovery_reapply "$2" "$3" ;;
        *) return 1 ;;
    esac
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
    rka_private_file_is_valid "$webui_sentinel_path" || return 0
    [ "$(wc -l < "$webui_sentinel_path")" -eq 4 ] || return 0
    [ "$(sed -n '1p' "$webui_sentinel_path")" = version=1 ] || return 0
    webui_sentinel_id=$(sed -n '2s/^sentinel_id=//p' "$webui_sentinel_path")
    webui_sentinel_boot=$(sed -n '3s/^boot_id=//p' "$webui_sentinel_path")
    webui_sentinel_sample=$(sed -n '4s/^sample_ms=//p' "$webui_sentinel_path")
    case $webui_sentinel_id in ????????????????????????????????) ;; *) return 0 ;; esac
    case $webui_sentinel_id in *[!0123456789abcdef]*) return 0 ;; esac
    case $webui_sentinel_sample in '' | *[!0-9]*) return 0 ;; esac
    webui_current_boot=$(cat "${RKA_RECOVERY_BOOT_ID_PATH:-/proc/sys/kernel/random/boot_id}") || return 0
    [ "$webui_sentinel_boot" = "$webui_current_boot" ] || return 0
    webui_sentinel=LIVE
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
    webui_rkp_provisioning_status || return 1
    printf 'role=%s\n' "$webui_role"
    printf 'phone_role=%s\n' "$(webui_phone_role "$webui_role")"
    printf 'profile_epoch=%s\n' "$webui_profile_epoch"
    printf 'direct_profile=%s\n' "$webui_direct_profile"
    printf 'direct_readiness=%s\n' "$webui_direct_readiness"
    printf 'pairing=%s\n' "$webui_pairing"
    printf 'diagnostic=%s\n' "$webui_diagnostic"
    printf 'runtime=%s\n' "$webui_runtime"
    printf 'sentinel=%s\n' "$webui_sentinel"
    printf 'rkp_provisioning=%s\n' "$webui_rkp_provisioning"
    printf 'quarantine_count=%s\n' "$(webui_quarantine_count)"
}

webui_rkp_provisioning_status() {
    webui_rkp_provisioning=NOT_APPLICABLE
    [ "$webui_role" = DONOR ] || return 0
    webui_rkp_provisioning=NOT_READY
    webui_provisioning_path=$rka_state_root/journal/provisioning.state
    if [ ! -e "$webui_provisioning_path" ] && [ ! -L "$webui_provisioning_path" ]; then
        return 0
    fi
    rka_private_file_is_valid "$webui_provisioning_path" || return 1
    [ "$(cat "$webui_provisioning_path")" = "version=1
status=PROVISIONED
profile_epoch=$webui_profile_epoch
key_count=1" ] || return 1
    webui_rkp_provisioning=PROVISIONED
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

webui_validate_profile() {
    webui_requested_role=$1
    case $webui_requested_role in DONOR|CANDIDATE) ;; *) return 1 ;; esac
    webui_read_active_profile || return 1
    webui_record_request "$rka_state_root/profiles/webui-profile.pending" "version=1
role=$webui_requested_role
profile_epoch=$webui_profile_epoch
"
}

webui_apply_profile() {
    webui_requested_role=$1
    webui_read_active_profile || return 1
    webui_pending_profile=$rka_state_root/profiles/webui-profile.pending
    rka_private_file_is_valid "$webui_pending_profile" || return 1
    [ "$(cat "$webui_pending_profile")" = "version=1
role=$webui_requested_role
profile_epoch=$webui_profile_epoch" ] || return 1
    webui_set_role "$webui_requested_role" || return 1
    rm -f "$webui_pending_profile"
}

webui_export_redacted() {
    webui_export_kind=$1
    case $webui_export_kind in audit|evidence) ;; *) return 1 ;; esac
    webui_export_snapshot=$(webui_status) || return 1
    [ "$(printf '%s' "$webui_export_snapshot" | wc -c)" -le 512 ] || return 1
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

webui_confirmation_path() {
    printf '%s\n' "$rka_state_root/run/webui.confirm"
}

webui_prepare_confirmation() {
    webui_confirm_action=$1
    webui_confirm_token=$(webui_next_nonce) || return 1
    webui_record_request "$(webui_confirmation_path)" "version=1
action=$webui_confirm_action
nonce=$webui_new_nonce
token=$webui_confirm_token
" || return 1
    printf 'confirmation_action=%s\nconfirmation_token=%s\n' \
        "$webui_confirm_action" "$webui_confirm_token"
}

webui_confirmation_matches() {
    webui_confirm_action=$1
    webui_confirm_nonce=$2
    webui_confirm_token=$3
    webui_nonce_is_valid "$webui_confirm_token" || return 1
    webui_confirm_path=$(webui_confirmation_path)
    rka_private_file_is_valid "$webui_confirm_path" || return 1
    [ "$(cat "$webui_confirm_path")" = "version=1
action=$webui_confirm_action
nonce=$webui_confirm_nonce
token=$webui_confirm_token" ] || return 1
    rm -f "$webui_confirm_path"
}

webui_recovery_request() {
    webui_recovery_target=$1
    webui_sentinel_status
    [ "$webui_sentinel" = LIVE ] || return 1
    recovery_read_profile || return 1
    recovery_select_target "$webui_recovery_target" || return 1
    webui_record_request "$rka_state_root/journal/recovery.request" "version=1
target=$(printf '%s' "$webui_recovery_target" | tr '[:lower:]' '[:upper:]')
" || return 1
    recovery_snapshot "$webui_recovery_target" >/dev/null || return 1
    webui_recovery_pid=$recovery_pid
    webui_recovery_start=$recovery_start
    recovery_restart_exact "$webui_recovery_target" \
        "$webui_recovery_pid" "$webui_recovery_start" >/dev/null || return 1
    recovery_ready "$webui_recovery_target" 30000 >/dev/null || return 1
    recovery_emit_snapshot "$webui_recovery_target" >/dev/null
}

webui_root_bundle_fields() {
    webui_bundle_path=$1
    rka_private_file_is_valid "$webui_bundle_path" || return 1
    [ "$(wc -c < "$webui_bundle_path")" -le 4096 ] || return 1
    webui_bundle_epoch=
    webui_bundle_pins=
    webui_bundle_authorization=
    webui_bundle_version=false
    while IFS= read -r webui_bundle_line || [ -n "$webui_bundle_line" ]; do
        case $webui_bundle_line in
            version=1) [ "$webui_bundle_version" = false ] || return 1; webui_bundle_version=true ;;
            epoch=*) [ -z "$webui_bundle_epoch" ] || return 1; webui_bundle_epoch=${webui_bundle_line#epoch=} ;;
            pin=*)
                webui_bundle_pin=${webui_bundle_line#pin=}
                case $webui_bundle_pin in
                    ????????????????????????????????????????????????????????????????) ;;
                    *) return 1 ;;
                esac
                case $webui_bundle_pin in *[!0123456789abcdef]*) return 1 ;; esac
                webui_bundle_pins="${webui_bundle_pins}${webui_bundle_pin}
"
                ;;
            authorization=*)
                [ -z "$webui_bundle_authorization" ] || return 1
                webui_bundle_authorization=${webui_bundle_line#authorization=}
                case $webui_bundle_authorization in
                    ????????????????????????????????????????????????????????????????) ;;
                    *) return 1 ;;
                esac
                case $webui_bundle_authorization in *[!0123456789abcdef]*) return 1 ;; esac
                ;;
            *) return 1 ;;
        esac
    done < "$webui_bundle_path"
    case $webui_bundle_epoch in ''|*[!0-9]*) return 1 ;; esac
    [ "$webui_bundle_version" = true ] && [ -n "$webui_bundle_pins" ]
}

webui_prepare_root_rotation() {
    webui_active_bundle=$rka_state_root/trust/root-bundle.active
    if rka_private_file_is_valid "$webui_active_bundle"; then
        webui_root_bundle_fields "$webui_active_bundle" || return 1
        webui_old_epoch=$webui_bundle_epoch
        webui_old_pins=$webui_bundle_pins
    else
        webui_read_active_profile || return 1
        webui_old_epoch=$webui_profile_epoch
        webui_old_pins='cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc
6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0
'
    fi
    webui_fetcher=${RKA_ROOT_FETCH:-curl}
    webui_fetched=$("$webui_fetcher" --fail --silent --show-error --proto '=https' \
        --tlsv1.2 --max-redirs 0 "$OFFICIAL_ATTESTATION_ROOT_URL") || return 1
    webui_candidate=$rka_state_root/trust/root-bundle.candidate
    rka_atomic_replace "$rka_state_root/trust" "$webui_candidate" "$webui_fetched
" || return 1
    webui_root_bundle_fields "$webui_candidate" || return 1
    [ -z "$webui_bundle_authorization" ] || return 1
    [ "$webui_bundle_epoch" -eq $((webui_old_epoch + 1)) ] || return 1
    webui_new_pins=$webui_bundle_pins
    webui_overlap=NO_OVERLAP
    while IFS= read -r webui_old_pin; do
        [ -n "$webui_old_pin" ] || continue
        if printf '%s' "$webui_new_pins" | grep -Fxq "$webui_old_pin"; then
            webui_overlap=OVERLAP
        fi
    done <<EOF
$webui_old_pins
EOF
    webui_old_hash=$(printf '%s' "$webui_old_pins" | LC_ALL=C sort | sha256sum | awk '{print $1}')
    webui_new_hash=$(printf '%s' "$webui_new_pins" | LC_ALL=C sort | sha256sum | awk '{print $1}')
    [ "$webui_old_hash" != "$webui_new_hash" ] || return 1
    if [ "$webui_overlap" = NO_OVERLAP ]; then
        webui_signed_bundle=$root/rka-root-bundle.signed
        webui_signed_signature=$root/rka-root-bundle.signed.sig
        webui_verifier=$script_directory/rka-agent-pgp-verify
        webui_agent_anchor=$script_directory/rka-agent-pgp-public.gpg
        [ -x "$webui_verifier" ] && [ ! -L "$webui_verifier" ] &&
            [ "$(stat -c '%u:%a' "$webui_verifier")" = "$(id -u):755" ] ||
            return 1
        [ -f "$webui_agent_anchor" ] && [ ! -L "$webui_agent_anchor" ] &&
            [ "$(stat -c '%u:%a' "$webui_agent_anchor")" = "$(id -u):644" ] ||
            return 1
        rka_private_file_is_valid "$webui_signed_bundle" &&
            rka_private_file_is_valid "$webui_signed_signature" || return 1
        [ "$(wc -c < "$webui_signed_signature")" -le 8192 ] || return 1
        "$webui_verifier" "$webui_signed_bundle" "$webui_signed_signature" \
            "$webui_old_hash" "$webui_new_hash" || return 1
        webui_root_bundle_fields "$webui_signed_bundle" || return 1
        [ "$webui_bundle_epoch" -eq $((webui_old_epoch + 1)) ] || return 1
        [ "$webui_bundle_pins" = "$webui_new_pins" ] || return 1
        [ -n "$webui_bundle_authorization" ] || return 1
        webui_candidate=$webui_signed_bundle
    fi
    rka_atomic_replace "$rka_state_root/trust" \
        "$rka_state_root/trust/root-bundle.next" "$(cat "$webui_candidate")
" || return 1
    printf 'root_old_hash=%s\nroot_new_hash=%s\nroot_overlap=%s\n' \
        "$webui_old_hash" "$webui_new_hash" "$webui_overlap"
}

webui_rotate_roots() {
    webui_sentinel_status
    [ "$webui_sentinel" = LIVE ] || return 1
    webui_next_bundle=$rka_state_root/trust/root-bundle.next
    rka_private_file_is_valid "$webui_next_bundle" || return 1
    webui_runtime_state || return 1
    webui_restart_after_rotation=false
    if [ "$webui_runtime" = RUNNING ]; then
        sh "$script_directory/rka-supervisor.sh" --root "$root" \
            --state-root "$rka_state_root" stop || return 1
        webui_restart_after_rotation=true
    fi
    RKA_STATE_ROOT="$rka_state_root" "${RKA_SIDECAR:-$script_directory/rka-sidecar}" rotate-roots ||
        {
            if [ "$webui_restart_after_rotation" = true ]; then
                RKA_REQUIRE_DIRECT_READY=true sh "$script_directory/rka-supervisor.sh" \
                    --root "$root" --state-root "$rka_state_root" start >/dev/null 2>&1 || :
            fi
            return 1
        }
    webui_next_epoch=$(RKA_STATE_ROOT="$rka_state_root" \
        "${RKA_SIDECAR:-$script_directory/rka-sidecar}" trust-epoch) || return 1
    case $webui_next_epoch in ''|*[!0-9]*) return 1 ;; esac
    webui_read_active_profile || return 1
    rka_atomic_replace "$rka_state_root/profiles" \
        "$rka_state_root/profiles/$RKA_PROFILE_NAME" "version=1
role=$webui_profile_role
profile_epoch=$webui_next_epoch
" || return 1
    if [ "$webui_restart_after_rotation" = true ]; then
        RKA_REQUIRE_DIRECT_READY=true sh "$script_directory/rka-supervisor.sh" \
            --root "$root" --state-root "$rka_state_root" start || return 1
    fi
}

webui_action_is_valid() {
    case $1 in
        status|role-donor|role-candidate|profile-validate-donor|profile-validate-candidate|profile-apply-donor|profile-apply-candidate|pair-direct|rotate-pairing|provision-rkp|rotate-attestation-roots|start|stop|recover-keystore2|recover-rkpd|export-audit|export-evidence|cleanup|quarantine) return 0 ;;
        *) return 1 ;;
    esac
}

webui_request() {
    webui_action=$1
    webui_nonce=$2
    webui_confirmation=${3:-}
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
        start) RKA_REQUIRE_DIRECT_READY=true sh "$script_directory/rka-supervisor.sh" --root "$root" --state-root "$rka_state_root" start && webui_request_ok=true ;;
        stop) sh "$script_directory/rka-supervisor.sh" --root "$root" --state-root "$rka_state_root" stop && webui_request_ok=true ;;
        profile-validate-donor) webui_validate_profile DONOR && printf '%s\n' profile_validation=VALID && webui_request_ok=true ;;
        profile-validate-candidate) webui_validate_profile CANDIDATE && printf '%s\n' profile_validation=VALID && webui_request_ok=true ;;
        profile-apply-donor) webui_apply_profile DONOR && printf '%s\n' profile_apply=VALIDATED && webui_request_ok=true ;;
        profile-apply-candidate) webui_apply_profile CANDIDATE && printf '%s\n' profile_apply=VALIDATED && webui_request_ok=true ;;
        recover-keystore2|recover-rkpd|provision-rkp|cleanup|rotate-attestation-roots)
            if [ -z "$webui_confirmation" ]; then
                webui_confirmation_ready=true
                case $webui_action in
                    recover-keystore2|recover-rkpd|rotate-attestation-roots)
                        webui_sentinel_status
                        [ "$webui_sentinel" = LIVE ] || webui_confirmation_ready=false
                        ;;
                    provision-rkp)
                        provision_rkp_inputs || webui_confirmation_ready=false
                        ;;
                esac
                if [ "$webui_action" = rotate-attestation-roots ] &&
                    ! webui_prepare_root_rotation; then
                    webui_confirmation_ready=false
                fi
                if [ "$webui_confirmation_ready" = true ] &&
                    webui_prepare_confirmation "$webui_action"; then
                    case $webui_action in
                        recover-keystore2) printf '%s\n' recovery_target=KEYSTORE2 ;;
                        recover-rkpd) printf '%s\n' recovery_target=RKPD ;;
                    esac
                    webui_request_ok=true
                fi
            elif webui_confirmation_matches "$webui_action" "$webui_nonce" "$webui_confirmation"; then
                case $webui_action in
                    recover-keystore2)
                        webui_recovery_request keystore2 &&
                            printf '%s\n' recovery_target=KEYSTORE2 &&
                            webui_request_ok=true
                        ;;
                    recover-rkpd)
                        webui_recovery_request rkpd &&
                            printf '%s\n' recovery_target=RKPD &&
                            webui_request_ok=true
                        ;;
                    provision-rkp)
                        provision_rkp &&
                            printf '%s\n' rkp_provisioning=PROVISIONED &&
                            webui_request_ok=true
                        ;;
                    cleanup) rka_wipe_runtime && webui_request_ok=true ;;
                    rotate-attestation-roots)
                        webui_rotate_roots &&
                            printf '%s\n' root_rotation=ACTIVATED &&
                            webui_request_ok=true
                        ;;
                esac
            fi
            ;;
        export-audit) webui_export_redacted audit && webui_request_ok=true ;;
        export-evidence) webui_export_redacted evidence && webui_request_ok=true ;;
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
            ensure_boot_sentinel || {
                print_inert
                exit 1
            }
            printf '%s\n' READY
            exit 0
            ;;
        provision-rkp)
            [ $# -eq 1 ] || exit 2
            provision_rkp || {
                print_inert
                exit 1
            }
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
        recover-exact)
            [ "$#" -ge 3 ] || exit 2
            shift
            recover_exact "$@" || exit 1
            exit 0
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
            { [ $# -eq 3 ] || [ $# -eq 4 ]; } || {
                webui_invalid_request
                exit 1
            }
            webui_request "$2" "$3" "${4:-}" || {
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
