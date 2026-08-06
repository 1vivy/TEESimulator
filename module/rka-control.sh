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
    printf '%s\n' 'usage: rka-control.sh [--root PATH] [--state-root PATH] {set-role ROLE|initialize|provision-rkp [--candidate CANDIDATE]|wipe|mutation-states|status|boot-decision|recover-exact ACTION TARGET [ARGS]|webui-open|webui ACTION NONCE [CONFIRMATION] [--candidate CANDIDATE]}' >&2
}

provision_getprop() {
    "${RKA_GETPROP:-getprop}" "$1"
}

provision_pm() {
    "${RKA_PM:-pm}" "$@"
}

provision_rkpd_metadata() {
    provision_preferences=${RKA_RKPD_PREFERENCES:-/data/user_de/0/com.android.rkpdapp/shared_prefs/com.android.rkpdapp.utils.preferences.xml}
    [ -f "$provision_preferences" ] && [ ! -L "$provision_preferences" ] || return 1
    provision_preferences_size=$(stat -c '%s' "$provision_preferences") || return 1
    case $provision_preferences_size in ''|*[!0-9]*) return 1 ;; esac
    [ "$provision_preferences_size" -le 65536 ] || return 1
    provision_id_line=$(sed -n '/name="settings_id"/p' "$provision_preferences") || return 1
    [ "$(printf '%s\n' "$provision_id_line" | wc -l)" -eq 1 ] || return 1
    provision_id=$(printf '%s\n' "$provision_id_line" | sed -n 's#^[[:space:]]*<int name="settings_id" value="\([0-9][0-9]*\)"[[:space:]]*/>[[:space:]]*$#\1#p') || return 1
    case $provision_id in ''|*[!0-9]*) return 1 ;; esac
    [ "$provision_id" -lt 1000000 ] || return 1
    provision_package=$(provision_pm list packages --show-versioncode com.android.rkpdapp) || return 1
    provision_version=${provision_package#package:com.android.rkpdapp versionCode:}
    [ "$provision_version" != "$provision_package" ] || return 1
    case $provision_version in ''|*[!0-9]*) return 1 ;; esac
    [ "$provision_version" -gt 0 ] || return 1
}

provision_rkp_inputs() {
    provision_requested_candidate=${1:-}
    provision_role=$(read_role) || return 1
    [ "$provision_role" = DONOR ] || return 1
    rka_layout_is_valid && rka_profile_is_valid || return 1
    provision_epoch=$(sed -n '3s/^profile_epoch=//p' "$rka_state_root/profiles/$RKA_PROFILE_NAME") || return 1
    case $provision_epoch in ''|*[!0-9]*) return 1 ;; esac
    webui_profile_epoch=$provision_epoch
    provision_profile=$rka_state_root/profiles/direct.conf
    provision_receipt=$rka_state_root/run/direct-profile.receipt
    provision_socket=$rka_state_root/run/sockets/broker.sock
    provision_candidate_id=GLOBAL
    provision_runtime_candidate=
    provision_candidates=$(webui_donor_candidates) || return 1
    if [ -n "$provision_candidates" ]; then
        rka_candidate_is_valid "$provision_requested_candidate" || return 1
        printf '%s\n' "$provision_candidates" | grep -Fxq "$provision_requested_candidate" || return 1
        provision_profile=$rka_state_root/profiles/direct.d/$provision_requested_candidate.conf
        provision_receipt=$rka_state_root/run/direct-profile-$provision_requested_candidate.receipt
        provision_socket=$rka_state_root/run/sockets/broker-$provision_requested_candidate.sock
        provision_candidate_id=$provision_requested_candidate
        provision_runtime_candidate=$provision_requested_candidate
    else
        [ -z "$provision_requested_candidate" ] || return 1
    fi
    [ -S "$provision_socket" ] && [ ! -L "$provision_socket" ] || return 1
    [ "$(stat -c '%u:%g:%a' "$provision_socket")" = "$(id -u):$(id -g):600" ] || return 1
    webui_direct_runtime_evidence_is_ready "$provision_runtime_candidate" || return 1
    provision_broker_generation=$(webui_broker_generation "$provision_runtime_candidate") || return 1
    provision_sidecar=${RKA_SIDECAR:-$rka_state_root/bin/rka-sidecar}
    [ -f "$provision_sidecar" ] && [ ! -L "$provision_sidecar" ] &&
        [ -x "$provision_sidecar" ] || return 1
    [ "$(stat -c '%u:%g:%a' "$provision_sidecar")" = "$(id -u):$(id -g):700" ] || return 1
    [ "$(provision_getprop remote_provisioning.enable_rkpd)" = true ] || return 1
    provision_hostname=$(provision_getprop remote_provisioning.hostname) || return 1
    case $provision_hostname in ''|.*|*..*|*.|*[!a-z0-9.-]*) return 1 ;; esac
    [ "$(printf '%s' "$provision_hostname" | wc -c)" -le 253 ] || return 1
    provision_fingerprint=$(provision_getprop ro.build.fingerprint) || return 1
    case $provision_fingerprint in ''|*[!A-Za-z0-9._:/-]*) return 1 ;; esac
    [ "$(printf '%s' "$provision_fingerprint" | wc -c)" -le 4096 ] || return 1
    provision_rkpd_metadata || return 1
}

provision_rkp() {
    provision_rkp_inputs "${1:-}" || {
        printf '%s\n' 'RKA_PROVISION_FAILED stage=INPUTS' >&2
        return 1
    }
    provision_output=$(
        RKA_STATE_ROOT="$rka_state_root" \
        RKA_PROFILE_PATH="$provision_profile" \
        RKA_PROFILE_RECEIPT_PATH="$provision_receipt" \
        RKA_EXPECTED_PROFILE_EPOCH="$provision_epoch" \
        RKA_DONOR_SOCKET="$provision_socket" \
        RKA_VALIDATOR_PKCS8="$rka_state_root/secrets/validator.pk8" \
        RKA_PROVISIONING_BASE="https://$provision_hostname/v1" \
        RKA_BUILD_FINGERPRINT="$provision_fingerprint" \
        RKA_PROVISIONING_ID="$provision_id" \
        RKA_PROVISIONING_VERSION="$provision_version" \
        RKA_PROFILE_EPOCH="$provision_epoch" \
        RKA_KEY_COUNT=1 \
            "$provision_sidecar" provision
    ) || {
        printf '%s\n' 'RKA_PROVISION_FAILED stage=SIDECAR' >&2
        return 1
    }
    [ "$provision_output" = "role=donor status=READY
RESULT=PROVISIONED" ] || {
        printf '%s\n' 'RKA_PROVISION_FAILED stage=OUTPUT' >&2
        return 1
    }
    provision_state_path=$(webui_provisioning_state_path "$provision_runtime_candidate") || return 1
    rka_atomic_replace "$rka_state_root/journal" \
        "$provision_state_path" "version=2
status=PROVISIONED
profile_epoch=$provision_epoch
key_count=1
candidate_id=$provision_candidate_id
broker_generation_sha256=$provision_broker_generation
" || {
        printf '%s\n' 'RKA_PROVISION_FAILED stage=STATE' >&2
        return 1
    }
    webui_provisioning_is_current "$provision_runtime_candidate" || {
        printf '%s\n' 'RKA_PROVISION_FAILED stage=POSTCONDITION' >&2
        return 1
    }
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
    [ "$#" -eq 4 ] || return 1
    case $2 in ''|*[!0-9]*) return 1 ;; esac
    case $3 in ''|*[!0-9]*) return 1 ;; esac
    case $4 in ''|*[!0-9]*) return 1 ;; esac
    [ "$2" -le 30000 ] || return 1
    recovery_attempts=$((($2 + 99) / 100))
    while [ "$recovery_attempts" -gt 0 ]; do
        if recovery_find_service &&
            { [ "$recovery_pid" != "$3" ] || [ "$recovery_start" != "$4" ]; }; then
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
        ready) [ "$#" -eq 5 ] && recovery_ready "$2" "$3" "$4" "$5" ;;
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
    webui_recover_role_transaction || return 1
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

webui_ipv4_is_valid() {
    webui_ipv4_remainder=$1
    webui_ipv4_index=1
    while [ "$webui_ipv4_index" -le 4 ]; do
        if [ "$webui_ipv4_index" -lt 4 ]; then
            case $webui_ipv4_remainder in
                *.*)
                    webui_ipv4_octet=${webui_ipv4_remainder%%.*}
                    webui_ipv4_remainder=${webui_ipv4_remainder#*.}
                    ;;
                *) return 1 ;;
            esac
        else
            case $webui_ipv4_remainder in
                *.*) return 1 ;;
                *) webui_ipv4_octet=$webui_ipv4_remainder ;;
            esac
        fi
        case $webui_ipv4_octet in ''|*[!0-9]*) return 1 ;; esac
        [ "$webui_ipv4_octet" -le 255 ] || return 1
        webui_ipv4_index=$((webui_ipv4_index + 1))
    done
}

webui_read_network_profile() {
    webui_network_peer_ip=UNAVAILABLE
    webui_network_local_ip=UNAVAILABLE
    webui_network_port=37373
    webui_network_profile_ready=false
    if [ -n "${webui_status_candidate:-}" ]; then
        webui_network_profile=$rka_state_root/profiles/direct.d/$webui_status_candidate.conf
    else
        webui_network_profile=$rka_state_root/profiles/direct.conf
    fi
    rka_private_file_is_valid "$webui_network_profile" || return 0
    webui_network_profile_role=$(sed -n 's/^role=//p' "$webui_network_profile") || return 1
    webui_network_profile_epoch=$(sed -n 's/^profile_epoch=//p' "$webui_network_profile") || return 1
    [ "$webui_network_profile_role" = "$webui_role" ] || return 0
    [ "$webui_network_profile_epoch" = "$webui_profile_epoch" ] || return 0
    webui_network_profile_peer=$(sed -n 's/^dial_endpoint=//p' "$webui_network_profile") || return 1
    webui_network_profile_local=$(sed -n 's/^listen_interface=//p' "$webui_network_profile") || return 1
    webui_ipv4_is_valid "$webui_network_profile_peer" || return 0
    webui_ipv4_is_valid "$webui_network_profile_local" || return 0
    webui_network_peer_ip=$webui_network_profile_peer
    webui_network_local_ip=$webui_network_profile_local
    webui_network_profile_ready=true
}

webui_save_network_profile() {
    webui_network_payload=$1
    webui_network_previous_ifs=$IFS
    IFS=,
    set -- $webui_network_payload
    IFS=$webui_network_previous_ifs
    [ "$#" -eq 3 ] || return 1
    webui_network_peer_ip=$1
    webui_network_local_ip=$2
    webui_network_port=$3
    webui_ipv4_is_valid "$webui_network_peer_ip" || return 1
    webui_ipv4_is_valid "$webui_network_local_ip" || return 1
    [ "$webui_network_port" = 37373 ] || return 1
    webui_network_role=$(read_role) || return 1
    if [ "$webui_network_role" = DONOR ]; then
        webui_network_candidates=$(webui_donor_candidates) || return 1
        [ -z "$webui_network_candidates" ] || return 1
    fi
    webui_network_profile=$rka_state_root/profiles/direct.conf
    rka_private_file_is_valid "$webui_network_profile" || return 1
    webui_network_profile_size=$(wc -c < "$webui_network_profile") || return 1
    case $webui_network_profile_size in ''|*[!0-9]*) return 1 ;; esac
    [ "$webui_network_profile_size" -le "$MAX_CONFIG_BYTES" ] || return 1
    [ "$(sed -n '/^dial_endpoint=/p' "$webui_network_profile" | wc -l)" -eq 1 ] || return 1
    [ "$(sed -n '/^listen_interface=/p' "$webui_network_profile" | wc -l)" -eq 1 ] || return 1
    webui_network_updated_profile=$(sed \
        -e "s/^dial_endpoint=.*/dial_endpoint=$webui_network_peer_ip/" \
        -e "s/^listen_interface=.*/listen_interface=$webui_network_local_ip/" \
        "$webui_network_profile") || return 1
    rka_atomic_replace "$rka_state_root/profiles" "$webui_network_profile" "$webui_network_updated_profile
"
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
    webui_current_uptime=$(awk '{printf "%d", $1 * 1000}' "${RKA_RECOVERY_UPTIME_PATH:-/proc/uptime}") || return 0
    case $webui_current_uptime in '' | *[!0-9]*) return 0 ;; esac
    [ "$webui_sentinel_sample" -le "$webui_current_uptime" ] || return 0
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
    webui_request_path=$(webui_pair_request_path "${webui_status_candidate:-}") || return 1
    rka_private_file_is_valid "$webui_request_path" || return 1
    [ "$(wc -c < "$webui_request_path")" -le 64 ] || return 1
    [ "$(cat "$webui_request_path")" = "version=1
action=PAIR_DIRECT" ]
}

webui_donor_candidates() {
    webui_candidate_directory=$rka_state_root/profiles/direct.d
    rka_path_is_private_directory "$webui_candidate_directory" || return 1
    webui_candidate_profiles=$(find "$webui_candidate_directory" -mindepth 1 -maxdepth 1 -name '*.conf' -print | LC_ALL=C sort) || return 1
    while IFS= read -r webui_candidate_profile; do
        [ -n "$webui_candidate_profile" ] || continue
        rka_private_file_is_valid "$webui_candidate_profile" || return 1
        webui_candidate_name=${webui_candidate_profile##*/}
        webui_candidate_name=${webui_candidate_name%.conf}
        rka_candidate_is_valid "$webui_candidate_name" || return 1
        printf '%s\n' "$webui_candidate_name"
    done <<EOF
$webui_candidate_profiles
EOF
}

webui_pair_request_path() {
    webui_selected_candidate=$1
    if [ -z "$webui_selected_candidate" ]; then
        printf '%s\n' "$rka_state_root/profiles/pair.request"
        return 0
    fi
    rka_candidate_is_valid "$webui_selected_candidate" || return 1
    [ "$(read_role)" = DONOR ] || {
        printf '%s\n' "$rka_state_root/profiles/pair.request"
        return 0
    }
    webui_selected_profile=$rka_state_root/profiles/direct.d/$webui_selected_candidate.conf
    rka_private_file_is_valid "$webui_selected_profile" || return 1
    printf '%s\n' "$rka_state_root/profiles/direct.d/$webui_selected_candidate.pair.request"
}

webui_runtime_state() {
    webui_runtime_graph=$(webui_supervisor_graph "${webui_status_candidate:-}") || return 1
    webui_runtime=$(printf '%s\n' "$webui_runtime_graph" | sed -n '1s/^state=//p') || return 1
    case $webui_runtime in STARTING|RUNNING|NOT_READY|STOPPING|STOPPED|FAILED_CRASH_CAP|QUARANTINED_AMBIGUOUS_MUTATION) return 0 ;; *) return 1 ;; esac
}

webui_supervisor_graph() {
    webui_graph_candidate=$1
    if [ -n "$webui_graph_candidate" ]; then
        rka_candidate_is_valid "$webui_graph_candidate" || return 1
        sh "$script_directory/rka-supervisor.sh" --root "$root" \
            --state-root "$rka_state_root" status "$webui_graph_candidate"
    else
        sh "$script_directory/rka-supervisor.sh" --root "$root" \
            --state-root "$rka_state_root" status
    fi
}

webui_supervisor_graph_is_ready() {
    webui_ready_graph=$(webui_supervisor_graph "$1") || return 1
    if [ -n "$1" ]; then
        [ "$webui_ready_graph" = "state=RUNNING
broker=RUNNING
sidecar=RUNNING" ]
    else
        printf '%s\n' "$webui_ready_graph" | grep -Fxq state=RUNNING &&
            printf '%s\n' "$webui_ready_graph" | grep -Fxq broker=RUNNING &&
            printf '%s\n' "$webui_ready_graph" | grep -Fxq sidecar=RUNNING
    fi
}

webui_supervisor_graph_is_stopped() {
    webui_stopped_graph=$(webui_supervisor_graph "$1") || return 1
    if [ -n "$1" ]; then
        [ "$webui_stopped_graph" = "state=STOPPED
broker=STOPPED
sidecar=STOPPED" ]
    else
        [ "$webui_stopped_graph" = "state=STOPPED
legacy=STOPPED
broker=STOPPED
sidecar=STOPPED" ]
    fi
}

webui_direct_runtime_paths() {
    webui_runtime_candidate=$1
    if [ -n "$webui_runtime_candidate" ]; then
        rka_candidate_is_valid "$webui_runtime_candidate" || return 1
        webui_runtime_profile=$rka_state_root/profiles/direct.d/$webui_runtime_candidate.conf
        webui_runtime_receipt=$rka_state_root/run/direct-profile-$webui_runtime_candidate.receipt
        webui_runtime_socket=$rka_state_root/run/sockets/broker-$webui_runtime_candidate.sock
        webui_runtime_broker_record=$rka_state_root/run/pids/broker-$webui_runtime_candidate.pid
    else
        webui_runtime_profile=$rka_state_root/profiles/direct.conf
        webui_runtime_receipt=$rka_state_root/run/direct-profile.receipt
        webui_runtime_socket=$rka_state_root/run/sockets/broker.sock
        webui_runtime_broker_record=$rka_state_root/run/pids/broker.pid
    fi
}

webui_profile_receipt_is_valid() {
    webui_direct_runtime_paths "$1" || return 1
    rka_private_file_is_valid "$webui_runtime_profile" || return 1
    rka_private_file_is_valid "$webui_runtime_receipt" || return 1
    webui_runtime_profile_hash=$(sha256sum "$webui_runtime_profile" | awk '{print $1}') || return 1
    [ "$(sed -n '1p' "$webui_runtime_receipt")" = version=1 ] || return 1
    [ "$(sed -n '2p' "$webui_runtime_receipt")" = "profile_sha256=$webui_runtime_profile_hash" ] || return 1
    [ "$(sed -n '3p' "$webui_runtime_receipt")" = "profile_epoch=$webui_profile_epoch" ] || return 1
    webui_runtime_pin_line=$(sed -n '4p' "$webui_runtime_receipt") || return 1
    case $webui_runtime_pin_line in peer_pin_sha256=????????????????????????????????????????????????????????????????) ;; *) return 1 ;; esac
    case ${webui_runtime_pin_line#peer_pin_sha256=} in *[!0123456789abcdef]*) return 1 ;; esac
    [ "$(sed -n '5p' "$webui_runtime_receipt")" = dial_mode=DONOR_DIALS ] || return 1
    [ "$(sed -n '6p' "$webui_runtime_receipt")" = transport=DIRECT ] || return 1
    [ "$(wc -l < "$webui_runtime_receipt")" -eq 6 ]
}

webui_direct_runtime_evidence_is_ready() {
    webui_direct_runtime_paths "$1" || return 1
    webui_profile_receipt_is_valid "$1" || return 1
    [ -S "$webui_runtime_socket" ] && [ ! -L "$webui_runtime_socket" ] || return 1
    [ "$(stat -c '%u:%g:%a' "$webui_runtime_socket")" = "$(id -u):$(id -g):600" ] || return 1
    webui_supervisor_graph_is_ready "$1"
}

webui_broker_generation() {
    webui_direct_runtime_paths "$1" || return 1
    webui_supervisor_graph_is_ready "$1" || return 1
    rka_private_file_is_valid "$webui_runtime_broker_record" || return 1
    [ "$(wc -c < "$webui_runtime_broker_record")" -le 128 ] || return 1
    webui_broker_record=$(cat "$webui_runtime_broker_record") || return 1
    case $webui_broker_record in *[!0-9\ ]*) return 1 ;; esac
    [ "$(printf '%s\n' "$webui_broker_record" | awk '{print NF}')" -eq 3 ] || return 1
    sha256sum "$webui_runtime_broker_record" | awk '{print $1}'
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

webui_transport_identity_is_valid() {
    webui_transport_identity=$rka_state_root/trust/transport-identity.commit
    webui_transport_pin=$rka_state_root/trust/transport.pin
    rka_private_file_is_valid "$webui_transport_identity" || return 1
    rka_private_file_is_valid "$webui_transport_pin" || return 1
    webui_transport_identity_pin=$(sed -n '2s/^spki_sha256=//p' "$webui_transport_identity") || return 1
    case $webui_transport_identity_pin in
        ????????????????????????????????????????????????????????????????) ;;
        *) return 1 ;;
    esac
    case $webui_transport_identity_pin in *[!0123456789abcdef]*) return 1 ;; esac
    [ "$(cat "$webui_transport_identity")" = "version=1
spki_sha256=$webui_transport_identity_pin" ] || return 1
    [ "$(cat "$webui_transport_pin")" = "$webui_transport_identity_pin" ]
}

webui_status_state() {
    webui_pairing=UNPAIRED
    webui_direct_profile=UNAVAILABLE
    webui_direct_readiness=NOT_READY
    webui_diagnostic=DIAGNOSTIC_ONLY
    webui_status_request=$(webui_pair_request_path "${webui_status_candidate:-}") || return 1
    if [ ! -e "$webui_status_request" ] && [ ! -L "$webui_status_request" ]; then
        return 0
    fi
    webui_pair_request_is_valid || return 1
    webui_pairing=PENDING
    [ "${webui_network_profile_ready:-false}" = true ] || return 0
    webui_direct_profile=DIRECT_NETWORK
    if webui_transport_key_is_valid && webui_transport_trust_is_valid &&
        webui_transport_identity_is_valid &&
        webui_direct_runtime_evidence_is_ready "${webui_status_candidate:-}"; then
        webui_pairing=PAIRED
        if [ "$webui_runtime" = RUNNING ] && [ "$webui_sentinel" = LIVE ]; then
            webui_direct_readiness=READY
        fi
    fi
}

webui_status_block() {
    webui_status_candidate=${1:-}
    webui_role=$(read_role) || return 1
    webui_read_active_profile || return 1
    [ "$webui_role" = "$webui_profile_role" ] || return 1
    webui_runtime_state || return 1
    webui_sentinel_status
    webui_read_network_profile || return 1
    webui_status_state || return 1
    webui_rkp_provisioning_status || return 1
    webui_synthetic_lease_status
    if [ -n "$webui_status_candidate" ]; then
        printf 'candidate_id=%s\n' "$webui_status_candidate"
    fi
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
    printf 'synthetic_lease=%s\n' "$webui_synthetic_lease"
    printf 'lease_epoch=%s\n' "$webui_lease_epoch"
    printf 'lease_next=%s\n' "$webui_lease_next"
    printf 'lease_valid_until_millis=%s\n' "$webui_lease_valid_until_millis"
    printf 'network_peer_ip=%s\n' "$webui_network_peer_ip"
    printf 'network_local_ip=%s\n' "$webui_network_local_ip"
    printf 'network_port=%s\n' "$webui_network_port"
    printf 'quarantine_count=%s\n' "$(webui_quarantine_count)"
}

webui_status() {
    webui_requested_candidate=${1:-}
    webui_status_role=$(read_role) || return 1
    if [ "$webui_status_role" != DONOR ]; then
        webui_status_block
        return $?
    fi
    if [ -n "$webui_requested_candidate" ]; then
        webui_pair_request_path "$webui_requested_candidate" >/dev/null || return 1
        printf 'candidate_begin=%s\n' "$webui_requested_candidate"
        webui_status_block "$webui_requested_candidate" || return 1
        printf 'candidate_end=%s\n' "$webui_requested_candidate"
        return 0
    fi
    webui_status_candidates=$(webui_donor_candidates) || return 1
    if [ -z "$webui_status_candidates" ]; then
        webui_status_block
        return $?
    fi
    while IFS= read -r webui_status_candidate_name; do
        [ -n "$webui_status_candidate_name" ] || continue
        printf 'candidate_begin=%s\n' "$webui_status_candidate_name"
        webui_status_block "$webui_status_candidate_name" || return 1
        printf 'candidate_end=%s\n' "$webui_status_candidate_name"
    done <<EOF
$webui_status_candidates
EOF
}

webui_provisioning_state_path() {
    webui_provisioning_candidate_selector=$1
    if [ -z "$webui_provisioning_candidate_selector" ]; then
        printf '%s\n' "$rka_state_root/journal/provisioning.state"
        return 0
    fi
    rka_candidate_is_valid "$webui_provisioning_candidate_selector" || return 1
    printf '%s\n' "$rka_state_root/journal/provisioning-$webui_provisioning_candidate_selector.state"
}

webui_provisioning_is_current() {
    webui_provisioning_runtime_candidate=$1
    webui_provisioning_path=$(webui_provisioning_state_path "$webui_provisioning_runtime_candidate") || return 1
    if [ ! -e "$webui_provisioning_path" ] && [ ! -L "$webui_provisioning_path" ]; then
        return 1
    fi
    rka_private_file_is_valid "$webui_provisioning_path" || return 1
    webui_provisioning_candidate=${webui_provisioning_runtime_candidate:-GLOBAL}
    webui_provisioning_contents=$(cat "$webui_provisioning_path") || return 1
    webui_provisioning_generation=$(sed -n '6s/^broker_generation_sha256=//p' "$webui_provisioning_path") || return 1
    case $webui_provisioning_generation in
        ????????????????????????????????????????????????????????????????) ;;
        *) return 1 ;;
    esac
    case $webui_provisioning_generation in *[!0123456789abcdef]*) return 1 ;; esac
    [ "$webui_provisioning_contents" = "version=2
status=PROVISIONED
profile_epoch=$webui_profile_epoch
key_count=1
candidate_id=$webui_provisioning_candidate
broker_generation_sha256=$webui_provisioning_generation" ] || return 1
    webui_direct_runtime_evidence_is_ready "$webui_provisioning_runtime_candidate" || return 1
    webui_current_generation=$(webui_broker_generation "$webui_provisioning_runtime_candidate") || return 1
    [ "$webui_current_generation" = "$webui_provisioning_generation" ]
}

webui_rkp_provisioning_status() {
    webui_rkp_provisioning=NOT_APPLICABLE
    [ "$webui_role" = DONOR ] || return 0
    webui_rkp_provisioning=NOT_READY
    if webui_provisioning_is_current "${webui_status_candidate:-}"; then
        webui_rkp_provisioning=PROVISIONED
    fi
}

webui_synthetic_lease_status() {
    webui_synthetic_lease=NOT_APPLICABLE
    webui_lease_epoch=NOT_APPLICABLE
    webui_lease_next=EMPTY
    webui_lease_valid_until_millis=NOT_APPLICABLE
    [ "$webui_role" = CANDIDATE ] || return 0
    webui_synthetic_lease=NOT_READY
    webui_lease_state=$rka_state_root/synthetic-leases/state.bin
    if [ ! -e "$webui_lease_state" ] && [ ! -L "$webui_lease_state" ]; then
        return 0
    fi
    webui_lease_directory=${webui_lease_state%/*}
    if ! rka_path_is_private_directory "$webui_lease_directory" ||
        ! rka_private_file_is_valid "$webui_lease_state"; then
        webui_synthetic_lease=UNAVAILABLE
        return 0
    fi
    webui_lease_sidecar=${RKA_SIDECAR:-$rka_state_root/bin/rka-sidecar}
    if [ ! -f "$webui_lease_sidecar" ] || [ -L "$webui_lease_sidecar" ] ||
        [ ! -x "$webui_lease_sidecar" ] ||
        [ "$(stat -c '%u:%g:%a' "$webui_lease_sidecar")" != "$(id -u):$(id -g):700" ]; then
        webui_synthetic_lease=UNAVAILABLE
        return 0
    fi
    webui_lease_output=$(
        RKA_STATE_ROOT="$rka_state_root" \
        RKA_PROFILE_PATH="$rka_state_root/profiles/direct.conf" \
        RKA_EXPECTED_PROFILE_EPOCH="$webui_profile_epoch" \
            "$webui_lease_sidecar" synthetic-lease-status 2>/dev/null
    ) || {
        webui_synthetic_lease=UNAVAILABLE
        return 0
    }
    [ "$(printf '%s' "$webui_lease_output" | wc -c)" -le 256 ] || {
        webui_synthetic_lease=UNAVAILABLE
        return 0
    }
    webui_lease_status_value=
    webui_lease_epoch_value=
    webui_lease_next_value=
    webui_lease_valid_value=
    webui_lease_count_value=
    webui_lease_lines=0
    while IFS= read -r webui_lease_line || [ -n "$webui_lease_line" ]; do
        webui_lease_lines=$((webui_lease_lines + 1))
        case $webui_lease_line in
            synthetic_lease_status=*)
                [ -z "$webui_lease_status_value" ] || webui_lease_lines=99
                webui_lease_status_value=${webui_lease_line#synthetic_lease_status=}
                ;;
            lease_epoch=*)
                [ -z "$webui_lease_epoch_value" ] || webui_lease_lines=99
                webui_lease_epoch_value=${webui_lease_line#lease_epoch=}
                ;;
            lease_next=*)
                [ -z "$webui_lease_next_value" ] || webui_lease_lines=99
                webui_lease_next_value=${webui_lease_line#lease_next=}
                ;;
            lease_valid_until_millis=*)
                [ -z "$webui_lease_valid_value" ] || webui_lease_lines=99
                webui_lease_valid_value=${webui_lease_line#lease_valid_until_millis=}
                ;;
            lease_certificate_count=*)
                [ -z "$webui_lease_count_value" ] || webui_lease_lines=99
                webui_lease_count_value=${webui_lease_line#lease_certificate_count=}
                ;;
            *) webui_lease_lines=99 ;;
        esac
    done <<EOF
$webui_lease_output
EOF
    case $webui_lease_epoch_value in ''|*[!0-9]*) webui_lease_lines=99 ;; esac
    case $webui_lease_valid_value in ''|*[!0-9]*) webui_lease_lines=99 ;; esac
    case $webui_lease_count_value in ''|*[!0-9]*) webui_lease_lines=99 ;; esac
    case $webui_lease_next_value in
        EMPTY) ;;
        STAGED_*)
            webui_lease_next_epoch=${webui_lease_next_value#STAGED_}
            case $webui_lease_next_epoch in ''|*[!0-9]*) webui_lease_lines=99 ;; esac
            ;;
        *) webui_lease_lines=99 ;;
    esac
    if [ "$webui_lease_lines" -ne 5 ] || [ "$webui_lease_status_value" != ACTIVE ] ||
        [ "$webui_lease_count_value" -lt 2 ] || [ "$webui_lease_count_value" -gt 8 ]; then
        webui_synthetic_lease=UNAVAILABLE
        webui_lease_epoch=NOT_APPLICABLE
        webui_lease_next=EMPTY
        webui_lease_valid_until_millis=NOT_APPLICABLE
        return 0
    fi
    webui_synthetic_lease=ACTIVE
    webui_lease_epoch=$webui_lease_epoch_value
    webui_lease_next=$webui_lease_next_value
    webui_lease_valid_until_millis=$webui_lease_valid_value
}

synthetic_lease_renew_inputs() {
    webui_role=$(read_role) || return 1
    [ "$webui_role" = CANDIDATE ] || return 1
    rka_layout_is_valid && rka_profile_is_valid || return 1
    webui_read_active_profile || return 1
    [ "$webui_profile_role" = CANDIDATE ] || return 1
    webui_runtime_state || return 1
    [ "$webui_runtime" = RUNNING ] || return 1
    webui_sentinel_status
    webui_read_network_profile || return 1
    webui_status_state || return 1
    [ "$webui_direct_readiness" = READY ] || return 1
    synthetic_lease_socket=$rka_state_root/run/sockets/broker.sock
    [ -S "$synthetic_lease_socket" ] && [ ! -L "$synthetic_lease_socket" ] || return 1
    [ "$(stat -c '%u:%g:%a' "$synthetic_lease_socket")" = "$(id -u):$(id -g):600" ] || return 1
    synthetic_lease_sidecar=${RKA_SIDECAR:-$rka_state_root/bin/rka-sidecar}
    [ -f "$synthetic_lease_sidecar" ] && [ ! -L "$synthetic_lease_sidecar" ] &&
        [ -x "$synthetic_lease_sidecar" ] &&
        [ "$(stat -c '%u:%g:%a' "$synthetic_lease_sidecar")" = "$(id -u):$(id -g):700" ] ||
        return 1
}

synthetic_lease_renew() {
    synthetic_lease_renew_inputs || return 1
    synthetic_lease_output=$(
        RKA_STATE_ROOT="$rka_state_root" \
        RKA_PROFILE_PATH="$rka_state_root/profiles/direct.conf" \
        RKA_EXPECTED_PROFILE_EPOCH="$webui_profile_epoch" \
            "$synthetic_lease_sidecar" synthetic-lease-renew 2>/dev/null
    ) || return 1
    printf '%s\n' "$synthetic_lease_output" | grep -Eq \
        '^synthetic_lease_issue_status=READY slot=CURRENT epoch=[0-9]+ lease_id=[0-9a-f]{64} record_sha256=[0-9a-f]{64} certificate_count=[2-8] valid_until_millis=[0-9]+$' || return 1
    printf '%s\n' synthetic_lease_renewal=READY
}

webui_record_request() {
    webui_request_path=$1
    webui_request_body=$2
    rka_layout_is_valid || return 1
    rka_atomic_replace "$(dirname "$webui_request_path")" "$webui_request_path" "$webui_request_body"
}

webui_all_runtimes_are_stopped() {
    webui_supervisor_graph_is_stopped '' || return 1
    webui_stopped_candidates=$(webui_donor_candidates) || return 1
    while IFS= read -r webui_stopped_candidate; do
        [ -n "$webui_stopped_candidate" ] || continue
        webui_supervisor_graph_is_stopped "$webui_stopped_candidate" || return 1
    done <<EOF
$webui_stopped_candidates
EOF
}

webui_recover_role_transaction() {
    webui_role_transaction=$rka_state_root/journal/webui-role.state
    if [ ! -e "$webui_role_transaction" ] && [ ! -L "$webui_role_transaction" ]; then
        return 0
    fi
    rka_private_file_is_valid "$webui_role_transaction" || return 1
    [ "$(wc -l < "$webui_role_transaction")" -eq 4 ] || return 1
    [ "$(sed -n '1p' "$webui_role_transaction")" = version=1 ] || return 1
    webui_transaction_role=$(sed -n '2s/^requested_role=//p' "$webui_role_transaction") || return 1
    case $webui_transaction_role in DONOR|CANDIDATE) ;; *) return 1 ;; esac
    webui_transaction_epoch=$(sed -n '3s/^profile_epoch=//p' "$webui_role_transaction") || return 1
    case $webui_transaction_epoch in ''|*[!0-9]*) return 1 ;; esac
    webui_transaction_direct=$(sed -n '4s/^direct_present=//p' "$webui_role_transaction") || return 1
    case $webui_transaction_direct in true|false) ;; *) return 1 ;; esac
    webui_all_runtimes_are_stopped || return 1
    webui_transaction_direct_path=$rka_state_root/profiles/direct.conf
    if [ "$webui_transaction_direct" = true ]; then
        rka_private_file_is_valid "$webui_transaction_direct_path" || return 1
        [ "$(sed -n '/^role=/p' "$webui_transaction_direct_path" | wc -l)" -eq 1 ] || return 1
        webui_transaction_direct_contents=$(sed "s/^role=.*/role=$webui_transaction_role/" "$webui_transaction_direct_path") || return 1
        rka_atomic_replace "$rka_state_root/profiles" "$webui_transaction_direct_path" "$webui_transaction_direct_contents
" || return 1
    fi
    rka_atomic_replace "$rka_state_root/profiles" "$rka_state_root/profiles/$RKA_PROFILE_NAME" "version=1
role=$webui_transaction_role
profile_epoch=$webui_transaction_epoch
" || return 1
    set_role "$webui_transaction_role" || return 1
    [ "$(read_role)" = "$webui_transaction_role" ] || return 1
    [ "$(sed -n '2s/^role=//p' "$rka_state_root/profiles/$RKA_PROFILE_NAME")" = "$webui_transaction_role" ] || return 1
    if [ "$webui_transaction_direct" = true ]; then
        [ "$(sed -n '2s/^role=//p' "$webui_transaction_direct_path")" = "$webui_transaction_role" ] || return 1
    fi
    rm -f "$webui_role_transaction"
}

webui_set_role() {
    webui_requested_role=$1
    case $webui_requested_role in DONOR|CANDIDATE) ;; *) return 1 ;; esac
    webui_recover_role_transaction || return 1
    webui_all_runtimes_are_stopped || return 1
    webui_read_active_profile || return 1
    webui_direct_profile=$rka_state_root/profiles/direct.conf
    webui_direct_profile_present=false
    if [ -e "$webui_direct_profile" ] || [ -L "$webui_direct_profile" ]; then
        rka_private_file_is_valid "$webui_direct_profile" || return 1
        webui_direct_profile_present=true
    fi
    rka_atomic_replace "$rka_state_root/journal" "$rka_state_root/journal/webui-role.state" "version=1
requested_role=$webui_requested_role
profile_epoch=$webui_profile_epoch
direct_present=$webui_direct_profile_present
" || return 1
    webui_recover_role_transaction
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
    webui_confirm_candidate=${2:-}
    webui_confirm_token=$(webui_next_nonce) || return 1
    webui_record_request "$(webui_confirmation_path)" "version=1
action=$webui_confirm_action
candidate=$webui_confirm_candidate
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
    webui_confirm_candidate=${4:-}
    webui_nonce_is_valid "$webui_confirm_token" || return 1
    webui_confirm_path=$(webui_confirmation_path)
    rka_private_file_is_valid "$webui_confirm_path" || return 1
    [ "$(cat "$webui_confirm_path")" = "version=1
action=$webui_confirm_action
candidate=$webui_confirm_candidate
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
    recovery_ready "$webui_recovery_target" 30000 \
        "$webui_recovery_pid" "$webui_recovery_start" >/dev/null || return 1
    recovery_emit_snapshot "$webui_recovery_target" >/dev/null || return 1
    [ "$recovery_pid" != "$webui_recovery_pid" ] ||
        [ "$recovery_start" != "$webui_recovery_start" ]
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
        status|role-donor|role-candidate|profile-validate-donor|profile-validate-candidate|profile-apply-donor|profile-apply-candidate|network-save|pair-direct|rotate-pairing|provision-rkp|renew-synthetic-lease|rotate-attestation-roots|start|stop|recover-keystore2|recover-rkpd|export-audit|export-evidence|cleanup|quarantine) return 0 ;;
        *) return 1 ;;
    esac
}

webui_request() {
    webui_action=$1
    webui_nonce=$2
    webui_confirmation=${3:-}
    webui_candidate_selector=${4:-}
    webui_action_is_valid "$webui_action" || return 1
    if [ -n "$webui_candidate_selector" ]; then
        rka_candidate_is_valid "$webui_candidate_selector" || return 1
        case $webui_action in status|pair-direct|provision-rkp|renew-synthetic-lease) ;; *) return 1 ;; esac
    fi
    case $webui_action in
        status|quarantine) webui_nonce_matches "$webui_nonce" && webui_status "$webui_candidate_selector"; return $? ;;
    esac
    webui_consume_nonce "$webui_nonce" || return 1
    webui_request_ok=false
    case $webui_action in
        role-donor) webui_set_role DONOR && webui_request_ok=true ;;
        role-candidate) webui_set_role CANDIDATE && webui_request_ok=true ;;
        pair-direct) webui_pair_request=$(webui_pair_request_path "$webui_candidate_selector") &&
            webui_record_request "$webui_pair_request" "version=1
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
        network-save) webui_save_network_profile "$webui_confirmation" && webui_request_ok=true ;;
        recover-keystore2|recover-rkpd|provision-rkp|renew-synthetic-lease|cleanup|rotate-attestation-roots)
            if [ -z "$webui_confirmation" ]; then
                webui_confirmation_ready=true
                case $webui_action in
                    recover-keystore2|recover-rkpd|rotate-attestation-roots)
                        webui_sentinel_status
                        [ "$webui_sentinel" = LIVE ] || webui_confirmation_ready=false
                        ;;
                    provision-rkp)
                        provision_rkp_inputs "$webui_candidate_selector" || webui_confirmation_ready=false
                        ;;
                    renew-synthetic-lease)
                        synthetic_lease_renew_inputs || webui_confirmation_ready=false
                        ;;
                esac
                if [ "$webui_action" = rotate-attestation-roots ] &&
                    ! webui_prepare_root_rotation; then
                    webui_confirmation_ready=false
                fi
                if [ "$webui_confirmation_ready" = true ] &&
                    webui_prepare_confirmation "$webui_action" "$webui_candidate_selector"; then
                    case $webui_action in
                        recover-keystore2) printf '%s\n' recovery_target=KEYSTORE2 ;;
                        recover-rkpd) printf '%s\n' recovery_target=RKPD ;;
                    esac
                    webui_request_ok=true
                fi
            elif webui_confirmation_matches "$webui_action" "$webui_nonce" "$webui_confirmation" "$webui_candidate_selector"; then
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
                        provision_rkp "$webui_candidate_selector" >/dev/null &&
                            webui_request_ok=true
                        ;;
                    renew-synthetic-lease)
                        synthetic_lease_renew && webui_request_ok=true
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
            provision_candidate=
            case $# in
                1) ;;
                3)
                    [ "$2" = --candidate ] || exit 2
                    rka_candidate_is_valid "$3" || exit 2
                    provision_candidate=$3
                    ;;
                *) exit 2 ;;
            esac
            provision_rkp "$provision_candidate" || {
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
            { [ $# -ge 3 ] && [ $# -le 6 ]; } || {
                webui_invalid_request
                exit 1
            }
            webui_confirmation=
            webui_candidate_selector=
            case $# in
                3) ;;
                4) webui_confirmation=$4 ;;
                5)
                    [ "$4" = --candidate ] || {
                        webui_invalid_request
                        exit 1
                    }
                    webui_candidate_selector=$5
                    ;;
                6)
                    [ "$5" = --candidate ] || {
                        webui_invalid_request
                        exit 1
                    }
                    webui_confirmation=$4
                    webui_candidate_selector=$6
                    ;;
            esac
            webui_request "$2" "$3" "$webui_confirmation" "$webui_candidate_selector" || {
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
