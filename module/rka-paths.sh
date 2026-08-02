#!/bin/sh

set -f

readonly RKA_STATE_ROOT_DEFAULT=/data/adb/teesimulator-rka
readonly RKA_LAYOUT_DIRECTORY_MODE=700
readonly RKA_LAYOUT_FILE_MODE=600
readonly RKA_PROFILE_NAME=active.conf

rka_path_is_clean_absolute() {
    case $1 in
        /*) ;;
        *) return 1 ;;
    esac
    case $1 in
        *'//' | *'/./'* | *'/../'* | */. | */..) return 1 ;;
    esac
    return 0
}

rka_path_is_private_directory() {
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    [ "$(stat -c '%u:%a' "$1")" = "$(id -u):$RKA_LAYOUT_DIRECTORY_MODE" ]
}

rka_ensure_private_directory() {
    rka_requested_directory=$1
    rka_path_is_clean_absolute "$rka_requested_directory" || return 1
    rka_remaining_components=${rka_requested_directory#/}
    rka_component_path=
    while [ -n "$rka_remaining_components" ]; do
        case $rka_remaining_components in
            */*)
                rka_component=${rka_remaining_components%%/*}
                rka_remaining_components=${rka_remaining_components#*/}
                ;;
            *)
                rka_component=$rka_remaining_components
                rka_remaining_components=
                ;;
        esac
        [ -n "$rka_component" ] || return 1
        rka_component_path=$rka_component_path/$rka_component
        [ ! -L "$rka_component_path" ] || return 1
        if [ -e "$rka_component_path" ]; then
            [ -d "$rka_component_path" ] || return 1
        else
            mkdir "$rka_component_path" || return 1
            chmod "$RKA_LAYOUT_DIRECTORY_MODE" "$rka_component_path" || return 1
            rka_path_is_private_directory "$rka_component_path" || return 1
        fi
    done
    rka_path_is_private_directory "$rka_requested_directory"
}

rka_private_file_is_valid() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    [ "$(stat -c '%u:%a' "$1")" = "$(id -u):$RKA_LAYOUT_FILE_MODE" ]
}

rka_optional_private_file_is_valid() {
    [ ! -e "$1" ] && [ ! -L "$1" ] || rka_private_file_is_valid "$1"
}

rka_private_tree_is_valid() {
    rka_path_is_private_directory "$1" || return 1
    rka_entries=$(find "$1" -mindepth 1 -print) || return 1
    while IFS= read -r rka_entry; do
        [ -n "$rka_entry" ] || continue
        [ ! -L "$rka_entry" ] || return 1
        if [ -d "$rka_entry" ]; then
            rka_path_is_private_directory "$rka_entry" || return 1
        else
            rka_private_file_is_valid "$rka_entry" || return 1
        fi
    done <<EOF
$rka_entries
EOF
}

rka_atomic_replace() {
    rka_parent_directory=$1
    rka_destination=$2
    rka_contents=$3
    rka_path_is_private_directory "$rka_parent_directory" || return 1
    [ ! -L "$rka_destination" ] || return 1
    rka_temporary=$(mktemp "$rka_parent_directory/.rka.XXXXXX") || return 1
    trap 'rm -f "$rka_temporary"' EXIT HUP INT TERM
    printf '%s' "$rka_contents" > "$rka_temporary" || return 1
    chmod "$RKA_LAYOUT_FILE_MODE" "$rka_temporary" || return 1
    sync -f "$rka_temporary" || return 1
    mv -f "$rka_temporary" "$rka_destination" || return 1
    sync -f "$rka_parent_directory" || return 1
    trap - EXIT HUP INT TERM
}

rka_layout_directories() {
    printf '%s\n' \
        "$rka_state_root" \
        "$rka_state_root/profiles" \
        "$rka_state_root/secrets" \
        "$rka_state_root/trust" \
        "$rka_state_root/journal" \
        "$rka_state_root/sidecar" \
        "$rka_state_root/sidecar/sessions" \
        "$rka_state_root/sidecar/replay" \
        "$rka_state_root/sidecar/audit" \
        "$rka_state_root/bin" \
        "$rka_state_root/run" \
        "$rka_state_root/run/sockets" \
        "$rka_state_root/run/pids" \
        "$rka_state_root/staging" \
        "$rka_state_root/quarantine" \
        "$rka_state_root/test-keys"
}

rka_mutation_states() {
    printf '%s\n' \
        RKP_KEY_GENERATING \
        RKP_KEY_RECORDED \
        CSR_PREPARED \
        CSR_POSTING \
        POST_AMBIGUOUS \
        RKP_CERTIFIED \
        APP_KEY_GENERATING \
        APP_KEY_RECORDED \
        EXPOSED \
        TERMINAL \
        DELETE
}

rka_layout_is_valid() {
    rka_path_is_clean_absolute "$rka_state_root" || return 1
    while IFS= read -r rka_directory; do
        rka_path_is_private_directory "$rka_directory" || return 1
    done <<EOF
$(rka_layout_directories)
EOF
    rka_optional_private_file_is_valid "$rka_state_root/profiles/$RKA_PROFILE_NAME" || return 1
    rka_optional_private_file_is_valid "$rka_state_root/secrets/transport.key" || return 1
    rka_optional_private_file_is_valid "$rka_state_root/trust/transport-trust.pem" || return 1
    rka_optional_private_file_is_valid "$rka_state_root/journal/mutation.state" || return 1
    for rka_protected_tree in \
        "$rka_state_root/profiles" \
        "$rka_state_root/secrets" \
        "$rka_state_root/trust" \
        "$rka_state_root/journal" \
        "$rka_state_root/sidecar" \
        "$rka_state_root/run" \
        "$rka_state_root/staging" \
        "$rka_state_root/quarantine" \
        "$rka_state_root/test-keys"; do
        rka_private_tree_is_valid "$rka_protected_tree" || return 1
    done
}

rka_profile_is_valid() {
    rka_profile_path=$rka_state_root/profiles/$RKA_PROFILE_NAME
    rka_private_file_is_valid "$rka_profile_path" || return 1
    rka_version_seen=false
    rka_role_seen=false
    rka_epoch_seen=false
    while IFS= read -r rka_profile_line || [ -n "$rka_profile_line" ]; do
        rka_profile_key=${rka_profile_line%%=*}
        rka_profile_value=${rka_profile_line#*=}
        [ "$rka_profile_key" != "$rka_profile_line" ] || return 1
        case $rka_profile_key in
            version)
                [ "$rka_version_seen" = false ] && [ "$rka_profile_value" = 1 ] || return 1
                rka_version_seen=true
                ;;
            role)
                [ "$rka_role_seen" = false ] && role_is_valid "$rka_profile_value" || return 1
                rka_role_seen=true
                ;;
            profile_epoch)
                case $rka_profile_value in
                    '' | *[!0-9]*) return 1 ;;
                    *) [ "$rka_epoch_seen" = false ] || return 1 ;;
                esac
                rka_epoch_seen=true
                ;;
            *) return 1 ;;
        esac
    done < "$rka_profile_path"
    [ "$rka_version_seen" = true ] && [ "$rka_role_seen" = true ] && [ "$rka_epoch_seen" = true ]
}

rka_initialize_layout() {
    rka_requested_role=$1
    role_is_valid "$rka_requested_role" || return 1
    [ "$rka_requested_role" != DISABLED ] || return 1
    umask 077
    while IFS= read -r rka_directory; do
        rka_ensure_private_directory "$rka_directory" || return 1
    done <<EOF
$(rka_layout_directories)
EOF
    rka_layout_is_valid || return 1
    rka_profile_path=$rka_state_root/profiles/$RKA_PROFILE_NAME
    if [ -e "$rka_profile_path" ] || [ -L "$rka_profile_path" ]; then
        rka_profile_is_valid || return 1
    else
        rka_atomic_replace "$rka_state_root/profiles" "$rka_profile_path" "version=1
role=$rka_requested_role
profile_epoch=0
" || return 1
    fi
}

rka_wipe_runtime() {
    rka_layout_is_valid || return 1
    rka_profile_is_valid || return 1
    for rka_wipe_path in "$rka_state_root/sidecar/sessions" "$rka_state_root/test-keys" "$rka_state_root/quarantine"; do
        rka_path_is_private_directory "$rka_wipe_path" || return 1
        rm -rf "$rka_wipe_path" || return 1
        rka_ensure_private_directory "$rka_wipe_path" || return 1
    done
}
