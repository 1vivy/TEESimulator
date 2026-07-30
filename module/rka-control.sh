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
    printf '%s\n' 'usage: rka-control.sh [--root PATH] [--state-root PATH] {set-role ROLE|initialize|wipe|mutation-states|status|boot-decision}' >&2
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
        *) usage; exit 2 ;;
    esac
done

usage
exit 2
