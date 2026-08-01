#!/usr/bin/env bash
# allow: SIZE_OK — the host and streamed remote transaction form one audited rollback state machine.
set -euo pipefail
set -f
umask 077

readonly REMOTE_ZIP='/data/adb/teesimulator-rka/upload/role-neutral-release.zip'
readonly STATE_ROOT='/data/adb/teesimulator-rka'
readonly KSU_NEXT_PROFILE='KSU_NEXT_330'

fail() {
    printf 'RESULT=%s\n' "$1" >&2
    exit "${2:-2}"
}

pair_fd_env=
zip_path=
network=
evidence=
no_reboot=false
candidate_manager_mode=compatible_manager
while (( $# > 0 )); do
    case "$1" in
        --pair-fd-env) pair_fd_env="${2-}"; shift 2 ;;
        --zip) zip_path="${2-}"; shift 2 ;;
        --network) network="${2-}"; shift 2 ;;
        --evidence) evidence="${2-}"; shift 2 ;;
        --candidate-manager-mode) candidate_manager_mode="${2-}"; shift 2 ;;
        --no-reboot) no_reboot=true; shift ;;
        *) fail ARGUMENT_INVALID ;;
    esac
done
[[ "$pair_fd_env" == RKA_DEVICE_PAIR_FD && "$network" == direct-auto && "$no_reboot" == true ]] ||
    fail ARGUMENT_INVALID
[[ -n "$zip_path" && -f "$zip_path" && ! -L "$zip_path" && -n "$evidence" ]] ||
    fail ARGUMENT_INVALID
[[ "$evidence" = /* && ! -L "$evidence" ]] || fail ARGUMENT_INVALID
case "$candidate_manager_mode" in compatible_manager|authorized_headless) ;; *) fail ARGUMENT_INVALID ;; esac

project_root="$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=scripts/rka-adb-root.sh
source "$project_root/scripts/rka-adb-root.sh"
pair_fd="${!pair_fd_env-}"
[[ "$pair_fd" =~ ^[0-9]+$ && -r "/proc/self/fd/$pair_fd" ]] || fail PAIR_DESCRIPTOR_INVALID
mapfile -t pair_values < <(
    python3 - "$pair_fd" <<'PY'
import fcntl
import json
import os
import re
import stat
import sys

fd = int(sys.argv[1])
facts = os.fstat(fd)
expected_seals = (
    fcntl.F_SEAL_SEAL
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_WRITE
)
if (
    os.readlink(f"/proc/self/fd/{fd}") != "/memfd:rka-device-pair (deleted)"
    or not stat.S_ISREG(facts.st_mode)
    or facts.st_size < 1
    or facts.st_size > 65536
    or fcntl.fcntl(fd, fcntl.F_GET_SEALS) != expected_seals
    or fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
):
    raise SystemExit(2)
os.lseek(fd, 0, os.SEEK_SET)
raw = os.read(fd, 65537)
if len(raw) > 65536:
    raise SystemExit(2)
value = json.loads(raw)
if set(value) != {"candidate_serial", "donor_serial", "profile_sha256", "schema_version"}:
    raise SystemExit(2)
if value["schema_version"] != 1 or not re.fullmatch(r"[0-9a-f]{64}", value["profile_sha256"]):
    raise SystemExit(2)
for name in ("donor_serial", "candidate_serial"):
    serial = value[name]
    if not isinstance(serial, str) or not serial or len(serial) > 255 or "\n" in serial or "\0" in serial:
        raise SystemExit(2)
    print(serial)
print(value["profile_sha256"])
PY
) || fail PAIR_DESCRIPTOR_INVALID
[[ "${#pair_values[@]}" -eq 3 && "${pair_values[0]}" != "${pair_values[1]}" ]] ||
    fail PAIR_DESCRIPTOR_INVALID
donor_serial="${pair_values[0]}"
candidate_serial="${pair_values[1]}"
profile_sha="${pair_values[2]}"

[[ -z "$(git -C "$project_root" status --porcelain --untracked-files=no)" ]] ||
    fail SOURCE_WORKTREE_DIRTY
git -C "$project_root" verify-commit HEAD >/dev/null 2>&1 || fail SOURCE_SIGNATURE_INVALID
"$project_root/scripts/rka-audit.sh" secrets --base HEAD --archive "$zip_path" >/dev/null ||
    fail ARCHIVE_INVALID
archive_listing="$(unzip -l -- "$zip_path")" || fail ARCHIVE_INVALID
for required_entry in \
    META-INF/rka-artifacts.sha256 \
    module.prop \
    rka-control.sh \
    rka-runtime.manifest \
    rka-sidecar \
    rka-supervisor.sh \
    sepolicy.probes \
    sepolicy.rule \
    webroot/index.html; do
    archive_entry_count=$(printf '%s\n' "$archive_listing" | awk -v entry="$required_entry" '$NF == entry { count++ } END { print count + 0 }')
    [[ "$archive_entry_count" == 1 ]] || fail ARCHIVE_INVALID
done

adb_command="${RKA_DEPLOY_ADB:-adb}"
command -v "$adb_command" >/dev/null 2>&1 || [[ -x "$adb_command" ]] || fail ADB_UNAVAILABLE
archive_sha="$(sha256sum -- "$zip_path" | awk '{print $1}')"
source_sha="$(git -C "$project_root" rev-parse HEAD 2>/dev/null || true)"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || fail SOURCE_SHA_INVALID
[[ -f "$zip_path.source-sha" && ! -L "$zip_path.source-sha" ]] || fail ARCHIVE_SOURCE_UNBOUND
[[ "$(cat "$zip_path.source-sha")" == "$source_sha" ]] || fail ARCHIVE_SOURCE_MISMATCH
attempt_nonce="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
[[ "$attempt_nonce" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] ||
    fail ATTEMPT_ID_UNAVAILABLE
transaction_id="${source_sha:0:12}-${archive_sha:0:12}-$attempt_nonce"

remote_helper="$(cat <<'REMOTE_HELPER'
set -eu
set -f
mode=$1
shift
active=/data/adb/modules/tricky_store
pending=/data/adb/modules_update/tricky_store
state=/data/adb/teesimulator-rka
expected_version="3.2.5-12-g824f2f23 (uapi: 2)"
expected_manager=me.weishu.kernelsu/.ui.MainActivity
expected_manager_version=v3.2.5-12-g824f2f23
expected_manager_code=32537
expected_ksud_sha=a75099ef6dd9eb5f528df2fdf1aaa2eaa080af3df70b6c69216d28778a8c66c9
expected_source=824f2f235d37dac7f06b31869a138ee7a9309a43
next_version="ksud 3.3.0 (uapi: 2)"
next_sha=f4359553a597955956b97e86277e08bc426f644de0dba5ff13da562fba29c55d
next_reference=3b18216f71df189ab3d1b1ce0bdb21be1268e771
next_manager=com.rifsxd.ksunext
next_activity=com.rifsxd.ksunext/.ui.MainActivity
tree_hash() {
    path=$1
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then printf ABSENT; return; fi
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    entries=$(find "$path" -xdev -print | LC_ALL=C sort) || return 1
    payload=$(
    while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        [ ! -L "$entry" ] || exit 1
        relative=${entry#"$path"}
        printf "%s|" "${relative:-/}"
        stat -c "%F|%u|%g|%a|%Y" "$entry" || exit 1
        label_record=$(ls -Zd "$entry" 2>/dev/null) || exit 1
        label=${label_record%% *}
        attributes_record=$(lsattr -d "$entry" 2>/dev/null) || exit 1
        attributes=${attributes_record%% *}
        printf "%s\n%s\n" "$label" "$attributes"
        if [ -f "$entry" ]; then
            digest_record=$(sha256sum "$entry") || exit 1
            digest=${digest_record%% *}
            printf "%s\n" "$digest"
        fi
    done <<EOF
$entries
EOF
    ) || return 1
    printf "%s\n" "$payload" | sha256sum | awk "{print \$1}"
}
metadata_hash() {
    path=$1
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then printf ABSENT; return; fi
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    entries=$(find "$path" -xdev -print | LC_ALL=C sort) || return 1
    payload=$(
    while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        [ ! -L "$entry" ] || exit 1
        relative=${entry#"$path"}
        printf "%s|" "${relative:-/}"
        stat -c "%F|%u|%g|%a|%Y" "$entry" || exit 1
        label_record=$(ls -Zd "$entry" 2>/dev/null) || exit 1
        label=${label_record%% *}
        attributes_record=$(lsattr -d "$entry" 2>/dev/null) || exit 1
        attributes=${attributes_record%% *}
        printf "%s\n%s\n" "$label" "$attributes"
    done <<EOF
$entries
EOF
    ) || return 1
    printf "%s\n" "$payload" | sha256sum | awk "{print \$1}"
}
set_phase() {
    value=$1
    printf "%s\n" "$value" > "$txn/phase.next"
    chmod 600 "$txn/phase.next"
    mv "$txn/phase.next" "$txn/phase"
    sync "$txn/phase"
}
restore_prior_runtime() {
    prior_bind=$(cat "$txn/prior.bind" 2>/dev/null) || prior_bind=false
    if [ "$prior_bind" = true ] && ! awk -v p="$active" "\$5 == p {found=1} END {exit !found}" /proc/1/mountinfo; then
        [ -d "$pending" ] && [ -d "$active" ] || return 1
        nsenter -t 1 -m -- mount --bind "$pending" "$active" || return 1
    fi
    [ -f "$txn/prior.graph" ] || return 0
    if grep -Eq "^(legacy|broker|sidecar)=RUNNING$" "$txn/prior.graph"; then
        nsenter -t 1 -m -- "$active/rka-supervisor.sh" start || return 1
    else
        nsenter -t 1 -m -- "$active/rka-supervisor.sh" stop || return 1
    fi
    nsenter -t 1 -m -- "$active/rka-supervisor.sh" status > "$txn/recovered.graph" || return 1
    cmp -s "$txn/prior.graph" "$txn/recovered.graph"
}
validate_metadata_manifest() {
    metadata_file=$1
    metadata_kind=$2
    metadata_expected_source=$3
    metadata_seen="$txn/metadata/$metadata_kind.seen"
    : > "$metadata_seen"
    chmod 600 "$metadata_seen"
    metadata_first=true
    metadata_count=0
    while IFS= read -r metadata_line || [ -n "$metadata_line" ]; do
        [ "${#metadata_line}" -le 512 ] || return 1
        if [ "$metadata_kind" = source ] && [ "$metadata_first" = true ]; then
            [ "$metadata_line" = "commit=$metadata_expected_source" ] || return 1
            metadata_first=false
            continue
        fi
        metadata_first=false
        metadata_digest=${metadata_line%%"  "*}
        metadata_path=${metadata_line#*"  "}
        [ "$metadata_digest" != "$metadata_line" ] || return 1
        case "$metadata_digest" in *[!0-9a-f]*|"") return 1 ;; esac
        [ "$(printf %s "$metadata_digest" | wc -c)" -eq 64 ] || return 1
        case "$metadata_path" in
            ""|/*|*/|*//*|*\\*|*[!A-Za-z0-9._/-]*) return 1 ;;
        esac
        metadata_remaining=$metadata_path
        while [ -n "$metadata_remaining" ]; do
            metadata_component=${metadata_remaining%%/*}
            case "$metadata_component" in
                ""|.|..) return 1 ;;
            esac
            case "$metadata_remaining" in
                */*) metadata_remaining=${metadata_remaining#*/} ;;
                *) metadata_remaining= ;;
            esac
        done
        [ "$(printf %s "$metadata_path" | wc -c)" -le 240 ] || return 1
        ! grep -Fxq "$metadata_path" "$metadata_seen" || return 1
        printf '%s\n' "$metadata_path" >> "$metadata_seen"
        metadata_count=$((metadata_count + 1))
        [ "$metadata_count" -le 256 ] || return 1
    done < "$metadata_file"
    [ "$metadata_first" = false ] && [ "$metadata_count" -gt 0 ]
}
prepare_ksu_metadata() {
    metadata_listing=$(unzip -l "$archive") || return 1
    mkdir "$txn/metadata" || return 1
    chmod 700 "$txn/metadata"
    for metadata_entry in META-INF/rka-artifacts.sha256 META-INF/rka-source.sha256; do
        metadata_count=$(printf '%s\n' "$metadata_listing" | awk -v entry="$metadata_entry" '$NF == entry { count++ } END { print count + 0 }')
        [ "$metadata_count" = 1 ] || return 1
        metadata_name=${metadata_entry#META-INF/}
        metadata_next="$txn/metadata/$metadata_name.next"
        unzip -p "$archive" "$metadata_entry" > "$metadata_next" || return 1
        [ -f "$metadata_next" ] && [ ! -L "$metadata_next" ] || return 1
        metadata_bytes=$(stat -c %s "$metadata_next") || return 1
        [ "$metadata_bytes" -gt 0 ] && [ "$metadata_bytes" -le 1048576 ] || return 1
        chmod 600 "$metadata_next"
        mv "$metadata_next" "$txn/metadata/$metadata_name"
    done
    validate_metadata_manifest "$txn/metadata/rka-artifacts.sha256" artifact "$expected_source_sha" || return 1
    validate_metadata_manifest "$txn/metadata/rka-source.sha256" source "$expected_source_sha"
}
reinject_ksu_metadata() {
    [ -d "$pending" ] && [ ! -L "$pending" ] || return 1
    metadata_target="$pending/META-INF"
    [ ! -e "$metadata_target" ] && [ ! -L "$metadata_target" ] || return 1
    metadata_next="$pending/.rka-metadata-$tx"
    [ ! -e "$metadata_next" ] && [ ! -L "$metadata_next" ] || return 1
    mkdir "$metadata_next" || return 1
    chmod 700 "$metadata_next"
    for metadata_name in rka-artifacts.sha256 rka-source.sha256; do
        cp "$txn/metadata/$metadata_name" "$metadata_next/$metadata_name.next" || return 1
        chown 0:0 "$metadata_next/$metadata_name.next" || return 1
        chmod 600 "$metadata_next/$metadata_name.next" || return 1
        cmp -s "$txn/metadata/$metadata_name" "$metadata_next/$metadata_name.next" || return 1
        mv "$metadata_next/$metadata_name.next" "$metadata_next/$metadata_name" || return 1
    done
    [ "$(find "$metadata_next" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 2 ] || return 1
    [ -z "$(find "$metadata_next" -mindepth 1 -maxdepth 1 ! -type f -print)" ] || return 1
    chown 0:0 "$metadata_next" || return 1
    chmod 700 "$metadata_next" || return 1
    mv "$metadata_next" "$metadata_target" || return 1
    [ -d "$metadata_target" ] && [ ! -L "$metadata_target" ] || return 1
}
discard_ksu_metadata() {
    metadata_staging="$txn/metadata"
    [ ! -e "$metadata_staging" ] && [ ! -L "$metadata_staging" ] && return 0
    [ -d "$metadata_staging" ] && [ ! -L "$metadata_staging" ] || return 1
    rm -rf "$metadata_staging"
    [ ! -e "$metadata_staging" ] && [ ! -L "$metadata_staging" ]
}
prepare_active_view_without_update() {
    active_view_source=$1
    active_view_destination=$2
    [ ! -e "$active_view_source" ] && [ ! -L "$active_view_source" ] && return 0
    [ -d "$active_view_source" ] && [ ! -L "$active_view_source" ] || return 1
    cp -a "$active_view_source" "$active_view_destination" || return 1
    if [ -e "$active_view_destination/update" ] || [ -L "$active_view_destination/update" ]; then
        [ -f "$active_view_destination/update" ] && [ ! -L "$active_view_destination/update" ] || return 1
        rm -f "$active_view_destination/update" || return 1
    fi
}
validate_ksu_active_layout() {
    active_layout=$(cat "$txn/layout.before") || return 1
    [ -d "$active" ] && [ ! -L "$active" ] || return 1
    [ -f "$active/update" ] && [ ! -L "$active/update" ] || return 1
    case "$active_layout" in
        FIRST_INSTALL_ABSENT_LAYOUT)
            active_entries=$(find "$active" -mindepth 1 -maxdepth 1 -print | LC_ALL=C sort) || return 1
            expected_active_entries=$(printf '%s\n%s' "$active/module.prop" "$active/update")
            [ "$active_entries" = "$expected_active_entries" ] || return 1
            [ -f "$active/module.prop" ] && [ ! -L "$active/module.prop" ] || return 1
            [ "$(stat -c %u:%g:%a "$active/module.prop")" = 0:0:644 ] || return 1
            cmp -s "$active/module.prop" "$pending/module.prop"
            ;;
        PRESENT_LAYOUT)
            prepare_active_view_without_update "$active" "$txn/active.after.without-update.tree" || return 1
            if [ -d "$txn/active.after.without-update.tree" ]; then
                toybox touch -r "$txn/active.before.without-update.tree" "$txn/active.after.without-update.tree" || return 1
            fi
            [ "$(tree_hash "$txn/active.after.without-update.tree")" = "$(cat "$txn/active.before.without-update")" ] || return 1
            [ "$(metadata_hash "$txn/active.after.without-update.tree")" = "$(cat "$txn/active.metadata.before.without-update")" ] || return 1
            case "$(cat "$txn/active.update.before")" in
                PRESENT) cmp -s "$active/update" "$txn/active.tree/update" ;;
                ABSENT) ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}
case "$mode" in
preflight)
    [ "$(id -u)" = 0 ] || { printf "RESULT=INCOMPATIBLE reason=ROOT\n"; exit; }
    ksud=$(command -v ksud) || { printf "RESULT=INCOMPATIBLE reason=KSUD_MISSING\n"; exit; }
    version=$(ksud --version 2>/dev/null | head -n 1) || :
    if [ "$version" = "$next_version" ]; then
        [ "$ksud" = /data/adb/ksu/bin/ksud ] || { printf "RESULT=INCOMPATIBLE reason=KSUD_LAUNCHER\n"; exit; }
        [ "$(readlink -f "$ksud")" = /data/adb/ksud ] || { printf "RESULT=INCOMPATIBLE reason=KSUD_PATH\n"; exit; }
        [ "$(stat -c %u:%g:%a /data/adb/ksud)" = 0:0:755 ] || { printf "RESULT=INCOMPATIBLE reason=KSUD_METADATA\n"; exit; }
        [ "$(ls -Zd /data/adb/ksud | awk '{print $1}')" = u:object_r:ksu_file:s0 ] || { printf "RESULT=INCOMPATIBLE reason=KSUD_CONTEXT\n"; exit; }
        [ "$(sha256sum /data/adb/ksud | awk '{print $1}')" = "$next_sha" ] || { printf "RESULT=INCOMPATIBLE reason=KSUD_BINARY\n"; exit; }
        module_tree=$(ksud module help 2>/dev/null | sed -n 's/^  \([a-z][a-z-]*\).*$/\1/p' | tr '\n' ' ' | sed 's/ $//') || :
        [ "$module_tree" = "install restore uninstall enable disable action metamodule list config help" ] || { printf "RESULT=INCOMPATIBLE reason=MODULE_CLI\n"; exit; }
        sepolicy_tree=$(ksud sepolicy help 2>/dev/null | sed -n 's/^  \([a-z][a-z-]*\).*$/\1/p' | tr '\n' ' ' | sed 's/ $//') || :
        [ "$sepolicy_tree" = "patch apply check help" ] || { printf "RESULT=INCOMPATIBLE reason=SEPOLICY_CLI\n"; exit; }
        module_layout=PRESENT_LAYOUT
        if [ ! -e /data/adb/modules ] && [ ! -L /data/adb/modules ] && [ ! -e /data/adb/modules_update ] && [ ! -L /data/adb/modules_update ]; then
            [ ! -e "$active" ] && [ ! -L "$active" ] && [ ! -e "$pending" ] && [ ! -L "$pending" ] || { printf "RESULT=INCOMPATIBLE reason=MODULE_LAYOUT\n"; exit; }
            ! awk -v p="$active" "\$5 == p {found=1} END {exit !found}" /proc/1/mountinfo || { printf "RESULT=INCOMPATIBLE reason=MODULE_LAYOUT\n"; exit; }
            [ ! -d "$state/run/pids" ] || { printf "RESULT=INCOMPATIBLE reason=MODULE_LAYOUT\n"; exit; }
            module_layout=FIRST_INSTALL_ABSENT_LAYOUT
        else
            for path in /data/adb/modules /data/adb/modules_update; do
                [ -d "$path" ] && [ ! -L "$path" ] || { printf "RESULT=INCOMPATIBLE reason=MODULE_LAYOUT\n"; exit; }
            done
        fi
        if [ -e /data/adb/metamodule ] || [ -L /data/adb/metamodule ]; then
            [ -L /data/adb/metamodule ] || { printf "RESULT=INCOMPATIBLE reason=METAMODULE_LAYOUT\n"; exit; }
            case "$(readlink -f /data/adb/metamodule)" in /data/adb/modules/*) ;; *) printf "RESULT=INCOMPATIBLE reason=METAMODULE_LAYOUT\n"; exit ;; esac
        fi
        init_ns=$(readlink /proc/1/ns/mnt) || { printf "RESULT=INCOMPATIBLE reason=INIT_NAMESPACE\n"; exit; }
        [ -n "$init_ns" ] || { printf "RESULT=INCOMPATIBLE reason=MOUNT_SEMANTICS\n"; exit; }
        for command in base64 find head lsattr logcat mktemp nsenter sha256sum stat timeout toybox unzip xxd; do
            command -v "$command" >/dev/null 2>&1 || { printf "RESULT=INCOMPATIBLE reason=DEPLOY_TOOLING\n"; exit; }
        done
        boot_hash=$(sha256sum /proc/sys/kernel/random/boot_id | awk "{print \$1}")
        printf "RESULT=COMPATIBLE profile=KSU_NEXT_330 layout=%s boot_hash=%s binary_evidence=exact-observed-binary binary_sha256=%s reference_evidence=reference-source reference_commit=%s markers=update,disable,remove metamodule=single-active-symlink\n" "$module_layout" "$boot_hash" "$next_sha" "$next_reference"
        exit
    fi
    [ "$version" = "$expected_version" ] || { printf "RESULT=INCOMPATIBLE reason=KSUD_VERSION\n"; exit; }
    [ "$(sha256sum "$ksud" | awk "{print \$1}")" = "$expected_ksud_sha" ] || { printf "RESULT=INCOMPATIBLE reason=KSUD_BINARY\n"; exit; }
    ksud module --help >/dev/null 2>&1 || { printf "RESULT=INCOMPATIBLE reason=MODULE_CLI\n"; exit; }
    ksud sepolicy --help >/dev/null 2>&1 || { printf "RESULT=INCOMPATIBLE reason=SEPOLICY_CLI\n"; exit; }
    provenance=/data/adb/ksu/.metadata/ksud.provenance
    [ -f "$provenance" ] && [ ! -L "$provenance" ] && [ "$(stat -c %u:%a "$provenance")" = 0:600 ] || { printf "RESULT=INCOMPATIBLE reason=KSUD_PROVENANCE\n"; exit; }
    [ "$(cat "$provenance")" = "version=1
ksud_version=$expected_version
ksud_sha256=$expected_ksud_sha
source_commit=$expected_source
module_cli=true
sepolicy_cli=true" ] || { printf "RESULT=INCOMPATIBLE reason=KSUD_PROVENANCE\n"; exit; }
    activity=$(cmd package resolve-activity --brief "$expected_manager" 2>/dev/null | tail -n 1) || :
    [ "$activity" = "$expected_manager" ] || { printf "RESULT=INCOMPATIBLE reason=MANAGER_ACTIVITY\n"; exit; }
    package=$(dumpsys package me.weishu.kernelsu 2>/dev/null) || :
    printf "%s\n" "$package" | grep -Fq "versionName=$expected_manager_version" || { printf "RESULT=INCOMPATIBLE reason=MANAGER_VERSION\n"; exit; }
    printf "%s\n" "$package" | grep -Eq "versionCode=$expected_manager_code([[:space:]]|$)" || { printf "RESULT=INCOMPATIBLE reason=MANAGER_CODE\n"; exit; }
    for path in /data/adb/modules /data/adb/modules_update; do
        [ -d "$path" ] && [ ! -L "$path" ] || { printf "RESULT=INCOMPATIBLE reason=MODULE_LAYOUT\n"; exit; }
    done
    for path in "$active" "$pending"; do [ ! -L "$path" ] || { printf "RESULT=INCOMPATIBLE reason=MODULE_SYMLINK\n"; exit; }; done
    init_ns=$(readlink /proc/1/ns/mnt) || { printf "RESULT=INCOMPATIBLE reason=INIT_NAMESPACE\n"; exit; }
    ksud_pid=$(pidof ksud) || { printf "RESULT=INCOMPATIBLE reason=KSUD_PROCESS\n"; exit; }
    case "$ksud_pid" in *" "*) printf "RESULT=INCOMPATIBLE reason=KSUD_PROCESS\n"; exit ;; esac
    ksud_ns=$(readlink "/proc/$ksud_pid/ns/mnt") || { printf "RESULT=INCOMPATIBLE reason=KSUD_NAMESPACE\n"; exit; }
    [ -n "$init_ns" ] && [ -n "$ksud_ns" ] || { printf "RESULT=INCOMPATIBLE reason=MOUNT_SEMANTICS\n"; exit; }
    for command in base64 find head lsattr logcat mktemp nsenter sha256sum stat timeout toybox xxd; do
        command -v "$command" >/dev/null 2>&1 || { printf "RESULT=INCOMPATIBLE reason=DEPLOY_TOOLING\n"; exit; }
    done
    if [ -x "$active/rka-control.sh" ]; then
        expected_control=$(awk "\$2 == \"rka-control.sh\" {print \$1}" "$active/META-INF/rka-artifacts.sha256" 2>/dev/null) || :
        [ -n "$expected_control" ] && [ "$(sha256sum "$active/rka-control.sh" | awk "{print \$1}")" = "$expected_control" ] || { printf "RESULT=INCOMPATIBLE reason=ACTIVE_CONTROL_HASH\n"; exit; }
    fi
    if awk -v p="$active" "\$5 == p {found=1} END {exit !found}" /proc/1/mountinfo; then
        [ -d "$pending" ] && [ -f "$active/module.prop" ] && [ -f "$pending/module.prop" ] || { printf "RESULT=INCOMPATIBLE reason=LIVE_BIND_SOURCE\n"; exit; }
        init_active_inode=$(nsenter -t 1 -m -- stat -c %d:%i "$active/module.prop") || { printf "RESULT=INCOMPATIBLE reason=LIVE_BIND_SOURCE\n"; exit; }
        [ "$init_active_inode" = "$(stat -c %d:%i "$pending/module.prop")" ] || { printf "RESULT=INCOMPATIBLE reason=LIVE_BIND_SOURCE\n"; exit; }
        [ "$(stat -c %d:%i "$active/module.prop")" != "$(stat -c %d:%i "$pending/module.prop")" ] || { printf "RESULT=INCOMPATIBLE reason=ACTIVE_PLACEHOLDER_HIDDEN\n"; exit; }
    fi
    boot_hash=$(sha256sum /proc/sys/kernel/random/boot_id | awk "{print \$1}")
    printf "RESULT=COMPATIBLE boot_hash=%s active_hash=%s pending_hash=%s bind_hash=%s\n" "$boot_hash" "$(tree_hash "$active")" "$(tree_hash "$pending")" "$(awk -v p="$active" "\$5 == p {print \$1 \"|\" \$4}" /proc/1/mountinfo | sha256sum | awk "{print \$1}")"
    ;;
READ_ONLY_PROBE_TRANSFER)
    tx=$1 probe=$2 expected_probe_sha=$3 role=$4
    case "$tx$expected_probe_sha" in *[!A-Za-z0-9._-]*) exit 2 ;; esac
    case "$role" in DONOR|CANDIDATE) ;; *) exit 2 ;; esac
    [ "$probe" = "$state/probes/$tx.$role.manager-appid" ] || exit 2
    [ -f "$probe" ] && [ ! -L "$probe" ] || exit 1
    chown 0:0 "$probe"
    chmod 700 "$probe"
    [ "$(sha256sum "$probe" | awk '{print $1}')" = "$expected_probe_sha" ] || { rm -f "$probe"; exit 1; }
    printf 'RESULT=READ_ONLY_PROBE_TRANSFER sha256=%s\n' "$expected_probe_sha"
    ;;
manager-probe)
    tx=$1 probe=$2 expected_probe_sha=$3 expected_boot=$4 role=$5 authorization_mode=$6
    case "$tx$expected_probe_sha" in *[!A-Za-z0-9._-]*) exit 2 ;; esac
    case "$role:$authorization_mode" in DONOR:compatible_manager|CANDIDATE:compatible_manager|CANDIDATE:authorized_headless) ;; *) exit 2 ;; esac
    [ "$(printf %s "$expected_probe_sha" | wc -c)" -eq 64 ] || exit 2
    expected_probe="$state/probes/$tx.$role.manager-appid"
    [ "$probe" = "$expected_probe" ] && [ -f "$probe" ] && [ ! -L "$probe" ] || exit 1
    cleanup_probe() { rm -f "$probe"; }
    trap cleanup_probe EXIT HUP INT TERM
    [ "$(stat -c %u:%g:%a "$probe")" = 0:0:700 ] || exit 1
    [ "$(sha256sum "$probe" | awk '{print $1}')" = "$expected_probe_sha" ] || exit 1
    [ "$(sha256sum /proc/sys/kernel/random/boot_id | awk '{print $1}')" = "$expected_boot" ] || exit 1
    appid=$($probe manager-appid 2>/dev/null) || { printf "RESULT=INCOMPATIBLE reason=MANAGER_APPID_PROBE\n"; exit; }
    case "$appid" in 0|*[!0-9]*) printf "RESULT=INCOMPATIBLE reason=MANAGER_APPID_INVALID\n"; exit ;; esac
    [ "$appid" -lt 100000 ] || { printf "RESULT=INCOMPATIBLE reason=MANAGER_APPID_INVALID\n"; exit; }
    packages=/data/system/packages.list
    [ -f "$packages" ] && [ ! -L "$packages" ] && [ "$(wc -c < "$packages")" -le 1048576 ] || { printf "RESULT=INCOMPATIBLE reason=PACKAGES_LIST\n"; exit; }
    awk 'NF < 2 || $1 !~ /^[A-Za-z0-9._]+$/ || $2 !~ /^[0-9]+$/ {exit 1}' "$packages" || { printf "RESULT=INCOMPATIBLE reason=PACKAGES_LIST\n"; exit; }
    matches=$(awk -v appid="$appid" 'NF >= 2 && $1 ~ /^[A-Za-z0-9._]+$/ && $2 ~ /^[0-9]+$/ && ($2 % 100000) == appid {print $1 "|" $2}' "$packages") || :
    [ "$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l)" -eq 1 ] || { printf "RESULT=INCOMPATIBLE reason=MANAGER_PACKAGE_AMBIGUOUS\n"; exit; }
    printf '%s\n' "$matches" | grep -Eq '^[A-Za-z0-9._]+[|][0-9]+$' || { printf "RESULT=INCOMPATIBLE reason=MANAGER_PACKAGE_INVALID\n"; exit; }
    IFS='|' read -r package package_uid <<EOF
$matches
EOF
    [ $((package_uid % 100000)) -eq "$appid" ] || { printf "RESULT=INCOMPATIBLE reason=MANAGER_UID_MISMATCH\n"; exit; }
    package_user=$((package_uid / 100000))
    uid_record=$(cmd package list packages -U --user "$package_user" "$package" 2>/dev/null) || { printf "RESULT=INCOMPATIBLE reason=MANAGER_UID_SOURCE\n"; exit; }
    [ "$(printf %s "$uid_record" | wc -c)" -le 4096 ] || { printf "RESULT=INCOMPATIBLE reason=MANAGER_UID_SOURCE\n"; exit; }
    uid_payload=${uid_record#package:}
    bound_package=${uid_payload%% *}
    bound_uid=${uid_payload#* uid:}
    case "$bound_package" in ""|*[!A-Za-z0-9._]*) printf "RESULT=INCOMPATIBLE reason=MANAGER_UID_SOURCE\n"; exit ;; esac
    case "$bound_uid" in ""|*[!0-9]*) printf "RESULT=INCOMPATIBLE reason=MANAGER_UID_SOURCE\n"; exit ;; esac
    [ "$uid_record" = "package:$bound_package uid:$bound_uid" ] && [ "$bound_package" = "$package" ] && [ "$bound_uid" = "$package_uid" ] || { printf "RESULT=INCOMPATIBLE reason=MANAGER_UID_SOURCE\n"; exit; }
    [ $((bound_uid % 100000)) -eq "$appid" ] || { printf "RESULT=INCOMPATIBLE reason=MANAGER_UID_MISMATCH\n"; exit; }
    package_dump=$(dumpsys package "$package" 2>/dev/null) || :
    signing=$(printf '%s\n' "$package_dump" | sed -n -e 's/^ *signatures=//p' -e 's/^ *signingDetails=//p')
    [ -n "$signing" ] && [ "$(printf '%s\n' "$signing" | wc -l)" -eq 1 ] || { printf "RESULT=INCOMPATIBLE reason=MANAGER_SIGNING_METADATA\n"; exit; }
    signing_sha=$(printf %s "$signing" | sha256sum | awk '{print $1}')
    surface=HEADLESS_AUTHORIZED_MANAGER
    if [ "$package" = "$next_manager" ]; then
        activity=$(cmd package resolve-activity --brief "$next_activity" 2>/dev/null | tail -n 1) || :
        [ "$activity" = "$next_activity" ] || { printf "RESULT=INCOMPATIBLE reason=MANAGER_ACTIVITY\n"; exit; }
        printf '%s\n' "$package_dump" | grep -Fq 'versionName=v3.3.0' || { printf "RESULT=INCOMPATIBLE reason=MANAGER_VERSION\n"; exit; }
        printf '%s\n' "$package_dump" | grep -Eq 'versionCode=33214([[:space:]]|$)' || { printf "RESULT=INCOMPATIBLE reason=MANAGER_CODE\n"; exit; }
        surface=KSU_NEXT_MANAGER
    else
        [ "$role:$authorization_mode" = CANDIDATE:authorized_headless ] || { printf "RESULT=INCOMPATIBLE reason=MANAGER_AUTHORIZATION_MODE\n"; exit; }
    fi
    [ "$(sha256sum /proc/sys/kernel/random/boot_id | awk '{print $1}')" = "$expected_boot" ] || { printf "RESULT=INCOMPATIBLE reason=BOOT_ID_DRIFT\n"; exit; }
    receipt="$state/manager-authorizations/$tx"
    mkdir -p "$state/manager-authorizations"
    chmod 700 "$state/manager-authorizations"
    printf 'version=1\nprofile=KSU_NEXT_330\nsurface=%s\npackage=%s\nuid=%s\nappid=%s\nsigning_metadata_sha256=%s\nprobe_transfer=READ_ONLY_PROBE_TRANSFER\nprobe_cleanup=REMOVED\nbinary_evidence=exact-observed-binary\nbinary_sha256=%s\nreference_evidence=reference-source\nreference_commit=%s\nauthorization_mode=%s\n' "$surface" "$package" "$package_uid" "$appid" "$signing_sha" "$next_sha" "$next_reference" "$authorization_mode" > "$receipt"
    chmod 600 "$receipt"
    cleanup_probe
    trap - EXIT HUP INT TERM
    [ ! -e "$probe" ] && [ ! -L "$probe" ] || exit 1
    printf 'RESULT=AUTHORIZED surface=%s appid=%s package=%s probe_cleanup=REMOVED\n' "$surface" "$appid" "$package"
    ;;
prepare-probe)
    mkdir -p "$state/probes"
    chmod 700 "$state" "$state/probes"
    ;;
cleanup-probe)
    tx=$1 role=$2
    case "$tx" in ""|*[!A-Za-z0-9._-]*) exit 2 ;; esac
    case "$role" in DONOR|CANDIDATE) ;; *) exit 2 ;; esac
    probe="$state/probes/$tx.$role.manager-appid"
    : PROBE_CLEANUP_ROLLBACK
    rm -f "$probe"
    [ ! -e "$probe" ] && [ ! -L "$probe" ]
    ;;
prepare-upload)
    mkdir -p "$state/upload"
    chmod 700 "$state" "$state/upload"
    ;;
network)
    network_mode=${1-}
    network_side=${2-}
    network_purpose=${3-}
    case "$network_mode:$network_side:$network_purpose" in
        DONOR_DIALS:DONOR:SOURCE) interface_class='wlan|wifi' ;;
        DONOR_DIALS:CANDIDATE:TARGET) interface_class='tun' ;;
        CANDIDATE_DIALS:*) interface_class='tailscale|wlan|wifi' ;;
        *) exit 2 ;;
    esac
    endpoints=$(ip -o -4 addr show up scope global 2>/dev/null | awk -v interface_class="$interface_class" '
        function valid_ipv4(value, address, octet, part) {
            if (value !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/) return 0
            split(value, address, "/")
            split(address[1], octet, ".")
            if (octet[1] !~ /^[0-9]+$/ || octet[2] !~ /^[0-9]+$/ || octet[3] !~ /^[0-9]+$/ || octet[4] !~ /^[0-9]+$/) return 0
            for (part = 1; part <= 4; part++) if (octet[part] > 255) return 0
            if (octet[1] == 0 || octet[1] == 127 || octet[1] >= 224 || (octet[1] == 169 && octet[2] == 254)) return 0
            return 1
        }
        {
            interface = ""
            endpoint = ""
            global_scope = 0
            for (field = 1; field <= NF; field++) {
                token = $field
                normalized = token
                sub(/@.*/, "", normalized)
                if (token ~ ("^(" interface_class ")[[:alnum:]_.-]*(@[[:alnum:]_.:-]+)?$") && normalized ~ ("^(" interface_class ")[[:alnum:]_.-]*$")) interface = normalized
                if (token == "inet" && field < NF && valid_ipv4($(field + 1))) endpoint = $(field + 1)
                if (token == "scope" && field < NF && $(field + 1) == "global") global_scope = 1
            }
            if (interface != "" && endpoint != "" && global_scope) {
                split(endpoint, address, "/")
                print address[1]
            }
        }
    ')
    [ "$(printf '%s\n' "$endpoints" | sed '/^$/d' | wc -l)" -eq 1 ] || exit 1
    endpoint=$endpoints
    case "$endpoint" in ""|*[!0-9.]*) exit 1 ;; esac
    printf '%s\n' "$endpoint" | awk -F. 'NF == 4 && $1 > 0 && $1 < 224 && $1 != 127 && !($1 == 169 && $2 == 254) {for (i=1;i<=4;i++) if ($i !~ /^[0-9]+$/ || $i > 255) exit 1; exit 0} {exit 1}' || exit 1
    printf "RESULT=NETWORK endpoint=%s\n" "$endpoint"
    ;;
identity-public)
    certificate=$state/trust/transport-self.pem
    [ -f "$certificate" ] && [ ! -L "$certificate" ] && [ "$(stat -c '%u:%a' "$certificate")" = "$(id -u):600" ] || exit 1
    certificate_hex=$(xxd -p "$certificate" | tr -d '\n') || exit 1
    [ -n "$certificate_hex" ] && [ "$(printf %s "$certificate_hex" | wc -c)" -le 32768 ] || exit 1
    printf 'RESULT=IDENTITY_PUBLIC certificate_hex=%s\n' "$certificate_hex"
    ;;
deploy)
    tx=$1 archive=$2 role=$3 expected_archive_sha=$4 expected_source_sha=$5
    case "$tx" in ""|*[!A-Za-z0-9._-]*) exit 2 ;; esac
    case "$role" in DONOR|CANDIDATE) ;; *) exit 2 ;; esac
    case "$expected_archive_sha" in *[!0-9a-f]*) exit 2 ;; esac
    case "$expected_source_sha" in *[!0-9a-f]*) exit 2 ;; esac
    [ "$(printf %s "$expected_archive_sha" | wc -c)" -eq 64 ] || exit 2
    [ "$(printf %s "$expected_source_sha" | wc -c)" -eq 40 ] || exit 2
    [ "$archive" = /data/adb/teesimulator-rka/upload/role-neutral-release.zip ] || exit 2
    txn="$state/deploy-transactions/$tx"
    quarantine="$state/module-quarantine"
    mkdir -p "$state/deploy-transactions" "$quarantine" "$state/upload"
    mkdir "$txn" || exit 1
    chmod 700 "$state" "$state/deploy-transactions" "$txn" "$quarantine" "$state/upload"
    [ "$(sha256sum "$archive" | awk "{print \$1}")" = "$expected_archive_sha" ] || exit 1
    source_receipt=$archive.source-sha
    [ -f "$source_receipt" ] && [ ! -L "$source_receipt" ] || exit 1
    [ "$(cat "$source_receipt")" = "$expected_source_sha" ] || exit 1
    installed_ksud_version=$(ksud --version 2>/dev/null | head -n 1) || exit 1
    if [ "$installed_ksud_version" = "$next_version" ]; then
        metadata_bridge=true
    else
        metadata_bridge=false
    fi
    printf "source_sha=%s\narchive_sha256=%s\n" "$expected_source_sha" "$expected_archive_sha" > "$txn/source.receipt"
    chmod 600 "$txn/source.receipt"
    if [ ! -e /data/adb/modules ] && [ ! -L /data/adb/modules ] && [ ! -e /data/adb/modules_update ] && [ ! -L /data/adb/modules_update ]; then
        printf 'FIRST_INSTALL_ABSENT_LAYOUT\n' > "$txn/layout.before"
    else
        printf 'PRESENT_LAYOUT\n' > "$txn/layout.before"
    fi
    chmod 600 "$txn/layout.before"
    tree_hash "$pending" > "$txn/pending.before"
    metadata_hash "$pending" > "$txn/pending.metadata.before"
    cp -a "$pending" "$txn/pending.tree" 2>/dev/null || [ ! -e "$pending" ]
    if [ -d "$txn/pending.tree" ]; then [ "$(tree_hash "$txn/pending.tree")" = "$(cat "$txn/pending.before")" ] || exit 1; fi
    prior_bind=false
    if awk -v p="$active" "\$5 == p {found=1} END {exit !found}" /proc/1/mountinfo; then prior_bind=true; fi
    printf "%s\n" "$prior_bind" > "$txn/prior.bind"
    if [ -x "$active/rka-control.sh" ]; then
        expected_control=$(awk "\$2 == \"rka-control.sh\" {print \$1}" "$active/META-INF/rka-artifacts.sha256" 2>/dev/null) || :
        [ -n "$expected_control" ] && [ "$(sha256sum "$active/rka-control.sh" | awk "{print \$1}")" = "$expected_control" ] || exit 1
        nsenter -t 1 -m -- "$active/rka-supervisor.sh" status > "$txn/prior.graph"
    fi
    set_phase PREPARED
    if [ -x "$active/rka-control.sh" ]; then
        set_phase STOP_INTENT
        nsenter -t 1 -m -- "$active/rka-supervisor.sh" stop
        set_phase STOPPED
        nsenter -t 1 -m -- "$active/rka-supervisor.sh" status > "$txn/stopped.graph"
        grep -Eq "^(legacy|broker|sidecar)=RUNNING$" "$txn/stopped.graph" && exit 1
    fi
    if [ "$prior_bind" = true ]; then
        set_phase UNMOUNT_INTENT
        nsenter -t 1 -m -- umount "$active"
        set_phase UNMOUNTED
        ! awk -v p="$active" "\$5 == p {found=1} END {exit !found}" /proc/1/mountinfo
    fi
    tree_hash "$active" > "$txn/active.before"
    metadata_hash "$active" > "$txn/active.metadata.before"
    cp -a "$active" "$txn/active.tree" 2>/dev/null || [ ! -e "$active" ]
    if [ -d "$txn/active.tree" ]; then [ "$(tree_hash "$txn/active.tree")" = "$(cat "$txn/active.before")" ] || exit 1; fi
    if [ -f "$state/manager-authorizations/$tx" ]; then
        if [ -e "$txn/active.tree/update" ] || [ -L "$txn/active.tree/update" ]; then
            [ -f "$txn/active.tree/update" ] && [ ! -L "$txn/active.tree/update" ] || exit 1
            printf 'PRESENT\n' > "$txn/active.update.before"
        else
            printf 'ABSENT\n' > "$txn/active.update.before"
        fi
        chmod 600 "$txn/active.update.before"
        prepare_active_view_without_update "$active" "$txn/active.before.without-update.tree" || exit 1
        if [ -d "$txn/active.before.without-update.tree" ]; then
            toybox touch -r "$active" "$txn/active.before.without-update.tree" || exit 1
        fi
        tree_hash "$txn/active.before.without-update.tree" > "$txn/active.before.without-update"
        metadata_hash "$txn/active.before.without-update.tree" > "$txn/active.metadata.before.without-update"
    fi
    touch "$txn/snapshot.ready"
    set_phase SNAPSHOTS_READY
    if [ "$metadata_bridge" = true ]; then prepare_ksu_metadata || exit 1; fi
    if [ -e "$pending" ]; then rm -rf "$pending"; fi
    if ! ksud module install "$archive"; then exit 1; fi
    [ -d "$pending" ] && [ ! -L "$pending" ] || exit 1
    if [ -f "$state/manager-authorizations/$tx" ]; then
        for path in /data/adb/modules /data/adb/modules_update "$active" "$pending"; do
            [ -d "$path" ] && [ ! -L "$path" ] || exit 1
        done
        validate_ksu_active_layout || exit 1
    fi
    if [ "$metadata_bridge" = true ]; then
        reinject_ksu_metadata || exit 1
        [ "${RKA_FAKE_FAULT:-}" != after-metadata ] || exit 1
    fi
    [ "${RKA_FAKE_FAULT:-}" != after-install ] || exit 1
    (cd "$pending" && sha256sum -c META-INF/rka-artifacts.sha256) > "$txn/staged-manifest.verify" 2>&1
    if [ "$metadata_bridge" = true ]; then discard_ksu_metadata || exit 1; fi
    policy="$pending/sepolicy.rule"
    probe_manifest="$pending/sepolicy.probes"
    : > "$txn/sepolicy.probes.validated"
    if [ -s "$policy" ]; then
        [ -f "$probe_manifest" ] && [ ! -L "$probe_manifest" ] || exit 1
        while IFS= read -r rule || [ -n "$rule" ]; do
            case "$rule" in ""|\#*) continue ;; esac
            ksud sepolicy check "$rule"
            rule_hash=$(printf %s "$rule" | sha256sum | awk "{print \$1}")
            probe=$(awk -F "|" -v hash="$rule_hash" "\$1 == hash {print \$2}" "$probe_manifest")
            [ -n "$probe" ] && [ "$(printf "%s\n" "$probe" | wc -l)" -eq 1 ] || exit 1
            case "$probe" in *[!A-Za-z0-9_=-]*) exit 1 ;; esac
            command=$(printf %s "$probe" | base64 -d) || exit 1
            [ -n "$command" ] && [ "$(printf %s "$command" | wc -c)" -le 256 ] || exit 1
            [ "$(printf %s "$command" | base64 | tr -d '\n')" = "$probe" ] || exit 1
            [ "$command" = "exec /data/adb/modules/tricky_store/rka-sepolicy-probe.sh $rule_hash" ] || exit 1
            printf "%s|%s\n" "$rule_hash" "$probe" >> "$txn/sepolicy.probes.validated"
        done < "$policy"
        wall_marker=$(date +%s.%N)
        monotonic_marker=$(awk "{print \$1}" /proc/uptime)
        printf "wall=%s\nmonotonic=%s\n" "$wall_marker" "$monotonic_marker" > "$txn/sepolicy.marker"
        ksud sepolicy apply "$policy" >"$txn/sepolicy.stdout" 2>"$txn/sepolicy.stderr"
        logcat -b all -T "$wall_marker" -d 2>/dev/null | grep -Ei "(ksud|kernelsu).*(warn|error|fail|partial)" > "$txn/sepolicy-logcat.reject" || :
        [ ! -s "$txn/sepolicy-logcat.reject" ]
        ! grep -Ei "warn|error|fail|partial" "$txn/sepolicy.stdout" "$txn/sepolicy.stderr"
        expected_probes=$(grep -Ev "^[[:space:]]*(#|$)" "$policy" | wc -l)
        [ "$(wc -l < "$txn/sepolicy.probes.validated")" -eq "$expected_probes" ]
        [ "$(wc -l < "$probe_manifest")" -eq "$expected_probes" ]
    fi
    mkdir -p "$active"
    nsenter -t 1 -m -- mount --bind "$pending" "$active"
    nsenter -t 1 -m -- "$active/rka-control.sh" set-role "$role"
    nsenter -t 1 -m -- "$active/rka-control.sh" initialize
    mkdir -p "$state/secrets" "$state/trust" "$state/profiles"
    chmod 700 "$state/secrets" "$state/trust" "$state/profiles"
    identity=$(RKA_STATE_ROOT="$state" nsenter -t 1 -m -- "$active/rka-sidecar" direct-identity) || exit 1
    printf "version=1\naction=PAIR_DIRECT\n" > "$state/profiles/pair.request"
    chmod 600 "$state/profiles/pair.request"
    pin=$(printf %s "$identity" | sed -n 's/^RESULT=IDENTITY spki_sha256=\([0-9a-f]\{64\}\)$/\1/p')
    [ -n "$pin" ] || exit 1
    active_inode=$(nsenter -t 1 -m -- stat -c %d:%i "$active/module.prop")
    [ "$active_inode" = "$(stat -c %d:%i "$pending/module.prop")" ]
    nsenter -t 1 -m -- cmp -s "$active/module.prop" "$pending/module.prop"
    nsenter -t 1 -m -- cmp -s "$active/webroot/index.html" "$pending/webroot/index.html"
    tree_hash "$pending" > "$txn/staged.after"
    touch "$txn/installed"
    sync "$txn/installed"
    printf "RESULT=DEPLOYED role=%s source_sha=%s archive_sha256=%s active_before=%s pending_before=%s staged_hash=%s bind_inode=%s pin=%s\n" "$role" "$expected_source_sha" "$expected_archive_sha" "$(cat "$txn/active.before")" "$(cat "$txn/pending.before")" "$(cat "$txn/staged.after")" "$active_inode" "$pin"
    ;;
pair)
    tx=$1 role=$2 peer_pin=$3 dial_endpoint=$4 listen_interface=$5
    shift 5
    peer_certificate_hex=$(printf %s "$@")
    case "$role" in DONOR|CANDIDATE) ;; *) exit 2 ;; esac
    case "$peer_pin" in *[!0-9a-f]*) exit 2 ;; esac
    [ "$(printf %s "$peer_pin" | wc -c)" -eq 64 ] || exit 2
    case "$dial_endpoint" in ""|*[!0-9.]*) exit 2 ;; esac
    case "$listen_interface" in ""|*[!0-9.]*) exit 2 ;; esac
    case "$peer_certificate_hex" in ""|*[!0-9a-f]*) exit 2 ;; esac
    peer_certificate_length=$(printf %s "$peer_certificate_hex" | wc -c)
    [ "$peer_certificate_length" -le 32768 ] && [ $((peer_certificate_length % 2)) -eq 0 ] || exit 2
    txn="$state/deploy-transactions/$tx"
    [ -f "$txn/installed" ] || exit 1
    profile_epoch=$(sed -n '3s/^profile_epoch=//p' "$state/profiles/active.conf") || exit 1
    case "$profile_epoch" in ""|*[!0-9]*) exit 1 ;; esac
    profile_tmp="$state/profiles/.direct.$tx.tmp"
    [ ! -e "$profile_tmp" ] && [ ! -L "$profile_tmp" ] || exit 1
    peer_trust_tmp="$state/trust/.transport-peer.$tx.tmp"
    printf %s "$peer_certificate_hex" | xxd -r -p > "$peer_trust_tmp" || exit 1
    [ "$(xxd -p "$peer_trust_tmp" | tr -d '\n')" = "$peer_certificate_hex" ] || exit 1
    [ "$(sed -n '1p' "$peer_trust_tmp")" = '-----BEGIN CERTIFICATE-----' ] &&
        [ "$(tail -n 1 "$peer_trust_tmp")" = '-----END CERTIFICATE-----' ] || exit 1
    chmod 600 "$peer_trust_tmp"
    mv "$peer_trust_tmp" "$state/trust/transport-peer.pem"
    printf "version=2\nrole=%s\nprofile_epoch=%s\ndial_mode=DONOR_DIALS\ndial_endpoint=%s\nlisten_interface=%s\npeer_spki_sha256=%s\ntransport=DIRECT\n" "$role" "$profile_epoch" "$dial_endpoint" "$listen_interface" "$peer_pin" > "$profile_tmp"
    chmod 600 "$profile_tmp"
    profile_sha=$(sha256sum "$profile_tmp" | awk "{print \$1}")
    mv "$profile_tmp" "$state/profiles/direct.conf"
    RKA_REQUIRE_DIRECT_READY=true RKA_DIRECT_PROFILE_PATH="$state/profiles/direct.conf" nsenter -t 1 -m -- "$active/rka-supervisor.sh" start
    : > "$txn/sepolicy-probes.stdout"
    : > "$txn/sepolicy-probes.stderr"
    probe_marker=$(date +%s.%N)
    while IFS="|" read -r rule_hash probe; do
        [ -n "$rule_hash" ] && [ -n "$probe" ] || exit 1
        command=$(printf %s "$probe" | base64 -d) || exit 1
        [ -n "$command" ] && [ "$(printf %s "$command" | wc -c)" -le 256 ] || exit 1
        timeout 5 nsenter -t 1 -m -- sh -eu -c "$command" >> "$txn/sepolicy-probes.stdout" 2>> "$txn/sepolicy-probes.stderr"
    done < "$txn/sepolicy.probes.validated"
    logcat -b all -T "$probe_marker" -d 2>/dev/null | grep -Ei "avc:.*denied.*(teesimulator|rka|ksu)" > "$txn/sepolicy-probes.reject" || :
    [ ! -s "$txn/sepolicy-probes.reject" ]
    nsenter -t 1 -m -- "$active/rka-supervisor.sh" status > "$txn/new.graph"
    grep -q "broker=RUNNING" "$txn/new.graph"
    grep -q "sidecar=RUNNING" "$txn/new.graph"
    receipt="$state/run/direct-profile.receipt"
    peer_pin_sha=$(printf %s "$peer_pin" | xxd -r -p | sha256sum | awk "{print \$1}")
    [ -f "$receipt" ] && [ ! -L "$receipt" ] && [ "$(cat "$receipt")" = "version=1
profile_sha256=$profile_sha
profile_epoch=$profile_epoch
peer_pin_sha256=$peer_pin_sha
dial_mode=DONOR_DIALS
transport=DIRECT" ] || exit 1
    init_ns=$(readlink /proc/1/ns/mnt) || exit 1
    manager_process=me.weishu.kernelsu
    include_ksud=true
    authorization="$state/manager-authorizations/$tx"
    if [ -f "$authorization" ] && [ ! -L "$authorization" ]; then
        [ "$(sed -n '2s/^profile=//p' "$authorization")" = KSU_NEXT_330 ] || exit 1
        surface=$(sed -n '3s/^surface=//p' "$authorization") || exit 1
        manager_process=$(sed -n '4s/^package=//p' "$authorization") || exit 1
        include_ksud=false
        if [ "$surface" = HEADLESS_AUTHORIZED_MANAGER ]; then
            [ -n "$manager_process" ] || exit 1
            [ "$(sed -n '14s/^authorization_mode=//p' "$authorization")" = authorized_headless ] || exit 1
            nsenter -t 1 -m -- cmp -s "$active/webroot/index.html" "$pending/webroot/index.html" || exit 1
            printf 'surface=HEADLESS_AUTHORIZED_MANAGER\nauthorized_package=%s\nomitted_views=manager,webui\nreason=NO_MANAGER_COMPONENT\n' "$manager_process" > "$txn/webui-owner.receipt"
            chmod 600 "$txn/webui-owner.receipt"
            active_inode=$(nsenter -t 1 -m -- stat -c %d:%i "$active/module.prop") || exit 1
            printf "init=%s\n" "$init_ns" > "$txn/mount-views.receipt"
            for name in broker sidecar; do
                record="$state/run/pids/$name.pid"
                [ -f "$record" ] || exit 1
                pid=$(awk "{print \$1}" "$record")
                ns=$(readlink "/proc/$pid/ns/mnt") || exit 1
                inode=$(nsenter -t "$pid" -m -- stat -c %d:%i "$active/module.prop") || exit 1
                [ "$inode" = "$active_inode" ] || exit 1
                printf "%s=%s|%s\n" "$name" "$ns" "$inode" >> "$txn/mount-views.receipt"
            done
            chmod 600 "$txn/mount-views.receipt"
            printf "RESULT=PAIRED profile_sha256=%s graph_hash=%s mount_views_sha256=%s surface=HEADLESS_AUTHORIZED_MANAGER\n" "$profile_sha" "$(sha256sum "$txn/new.graph" | awk "{print \$1}")" "$(sha256sum "$txn/mount-views.receipt" | awk "{print \$1}")"
            exit 0
        fi
        [ "$surface" = KSU_NEXT_MANAGER ] && [ "$manager_process" = com.rifsxd.ksunext ] || exit 1
    fi
    if [ "$include_ksud" = true ]; then
        ksud_pid=$(pidof ksud) || exit 1
        case "$ksud_pid" in *" "*|*[!0-9]*) exit 1 ;; esac
    fi
    manager_pid=$(pidof "$manager_process") || exit 1
    case "$manager_pid" in *" "*|*[!0-9]*) exit 1 ;; esac
    manager_command=$(cat "/proc/$manager_pid/cmdline" | tr '\0' '\n' | head -n 1) || exit 1
    [ "$manager_command" = "$manager_process" ] || exit 1
    manager_uid=$(awk '/^Uid:/ {print $2; exit}' "/proc/$manager_pid/status") || exit 1
    case "$manager_uid" in ""|*[!0-9]*) exit 1 ;; esac
    if [ -f "$authorization" ]; then
        [ "$manager_uid" = "$(sed -n '5s/^uid=//p' "$authorization")" ] || exit 1
    fi
    webui_pids=$(pidof com.google.android.webview:sandboxed_process0) || exit 1
    services_dump="$state/run/activity-services.$tx"
    rm -f "$services_dump"
    dumpsys activity -a services com.google.android.webview > "$services_dump" || { rm -f "$services_dump"; exit 1; }
    chmod 600 "$services_dump"
    [ "$(wc -c < "$services_dump")" -le 1048576 ] && [ "$(wc -l < "$services_dump")" -le 4096 ] || { rm -f "$services_dump"; exit 1; }
    ownership_records=$(awk -v manager_pid="$manager_pid" -v manager_process="$manager_process" -v candidates="$webui_pids" '
function process_record(line, fields, identity, pid, process) {
    sub(/^.*ProcessRecord\{/, "", line)
    split(line, fields, " ")
    identity = fields[2]
    sub(/\}.*/, "", identity)
    pid = identity
    sub(/:.*/, "", pid)
    process = identity
    sub(/^[^:]*:/, "", process)
    sub(/\/.*/, "", process)
    return pid "|" process "|" fields[1]
}
/^[[:space:]]*\* ServiceRecord\{/ {
    hosting = $0
    sub(/^.*ServiceRecord\{[^ ]+ [^ ]+ /, "", hosting)
    sub(/\}.*/, "", hosting)
    package_name = process_name = renderer = ""
    next
}
/^[[:space:]]*packageName=/ { package_name = $0; sub(/^.*=/, "", package_name); next }
/^[[:space:]]*processName=/ { process_name = $0; sub(/^.*=/, "", process_name); next }
/^[[:space:]]*(app|isolatedProc|isolationHostProc)=ProcessRecord\{/ { renderer = process_record($0); next }
/ -> ProcessRecord\{|\* Client AppBindRecord\{.*ProcessRecord\{/ {
    client = process_record($0)
    split(renderer, renderer_fields, "|")
    split(client, client_fields, "|")
    key = renderer_fields[1] "|" renderer_fields[3] "|" client_fields[3]
    if (package_name == "com.google.android.webview" &&
        process_name == "com.google.android.webview:sandboxed_process0" &&
        hosting ~ /^com.google.android.webview\/.*SandboxedProcessService/ &&
        index(" " candidates " ", " " renderer_fields[1] " ") > 0 &&
        renderer_fields[2] == "com.google.android.webview:sandboxed_process0" &&
        client_fields[1] == manager_pid && client_fields[2] == manager_process &&
        !seen[key]++) {
        print renderer_fields[1] "|" renderer_fields[3] "|" client_fields[3] "|" hosting
    }
}
' "$services_dump") || { rm -f "$services_dump"; exit 1; }
    rm -f "$services_dump"
    [ "$(printf "%s\n" "$ownership_records" | sed '/^$/d' | wc -l)" -eq 1 ] || exit 1
    webui_pid=${ownership_records%%|*}
    ownership_tail=${ownership_records#*|}
    renderer_record=${ownership_tail%%|*}
    ownership_tail=${ownership_tail#*|}
    manager_record=${ownership_tail%%|*}
    hosting_record=${ownership_tail#*|}
    case "$webui_pid$renderer_record$manager_record" in *" "*|*[!0-9a-f]*) exit 1 ;; esac
    renderer_status="$state/run/renderer-status.$tx"
    zygote_status="$state/run/zygote-status.$tx"
    zygote_cmdline="$state/run/zygote-cmdline.$tx"
    rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"
    head -c 4097 "/proc/$webui_pid/status" > "$renderer_status" || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    [ "$(wc -c < "$renderer_status")" -le 4096 ] || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    webui_uid=$(awk '/^Uid:/ {print $2; exit}' "$renderer_status") || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    case "$webui_uid" in ""|*[!0-9]*) exit 1 ;; esac
    webui_app_id=$((webui_uid % 100000))
    [ "$webui_app_id" -ge 99000 ] && [ "$webui_app_id" -le 99999 ] || exit 1
    webui_command=$(cat "/proc/$webui_pid/cmdline" | tr '\0' '\n' | head -n 1) || exit 1
    [ "$webui_command" = com.google.android.webview:sandboxed_process0 ] || exit 1
    renderer_parent_pid=$(awk '/^PPid:/ {print $2; exit}' "$renderer_status") || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    zygote_pid=$(pidof webview_zygote) || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    case "$renderer_parent_pid$zygote_pid" in *" "*|*[!0-9]*) rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1 ;; esac
    [ "$renderer_parent_pid" = "$zygote_pid" ] || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    head -c 4097 "/proc/$zygote_pid/status" > "$zygote_status" || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    [ "$(wc -c < "$zygote_status")" -le 4096 ] || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    zygote_name=$(awk '/^Name:/ {print $2; exit}' "$zygote_status") || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    zygote_uid=$(awk '/^Uid:/ {print $2; exit}' "$zygote_status") || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    [ "$zygote_name" = webview_zygote ] && [ "$zygote_uid" = 1053 ] || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    head -c 257 "/proc/$zygote_pid/cmdline" > "$zygote_cmdline" || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    [ "$(wc -c < "$zygote_cmdline")" -le 256 ] || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    zygote_command=$(tr '\0' '\n' < "$zygote_cmdline" | sed -n '1p') || { rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"; exit 1; }
    rm -f "$renderer_status" "$zygote_status" "$zygote_cmdline"
    [ "$zygote_command" = webview_zygote ] || exit 1
    if [ -n "${surface:-}" ]; then
        printf "surface=%s\nmanager_pid=%s\nmanager_uid=%s\nmanager_process=%s\nmanager_record=%s\nrenderer_pid=%s\nrenderer_uid=%s\nrenderer_process=com.google.android.webview:sandboxed_process0\nrenderer_record=%s\nrenderer_parent_pid=%s\nzygote_pid=%s\nzygote_name=%s\nzygote_uid=%s\nzygote_command=%s\nprovider_package=com.google.android.webview\nhosting_record=%s\n" "$surface" "$manager_pid" "$manager_uid" "$manager_process" "$manager_record" "$webui_pid" "$webui_uid" "$renderer_record" "$renderer_parent_pid" "$zygote_pid" "$zygote_name" "$zygote_uid" "$zygote_command" "$hosting_record" > "$txn/webui-owner.receipt"
    else
        printf "manager_pid=%s\nmanager_uid=%s\nmanager_process=me.weishu.kernelsu\nmanager_record=%s\nrenderer_pid=%s\nrenderer_uid=%s\nrenderer_process=com.google.android.webview:sandboxed_process0\nrenderer_record=%s\nrenderer_parent_pid=%s\nzygote_pid=%s\nzygote_name=%s\nzygote_uid=%s\nzygote_command=%s\nprovider_package=com.google.android.webview\nhosting_record=%s\n" "$manager_pid" "$manager_uid" "$manager_record" "$webui_pid" "$webui_uid" "$renderer_record" "$renderer_parent_pid" "$zygote_pid" "$zygote_name" "$zygote_uid" "$zygote_command" "$hosting_record" > "$txn/webui-owner.receipt"
    fi
    chmod 600 "$txn/webui-owner.receipt"
    active_inode=$(nsenter -t 1 -m -- stat -c %d:%i "$active/module.prop") || exit 1
    printf "init=%s\n" "$init_ns" > "$txn/mount-views.receipt"
    process_views="manager:$manager_pid webui:$webui_pid"
    if [ "$include_ksud" = true ]; then process_views="ksud:$ksud_pid $process_views"; fi
    for process in $process_views; do
        name=${process%%:*}
        pid=${process#*:}
        ns=$(readlink "/proc/$pid/ns/mnt") || exit 1
        inode=$(nsenter -t "$pid" -m -- stat -c %d:%i "$active/module.prop") || exit 1
        [ "$inode" = "$active_inode" ] || exit 1
        printf "%s=%s|%s\n" "$name" "$ns" "$inode" >> "$txn/mount-views.receipt"
    done
    for name in broker sidecar; do
        record="$state/run/pids/$name.pid"
        [ -f "$record" ] || exit 1
        pid=$(awk "{print \$1}" "$record")
        ns=$(readlink "/proc/$pid/ns/mnt") || exit 1
        inode=$(nsenter -t "$pid" -m -- stat -c %d:%i "$active/module.prop") || exit 1
        [ "$inode" = "$active_inode" ] || exit 1
        printf "%s=%s|%s\n" "$name" "$ns" "$inode" >> "$txn/mount-views.receipt"
    done
    chmod 600 "$txn/mount-views.receipt"
    printf "RESULT=PAIRED profile_sha256=%s graph_hash=%s mount_views_sha256=%s\n" "$profile_sha" "$(sha256sum "$txn/new.graph" | awk "{print \$1}")" "$(sha256sum "$txn/mount-views.receipt" | awk "{print \$1}")"
    ;;
direct-probe)
    tx=$1 role=$2
    case "$role" in DONOR) runtime_role=donor ;; CANDIDATE) runtime_role=candidate ;; *) exit 2 ;; esac
    txn="$state/deploy-transactions/$tx"
    [ -f "$txn/installed" ] && [ -s "$state/profiles/direct.conf" ] || exit 1
    nsenter -t 1 -m -- "$active/rka-supervisor.sh" status | grep -q "sidecar=RUNNING"
    profile_epoch=$(sed -n '3s/^profile_epoch=//p' "$state/profiles/active.conf") || exit 1
    case "$profile_epoch" in ""|*[!0-9]*) exit 1 ;; esac
    RKA_STATE_ROOT="$state" \
    RKA_PROFILE_PATH="$state/profiles/direct.conf" \
    RKA_EXPECTED_PROFILE_EPOCH="$profile_epoch" \
    RKA_DIRECT_PROBE_ROLE="$runtime_role" \
    RKA_DIRECT_PROBE_RECEIPT_PATH="$txn/direct-probe.receipt" \
        nsenter -t 1 -m -- "$active/rka-sidecar" direct-probe
    ;;
verify)
    tx=$1 expected_boot=$2
    [ "$(sha256sum /proc/sys/kernel/random/boot_id | awk "{print \$1}")" = "$expected_boot" ] || exit 1
    [ -f "$state/deploy-transactions/$tx/installed" ] || exit 1
    awk -v p="$active" "\$5 == p {found=1} END {exit !found}" /proc/1/mountinfo
    nsenter -t 1 -m -- cmp -s "$active/module.prop" "$pending/module.prop"
    [ "$(nsenter -t 1 -m -- stat -c %d:%i "$active/module.prop")" = "$(stat -c %d:%i "$pending/module.prop")" ]
    nsenter -t 1 -m -- test -r "$active/webroot/index.html"
    printf "RESULT=VERIFIED boot_unchanged=true\n"
    ;;
rollback)
    tx=$1 role=$2
    txn="$state/deploy-transactions/$tx"
    [ -d "$txn" ] || { printf "RESULT=ROLLED_BACK\n"; exit; }
    [ ! -f "$txn/rollback.complete" ] || { printf "RESULT=ROLLED_BACK role=%s additive_sepolicy_may_persist=true\n" "$role"; exit; }
    discard_ksu_metadata || exit 1
    phase=$(cat "$txn/phase" 2>/dev/null) || phase=
    case "$phase" in
        "") printf "RESULT=ROLLED_BACK role=%s additive_sepolicy_may_persist=true\n" "$role"; exit ;;
        PREPARED|STOP_INTENT|STOPPED|UNMOUNT_INTENT|UNMOUNTED)
            restore_prior_runtime || exit 1
            touch "$txn/rollback.complete"
            sync "$txn/rollback.complete"
            printf "RESULT=ROLLED_BACK role=%s additive_sepolicy_may_persist=true\n" "$role"
            exit
            ;;
        SNAPSHOTS_READY) ;;
        *) exit 1 ;;
    esac
    if [ -x "$active/rka-supervisor.sh" ]; then nsenter -t 1 -m -- "$active/rka-supervisor.sh" stop || :; fi
    if awk -v p="$active" "\$5 == p {found=1} END {exit !found}" /proc/1/mountinfo; then
        nsenter -t 1 -m -- umount "$active" || exit 1
        ! awk -v p="$active" "\$5 == p {found=1} END {exit !found}" /proc/1/mountinfo || exit 1
    fi
    if [ -d "$pending" ]; then mv "$pending" "$state/module-quarantine/$tx.failed"; fi
    rm -rf "$active"
    if [ -d "$txn/active.tree" ]; then mv "$txn/active.tree" "$active"; fi
    if [ -d "$txn/pending.tree" ]; then mv "$txn/pending.tree" "$pending"; fi
    [ "$(tree_hash "$active")" = "$(cat "$txn/active.before")" ] || exit 1
    [ "$(tree_hash "$pending")" = "$(cat "$txn/pending.before")" ] || exit 1
    [ "$(metadata_hash "$active")" = "$(cat "$txn/active.metadata.before")" ] || exit 1
    [ "$(metadata_hash "$pending")" = "$(cat "$txn/pending.metadata.before")" ] || exit 1
    if [ "$(cat "$txn/layout.before" 2>/dev/null)" = FIRST_INSTALL_ABSENT_LAYOUT ]; then
        for parent in /data/adb/modules /data/adb/modules_update; do
            [ ! -L "$parent" ] || exit 1
            if [ -e "$parent" ]; then
                [ -d "$parent" ] || exit 1
                [ -z "$(find "$parent" -mindepth 1 -maxdepth 1 -print)" ] || exit 1
                rmdir "$parent" || exit 1
            fi
            [ ! -e "$parent" ] && [ ! -L "$parent" ] || exit 1
        done
    fi
    if [ "$(cat "$txn/prior.bind" 2>/dev/null)" = true ]; then
        nsenter -t 1 -m -- mount --bind "$pending" "$active"
        [ "$(nsenter -t 1 -m -- stat -c %d:%i "$active/module.prop")" = "$(stat -c %d:%i "$pending/module.prop")" ] || exit 1
    fi
    if grep -Eq "^(legacy|broker|sidecar)=RUNNING$" "$txn/prior.graph" 2>/dev/null; then
        nsenter -t 1 -m -- "$active/rka-supervisor.sh" start
        nsenter -t 1 -m -- "$active/rka-supervisor.sh" status > "$txn/restored.graph"
        cmp -s "$txn/prior.graph" "$txn/restored.graph" || exit 1
    fi
    touch "$txn/rollback.complete"
    sync "$txn/rollback.complete"
    printf "RESULT=ROLLED_BACK role=%s additive_sepolicy_may_persist=true\n" "$role"
    ;;
*) exit 2 ;;
esac
REMOTE_HELPER
)"
remote_helper+=$'\n'

remote() {
    local serial="$1"
    shift
    rka_adb_root_run "$adb_command" "$serial" "$remote_helper" "$@"
}

preflight_one() {
    local serial="$1"
    local output
    output="$(remote "$serial" preflight)" || fail KSU_PREFLIGHT_FAILED 3
    if [[ "$output" != RESULT=COMPATIBLE\ * ]]; then
        reason="${output##*reason=}"
        [[ "$reason" =~ ^[A-Z0-9_]+$ ]] || reason=UNPARSEABLE
        printf 'RESULT=KSU_COMPATIBILITY_MISMATCH reason=%s\n' "$reason" >&2
        exit 3
    fi
    printf '%s' "$output"
}

donor_preflight="$(preflight_one "$donor_serial")"
candidate_preflight="$(preflight_one "$candidate_serial")"
donor_boot="$(sed -n 's/.* boot_hash=\([0-9a-f]\{64\}\).*/\1/p' <<<"$donor_preflight")"
candidate_boot="$(sed -n 's/.* boot_hash=\([0-9a-f]\{64\}\).*/\1/p' <<<"$candidate_preflight")"
donor_ksu_profile="$(sed -n 's/.* profile=\([A-Z0-9_]*\).*/\1/p' <<<"$donor_preflight")"
candidate_ksu_profile="$(sed -n 's/.* profile=\([A-Z0-9_]*\).*/\1/p' <<<"$candidate_preflight")"
[[ -n "$donor_boot" && -n "$candidate_boot" ]] || fail KSU_PREFLIGHT_INVALID 3

authorize_next_manager() {
    local serial="$1" role="$2" boot="$3" profile="$4" authorization_mode="$5"
    [[ "$profile" == "$KSU_NEXT_PROFILE" ]] || return 0
    local remote_probe="$STATE_ROOT/probes/$transaction_id.$role.manager-appid"
    cleanup_remote_probe() {
        remote "$serial" cleanup-probe "$transaction_id" "$role"
    }
    remote "$serial" prepare-probe >/dev/null
    rka_adb_protected_push "$adb_command" "$serial" "$local_probe" "$remote_probe" "$probe_sha" 700 "$transaction_id" "$role-probe" || {
        cleanup_remote_probe >/dev/null 2>&1 || fail KSU_PROBE_CLEANUP_FAILED 3
        fail KSU_MANAGER_AUTHORIZATION_FAILED 3
    }
    remote "$serial" READ_ONLY_PROBE_TRANSFER "$transaction_id" "$remote_probe" "$probe_sha" "$role" >/dev/null || {
        cleanup_remote_probe >/dev/null 2>&1 || fail KSU_PROBE_CLEANUP_FAILED 3
        fail KSU_MANAGER_AUTHORIZATION_FAILED 3
    }
    local result
    result="$(remote "$serial" manager-probe "$transaction_id" "$remote_probe" "$probe_sha" "$boot" "$role" "$authorization_mode")" || {
        cleanup_remote_probe >/dev/null 2>&1 || fail KSU_PROBE_CLEANUP_FAILED 3
        fail KSU_MANAGER_AUTHORIZATION_FAILED 3
    }
    [[ "$result" == RESULT=AUTHORIZED\ *probe_cleanup=REMOVED ]] || fail KSU_MANAGER_AUTHORIZATION_FAILED 3
}

if [[ "$donor_ksu_profile" == "$KSU_NEXT_PROFILE" || "$candidate_ksu_profile" == "$KSU_NEXT_PROFILE" ]]; then
    probe_sha="$(unzip -p -- "$zip_path" META-INF/rka-artifacts.sha256 | awk '$2 == "rka-sidecar" {print $1}')"
    [[ "$probe_sha" =~ ^[0-9a-f]{64}$ ]] || fail ARCHIVE_INVALID
    probe_parent="${evidence%/*}"
    [[ "$probe_parent" != "$evidence" ]] || probe_parent=.
    mkdir -p -- "$probe_parent"
    local_probe="$(mktemp "$probe_parent/.rka-manager-probe.XXXXXX")"
    trap 'rm -f -- "$local_probe"' EXIT
    unzip -p -- "$zip_path" rka-sidecar > "$local_probe"
    chmod 700 "$local_probe"
    [[ "$(sha256sum -- "$local_probe" | awk '{print $1}')" == "$probe_sha" ]] || fail ARCHIVE_INVALID
    authorize_next_manager "$donor_serial" DONOR "$donor_boot" "$donor_ksu_profile" compatible_manager
    authorize_next_manager "$candidate_serial" CANDIDATE "$candidate_boot" "$candidate_ksu_profile" "$candidate_manager_mode"
    rm -f -- "$local_probe"
    trap - EXIT
fi
donor_network="$(remote "$donor_serial" network DONOR_DIALS DONOR SOURCE)" || fail DIRECT_PATH_UNAVAILABLE 3
candidate_network="$(remote "$candidate_serial" network DONOR_DIALS CANDIDATE TARGET)" || fail DIRECT_PATH_UNAVAILABLE 3
donor_endpoint="${donor_network##* endpoint=}"
candidate_endpoint="${candidate_network##* endpoint=}"
[[ "$donor_endpoint" =~ ^[0-9.]+$ && "$candidate_endpoint" =~ ^[0-9.]+$ ]] ||
    fail DIRECT_PATH_UNAVAILABLE 3

remote "$donor_serial" prepare-upload >/dev/null
remote "$candidate_serial" prepare-upload >/dev/null
source_receipt_sha="$(sha256sum -- "$zip_path.source-sha" | awk '{print $1}')"
[[ "$source_receipt_sha" =~ ^[0-9a-f]{64}$ ]] || fail ARCHIVE_INVALID
rka_adb_protected_push "$adb_command" "$donor_serial" "$zip_path" "$REMOTE_ZIP" "$archive_sha" 600 "$transaction_id" DONOR-archive
rka_adb_protected_push "$adb_command" "$candidate_serial" "$zip_path" "$REMOTE_ZIP" "$archive_sha" 600 "$transaction_id" CANDIDATE-archive
rka_adb_protected_push "$adb_command" "$donor_serial" "$zip_path.source-sha" "$REMOTE_ZIP.source-sha" "$source_receipt_sha" 600 "$transaction_id" DONOR-source
rka_adb_protected_push "$adb_command" "$candidate_serial" "$zip_path.source-sha" "$REMOTE_ZIP.source-sha" "$source_receipt_sha" 600 "$transaction_id" CANDIDATE-source

rollback_pair() {
    set +e
    remote "$candidate_serial" rollback "$transaction_id" CANDIDATE >/dev/null
    remote "$donor_serial" rollback "$transaction_id" DONOR >/dev/null
    set -e
}
trap 'rollback_pair' ERR INT TERM
donor_result="$(remote "$donor_serial" deploy "$transaction_id" "$REMOTE_ZIP" DONOR "$archive_sha" "$source_sha")" || {
    rollback_pair
    trap - ERR INT TERM
    fail DEPLOY_TRANSACTION_FAILED 4
}
candidate_result="$(remote "$candidate_serial" deploy "$transaction_id" "$REMOTE_ZIP" CANDIDATE "$archive_sha" "$source_sha")" || {
    rollback_pair
    trap - ERR INT TERM
    fail DEPLOY_TRANSACTION_FAILED 4
}
donor_pin="$(sed -n 's/.* pin=\([0-9a-f]\{64\}\).*/\1/p' <<<"$donor_result")"
candidate_pin="$(sed -n 's/.* pin=\([0-9a-f]\{64\}\).*/\1/p' <<<"$candidate_result")"
donor_identity="$(remote "$donor_serial" identity-public)" || fail PAIR_PIN_INVALID 4
candidate_identity="$(remote "$candidate_serial" identity-public)" || fail PAIR_PIN_INVALID 4
donor_certificate="${donor_identity##* certificate_hex=}"
candidate_certificate="${candidate_identity##* certificate_hex=}"
donor_staged="$(sed -n 's/.* staged_hash=\([0-9a-f]\{64\}\).*/\1/p' <<<"$donor_result")"
candidate_staged="$(sed -n 's/.* staged_hash=\([0-9a-f]\{64\}\).*/\1/p' <<<"$candidate_result")"
[[ -n "$donor_pin" && -n "$candidate_pin" && "$donor_pin" != "$candidate_pin" && -n "$donor_staged" && -n "$candidate_staged" &&
    "$donor_identity" == "RESULT=IDENTITY_PUBLIC certificate_hex=$donor_certificate" &&
    "$candidate_identity" == "RESULT=IDENTITY_PUBLIC certificate_hex=$candidate_certificate" &&
    "$donor_certificate" =~ ^[0-9a-f]+$ && "$candidate_certificate" =~ ^[0-9a-f]+$ &&
    ${#donor_certificate} -le 32768 && ${#candidate_certificate} -le 32768 ]] || {
    rollback_pair
    trap - ERR INT TERM
    fail PAIR_PIN_INVALID 4
}
split_certificate() {
    local value=$1
    while [[ -n "$value" ]]; do
        printf '%s\n' "${value:0:1024}"
        value=${value:1024}
    done
}
mapfile -t donor_certificate_arguments < <(split_certificate "$donor_certificate")
mapfile -t candidate_certificate_arguments < <(split_certificate "$candidate_certificate")
complete_pair() {
    donor_pair_result="$(remote "$donor_serial" pair "$transaction_id" DONOR "$candidate_pin" "$candidate_endpoint" "$donor_endpoint" "${candidate_certificate_arguments[@]}")" || return 1
    candidate_pair_result="$(remote "$candidate_serial" pair "$transaction_id" CANDIDATE "$donor_pin" "$candidate_endpoint" "$candidate_endpoint" "${donor_certificate_arguments[@]}")" || return 1
    remote "$donor_serial" direct-probe "$transaction_id" DONOR >/dev/null || return 1
    remote "$candidate_serial" direct-probe "$transaction_id" CANDIDATE >/dev/null || return 1
    remote "$donor_serial" verify "$transaction_id" "$donor_boot" >/dev/null || return 1
    remote "$candidate_serial" verify "$transaction_id" "$candidate_boot" >/dev/null || return 1
}
complete_pair || {
    rollback_pair
    trap - ERR INT TERM
    fail PAIR_VERIFICATION_FAILED 4
}
trap - ERR INT TERM

evidence_parent="${evidence%/*}"
[[ "$evidence_parent" != "$evidence" ]] || evidence_parent=.
mkdir -p -- "$evidence_parent"
temporary="$(mktemp "$evidence_parent/.rka-deploy.XXXXXX")"
trap 'rm -f -- "$temporary"' EXIT
printf '{"archive_sha256":"%s","boot_ids_unchanged":true,"candidate_pair_receipt_sha256":"%s","candidate_receipt_sha256":"%s","candidate_role":"CANDIDATE","candidate_staged_manifest":"%s","direct_path_verified":true,"donor_pair_receipt_sha256":"%s","donor_receipt_sha256":"%s","donor_role":"DONOR","donor_staged_manifest":"%s","network":"DIRECT","profile_sha256":"%s","result":"DEPLOYED_NO_REBOOT","source_sha":"%s","transaction_sha256":"%s","version":1}\n' \
    "$archive_sha" "$(printf %s "$candidate_pair_result" | sha256sum | awk '{print $1}')" "$(printf %s "$candidate_result" | sha256sum | awk '{print $1}')" "$candidate_staged" "$(printf %s "$donor_pair_result" | sha256sum | awk '{print $1}')" "$(printf %s "$donor_result" | sha256sum | awk '{print $1}')" "$donor_staged" "$profile_sha" "$source_sha" "$(printf '%s' "$transaction_id" | sha256sum | awk '{print $1}')" > "$temporary"
chmod 600 "$temporary"
mv -f -- "$temporary" "$evidence"
trap - EXIT
printf '{"archive_sha256":"%s","result":"DEPLOYED_NO_REBOOT","source_sha":"%s","transport":"DIRECT"}\n' "$archive_sha" "$source_sha"
