#!/usr/bin/env bash
# allow: SIZE_OK — the host and streamed remote transaction form one audited rollback state machine.
set -euo pipefail
set -f
umask 077

readonly REMOTE_ZIP='/data/adb/teesimulator-rka/upload/role-neutral-release.zip'
readonly STATE_ROOT='/data/adb/teesimulator-rka'

fail() {
    printf 'RESULT=%s\n' "$1" >&2
    exit "${2:-2}"
}

pair_fd_env=
zip_path=
network=
evidence=
no_reboot=false
while (( $# > 0 )); do
    case "$1" in
        --pair-fd-env) pair_fd_env="${2-}"; shift 2 ;;
        --zip) zip_path="${2-}"; shift 2 ;;
        --network) network="${2-}"; shift 2 ;;
        --evidence) evidence="${2-}"; shift 2 ;;
        --no-reboot) no_reboot=true; shift ;;
        *) fail ARGUMENT_INVALID ;;
    esac
done
[[ "$pair_fd_env" == RKA_DEVICE_PAIR_FD && "$network" == direct-auto && "$no_reboot" == true ]] ||
    fail ARGUMENT_INVALID
[[ -n "$zip_path" && -f "$zip_path" && ! -L "$zip_path" && -n "$evidence" ]] ||
    fail ARGUMENT_INVALID
[[ "$evidence" = /* && ! -L "$evidence" ]] || fail ARGUMENT_INVALID

project_root="$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
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
archive_entries="$(unzip -Z1 -- "$zip_path")" || fail ARCHIVE_INVALID
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
    grep -Fxq "$required_entry" <<<"$archive_entries" || fail ARCHIVE_INVALID
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
case "$mode" in
preflight)
    [ "$(id -u)" = 0 ] || { printf "RESULT=INCOMPATIBLE reason=ROOT\n"; exit; }
    ksud=$(command -v ksud) || { printf "RESULT=INCOMPATIBLE reason=KSUD_MISSING\n"; exit; }
    version=$(ksud --version 2>/dev/null | head -n 1) || :
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
    for path in "$active" "$pending"; do [ ! -L "$path" ] || { printf "RESULT=INCOMPATIBLE reason=MODULE_SYMLINK\n"; exit; }; done
    init_ns=$(readlink /proc/1/ns/mnt) || { printf "RESULT=INCOMPATIBLE reason=INIT_NAMESPACE\n"; exit; }
    ksud_pid=$(pidof ksud) || { printf "RESULT=INCOMPATIBLE reason=KSUD_PROCESS\n"; exit; }
    case "$ksud_pid" in *" "*) printf "RESULT=INCOMPATIBLE reason=KSUD_PROCESS\n"; exit ;; esac
    ksud_ns=$(readlink "/proc/$ksud_pid/ns/mnt") || { printf "RESULT=INCOMPATIBLE reason=KSUD_NAMESPACE\n"; exit; }
    [ -n "$init_ns" ] && [ -n "$ksud_ns" ] || { printf "RESULT=INCOMPATIBLE reason=MOUNT_SEMANTICS\n"; exit; }
    for command in base64 find lsattr logcat nsenter openssl sha256sum stat timeout toybox xxd; do
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
network)
    endpoint=$(ip -o -4 addr show up scope global 2>/dev/null | awk "\$2 ~ /^(tailscale|wlan)/ {split(\$4, value, \"/\"); print value[1]}" | head -n 1)
    case "$endpoint" in ""|*[!0-9.]*) exit 1 ;; esac
    printf "RESULT=NETWORK endpoint=%s\n" "$endpoint"
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
    printf "source_sha=%s\narchive_sha256=%s\n" "$expected_source_sha" "$expected_archive_sha" > "$txn/source.receipt"
    chmod 600 "$txn/source.receipt"
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
    touch "$txn/snapshot.ready"
    set_phase SNAPSHOTS_READY
    if [ -e "$pending" ]; then rm -rf "$pending"; fi
    if ! ksud module install "$archive"; then exit 1; fi
    [ -d "$pending" ] && [ ! -L "$pending" ] || exit 1
    (cd "$pending" && sha256sum -c META-INF/rka-artifacts.sha256) > "$txn/staged-manifest.verify" 2>&1
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
    if [ ! -s "$state/secrets/transport.key" ]; then
        command -v openssl >/dev/null
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj /CN=teesimulator-rka -keyout "$state/secrets/transport.key" -out "$state/trust/transport-self.pem" >/dev/null 2>&1
        chmod 600 "$state/secrets/transport.key" "$state/trust/transport-self.pem"
    fi
    cp "$state/trust/transport-self.pem" "$state/trust/transport-trust.pem"
    chmod 600 "$state/trust/transport-trust.pem"
    printf "version=1\naction=PAIR_DIRECT\n" > "$state/profiles/pair.request"
    chmod 600 "$state/profiles/pair.request"
    pin=$(openssl x509 -in "$state/trust/transport-self.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk "{print \$1}")
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
    tx=$1 role=$2 peer_pin=$3 peer_endpoint=$4
    case "$role" in DONOR|CANDIDATE) ;; *) exit 2 ;; esac
    case "$peer_pin" in *[!0-9a-f]*) exit 2 ;; esac
    [ "$(printf %s "$peer_pin" | wc -c)" -eq 64 ] || exit 2
    case "$peer_endpoint" in ""|*[!0-9.]*) exit 2 ;; esac
    txn="$state/deploy-transactions/$tx"
    [ -f "$txn/installed" ] || exit 1
    profile_epoch=$(sed -n '3s/^profile_epoch=//p' "$state/profiles/active.conf") || exit 1
    case "$profile_epoch" in ""|*[!0-9]*) exit 1 ;; esac
    profile_tmp="$state/profiles/.direct.$tx.tmp"
    [ ! -e "$profile_tmp" ] && [ ! -L "$profile_tmp" ] || exit 1
    printf "version=1\nrole=%s\nprofile_epoch=%s\npeer_endpoint=%s\npeer_spki_sha256=%s\ntransport=DIRECT\n" "$role" "$profile_epoch" "$peer_endpoint" "$peer_pin" > "$profile_tmp"
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
transport=DIRECT" ] || exit 1
    init_ns=$(readlink /proc/1/ns/mnt) || exit 1
    ksud_pid=$(pidof ksud) || exit 1
    manager_pid=$(pidof me.weishu.kernelsu) || exit 1
    case "$ksud_pid$manager_pid" in *" "*|*[!0-9]*) exit 1 ;; esac
    manager_command=$(cat "/proc/$manager_pid/cmdline" | tr '\0' '\n' | head -n 1) || exit 1
    [ "$manager_command" = me.weishu.kernelsu ] || exit 1
    manager_uid=$(awk '/^Uid:/ {print $2; exit}' "/proc/$manager_pid/status") || exit 1
    case "$manager_uid" in ""|*[!0-9]*) exit 1 ;; esac
    webui_pids=$(pidof com.google.android.webview:sandboxed_process0) || exit 1
    services_dump="$state/run/activity-services.$tx"
    rm -f "$services_dump"
    dumpsys activity -a services com.google.android.webview > "$services_dump" || { rm -f "$services_dump"; exit 1; }
    chmod 600 "$services_dump"
    [ "$(wc -c < "$services_dump")" -le 1048576 ] && [ "$(wc -l < "$services_dump")" -le 4096 ] || { rm -f "$services_dump"; exit 1; }
    ownership_records=$(awk -v manager_pid="$manager_pid" -v candidates="$webui_pids" '
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
        client_fields[1] == manager_pid && client_fields[2] == "me.weishu.kernelsu" &&
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
    webui_uid=$(awk '/^Uid:/ {print $2; exit}' "/proc/$webui_pid/status") || exit 1
    case "$webui_uid" in ""|*[!0-9]*) exit 1 ;; esac
    webui_app_id=$((webui_uid % 100000))
    [ "$webui_app_id" -ge 99000 ] && [ "$webui_app_id" -le 99999 ] || exit 1
    webui_command=$(cat "/proc/$webui_pid/cmdline" | tr '\0' '\n' | head -n 1) || exit 1
    [ "$webui_command" = com.google.android.webview:sandboxed_process0 ] || exit 1
    printf "manager_pid=%s\nmanager_uid=%s\nmanager_process=me.weishu.kernelsu\nmanager_record=%s\nrenderer_pid=%s\nrenderer_uid=%s\nrenderer_process=com.google.android.webview:sandboxed_process0\nrenderer_record=%s\nprovider_package=com.google.android.webview\nhosting_record=%s\n" "$manager_pid" "$manager_uid" "$manager_record" "$webui_pid" "$webui_uid" "$renderer_record" "$hosting_record" > "$txn/webui-owner.receipt"
    chmod 600 "$txn/webui-owner.receipt"
    active_inode=$(nsenter -t 1 -m -- stat -c %d:%i "$active/module.prop") || exit 1
    printf "init=%s\n" "$init_ns" > "$txn/mount-views.receipt"
    for process in "ksud:$ksud_pid" "manager:$manager_pid" "webui:$webui_pid"; do
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
    tx=$1 peer_endpoint=$2 peer_pin=$3
    [ -f "$state/deploy-transactions/$tx/installed" ] && [ -s "$state/profiles/direct.conf" ] || exit 1
    nsenter -t 1 -m -- "$active/rka-supervisor.sh" status | grep -q "sidecar=RUNNING"
    ping -c 1 -W 2 "$peer_endpoint" >/dev/null 2>&1
    peer_certificate="$state/run/peer-certificate.pem"
    printf "\n" | openssl s_client -connect "$peer_endpoint:37373" -tls1_3 -showcerts 2>/dev/null | openssl x509 -out "$peer_certificate"
    chmod 600 "$peer_certificate"
    observed_pin=$(openssl x509 -in "$peer_certificate" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk "{print \$1}")
    rm -f "$peer_certificate"
    [ "$observed_pin" = "$peer_pin" ]
    printf "RESULT=DIRECT\n"
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

remote() {
    local serial="$1"
    shift
    printf '%s\n' "$remote_helper" |
        "$adb_command" -s "$serial" shell su 0 sh -s -- "$@"
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
[[ -n "$donor_boot" && -n "$candidate_boot" ]] || fail KSU_PREFLIGHT_INVALID 3
donor_network="$(remote "$donor_serial" network)" || fail DIRECT_PATH_UNAVAILABLE 3
candidate_network="$(remote "$candidate_serial" network)" || fail DIRECT_PATH_UNAVAILABLE 3
donor_endpoint="${donor_network##* endpoint=}"
candidate_endpoint="${candidate_network##* endpoint=}"
[[ "$donor_endpoint" =~ ^[0-9.]+$ && "$candidate_endpoint" =~ ^[0-9.]+$ ]] ||
    fail DIRECT_PATH_UNAVAILABLE 3

mkdir_remote=(shell su 0 sh -c "mkdir -p '$STATE_ROOT/upload' && chmod 700 '$STATE_ROOT' '$STATE_ROOT/upload'")
"$adb_command" -s "$donor_serial" "${mkdir_remote[@]}" >/dev/null
"$adb_command" -s "$candidate_serial" "${mkdir_remote[@]}" >/dev/null
"$adb_command" -s "$donor_serial" push "$zip_path" "$REMOTE_ZIP" >/dev/null
"$adb_command" -s "$candidate_serial" push "$zip_path" "$REMOTE_ZIP" >/dev/null
"$adb_command" -s "$donor_serial" push "$zip_path.source-sha" "$REMOTE_ZIP.source-sha" >/dev/null
"$adb_command" -s "$candidate_serial" push "$zip_path.source-sha" "$REMOTE_ZIP.source-sha" >/dev/null

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
donor_staged="$(sed -n 's/.* staged_hash=\([0-9a-f]\{64\}\).*/\1/p' <<<"$donor_result")"
candidate_staged="$(sed -n 's/.* staged_hash=\([0-9a-f]\{64\}\).*/\1/p' <<<"$candidate_result")"
[[ -n "$donor_pin" && -n "$candidate_pin" && "$donor_pin" != "$candidate_pin" && -n "$donor_staged" && -n "$candidate_staged" ]] || {
    rollback_pair
    trap - ERR INT TERM
    fail PAIR_PIN_INVALID 4
}
complete_pair() {
    donor_pair_result="$(remote "$donor_serial" pair "$transaction_id" DONOR "$candidate_pin" "$candidate_endpoint")" || return 1
    candidate_pair_result="$(remote "$candidate_serial" pair "$transaction_id" CANDIDATE "$donor_pin" "$donor_endpoint")" || return 1
    remote "$donor_serial" direct-probe "$transaction_id" "$candidate_endpoint" "$candidate_pin" >/dev/null || return 1
    remote "$candidate_serial" direct-probe "$transaction_id" "$donor_endpoint" "$donor_pin" >/dev/null || return 1
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
