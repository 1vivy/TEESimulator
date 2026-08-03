#!/usr/bin/env bash

set -euo pipefail
set -f

readonly USAGE='usage: rka-probe-synthetic-lease.sh --adb PATH --serial SERIAL'

if (( $# != 4 )) || [[ $1 != --adb || $3 != --serial ]]; then
    printf '%s\n' "$USAGE" >&2
    exit 64
fi

readonly adb_command=$2
readonly donor_serial=$4
if [[ ! "$donor_serial" =~ ^[A-Za-z0-9._:-]{1,255}$ ]] ||
    ! command -v "$adb_command" >/dev/null 2>&1; then
    printf '%s\n' "$USAGE" >&2
    exit 64
fi

readonly project_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/rka-adb-root.sh
source "$project_root/scripts/rka-adb-root.sh"

read -r -d '' donor_probe <<'RKA_SYNTHETIC_LEASE_PROBE' || :
set -eu
set -f
state=/data/adb/teesimulator-rka
sidecar=$state/bin/rka-sidecar
socket=$state/run/sockets/broker.sock
role=/data/adb/tricky_store/rka/role.conf

[ -d "$state" ] && [ ! -L "$state" ] || exit 1
[ "$(stat -c '%u:%g:%a' "$state")" = 0:0:700 ] || exit 1
[ -f "$sidecar" ] && [ ! -L "$sidecar" ] && [ -x "$sidecar" ] || exit 1
[ "$(stat -c '%u:%g:%a' "$sidecar")" = 0:0:700 ] || exit 1
[ -S "$socket" ] && [ ! -L "$socket" ] || exit 1
[ "$(stat -c '%u:%g:%a' "$socket")" = 0:0:600 ] || exit 1
[ -f "$role" ] && [ ! -L "$role" ] || exit 1
[ "$(sed -n '2p' "$role")" = role=DONOR ] || exit 1

RKA_STATE_ROOT="$state" RKA_DONOR_SOCKET="$socket" \
    nsenter -t 1 -m -- "$sidecar" synthetic-lease-probe
RKA_SYNTHETIC_LEASE_PROBE
donor_probe+=$'\n'

receipt=$(rka_adb_root_run "$adb_command" "$donor_serial" "$donor_probe" probe)
if [[ ! "$receipt" =~ ^synthetic_lease_probe_status=READY\ certificate_count=([2-9]|1[0-9]|20)\ spki_sha256=[0-9a-f]{64}\ chain_sha256=[0-9a-f]{64}\ leaf_ca=(true|false)\ leaf_key_cert_sign=(true|false)$ ]]; then
    printf '%s\n' 'synthetic_lease_probe_status=invalid_receipt' >&2
    exit 2
fi
printf '%s\n' "$receipt"
