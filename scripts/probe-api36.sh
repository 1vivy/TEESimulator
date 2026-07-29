#!/usr/bin/env bash
set -euo pipefail

# Host-only, read-only probe. It does not transfer files, write on the device,
# trace/inject processes, create keys, alter properties, or control services.
readonly ADB=${ADB:-adb}
readonly ADB_TIMEOUT_SECONDS=${ADB_TIMEOUT_SECONDS:-20}
readonly AIDL_VERSION_TRANSACTION=16777215
readonly AIDL_HASH_TRANSACTION=16777214

failed=0
declare -a check_names=()
declare -a check_verdicts=()

pass() {
  printf 'PASS %s\n' "$1"; check_names+=("$1"); check_verdicts+=(PASS)
}

stop() {
  printf 'STOP %s\n' "$1"; check_names+=("$1"); check_verdicts+=(STOP); failed=1
}

emit_json() {
  local verdict=PASS index
  (( failed == 0 )) || verdict=STOP
  printf '{"verdict":"%s","checks":[' "$verdict"
  for index in "${!check_names[@]}"; do
    (( index == 0 )) || printf ','
    printf '{"name":"%s","verdict":"%s"}' "${check_names[index]}" "${check_verdicts[index]}"
  done
  printf ']}\n'
}

finish() { (( failed == 0 )) && printf 'PASS G1\n' || printf 'STOP G1\n'; emit_json; }
adb_command() { timeout "$ADB_TIMEOUT_SECONDS" "$ADB" -s "$ADB_SERIAL" "$@" 2>/dev/null || true; }
shell_read() { adb_command shell "$@" | tr -d '\000\r'; }
root_read() {
  local command=$1 escaped
  escaped=${command//\'/\'\"\'\"\'}
  shell_read "su -c '$escaped'"
}

readonly SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/probe-api36-lib.sh"

if [[ $# != 2 || -z "${1:-}" || -z "${2:-}" || "$1" == -* || ! -r "$2" || ! -f "$2" ]]; then
  stop arguments-required
  finish
  exit 2
fi

readonly ADB_SERIAL=$1
readonly PROFILE=$2
if ! load_profile; then
  finish
  exit 2
fi

check_equals api-36 "$(shell_read getprop ro.build.version.sdk)" "$SDK"
check_equals abi-arm64-v8a "$(shell_read getprop ro.product.cpu.abi)" "$ABI"
check_equals selinux-enforcing "$(shell_read getenforce | tr '[:upper:]' '[:lower:]')" "$SELINUX"
check_equals avb-green "$(shell_read getprop ro.boot.verifiedbootstate)" "$AVB_STATE"

services=$(shell_read service list)
grep -Fq "$DEFAULT_INSTANCE" <<<"$services" && pass service-keymint-default || stop service-keymint-default

pid1=$(shell_read pidof keystore2)
sleep 1
pid2=$(shell_read pidof keystore2)
if [[ "$pid1" =~ ^[0-9]+$ && "$pid2" =~ ^[0-9]+$ ]]; then
  start1=$(root_read "stat -c %Y /proc/$pid1" || true)
  maps1=$(root_read "sha256sum /proc/$pid1/maps" | awk '{print $1}' || true)
  start2=$(root_read "stat -c %Y /proc/$pid2" || true)
  maps2=$(root_read "sha256sum /proc/$pid2/maps" | awk '{print $1}' || true)
  [[ "$pid1" == "$pid2" ]] && pass keystore2-pid-stable || stop keystore2-pid-stable
  [[ -n "$start1" && "$start1" == "$start2" ]] && pass keystore2-start-stable || stop keystore2-start-stable
  [[ "$maps1" =~ ^[0-9a-f]{64}$ && "$maps1" == "$maps2" ]] && pass keystore2-maps-stable || stop keystore2-maps-stable
else
  stop keystore2-pid-stable
  stop keystore2-start-stable
  stop keystore2-maps-stable
  maps=
fi

if [[ "$pid1" =~ ^[0-9]+$ ]]; then
  context=$(root_read "cat /proc/$pid1/attr/current" || true)
  check_equals keystore2-context "$context" "$KEYSTORE_CONTEXT"
  grep -Eq '(^|[[:space:]])binder([[:space:]]|$)|/dev/binder' <<<"$(root_read "cat /proc/$pid1/mountinfo; ls -l /proc/$pid1/fd" || true)" \
    && pass binder-route || stop binder-route

  maps_probe=$(root_read "test -r /proc/$pid1/maps && { printf MAPS_READY; cat /proc/$pid1/maps; }" || true)
  if [[ "$maps_probe" == MAPS_READY* ]]; then
    maps=${maps_probe#MAPS_READY}
    pass keystore2-maps-readable
  else
    maps=
    stop keystore2-maps-readable
  fi
else
  stop keystore2-context
  stop binder-route
  stop keystore2-maps-readable
fi
if grep -Eqi 'teesimulator|libinject|tricky.?store|keybox' <<<"$maps"; then
  stop competing-hook
else
  pass no-competing-hook
fi

restart_tools=$(shell_read su -c 'command -v setprop >/dev/null && command -v start >/dev/null && command -v stop >/dev/null && printf TOOLS_READY')
if [[ "$restart_tools" == TOOLS_READY ]]; then
  pass controlled-restart-tools-available
else
  stop controlled-restart-tools-available
fi

version_reply=$(root_read "service call $DEFAULT_INSTANCE $AIDL_VERSION_TRANSACTION")
hash_reply=$(root_read "service call $DEFAULT_INSTANCE $AIDL_HASH_TRANSACTION")
keymint_version=$(decode_aidl_version "$version_reply" || true)
keymint_hash=$(decode_aidl_hash "$hash_reply" || true)
aidl_version_is_approved "$keymint_version" && pass stable-aidl-version || stop stable-aidl-version
aidl_hash_is_approved "$keymint_version" "$keymint_hash" && pass stable-aidl-hash || stop stable-aidl-hash

if [[ -n "$maps" ]]; then
  check_elf_chain
else
  stop keystore2-build-id
  stop keystore2-dependencies
  stop elf-dependency-chain
fi

root_context=$(root_read 'id -Z')
check_equals kernelsu-domain "$root_context" "$KERNELSU_DOMAIN"
module_present=$(root_read "test -d $MODULE_DIRECTORY && printf MODULE_READY")
if [[ "$module_present" == MODULE_READY ]]; then
  pass module-directory
  module_metadata=$(root_read "ls -Zd $MODULE_DIRECTORY; stat -c %a:%U:%G $MODULE_DIRECTORY")
  module_context=${module_metadata%%[[:space:]]*}
  module_permissions=${module_metadata##*$'\n'}
  check_equals module-context "$module_context" "$MODULE_CONTEXT"
  check_equals module-permissions "$module_permissions" "$MODULE_MODE:$MODULE_OWNER"
else
  pass module-absent-preinstall
fi

avc_dump=$(root_read 'command -v logcat >/dev/null && { printf AVC_LOG_READY; logcat -d -b all -v epoch -t 2000; }')
if [[ "$avc_dump" != AVC_LOG_READY* ]]; then
  stop avc-log-unavailable
elif grep -Eiq 'avc: denied.*(keystore2|keystore|ksu|teesimulator_api36_probe)|(keystore2|keystore|ksu|teesimulator_api36_probe).*avc: denied' <<<"${avc_dump#AVC_LOG_READY}"; then
  stop matching-avc-denial
else
  pass no-matching-avc-denial
fi

finish
(( failed == 0 )) && exit 0
exit 1
