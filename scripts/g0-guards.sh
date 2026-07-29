#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'FAIL %s\n' "$1" >&2; exit 1; }
pass() { printf 'PASS %s\n' "$1"; }

source_root=''
cross_device_protocol_marker='org\.matrix\.teesimulator\.twophone\.'
twophone_import_marker='^[[:space:]]*import[[:space:]]+org\.matrix\.teesimulator\.twophone\.'
twophone_reference_marker='org\.matrix\.teesimulator\.twophone\.'
twophone_public_pin_import_marker='^[[:space:]]*import[[:space:]]+org\.matrix\.teesimulator\.twophone\.SpkiPin([[:space:]]+as[[:space:]]+[[:alpha:]_][[:alnum:]_]*)?[[:space:]]*;?[[:space:]]*$'

scan_paths() {
  local label=$1
  local pattern=$2
  shift 2
  local relative_path=''
  local scan_path=''
  local candidate=''

  for relative_path in "$@"; do
    scan_path="$source_root/$relative_path"
    [[ -d "$scan_path" ]] || continue
    while IFS= read -r -d '' candidate; do
      case "$candidate" in
        "$source_root/scripts/g0-guards.sh"|"$source_root/scripts/verify.sh") continue ;;
      esac
      if grep -aEq -- "$pattern" "$candidate"; then
        fail "$label"
      fi
    done < <(
      find "$scan_path" \
        \( -type d \( -name .git -o -name .gradle -o -name __pycache__ -o -name build \) -prune \) \
        -o \( -type f -print0 \)
    )
  done
}

scan_file() {
  local label=$1
  local pattern=$2
  local relative_path=$3
  local candidate="$source_root/$relative_path"

  if [[ -f "$candidate" ]] && grep -aEq -- "$pattern" "$candidate"; then
    fail "$label"
  fi
}

scan_signing_material_paths() {
  local candidate=''

  while IFS= read -r -d '' candidate; do
    fail committed-signing-material
  done < <(
    find "$source_root" \
      \( -type d \( -name .git -o -name .gradle -o -name .android-sdk -o -name __pycache__ -o -name build -o -name out \) -prune \) \
      -o \( -type f \( -iname '*.p12' -o -iname '*.pfx' -o -iname '*.jks' -o -iname '*.keystore' -o -iname '*.pk8' -o -iname '*.key' \) -print0 \)
  )
}

scan_cross_device_protocol_paths() {
  local label=$1
  local pattern=$2
  local relative_path=$3
  local marker=${4:-"$cross_device_protocol_marker"}
  local scan_path="$source_root/$relative_path"
  local candidate=''

  [[ -d "$scan_path" ]] || return 0
  while IFS= read -r -d '' candidate; do
    if grep -aEq -- "$marker" "$candidate" &&
      grep -aEq -- "$pattern" "$candidate"; then
      fail "$label"
    fi
  done < <(
    find "$scan_path" \
      \( -type d \( -name .git -o -name .gradle -o -name __pycache__ -o -name build \) -prune \) \
      -o \( -type f -print0 \)
  )
}

has_twophone_protocol_reference() {
  local candidate=$1
  local line=''

  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ $twophone_import_marker ]]; then
      [[ "$line" =~ $twophone_public_pin_import_marker ]] || return 0
    elif [[ "$line" =~ $twophone_reference_marker ]]; then
      return 0
    fi
  done <"$candidate"
  return 1
}

scan_target_protocol_custody_paths() {
  local label=$1
  local pattern=$2
  local two_phone_source_path="$source_root/two-phone/src/main"
  local physical_harness_source_path="$source_root/physical-harness/src"
  local candidate=''

  if [[ -d "$two_phone_source_path" ]]; then
    while IFS= read -r -d '' candidate; do
      if grep -aEq -- "$pattern" "$candidate"; then
        fail "$label"
      fi
    done < <(
      find "$two_phone_source_path" \
        \( -type d \( -name .git -o -name .gradle -o -name __pycache__ -o -name build \) -prune \) \
        -o \( -type f -print0 \)
    )
  fi

  if [[ -d "$physical_harness_source_path" ]]; then
    while IFS= read -r -d '' candidate; do
      if has_twophone_protocol_reference "$candidate" &&
        grep -aEq -- "$pattern" "$candidate"; then
        fail "$label"
      fi
    done < <(
      find "$physical_harness_source_path" \
        \( -type d \( -name .git -o -name .gradle -o -name __pycache__ -o -name build \) -prune \) \
        -o \( -type f -print0 \)
    )
  fi
}

scan_source() {
  [[ -d "$source_root" ]] || fail invalid-source-input
  [[ ! -e "$source_root/module/keybox.xml" ]] || fail bundled-keybox

  scan_paths secret-or-forbidden-rkp \
    '(BEGIN (RSA |EC |)PRIVATE KEY|<Keybox|remote_provisioning.+(csr|certify))' \
    app module profiles scripts physical-harness
  scan_signing_material_paths
  scan_paths device-identifier-collection \
    'ro\.(serialno|boot\.serialno)|getprop.*(serial|fingerprint)|adb devices -l' \
    scripts tests profiles module physical-harness
  scan_paths raw-binder-cross-device-protocol \
    'android\.os\.(Parcel|IBinder)' \
    two-phone
  scan_cross_device_protocol_paths raw-binder-cross-device-protocol \
    'android\.os\.(Parcel|IBinder)' \
    physical-harness/src
  scan_target_protocol_custody_paths target-protocol-custody \
    '(^|[^[:alnum:]_])(privateKey|donorAlias)([^[:alnum:]_]|$)'
  pass g0-source-guards
}

project_list_has() {
  local project=$1
  local project_listing=''

  project_listing=$(cat)
  [[ "$project_listing" == *"$project"* ]]
}

scan_package() {
  local package=$1
  local zip_status=0

  [[ -f "$package" ]] || fail invalid-package-input
  if python3 - "$package" <<'PY'
from pathlib import PurePosixPath
from sys import argv, exit
from zipfile import BadZipFile, ZipFile

forbidden_members = frozenset(("keybox.xml", "target.txt", "sepolicy.rule"))

try:
    with ZipFile(argv[1]) as archive:
        for member in archive.infolist():
            name = member.filename
            if "\x00" in name or "\n" in name or "\r" in name:
                exit(1)
            if PurePosixPath(name).name in forbidden_members:
                exit(1)
except (BadZipFile, OSError):
    exit(2)
PY
  then
    :
  else
    zip_status=$?
    case "$zip_status" in
      1) fail unsafe-package-content ;;
      *) fail invalid-package-input ;;
    esac
  fi
  pass g0-package-guards
}

case "${1:-}" in
  source)
    [[ $# -eq 2 ]] || fail g0-guards-usage
    source_root=$2
    scan_source
    ;;
  package)
    [[ $# -eq 2 ]] || fail g0-guards-usage
    scan_package "$2"
    ;;
  project-list-has)
    [[ $# -eq 2 ]] || fail g0-guards-usage
    project_list_has "$2"
    ;;
  *) fail g0-guards-usage ;;
esac
