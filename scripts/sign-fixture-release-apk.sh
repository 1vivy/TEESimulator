#!/usr/bin/env bash
set -euo pipefail

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$script_directory/fixture-signing-lib.sh"
fixture_close_stdin

input_apk=''
output_apk=''
apksigner=''
zipalign=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --input) input_apk=${2:-}; shift 2 ;;
    --output) output_apk=${2:-}; shift 2 ;;
    --apksigner) apksigner=${2:-}; shift 2 ;;
    --zipalign) zipalign=${2:-}; shift 2 ;;
    *) fixture_fail FIXTURE_SIGNING_USAGE ;;
  esac
done
[[ -f "$input_apk" && ! -L "$input_apk" && -n "$output_apk" && -n "$apksigner" && -n "$zipalign" ]] ||
  fixture_fail FIXTURE_SIGNING_USAGE
[[ -x "$apksigner" && -x "$zipalign" ]] || fixture_fail FIXTURE_SIGNING_TOOL_UNAVAILABLE

fixture_create_temporary_directory
trap fixture_cleanup_temporary_directory EXIT HUP INT TERM
fixture_load_signing_environment
fixture_validate_key_alias "$(command -v keytool || fixture_fail FIXTURE_SIGNING_TOOL_UNAVAILABLE)" \
  "$fixture_temporary_directory/keytool-output"

normalized_apk="$fixture_temporary_directory/normalized.apk"
aligned_apk="$fixture_temporary_directory/aligned.apk"
python3 - "$input_apk" "$normalized_apk" <<'PY' || fixture_fail FIXTURE_APK_NORMALIZATION_FAILED
from pathlib import Path
from sys import argv
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

source = Path(argv[1])
destination = Path(argv[2])
with ZipFile(source) as source_archive, ZipFile(destination, "w", compression=ZIP_DEFLATED, compresslevel=9) as destination_archive:
    destination_archive.comment = b""
    for source_entry in sorted(source_archive.infolist(), key=lambda entry: entry.filename):
        destination_entry = ZipInfo(source_entry.filename, date_time=(1980, 1, 1, 0, 0, 0))
        destination_entry.compress_type = source_entry.compress_type
        destination_entry.create_system = 3
        destination_entry.external_attr = 0o40755 << 16 if source_entry.is_dir() else 0o100644 << 16
        destination_entry.flag_bits = source_entry.flag_bits & 0x800
        destination_archive.writestr(destination_entry, source_archive.read(source_entry))
PY
"$zipalign" -f 4 "$normalized_apk" "$aligned_apk" >"$fixture_temporary_directory/zipalign-output" 2>&1 || {
  if fixture_has_prompt_request "$fixture_temporary_directory/zipalign-output"; then
    fixture_fail INTERACTION_REQUIRED
  fi
  fixture_fail FIXTURE_APK_NORMALIZATION_FAILED
}
"$apksigner" sign --ks "$fixture_keystore" --ks-pass "file:$fixture_store_password_file" \
  --ks-key-alias "$fixture_key_alias" --key-pass "file:$fixture_key_password_file" --min-sdk-version 36 \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false \
  --out "$output_apk" "$aligned_apk" >"$fixture_temporary_directory/apksigner-output" 2>&1 || {
  if fixture_has_prompt_request "$fixture_temporary_directory/apksigner-output"; then
    fixture_fail INTERACTION_REQUIRED
  fi
  fixture_fail FIXTURE_SIGNING_CREDENTIALS_INVALID
}
"$apksigner" verify --verbose "$output_apk" >"$fixture_temporary_directory/verify-output" 2>&1 ||
  fixture_fail FIXTURE_APK_INVALID
fixture_pass FIXTURE_RELEASE_SIGNED
