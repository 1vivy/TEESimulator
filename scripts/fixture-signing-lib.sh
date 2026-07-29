#!/usr/bin/env bash
set -euo pipefail

fixture_fail() {
  printf 'FAIL %s\n' "$1" >&2
  exit 1
}

fixture_pass() {
  printf 'PASS %s\n' "$1"
}

fixture_close_stdin() {
  unset GPG_TTY
  exec </dev/null
}

fixture_temporary_directory=''

fixture_create_temporary_directory() {
  fixture_temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/teesim-fixture.XXXXXX") ||
    fixture_fail FIXTURE_SIGNING_TEMPORARY_STATE_FAILED
  chmod 700 -- "$fixture_temporary_directory" || fixture_fail FIXTURE_SIGNING_TEMPORARY_STATE_FAILED
}

fixture_cleanup_temporary_directory() {
  if [[ -n "$fixture_temporary_directory" ]]; then
    rm -rf -- "$fixture_temporary_directory"
  fi
}

fixture_has_prompt_request() {
  local output=$1

  grep -Eqi '(pinentry|enter .*(passphrase|password)|password:|cannot open /dev/tty|inappropriate ioctl)' "$output"
}

fixture_require_file_mode() {
  local path=$1
  local expected_mode=$2
  local failure=$3
  local mode=''

  [[ -f "$path" && ! -L "$path" ]] || fixture_fail "$failure"
  mode=$(stat -c '%a' -- "$path") || fixture_fail "$failure"
  [[ "$mode" == "$expected_mode" ]] || fixture_fail "$failure"
}

fixture_require_directory_mode() {
  local path=$1
  local expected_mode=$2
  local failure=$3
  local mode=''

  [[ -d "$path" && ! -L "$path" ]] || fixture_fail "$failure"
  mode=$(stat -c '%a' -- "$path") || fixture_fail "$failure"
  [[ "$mode" == "$expected_mode" ]] || fixture_fail "$failure"
}

fixture_load_signing_environment() {
  fixture_keystore=${TEESIM_FIXTURE_KEYSTORE:-}
  fixture_store_password_file=${TEESIM_FIXTURE_STORE_PASSWORD_FILE:-}
  fixture_key_alias=${TEESIM_FIXTURE_KEY_ALIAS:-}
  fixture_key_password_file=${TEESIM_FIXTURE_KEY_PASSWORD_FILE:-}

  [[ -n "$fixture_keystore" && -n "$fixture_store_password_file" &&
    -n "$fixture_key_alias" && -n "$fixture_key_password_file" ]] ||
    fixture_fail FIXTURE_SIGNING_CONFIG_MISSING
  fixture_require_file_mode "$fixture_keystore" 600 FIXTURE_SIGNING_KEYSTORE_MISSING
  fixture_require_directory_mode "$(dirname -- "$fixture_keystore")" 700 FIXTURE_SIGNING_CONFIG_MALFORMED
  fixture_require_file_mode "$fixture_store_password_file" 600 FIXTURE_SIGNING_PASSWORD_FILE_PERMISSIONS
  fixture_require_file_mode "$fixture_key_password_file" 600 FIXTURE_SIGNING_PASSWORD_FILE_PERMISSIONS
  [[ -s "$fixture_store_password_file" && -s "$fixture_key_password_file" ]] ||
    fixture_fail FIXTURE_SIGNING_CONFIG_MALFORMED
}

fixture_validate_key_alias() {
  local keytool=$1
  local output=$2

  "$keytool" -list -storetype PKCS12 -keystore "$fixture_keystore" \
    -storepass:file "$fixture_store_password_file" -alias "$fixture_key_alias" \
    >"$output" 2>&1 || {
    if fixture_has_prompt_request "$output"; then
      fixture_fail INTERACTION_REQUIRED
    fi
    if grep -Eqi '(alias.*does not exist|does not exist.*alias)' "$output"; then
      fixture_fail FIXTURE_SIGNING_ALIAS_INVALID
    fi
    fixture_fail FIXTURE_SIGNING_CREDENTIALS_INVALID
  }
}

fixture_default_build_tool() {
  local tool=$1
  local script_root=''
  local candidate=''

  script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
  for candidate in "${script_root}/.android-sdk/build-tools/36.0.0/${tool}" \
    "${ANDROID_HOME:-}/build-tools/36.0.0/${tool}" "$(command -v "$tool" || true)"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  fixture_fail FIXTURE_SIGNING_TOOL_UNAVAILABLE
}

fixture_apksigner_certificate_sha256() {
  local apksigner=$1
  local apk=$2
  local output=$3
  local digest=''

  "$apksigner" verify --verbose --print-certs "$apk" >"$output" 2>&1 ||
    fixture_fail FIXTURE_APK_INVALID
  digest=$(awk -F ': ' '/^Signer #1 certificate SHA-256 digest: / { print $2; exit }' "$output")
  [[ "$digest" =~ ^[[:xdigit:]]{64}$ ]] || fixture_fail FIXTURE_APK_INVALID
  printf '%s\n' "${digest,,}"
}

fixture_select_gpg_signer() {
  local output=$1
  local fingerprints=()
  local requested=${TEESIM_AGENT_GPG_KEY:-}
  local fingerprint=''

  command -v gpg >/dev/null 2>&1 || fixture_fail GPG_KEY_MISSING
  gpg --batch --no-tty --with-colons --list-secret-keys >"$output" 2>/dev/null ||
    fixture_fail GPG_KEY_MISSING
  while IFS= read -r fingerprint; do
    [[ "$fingerprint" =~ ^[[:xdigit:]]{40,64}$ ]] && fingerprints+=("${fingerprint^^}")
  done < <(awk -F: '$1 == "sec" { primary = 1; next } primary && $1 == "fpr" { print $10; primary = 0 }' "$output")

  if [[ -n "$requested" ]]; then
    requested=${requested^^}
    for fingerprint in "${fingerprints[@]}"; do
      if [[ "$fingerprint" == "$requested" ]]; then
        printf '%s\n' "$fingerprint"
        return
      fi
    done
    fixture_fail GPG_KEY_MISSING
  fi

  case "${#fingerprints[@]}" in
    0) fixture_fail GPG_KEY_MISSING ;;
    1) printf '%s\n' "${fingerprints[0]}" ;;
    *) fixture_fail GPG_KEY_AMBIGUOUS ;;
  esac
}
