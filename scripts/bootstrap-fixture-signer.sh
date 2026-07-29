#!/usr/bin/env bash
set -euo pipefail

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$script_directory/fixture-signing-lib.sh"
fixture_close_stdin

[[ $# -eq 1 ]] || fixture_fail FIXTURE_SIGNER_BOOTSTRAP_USAGE
state_directory=$(realpath -m -- "$1") || fixture_fail FIXTURE_SIGNING_STATE_INVALID
repository_root=$(cd -- "$script_directory/.." && pwd -P)
case "$state_directory" in
  "$repository_root"|"$repository_root"/*) fixture_fail FIXTURE_SIGNING_STATE_REPOSITORY_FORBIDDEN ;;
esac
[[ ! -L "$state_directory" ]] || fixture_fail FIXTURE_SIGNING_STATE_INVALID
[[ ! -e "$state_directory" || -d "$state_directory" ]] || fixture_fail FIXTURE_SIGNING_STATE_INVALID
mkdir -p -m 700 -- "$state_directory" || fixture_fail FIXTURE_SIGNING_STATE_INVALID
chmod 700 -- "$state_directory" || fixture_fail FIXTURE_SIGNING_STATE_INVALID

keystore="$state_directory/fixture-signer.p12"
store_password_file="$state_directory/fixture-store-password"
key_password_file="$state_directory/fixture-key-password"
for path in "$keystore" "$store_password_file" "$key_password_file"; do
  [[ ! -e "$path" && ! -L "$path" ]] || fixture_fail FIXTURE_SIGNING_STATE_EXISTS
done

fixture_create_temporary_directory
bootstrap_completed=0
cleanup_bootstrap_failure() {
  local exit_status=$?

  if [[ "$bootstrap_completed" -eq 0 ]]; then
    rm -f -- "$keystore" "$store_password_file" "$key_password_file"
  fi
  fixture_cleanup_temporary_directory
  exit "$exit_status"
}
trap cleanup_bootstrap_failure EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
umask 077
openssl rand -hex 32 >"$store_password_file" || fixture_fail FIXTURE_SIGNING_RANDOMNESS_FAILED
# PKCS#12 has one effective password; distinct protected files preserve the required interface.
cp -- "$store_password_file" "$key_password_file" || fixture_fail FIXTURE_SIGNING_RANDOMNESS_FAILED
chmod 600 -- "$store_password_file" "$key_password_file" || fixture_fail FIXTURE_SIGNING_STATE_INVALID

keytool_path=$(command -v keytool || true)
[[ -n "$keytool_path" ]] || fixture_fail FIXTURE_SIGNING_TOOL_UNAVAILABLE
keytool_output="$fixture_temporary_directory/keytool-output"
"$keytool_path" -genkeypair -noprompt -storetype PKCS12 -keystore "$keystore" \
  -storepass:file "$store_password_file" -alias teesim-fixture -keypass:file "$key_password_file" \
  -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -dname 'CN=TEESimulator Fixture Signing' \
  -validity 3650 >"$keytool_output" 2>&1 || {
  if fixture_has_prompt_request "$keytool_output"; then
    fixture_fail INTERACTION_REQUIRED
  fi
  fixture_fail FIXTURE_SIGNING_BOOTSTRAP_FAILED
}
chmod 600 -- "$keystore" || fixture_fail FIXTURE_SIGNING_STATE_INVALID
bootstrap_completed=1
fixture_pass FIXTURE_SIGNER_BOOTSTRAPPED
