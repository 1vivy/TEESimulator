#!/usr/bin/env bash
set -euo pipefail

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$script_directory/fixture-signing-lib.sh"
fixture_close_stdin

[[ $# -eq 2 && -f "$1" && ! -L "$1" && -f "$2" && ! -L "$2" ]] ||
  fixture_fail PROVENANCE_SIGNATURE_INVALID
manifest=$1
signature=$2

fixture_create_temporary_directory
trap fixture_cleanup_temporary_directory EXIT HUP INT TERM
expected_signer=$(fixture_select_gpg_signer "$fixture_temporary_directory/gpg-keys")
gpg --batch --no-tty --pinentry-mode loopback --status-fd 3 --verify "$signature" "$manifest" \
  3>"$fixture_temporary_directory/gpg-status" 2>"$fixture_temporary_directory/gpg-output" || {
  if fixture_has_prompt_request "$fixture_temporary_directory/gpg-output"; then
    fixture_fail INTERACTION_REQUIRED
  fi
  fixture_fail PROVENANCE_SIGNATURE_INVALID
}
signer=$(awk '$2 == "VALIDSIG" { print $3; exit }' "$fixture_temporary_directory/gpg-status")
[[ "$signer" =~ ^[[:xdigit:]]{40,64}$ ]] || fixture_fail PROVENANCE_SIGNATURE_INVALID
signer=${signer^^}
[[ "$signer" == "$expected_signer" ]] || fixture_fail PROVENANCE_SIGNER_MISMATCH
fixture_pass "PROVENANCE_SIGNATURE_VERIFIED $signer"
