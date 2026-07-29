#!/usr/bin/env bash
set -euo pipefail

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$script_directory/fixture-signing-lib.sh"
fixture_close_stdin

[[ $# -eq 1 && -f "$1" && ! -L "$1" ]] || fixture_fail PROVENANCE_MANIFEST_USAGE
manifest=$1
signature="${manifest}.asc"
[[ ! -e "$signature" && ! -L "$signature" ]] || fixture_fail PROVENANCE_SIGNATURE_EXISTS

fixture_create_temporary_directory
trap fixture_cleanup_temporary_directory EXIT HUP INT TERM
signer=$(fixture_select_gpg_signer "$fixture_temporary_directory/gpg-keys")
temporary_signature="$fixture_temporary_directory/provenance.asc"
gpg --batch --no-tty --pinentry-mode loopback --status-fd 3 --local-user "$signer" --armor --detach-sign \
  --output "$temporary_signature" "$manifest" 3>"$fixture_temporary_directory/gpg-status" \
  2>"$fixture_temporary_directory/gpg-output" || {
  if grep -Eq '\[GNUPG:\] (NEED_PASSPHRASE|INQUIRE_MAXLEN)' "$fixture_temporary_directory/gpg-status"; then
    fixture_fail GPG_KEY_PASSWORD_PROTECTED
  fi
  if fixture_has_prompt_request "$fixture_temporary_directory/gpg-output"; then
    fixture_fail INTERACTION_REQUIRED
  fi
  fixture_fail GPG_SIGNING_FAILED
}
mv -- "$temporary_signature" "$signature" || fixture_fail PROVENANCE_SIGNATURE_WRITE_FAILED
chmod 644 -- "$signature" || fixture_fail PROVENANCE_SIGNATURE_WRITE_FAILED
fixture_pass "PROVENANCE_MANIFEST_SIGNED $signer"
