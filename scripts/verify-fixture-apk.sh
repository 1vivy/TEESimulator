#!/usr/bin/env bash
set -euo pipefail

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$script_directory/fixture-signing-lib.sh"
fixture_close_stdin

[[ $# -eq 3 && -f "$1" && ! -L "$1" ]] || fixture_fail FIXTURE_APK_VERIFY_USAGE
apk=$1
expected_artifact_sha256=${2,,}
expected_signer_sha256=${3,,}
[[ "$expected_artifact_sha256" =~ ^[[:xdigit:]]{64}$ && "$expected_signer_sha256" =~ ^[[:xdigit:]]{64}$ ]] ||
  fixture_fail FIXTURE_APK_VERIFY_USAGE

fixture_create_temporary_directory
trap fixture_cleanup_temporary_directory EXIT HUP INT TERM
apksigner=$(fixture_default_build_tool apksigner) || fixture_fail FIXTURE_SIGNING_TOOL_UNAVAILABLE
actual_signer_sha256=$(fixture_apksigner_certificate_sha256 "$apksigner" "$apk" \
  "$fixture_temporary_directory/apksigner-output")
[[ "$actual_signer_sha256" == "$expected_signer_sha256" ]] || fixture_fail SIGNER_MISMATCH
actual_artifact_sha256=$(sha256sum -- "$apk")
actual_artifact_sha256=${actual_artifact_sha256%% *}
[[ "$actual_artifact_sha256" == "$expected_artifact_sha256" ]] || fixture_fail ARTIFACT_MISMATCH
fixture_pass FIXTURE_APK_VERIFIED
