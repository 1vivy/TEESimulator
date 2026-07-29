#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -z "${ANDROID_HOME:-}" && -d "$PWD/.android-sdk" ]]; then
  export ANDROID_HOME="$PWD/.android-sdk"
fi
if [[ -z "${JAVA_HOME:-}" && -d /usr/lib/jvm/java-21-openjdk ]]; then
  export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
  export PATH="$JAVA_HOME/bin:$PATH"
fi

fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS %s\n' "$*"; }

python3 -m unittest discover -s tests -p 'test_*.py'
pass unit-safety
./gradlew --no-daemon \
  :app:testDebugUnitTest \
  :two-phone:test :two-phone:ktfmtCheck \
  :physical-harness:test :physical-harness:ktfmtCheck \
  :physical-harness:lintDebug :physical-harness:assembleRelease
pass current-module-tests-format-lint-release
project_listing=$(./gradlew --no-daemon -q projects)
if scripts/g0-guards.sh project-list-has ':rka-fixture' <<<"$project_listing"; then
  ./gradlew --no-daemon \
    :rka-fixture:testDebugUnitTest :rka-fixture:ktfmtCheck \
    :rka-fixture:lintDebug :rka-fixture:assembleRelease
  pass rka-fixture-tests-format-lint-release
fi
bash -n module/service.sh module/action.sh module/customize.sh scripts/probe-api36.sh scripts/probe-api36-lib.sh scripts/g0-guards.sh \
  scripts/fixture-signing-lib.sh scripts/bootstrap-fixture-signer.sh scripts/sign-fixture-release-apk.sh \
  scripts/verify-fixture-apk.sh scripts/create-fixture-provenance.sh scripts/sign-fixture-provenance.sh \
  scripts/verify-fixture-provenance.sh
pass shell-parser

[[ -f LICENSE ]] && grep -Fq 'GNU GENERAL PUBLIC LICENSE' LICENSE || fail gpl-license
[[ -f PROVENANCE.md && -f THIRD_PARTY_NOTICES.md ]] || fail provenance
GIT_MASTER=1 git merge-base --is-ancestor 150a476 HEAD || fail upstream-history
pass gpl-provenance

scripts/g0-guards.sh source "$PWD"
pass secret-network-identifier-scan

./gradlew --no-daemon clean :two-phone:build :app:zipRelease
short_commit=$(GIT_MASTER=1 git rev-parse --short HEAD)
artifact=$(find out -maxdepth 1 -type f -name "TEESimulator-v0.1.0-probe.1-*-${short_commit}-Release.zip" -print -quit)
[[ -n "$artifact" ]] || fail module-package
zipinfo -1 "$artifact" | grep -Fxq action.sh || fail package-action
scripts/g0-guards.sh package "$artifact"
pass arm64-build-module-package

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
cp "$artifact" "$tmpdir/first.zip"
./gradlew --no-daemon clean :app:zipRelease
cmp -s "$tmpdir/first.zip" "$artifact" || fail reproducibility
sha256sum "$artifact"
pass reproducible

[[ -z "$(GIT_MASTER=1 git status --porcelain)" ]] || fail dirty-worktree
pass clean-worktree
