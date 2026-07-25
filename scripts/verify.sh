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
./gradlew --no-daemon :two-phone:test :two-phone:ktfmtCheck
pass two-phone-host-tests
bash -n module/service.sh module/action.sh module/customize.sh scripts/probe-api36.sh
pass shell-parser

[[ -f LICENSE ]] && grep -Fq 'GNU GENERAL PUBLIC LICENSE' LICENSE || fail gpl-license
[[ -f PROVENANCE.md && -f THIRD_PARTY_NOTICES.md ]] || fail provenance
GIT_MASTER=1 git merge-base --is-ancestor 150a476 HEAD || fail upstream-history
pass gpl-provenance

[[ ! -e module/keybox.xml ]] || fail bundled-keybox
if GIT_MASTER=1 git grep -IEn '(BEGIN (RSA |EC |)PRIVATE KEY|<Keybox|remote_provisioning.+(csr|certify))' \
  -- app module profiles scripts ':!scripts/verify.sh'; then
  fail secret-or-forbidden-rkp
fi
if GIT_MASTER=1 git grep -IEn 'ro\\.(serialno|boot\\.serialno)|getprop.*(serial|fingerprint)|adb devices -l' \
  -- scripts tests profiles module ':!scripts/verify.sh'; then
  fail device-identifier-collection
fi
if GIT_MASTER=1 git grep -IEn '(android\\.os\\.Parcel|android\\.os\\.IBinder)' -- two-phone; then
  fail raw-binder-cross-device-protocol
fi
if GIT_MASTER=1 git grep -IEn '(privateKey|donorAlias)' -- \
  two-phone/src/main/kotlin/org/matrix/teesimulator/twophone/Protocol.kt \
  two-phone/src/main/kotlin/org/matrix/teesimulator/twophone/Routing.kt; then
  fail target-protocol-custody
fi
pass secret-network-identifier-scan

./gradlew --no-daemon clean :two-phone:build :app:zipRelease
short_commit=$(GIT_MASTER=1 git rev-parse --short HEAD)
artifact=$(find out -maxdepth 1 -type f -name "TEESimulator-v0.1.0-probe.1-*-${short_commit}-Release.zip" -print -quit)
[[ -n "$artifact" ]] || fail module-package
zipinfo -1 "$artifact" | grep -Fxq action.sh || fail package-action
if zipinfo -1 "$artifact" | grep -Eq '(^|/)(keybox\\.xml|target\\.txt|sepolicy\\.rule)$'; then
  fail unsafe-package-content
fi
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
