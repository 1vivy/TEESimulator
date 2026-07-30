#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
audit="$repo_root/scripts/rka-audit.sh"
base="6d241e56d6e8146cd67ed4ac3dadc9c632969549"
test_root="$(mktemp -d)"
trap 'find "$test_root" -depth -delete' EXIT
chmod 700 "$test_root"

mkdir "$test_root/secret"
printf '%s%s\n' 'api_' 'key=fixture-only-noncredential' >"$test_root/secret/config.txt"
(cd "$test_root/secret" && zip -q "$test_root/secret.zip" config.txt)
if "$audit" secrets --base "$base" --archive "$test_root/secret.zip" >/dev/null 2>&1; then
    exit 1
fi
printf 'case=secret-content result=rejected\n'

mkdir "$test_root/clean"
printf 'role=DISABLED\nendpoint=127.0.0.1\n' >"$test_root/clean/config.txt"
printf '\177ELF\000api_key\000not-an-assignment\000' >"$test_root/clean/rka-sidecar"
: >"$test_root/clean/empty"
(cd "$test_root/clean" && zip -q "$test_root/clean.zip" config.txt empty rka-sidecar)
"$audit" secrets --base "$base" --archive "$test_root/clean.zip" >/dev/null
printf 'case=clean-text-empty-binary result=accepted\n'

mkdir "$test_root/link"
printf 'target\n' >"$test_root/link/target"
ln -s target "$test_root/link/member"
(cd "$test_root/link" && zip -qy "$test_root/link.zip" member)
if "$audit" secrets --base "$base" --archive "$test_root/link.zip" >/dev/null 2>&1; then
    exit 1
fi
printf 'case=symlink result=rejected\n'

mkdir "$test_root/traversal"
printf 'safe\n' >"$test_root/traversal/member"
(cd "$test_root/traversal" && zip -q "$test_root/traversal.zip" member)
printf '@ member\n@=../escape\n' | zipnote -w "$test_root/traversal.zip"
if "$audit" secrets --base "$base" --archive "$test_root/traversal.zip" >/dev/null 2>&1; then
    exit 1
fi
printf 'case=traversal result=rejected\n'

mkdir "$test_root/private-path"
printf 'public fixture\n' >"$test_root/private-path/private-key.pem"
(cd "$test_root/private-path" && zip -q "$test_root/private-path.zip" private-key.pem)
if "$audit" secrets --base "$base" --archive "$test_root/private-path.zip" >/dev/null 2>&1; then
    exit 1
fi
printf 'case=private-key-shaped-path result=rejected\n'

mkdir "$test_root/encrypted"
printf 'public fixture\n' >"$test_root/encrypted/config.txt"
(cd "$test_root/encrypted" && zip -q -P fixture-only "$test_root/encrypted.zip" config.txt)
if "$audit" secrets --base "$base" --archive "$test_root/encrypted.zip" >/dev/null 2>&1; then
    exit 1
fi
printf 'case=encrypted-member result=rejected\n'

mkdir "$test_root/oversized"
truncate -s 67108865 "$test_root/oversized/member"
(cd "$test_root/oversized" && zip -q "$test_root/oversized.zip" member)
if "$audit" secrets --base "$base" --archive "$test_root/oversized.zip" >/dev/null 2>&1; then
    exit 1
fi
printf 'case=oversized-member result=rejected\n'

printf 'archive audit contract passed\n'
