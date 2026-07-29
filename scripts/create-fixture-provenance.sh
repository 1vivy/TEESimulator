#!/usr/bin/env bash
set -euo pipefail

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$script_directory/fixture-signing-lib.sh"
fixture_close_stdin

[[ $# -eq 2 && -f "$1" && ! -L "$1" && ! -e "$2" ]] || fixture_fail PROVENANCE_MANIFEST_USAGE
apk=$1
manifest=$2
manifest_directory=$(dirname -- "$manifest")
[[ -d "$manifest_directory" && ! -L "$manifest_directory" ]] || fixture_fail PROVENANCE_MANIFEST_USAGE

fixture_create_temporary_directory
trap fixture_cleanup_temporary_directory EXIT HUP INT TERM
artifact_sha256=$(sha256sum -- "$apk")
artifact_sha256=${artifact_sha256%% *}
apksigner=$(fixture_default_build_tool apksigner) || fixture_fail FIXTURE_SIGNING_TOOL_UNAVAILABLE
signer_sha256=$(fixture_apksigner_certificate_sha256 "$apksigner" "$apk" \
  "$fixture_temporary_directory/apksigner-output")
source_root=$(git -C "$script_directory/.." rev-parse --show-toplevel 2>/dev/null) ||
  fixture_fail PROVENANCE_SOURCE_UNAVAILABLE
source_sha256=$(python3 - "$source_root" <<'PY'
from hashlib import sha256
from os import fsencode, lstat, readlink
from pathlib import Path
from stat import S_ISREG
from subprocess import run
from sys import argv, stdout

root = Path(argv[1])
listed = run(
    ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"],
    check=True,
    capture_output=True,
).stdout.split(b"\0")
digest = sha256()
for relative in sorted(path for path in listed if path and not path.startswith(b".omo/evidence/")):
    candidate = root / relative.decode("utf-8", "surrogateescape")
    metadata = lstat(candidate)
    if candidate.is_symlink():
        payload = b"symlink\0" + fsencode(readlink(candidate))
    elif S_ISREG(metadata.st_mode):
        payload = b"file:%o\0" % (metadata.st_mode & 0o777)
        payload += candidate.read_bytes()
    else:
        continue
    digest.update(b"path\0" + relative + b"\0")
    digest.update(sha256(payload).digest())
stdout.write(digest.hexdigest())
PY
) || fixture_fail PROVENANCE_SOURCE_UNAVAILABLE
printf '{"artifact_sha256":"%s","schema_version":1,"signer_certificate_sha256":"%s","source_sha256":"%s"}\n' \
  "$artifact_sha256" "$signer_sha256" "$source_sha256" >"$manifest" || fixture_fail PROVENANCE_MANIFEST_WRITE_FAILED
chmod 644 -- "$manifest" || fixture_fail PROVENANCE_MANIFEST_WRITE_FAILED
fixture_pass PROVENANCE_MANIFEST_CREATED
