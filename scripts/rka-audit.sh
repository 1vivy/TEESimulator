#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

fail() {
    printf 'rka-audit: %s\n' "$*" >&2
    exit 64
}

[[ "${1-}" == "secrets" ]] || fail "expected secrets"
shift
base=""
archive=""
while (( $# > 0 )); do
    case "$1" in
        --base)
            [[ $# -ge 2 ]] || fail "--base requires a revision"
            base="$2"
            shift 2
            ;;
        --archive)
            [[ $# -ge 2 ]] || fail "--archive requires a path"
            archive="$2"
            shift 2
            ;;
        *)
            fail "unsupported argument: $1"
            ;;
    esac
done
[[ -n "$base" ]] || fail "--base is required"
git -C "$repo_root" cat-file -e "$base^{commit}"

mapfile -d '' changed_files < <(
    git -C "$repo_root" diff --name-only --diff-filter=ACMR -z "$base" --
)
patterns='BEGIN [A-Z ]*PRIVATE KEY|(^|[^[:alnum:]_])(password|passwd|api[_-]?key|bearer|client[_-]?secret|transport[_-]?secret)[[:space:]]*[:=]'
violations=()
for relative_path in "${changed_files[@]}"; do
    [[ -f "$repo_root/$relative_path" ]] || continue
    [[ "$relative_path" == "scripts/rka-audit.sh" ]] && continue
    if LC_ALL=C grep -EIl -- "$patterns" "$repo_root/$relative_path" >/dev/null; then
        violations+=("$relative_path")
    fi
done
if (( ${#violations[@]} > 0 )); then
    printf 'rka-audit: secret-like content in %s\n' "${violations[@]}" >&2
    exit 1
fi

if [[ -n "$archive" ]]; then
    [[ -f "$archive" ]] || fail "archive does not exist"
    archive_listing="$(unzip -Z1 -- "$archive")"
    if grep -Eiq -- '(^|/)(id_[^/]+|[^/]*private[^/]*)$' <<<"$archive_listing"; then
        fail "archive contains a private-key-shaped path"
    fi
fi
printf 'rka secret audit passed\n'
