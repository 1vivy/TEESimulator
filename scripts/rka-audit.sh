#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
archive_scan_file=""

cleanup() {
    if [[ -n "$archive_scan_file" && -f "$archive_scan_file" ]]; then
        unlink "$archive_scan_file"
    fi
}
trap cleanup EXIT

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
    max_archive_bytes=134217728
    max_member_bytes=67108864
    max_total_bytes=268435456
    max_members=4096
    archive_command_timeout=30
    archive_bytes="$(stat -c '%s' -- "$archive")"
    (( archive_bytes <= max_archive_bytes )) || fail "archive exceeds compressed size limit"

    archive_summary="$(timeout "$archive_command_timeout" zipinfo -h -- "$archive")" ||
        fail "archive directory is invalid"
    member_count="$(
        sed -n 's/.*number of entries: \([0-9][0-9]*\).*/\1/p' <<<"$archive_summary" |
            head -n 1
    )"
    [[ "$member_count" =~ ^[0-9]+$ ]] || fail "archive entry count is unavailable"
    (( member_count <= max_members )) || fail "archive has too many members"

    archive_listing="$(timeout "$archive_command_timeout" unzip -Z1 -- "$archive")" ||
        fail "archive member listing failed"
    mapfile -t archive_members <<<"$archive_listing"
    (( ${#archive_members[@]} == member_count )) ||
        fail "archive contains an unsupported member name"

    archive_metadata="$(timeout "$archive_command_timeout" zipinfo -l -- "$archive")" ||
        fail "archive metadata is invalid"
    declare -A member_modes=()
    declare -A member_sizes=()
    metadata_count=0
    total_bytes=0
    while read -r mode _version _system member_bytes _text_mode _compressed _method _date _time member; do
        case "$mode" in
            -* | d*)
                [[ "$member_bytes" =~ ^[0-9]+$ ]] ||
                    fail "archive member size is invalid"
                (( member_bytes <= max_member_bytes )) ||
                    fail "archive member exceeds size limit"
                total_bytes=$(( total_bytes + member_bytes ))
                (( total_bytes <= max_total_bytes )) ||
                    fail "archive exceeds uncompressed size limit"
                [[ -n "$member" ]] || fail "archive member name is empty"
                [[ -z "${member_modes[$member]+present}" ]] ||
                    fail "archive contains duplicate member names"
                member_modes["$member"]="$mode"
                member_sizes["$member"]="$member_bytes"
                metadata_count=$(( metadata_count + 1 ))
                ;;
            l*)
                fail "archive contains a symbolic link"
                ;;
            c* | b* | p* | s*)
                fail "archive contains an unsupported special file"
                ;;
            *)
                ;;
        esac
    done <<<"$archive_metadata"
    (( metadata_count == member_count )) || fail "archive metadata count is inconsistent"
    archive_verbose="$(timeout "$archive_command_timeout" zipinfo -v -- "$archive")" ||
        fail "archive security metadata is invalid"
    if grep -F 'file security status:' <<<"$archive_verbose" |
        grep -Fv 'not encrypted' >/dev/null; then
        fail "encrypted archive members are unsupported"
    fi

    archive_scan_file="$(mktemp)"
    chmod 600 "$archive_scan_file"
    for member in "${archive_members[@]}"; do
        [[ -n "${member_modes[$member]+present}" ]] ||
            fail "archive member metadata is missing"
        if [[ "$member" == /* || "$member" == *\\* ||
            "$member" =~ (^|/)\.\.?(/|$) ]] ||
            printf '%s' "$member" | LC_ALL=C grep -q '[[:cntrl:]]'; then
            fail "archive contains an unsafe member path"
        fi
        if grep -Eiq -- '(^|/)(id_[^/]+|[^/]*private[^/]*)$' <<<"$member"; then
            fail "archive contains a private-key-shaped path"
        fi
        [[ "${member_modes[$member]}" == d* ]] && continue

        : >"$archive_scan_file"
        (
            ulimit -f "$(( max_member_bytes / 1024 ))"
            timeout "$archive_command_timeout" unzip -p -- "$archive" "$member"
        ) >"$archive_scan_file" ||
            fail "archive member failed integrity validation"
        [[ "$(stat -c '%s' -- "$archive_scan_file")" == "${member_sizes[$member]}" ]] ||
            fail "archive member size changed while reading"
        if LC_ALL=C grep -aE -- "$patterns" "$archive_scan_file" >/dev/null; then
            violations+=("archive:$member")
        fi
    done
    if (( ${#violations[@]} > 0 )); then
        printf 'rka-audit: secret-like content in %s\n' "${violations[@]}" >&2
        exit 1
    fi
fi
printf 'rka secret audit passed\n'
