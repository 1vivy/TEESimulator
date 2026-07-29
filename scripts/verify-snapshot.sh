#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'FAIL %s\n' "$1" >&2
  exit 1
}

pass() {
  printf 'PASS %s\n' "$*"
}

source_root=${1:-}
temporary_root=${VERIFY_SNAPSHOT_TMP_ROOT:-/tmp/opencode}
session_directory=''
clone_root=''
source_git_directory=''

cleanup() {
  local exit_status=$?

  trap - EXIT HUP INT TERM
  if [[ -n "$session_directory" ]]; then
    if rm -rf -- "$session_directory" &&
      [[ ! -e "$session_directory" && ! -L "$session_directory" ]]; then
      pass cleanup clone-removed
    else
      printf 'FAIL snapshot-cleanup\n' >&2
      exit 1
    fi
  fi
  exit "$exit_status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

source_git() {
  GIT_OPTIONAL_LOCKS=0 git -C "$source_root" "$@"
}

path_in_snapshot() {
  case "$1" in
    .git|.git/*|.omo/evidence|.omo/evidence/*) return 1 ;;
    /*|.|..|../*|*/../*) return 2 ;;
    *) return 0 ;;
  esac
}

path_digest() {
  local candidate=$1
  local digest=''
  local mode=''

  if [[ -L "$candidate" ]]; then
    python3 - "$candidate" <<'PY'
from hashlib import sha256
from os import fsencode, readlink
from sys import argv

print(sha256(b"symlink\0" + fsencode(readlink(argv[1]))).hexdigest())
PY
    return
  fi

  mode=$(stat -c '%a' -- "$candidate") || return 1
  digest=$({ printf 'file:%s\0' "$mode"; cat -- "$candidate"; } | sha256sum) || return 1
  printf '%s\n' "${digest%% *}"
}

write_manifest() {
  local root=$1
  local manifest=$2
  local relative_path=''
  local candidate=''
  local digest=''
  local path_status=0

  : >"$manifest"
  while IFS= read -r -d '' relative_path; do
    if path_in_snapshot "$relative_path"; then
      :
    else
      path_status=$?
      if [[ "$path_status" -eq 1 ]]; then
        continue
      fi
      fail snapshot-mismatch
    fi

    candidate="$root/$relative_path"
    if [[ ! -f "$candidate" && ! -L "$candidate" ]]; then
      continue
    fi
    digest=$(path_digest "$candidate") || fail snapshot-mismatch
    printf '%s\t%s\0' "$relative_path" "$digest" >>"$manifest"
  done < <(GIT_OPTIONAL_LOCKS=0 git -C "$root" ls-files -co --exclude-standard -z)
  LC_ALL=C sort -z -o "$manifest" "$manifest"
}

capture_source_state() {
  local state_directory=$1
  local stash_ref=''

  mkdir -p -- "$state_directory"
  source_git rev-parse --verify HEAD >"$state_directory/head" || fail snapshot-clone
  source_git status --porcelain=v1 -z >"$state_directory/status" || fail snapshot-clone
  source_git show-ref --head >"$state_directory/refs" || fail snapshot-clone
  source_git reflog show --all >"$state_directory/reflog" || fail snapshot-clone
  source_git_directory=$(source_git rev-parse --absolute-git-dir) || fail snapshot-clone
  [[ -f "$source_git_directory/index" ]] || fail snapshot-clone
  sha256sum -- "$source_git_directory/index" >"$state_directory/index" || fail snapshot-clone
  if stash_ref=$(source_git rev-parse --verify -q refs/stash); then
    printf '%s\0' "$stash_ref" >"$state_directory/stash"
  else
    printf 'absent\0' >"$state_directory/stash"
  fi
  write_manifest "$source_root" "$state_directory/manifest"
}

source_state_matches() {
  local before=$1
  local after=$2
  local field=''

  for field in head status refs reflog index stash manifest; do
    cmp -s "$before/$field" "$after/$field" || return 1
  done
}

assert_source_unchanged() {
  local before=$1
  local after=$2

  capture_source_state "$after"
  source_state_matches "$before" "$after" || fail snapshot-drift
}

replace_clone_worktree() {
  local relative_path=''
  local source_path=''
  local clone_path=''
  local path_status=0

  rm -rf -- "$clone_root/.omo/evidence"
  while IFS= read -r -d '' relative_path; do
    if path_in_snapshot "$relative_path"; then
      :
    else
      path_status=$?
      if [[ "$path_status" -eq 1 ]]; then
        continue
      fi
      fail snapshot-mismatch
    fi

    source_path="$source_root/$relative_path"
    clone_path="$clone_root/$relative_path"
    if [[ ! -f "$source_path" && ! -L "$source_path" &&
      ( -f "$clone_path" || -L "$clone_path" ) ]]; then
      rm -f -- "$clone_path" || fail snapshot-clone
    fi
  done < <(git -C "$clone_root" ls-files -c -z)

  while IFS= read -r -d '' relative_path; do
    if path_in_snapshot "$relative_path"; then
      :
    else
      path_status=$?
      if [[ "$path_status" -eq 1 ]]; then
        continue
      fi
      fail snapshot-mismatch
    fi

    source_path="$source_root/$relative_path"
    [[ -f "$source_path" || -L "$source_path" ]] || continue
    clone_path="$clone_root/$relative_path"
    mkdir -p -- "$(dirname -- "$clone_path")" || fail snapshot-clone
    cp -a -- "$source_path" "$clone_path" || fail snapshot-clone
  done < <(source_git ls-files -co --exclude-standard -z)
}

run_after_capture_hook() {
  local hook=${VERIFY_SNAPSHOT_TEST_HOOK_AFTER_CAPTURE:-}

  [[ -z "$hook" ]] && return
  [[ -x "$hook" ]] || fail snapshot-drift
  "$hook" "$source_root" || fail snapshot-drift
}

run_after_copy_hook() {
  local hook=${VERIFY_SNAPSHOT_TEST_HOOK_AFTER_COPY:-}

  [[ -z "$hook" ]] && return
  [[ -x "$hook" ]] || fail snapshot-mismatch
  "$hook" "$clone_root" || fail snapshot-mismatch
}

provision_ephemeral_fixture_signer() {
  local state_directory="$session_directory/g0-fixture-signer"

  [[ -z "${TEESIM_FIXTURE_KEYSTORE:-}" && -z "${TEESIM_FIXTURE_STORE_PASSWORD_FILE:-}" &&
    -z "${TEESIM_FIXTURE_KEY_ALIAS:-}" && -z "${TEESIM_FIXTURE_KEY_PASSWORD_FILE:-}" ]] || return
  [[ -f "$clone_root/scripts/bootstrap-fixture-signer.sh" &&
    -x "$clone_root/scripts/bootstrap-fixture-signer.sh" ]] || fail snapshot-g0
  "$clone_root/scripts/bootstrap-fixture-signer.sh" "$state_directory" || fail snapshot-g0
  export TEESIM_FIXTURE_KEYSTORE="$state_directory/fixture-signer.p12"
  export TEESIM_FIXTURE_STORE_PASSWORD_FILE="$state_directory/fixture-store-password"
  export TEESIM_FIXTURE_KEY_ALIAS=teesim-fixture
  export TEESIM_FIXTURE_KEY_PASSWORD_FILE="$state_directory/fixture-key-password"
  pass snapshot-fixture-signer-ephemeral
}

run_snapshot_g0() {
  local timeout_seconds=${VERIFY_SNAPSHOT_G0_TIMEOUT_SECONDS:-3600}

  [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || fail snapshot-g0
  [[ -f "$clone_root/scripts/verify.sh" && ! -L "$clone_root/scripts/verify.sh" &&
    -x "$clone_root/scripts/verify.sh" ]] || fail snapshot-g0
  provision_ephemeral_fixture_signer
  (
    cd "$clone_root"
    timeout --foreground --signal=TERM --kill-after=10s "${timeout_seconds}s" \
      ./scripts/verify.sh
  ) || fail snapshot-g0
}

[[ $# -eq 1 && -d "$source_root" && -d "$temporary_root" ]] || fail snapshot-clone
exec </dev/null
export GIT_TERMINAL_PROMPT=0
if [[ -z "${ANDROID_HOME:-}" && -d "$source_root/.android-sdk" ]]; then
  export ANDROID_HOME="$source_root/.android-sdk"
fi

session_directory=$(mktemp -d "$temporary_root/verify-snapshot.XXXXXX") || fail snapshot-clone
capture_source_state "$session_directory/source-before"
clone_root="$session_directory/clone"
git clone --recurse-submodules --no-local -- "$source_root" "$clone_root" >/dev/null 2>&1 || fail snapshot-clone

clone_git_directory=$(git -C "$clone_root" rev-parse --absolute-git-dir) || fail snapshot-clone
source_head=$(<"$session_directory/source-before/head")
[[ "$clone_git_directory" != "$source_git_directory" ]] || fail snapshot-clone
git -C "$clone_root" merge-base --is-ancestor "$source_head" HEAD || fail snapshot-clone
pass git-directories-distinct

replace_clone_worktree
run_after_copy_hook
run_after_capture_hook
assert_source_unchanged "$session_directory/source-before" "$session_directory/source-after-copy"
write_manifest "$clone_root" "$session_directory/clone-manifest"
cmp -s "$session_directory/source-before/manifest" "$session_directory/clone-manifest" ||
  fail snapshot-mismatch
pass snapshot-manifests-match

git -C "$clone_root" add -A || fail snapshot-clone
git -C "$clone_root" -c user.name=snapshot-verifier \
  -c user.email=snapshot-verifier@invalid commit --no-gpg-sign --allow-empty \
  -m 'verify snapshot' || fail snapshot-clone
run_snapshot_g0
assert_source_unchanged "$session_directory/source-before" "$session_directory/source-after-g0"
pass source-state-unchanged
pass snapshot-verified
