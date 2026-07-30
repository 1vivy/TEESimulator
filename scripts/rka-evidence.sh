#!/usr/bin/env bash
set -euo pipefail

die() { printf '%s\n' "$1" >&2; exit 64; }
hash_argv() { printf '%s\0' "$@" | sha256sum | awk '{print $1}'; }

trace() {
  [ "$#" -ge 4 ] || die ADB_ARGV_INVALID
  [ "$1" = adb ] && [ "$2" = -s ] || die ADB_ARGV_INVALID
  case "$3" in *[!A-Za-z0-9._:-]*|'') die ADB_ARGV_INVALID;; esac
  for argument in "${@:4}"; do case "$argument" in reboot|kill|pkill|killall|setprop|svc) die ADB_FORBIDDEN_OPERATION;; esac; done
  [ "$#" -eq 6 ] && [ "$4" = shell ] || die ADB_ARGV_INVALID
  case "$5" in getprop) ;; *) die ADB_ARGV_NOT_ALLOWLISTED;; esac
  case "$6" in ro.build.fingerprint|ro.build.version.release|ro.build.version.incremental|ro.vendor.build.fingerprint) ;; *) die ADB_ARGV_NOT_ALLOWLISTED;; esac
  for argument in "$@"; do case "$argument" in *';'*|*'&'*|*'|'*|*'`'*|*\$\(*|*'<'*|*'>'*|*\\*) die ADB_SHELL_SMUGGLING;; esac; done
  printf 'TRACE_HASH=%s\n' "$(hash_argv "$@")"
}

case "${1:-}" in
  trace) shift; trace "$@" ;;
  future-keystore2|future-rkpd) printf 'PLANNED_ONLY\n' ;;
  *) die 'usage: rka-evidence.sh trace adb -s SERIAL shell getprop PROPERTY' ;;
esac
