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

continuity() {
  [ "$#" -eq 5 ] || die LIVENESS_ARGV_INVALID
  for value in "$@"; do
    case "$value" in 0|[1-9]|[1-9][0-9]*) ;; *) die LIVENESS_INTEGER_INVALID;; esac
    case "${#value}" in
      [0-9]|1[0-8]) ;;
      19) case "$value" in 9223372036854775807|[1-8]*) ;; *) die LIVENESS_INTEGER_RANGE;; esac ;;
      *) die LIVENESS_INTEGER_RANGE ;;
    esac
  done
  local head_uptime="$1" tail_uptime="$2" head_observed="$3" tail_observed="$4" asserted="$5"
  (( tail_uptime > head_uptime )) || die UPTIME_NOT_INCREASING
  (( tail_observed > head_observed )) || die OBSERVATION_NOT_INCREASING
  local device_elapsed=$((tail_uptime - head_uptime)) observed_elapsed=$((tail_observed - head_observed))
  (( device_elapsed <= 2000 )) || die SAMPLE_GAP
  (( observed_elapsed <= 2000 )) || die OBSERVATION_GAP
  local drift=$((device_elapsed - observed_elapsed))
  (( drift < 0 )) && drift=$((-drift))
  (( drift <= 250 )) || die CLOCK_DRIFT
  (( asserted >= tail_observed && asserted - tail_observed <= 2000 )) || die STALE_ASSERTION
  printf 'LIVENESS=LIVE\n'
}

case "${1:-}" in
  trace) shift; trace "$@" ;;
  continuity) shift; continuity "$@" ;;
  future-keystore2|future-rkpd) printf 'PLANNED_ONLY\n' ;;
  *) die 'usage: rka-evidence.sh trace adb -s SERIAL shell getprop PROPERTY' ;;
esac
