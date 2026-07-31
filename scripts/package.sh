#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VARIANT="release"
CLEAN=false
BUILD_RUST=false

usage() {
    cat <<EOF
Usage: $(basename "$0") [--release|--debug|--all] [--clean] [--rust]

Builds a role-neutral KSU archive only. Deployment and service activation are
deliberately outside this packaging command.
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release) VARIANT="release"; shift ;;
        --debug) VARIANT="debug"; shift ;;
        --all) VARIANT="all"; shift ;;
        --clean) CLEAN=true; shift ;;
        --rust) BUILD_RUST=true; shift ;;
        --help|-h) usage ;;
        *) printf 'Unknown flag: %s\n' "$1" >&2; exit 2 ;;
    esac
done

if [[ "$BUILD_RUST" == true ]]; then
    (
        cd "$PROJECT_ROOT/native-certgen"
        "$PROJECT_ROOT/scripts/rka-toolchain.sh" cargo ndk -t arm64-v8a --platform 29 -- build --release
    )
fi

tasks=()
[[ "$CLEAN" == true ]] && tasks+=(clean)
case "$VARIANT" in
    release) tasks+=(zipRelease) ;;
    debug) tasks+=(zipDebug) ;;
    all) tasks+=(zipRelease zipDebug) ;;
esac

cd "$PROJECT_ROOT"
./gradlew "${tasks[@]}"
