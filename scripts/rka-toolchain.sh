#!/usr/bin/env bash
set -euo pipefail
umask 077

nixpkgs_revision="241313f4e8e508cb9b13278c2b0fa25b9ca27163"
rust_version="1.97.1"
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
runtime_root="$repo_root/.omo/runtime"

fail() {
    printf 'rka-toolchain: %s\n' "$*" >&2
    exit 64
}

ensure_private_root() {
    local variable_name="$1"
    local default_path="$2"
    local supplied="${!variable_name-}"
    local selected="$supplied"

    if [[ -z "$selected" ]]; then
        selected="$default_path"
        mkdir -p -- "$selected"
        chmod 700 -- "$selected"
    fi
    [[ "$selected" = /* ]] || fail "$variable_name must be an absolute path"
    [[ ! -L "$selected" ]] || fail "$variable_name must not be a symlink"
    [[ -d "$selected" ]] || fail "$variable_name must name an existing directory"

    local canonical
    canonical="$(realpath -e -- "$selected")"
    [[ "$canonical" == "$selected" ]] || fail "$variable_name must be canonical and unaliased"
    [[ "$(stat -c '%u' -- "$selected")" == "$(id -u)" ]] ||
        fail "$variable_name must be owned by the caller"
    [[ "$(stat -c '%a' -- "$selected")" == "700" ]] ||
        fail "$variable_name must have mode 0700"
    printf -v "$variable_name" '%s' "$selected"
    export "${variable_name?}"
}

validate_distinct_roots() {
    local roots=("$RUSTUP_HOME" "$CARGO_HOME" "$CARGO_TARGET_DIR" "$GRADLE_USER_HOME")
    local first
    local second
    for first in "${!roots[@]}"; do
        for second in "${!roots[@]}"; do
            if (( first < second )) && [[ "${roots[$first]}" == "${roots[$second]}" ]]; then
                fail "cache roots must not alias one another"
            fi
        done
    done
}

resolve_sdk() {
    local property_sdk=""
    local environment_sdk="${ANDROID_HOME-${ANDROID_SDK_ROOT-}}"
    local local_properties="$repo_root/local.properties"
    if [[ -f "$local_properties" ]]; then
        property_sdk="$(sed -n 's/^sdk\.dir=//p' "$local_properties")"
        [[ "$property_sdk" != *"\\"* ]] ||
            fail "local.properties sdk.dir escaping is unsupported; use a canonical path"
    fi
    [[ -n "$property_sdk" || -n "$environment_sdk" ]] ||
        fail "Android SDK is not configured by local.properties or ANDROID_HOME"

    if [[ -n "$property_sdk" && -n "$environment_sdk" ]]; then
        [[ "$(realpath -e -- "$property_sdk")" == "$(realpath -e -- "$environment_sdk")" ]] ||
            fail "local.properties and ANDROID_HOME must resolve to the same SDK"
    fi
    ANDROID_HOME="${property_sdk:-$environment_sdk}"
    [[ "$ANDROID_HOME" = /* && ! -L "$ANDROID_HOME" ]] ||
        fail "Android SDK root must be an absolute non-symlink path"
    ANDROID_HOME="$(realpath -e -- "$ANDROID_HOME")"
    ANDROID_SDK_ROOT="$ANDROID_HOME"
    export ANDROID_HOME ANDROID_SDK_ROOT
}

require_sdk_package() {
    local relative_path="$1"
    local package_id="$2"
    local package_root="$ANDROID_HOME/$relative_path"
    [[ -d "$package_root" && ! -L "$package_root" ]] ||
        fail "required Android SDK package is missing or symlinked: $package_id"
    [[ -f "$package_root/package.xml" ]] ||
        fail "Android SDK package metadata is missing: $package_id"
    grep -Fq "path=\"$package_id\"" "$package_root/package.xml" ||
        fail "Android SDK package metadata drifted: $package_id"
}

verify_versions() {
    local java_version
    java_version="$(
        java -version 2>&1 |
            sed -n 's/.*build \([0-9][0-9.]*+[0-9][0-9]*\).*/\1/p' |
            head -n 1
    )"
    [[ "$java_version" == "21.0.12+2" ]] || fail "OpenJDK must be 21.0.12+2"
    [[ "$(rustc --version)" == "rustc $rust_version "* ]] || fail "Rust must be $rust_version"
    [[ "$(cargo --version)" == "cargo $rust_version "* ]] || fail "Cargo must be $rust_version"
    [[ "$(cargo ndk --version)" == "cargo-ndk 4.1.2" ]] || fail "cargo-ndk must be 4.1.2"
    [[ "$(cargo deny --version)" == "cargo-deny 0.20.2" ]] ||
        fail "cargo-deny must be 0.20.2"
    [[ "$(shellcheck --version | sed -n 's/^version: //p')" == "0.11.0" ]] ||
        fail "ShellCheck must be 0.11.0"
    [[ "$(node --version)" == "v22.23.1" ]] || fail "Node must be 22.23.1"
    [[ "$(npm --version)" == "10.9.8" ]] || fail "npm must be 10.9.8"
}

mkdir -p -- "$runtime_root"
chmod 700 -- "$runtime_root"
ensure_private_root RUSTUP_HOME "$runtime_root/rustup"
ensure_private_root CARGO_HOME "$runtime_root/cargo"
ensure_private_root CARGO_TARGET_DIR "$runtime_root/cargo-target"
ensure_private_root GRADLE_USER_HOME "$runtime_root/gradle"
validate_distinct_roots

if [[ "${1-}" != "--inside" ]]; then
    quoted_wrapper="$(printf '%q' "$repo_root/scripts/rka-toolchain.sh")"
    quoted_arguments=""
    if (( $# > 0 )); then
        printf -v quoted_arguments ' %q' "$@"
    fi
    export RKA_TOOLCHAIN_REPO_ROOT="$repo_root"
    exec nix-shell \
        -I "nixpkgs=https://github.com/NixOS/nixpkgs/archive/$nixpkgs_revision.tar.gz" \
        -p openjdk21 rustup cargo-ndk cargo-deny shellcheck nodejs_22 \
        --run "exec $quoted_wrapper --inside$quoted_arguments"
fi
shift

[[ "${RKA_TOOLCHAIN_REPO_ROOT-}" == "$repo_root" ]] ||
    fail "Nix boundary repository root changed"
export RUSTUP_TOOLCHAIN="$rust_version"
JAVA_HOME="$(dirname -- "$(dirname -- "$(readlink -f -- "$(command -v javac)")")")"
export JAVA_HOME
verify_versions
resolve_sdk
require_sdk_package "platforms/android-36" "platforms;android-36"
require_sdk_package "build-tools/36.0.0" "build-tools;36.0.0"
require_sdk_package "ndk/27.3.13750724" "ndk;27.3.13750724"
ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.3.13750724"
export ANDROID_NDK_HOME

if [[ "${1-}" == "verify" ]]; then
    [[ $# -eq 1 ]] || fail "verify accepts no arguments"
    printf 'rka-toolchain verified\n'
    exit 0
fi
[[ $# -gt 0 ]] || fail "expected verify or a command"
if [[ "$1" == "cargo" && "${2-}" == "clean" ]]; then
    set +e
    "$@"
    clean_exit=$?
    set -e
    install -d -m 700 -- "$CARGO_TARGET_DIR"
    exit "$clean_exit"
fi
if [[ "$1" == "cargo" && "${2-}" == "deny" ]]; then
    shift 2
    exec cargo deny --manifest-path "$repo_root/rka-runtime/Cargo.toml" "$@"
fi
exec "$@"
