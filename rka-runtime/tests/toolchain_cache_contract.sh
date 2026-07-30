#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
wrapper="$repo_root/scripts/rka-toolchain.sh"
sdk_root="${ANDROID_HOME:?ANDROID_HOME is required}"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
chmod 700 "$test_root"

make_roots() {
    local lane="$1"
    install -d -m 700 \
        "$test_root/$lane/rustup" \
        "$test_root/$lane/cargo" \
        "$test_root/$lane/target" \
        "$test_root/$lane/gradle"
}

run_lane() {
    local lane="$1"
    shift
    RUSTUP_HOME="$test_root/$lane/rustup" \
        CARGO_HOME="$test_root/$lane/cargo" \
        CARGO_TARGET_DIR="$test_root/$lane/target" \
        GRADLE_USER_HOME="$test_root/$lane/gradle" \
        ANDROID_HOME="$sdk_root" \
        "$wrapper" "$@"
}

make_roots lane-a
make_roots lane-b
shared_sysroot="$(
    ANDROID_HOME="$sdk_root" "$wrapper" rustc --print sysroot
)"
host_triple="$(basename -- "$shared_sysroot" | sed 's/^1\.97\.1-//')"
for lane in lane-a lane-b; do
    mkdir -p -- "$test_root/$lane/rustup/toolchains"
    ln -s -- "$shared_sysroot" \
        "$test_root/$lane/rustup/toolchains/1.97.1-$host_triple"
done
preserved="$(
    run_lane lane-a bash -c \
        "printf '%s\n%s\n%s\n%s\n%s\n%s\n' \"\$RUSTUP_HOME\" \"\$CARGO_HOME\" \"\$CARGO_TARGET_DIR\" \"\$GRADLE_USER_HOME\" \"\$1\" \"\$2\"" \
        boundary "argument with spaces" "literal;\$value"
)"
expected="$test_root/lane-a/rustup
$test_root/lane-a/cargo
$test_root/lane-a/target
$test_root/lane-a/gradle
argument with spaces
literal;\$value"
[[ "$preserved" == "$expected" ]]

run_lane lane-a bash -c "printf lane-a > \"\$CARGO_TARGET_DIR/owner\"" &
lane_a_process=$!
run_lane lane-b bash -c "printf lane-b > \"\$CARGO_TARGET_DIR/owner\"" &
lane_b_process=$!
wait "$lane_a_process"
wait "$lane_b_process"
[[ "$(cat "$test_root/lane-a/target/owner")" == "lane-a" ]]
[[ "$(cat "$test_root/lane-b/target/owner")" == "lane-b" ]]

chmod 755 "$test_root/lane-a/gradle"
if run_lane lane-a verify >/dev/null 2>&1; then
    exit 1
fi
chmod 700 "$test_root/lane-a/gradle"

ln -s "$test_root/lane-a/cargo" "$test_root/cargo-link"
if RUSTUP_HOME="$test_root/lane-a/rustup" \
    CARGO_HOME="$test_root/cargo-link" \
    CARGO_TARGET_DIR="$test_root/lane-a/target" \
    GRADLE_USER_HOME="$test_root/lane-a/gradle" \
    ANDROID_HOME="$sdk_root" \
    "$wrapper" verify >/dev/null 2>&1; then
    exit 1
fi

if RUSTUP_HOME="$test_root/lane-a/rustup" \
    CARGO_HOME="$test_root/lane-a/rustup" \
    CARGO_TARGET_DIR="$test_root/lane-a/target" \
    GRADLE_USER_HOME="$test_root/lane-a/gradle" \
    ANDROID_HOME="$sdk_root" \
    "$wrapper" verify >/dev/null 2>&1; then
    exit 1
fi

if RUSTUP_HOME="$test_root/lane-a/rustup" \
    CARGO_HOME="$test_root/lane-a/../lane-a/cargo" \
    CARGO_TARGET_DIR="$test_root/lane-a/target" \
    GRADLE_USER_HOME="$test_root/lane-a/gradle" \
    ANDROID_HOME="$sdk_root" \
    "$wrapper" verify >/dev/null 2>&1; then
    exit 1
fi

printf 'toolchain cache contract passed\n'
