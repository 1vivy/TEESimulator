#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
manifest="$repo_root/rka-runtime/Cargo.toml"
gradle_file="$repo_root/app/build.gradle.kts"

test -f "$manifest"
test -f "$repo_root/rka-runtime/crates/rka-sidecar/Cargo.toml"
grep -Fq 'name = "rka-sidecar"' "$repo_root/rka-runtime/crates/rka-sidecar/Cargo.toml"
grep -Fq 'verifyRkaRuntimeAbis' "$gradle_file"
grep -Fq 'buildRkaRuntimeArm64' "$gradle_file"
