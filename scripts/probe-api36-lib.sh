read_profile_field() {
  local field=$1
  local -a matches=()
  mapfile -t matches < <(awk -F= -v field="$field" '$1 == field { print substr($0, length(field) + 2) }' "$PROFILE")
  [[ ${#matches[@]} == 1 && "${matches[0]}" =~ ^[^[:space:]#]+$ ]] || return 1
  printf -v "$field" '%s' "${matches[0]}"
}

load_profile() {
  local field
  local -a fields=(
    SDK ABI SELINUX AVB_STATE DEFAULT_INSTANCE KEYMINT_DEFAULT_AIDL_VARIANTS
    KEYSTORE_CONTEXT KERNELSU_DOMAIN MODULE_DIRECTORY MODULE_CONTEXT MODULE_MODE
    MODULE_OWNER KEYSTORE2_DEPENDENCIES ELF_ALLOWED_PATH_PREFIXES
  )
  for field in "${fields[@]}"; do
    read_profile_field "$field" || { stop profile-fields; return 1; }
  done
  [[ "$KEYMINT_DEFAULT_AIDL_VARIANTS" =~ ^[0-9]+:[0-9a-f]{40}(,[0-9]+:[0-9a-f]{40})*$ ]] || {
    stop profile-values
    return 1
  }
  [[ "$DEFAULT_INSTANCE" == android.hardware.security.keymint.IKeyMintDevice/* && "$MODULE_DIRECTORY" =~ ^/data/adb/modules/[A-Za-z0-9._-]+$ ]] || {
    stop profile-values
    return 1
  }
  [[ "$MODULE_MODE" =~ ^[0-7]{3,4}$ && "$MODULE_OWNER" =~ ^[A-Za-z0-9_-]+:[A-Za-z0-9_-]+$ ]] || {
    stop profile-values
    return 1
  }
}

check_equals() { local check=$1 actual=$2 expected=$3; [[ "$actual" == "$expected" ]] && pass "$check" || stop "$check"; }

decode_aidl_version() {
  local reply=$1 word
  local -a words=()
  mapfile -t words < <(grep -Eo '[0-9A-Fa-f]{8}' <<<"$reply" || true)
  (( ${#words[@]} >= 2 )) || return 1
  word=${words[${#words[@]} - 1]}
  printf '%d\n' "$((16#$word))"
}

decode_aidl_hash() {
  local reply=$1 line payload word unit character hash= skip=2 value
  while IFS= read -r line; do
    [[ "$line" =~ ^0x[0-9A-Fa-f]+:[[:space:]](.*)$ ]] || continue
    payload=${BASH_REMATCH[1]}
    for word in $payload; do
      [[ "$word" =~ ^[0-9A-Fa-f]{8}$ ]] || continue
      if (( skip > 0 )); then
        skip=$((skip - 1))
        continue
      fi
      for unit in "${word:4:4}" "${word:0:4}"; do
        [[ "$unit" == 0000 ]] && {
          [[ "$hash" =~ ^[0-9A-Fa-f]{40}$ ]] || return 1
          printf '%s\n' "${hash,,}"
          return 0
        }
        value=$((16#$unit))
        (( value >= 0x20 && value <= 0x7e )) || return 1
        printf -v character '%b' "\\$(printf '%03o' "$value")"
        hash+=$character
      done
    done
  done <<<"$reply"
  return 1
}

extract_build_id() {
  local metadata=$1 line
  while IFS= read -r line; do
    [[ "$line" =~ NT_GNU_BUILD_ID[[:space:]]+([0-9A-Fa-f]{32}([0-9A-Fa-f]{8})?)$ ]] && { printf '%s\n' "${BASH_REMATCH[1],,}"; return; }
  done <<<"$metadata"
  return 1
}

is_build_id() { [[ "$1" =~ ^[0-9a-f]{32}([0-9a-f]{8})?$ ]]; }

extract_needed() {
  local metadata=$1 line needed= separator=
  while IFS= read -r line; do
    [[ "$line" =~ Shared[[:space:]]library:[[:space:]]\[([A-Za-z0-9._@+-]+)\] ]] || continue
    needed+="$separator${BASH_REMATCH[1]}"
    separator=,
  done <<<"$metadata"
  [[ -n "$needed" ]] && printf '%s\n' "$needed"
}

path_is_allowed() {
  local path=$1 prefix IFS=,
  local -a prefixes=()
  read -r -a prefixes <<<"$ELF_ALLOWED_PATH_PREFIXES"
  for prefix in "${prefixes[@]}"; do
    [[ "$path" == "$prefix/"* ]] && return 0
  done
  return 1
}

resolve_dependency() {
  local dependency=$1 path
  local -a matches=()
  for path in "${map_paths[@]}"; do
    [[ "${path##*/}" == "$dependency" ]] && matches+=("$path")
  done
  [[ ${#matches[@]} == 1 ]] || return 1
  printf '%s\n' "${matches[0]}"
}

aidl_version_is_approved() {
  local version=$1 variant IFS=,
  local -a variants=()
  read -r -a variants <<<"$KEYMINT_DEFAULT_AIDL_VARIANTS"
  for variant in "${variants[@]}"; do [[ "${variant%%:*}" == "$version" ]] && return 0; done
  return 1
}

aidl_hash_is_approved() {
  local version=$1 hash=$2 variant IFS=,
  local -a variants=()
  read -r -a variants <<<"$KEYMINT_DEFAULT_AIDL_VARIANTS"
  for variant in "${variants[@]}"; do [[ "$variant" == "$version:$hash" ]] && return 0; done
  return 1
}

check_elf_chain() {
  local metadata actual_dependencies build_id dependency resolved dependency_metadata dependency_build_id
  metadata=$(root_read '/system/bin/readelf -d -n /system/bin/keystore2')
  build_id=$(extract_build_id "$metadata" || true)
  actual_dependencies=$(extract_needed "$metadata" || true)
  is_build_id "$build_id" && pass keystore2-build-id || stop keystore2-build-id
  [[ "$actual_dependencies" == "$KEYSTORE2_DEPENDENCIES" ]] && pass keystore2-dependencies || stop keystore2-dependencies

  mapfile -t map_paths < <(grep -Eo '/[^[:space:]]+\.so' <<<"$maps" | sort -u || true)
  (( ${#map_paths[@]} > 0 )) || { stop elf-dependency-chain; return; }

  local chain_ok=1
  for dependency in ${KEYSTORE2_DEPENDENCIES//,/ }; do
    resolved=$(resolve_dependency "$dependency" || true)
    if [[ -z "$resolved" ]] || ! path_is_allowed "$resolved"; then
      chain_ok=0
      continue
    fi
    dependency_metadata=$(root_read "/system/bin/readelf -d -n $resolved")
    dependency_build_id=$(extract_build_id "$dependency_metadata" || true)
    is_build_id "$dependency_build_id" || chain_ok=0
  done
  (( chain_ok == 1 )) && pass elf-dependency-chain || stop elf-dependency-chain
}
