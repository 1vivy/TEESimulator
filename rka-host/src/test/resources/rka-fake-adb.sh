#!/bin/bash
set -euo pipefail

serial=$2
shift 2
device="$RKA_FAKE_DEVICE_ROOT/$serial"
root="$device/root"

if [ "${1-}" = push ]; then
    printf '%s %s\n' "$serial" "$*" >> "$RKA_FAKE_LOG"
    mkdir -p "$root${3%/*}"
    cp "$2" "$root$3"
    if [ "${RKA_FAKE_CORRUPT_ARCHIVE_SERIAL:-}" = "$serial" ] && [ "$3" = /data/adb/teesimulator-rka/upload/role-neutral-release.zip ]; then
        printf 'corrupt\n' >> "$root$3"
    fi
    if [ "${RKA_FAKE_CORRUPT_SOURCE_SERIAL:-}" = "$serial" ] && [ "$3" = /data/adb/teesimulator-rka/upload/role-neutral-release.zip.source-sha ]; then
        printf '%040d\n' 0 > "$root$3"
    fi
    if [ "${RKA_FAKE_NEXT_MUTATION:-}" = probe-hash-mismatch ] && [[ "$3" = /data/adb/teesimulator-rka/probes/*.manager-appid ]]; then
        printf 'corrupt\n' >> "$root$3"
    fi
    exit 0
fi

[[ "$#" -eq 4 && "$1" = shell && "$2" = su && "$3" = 0 && "$4" = sh ]] || exit 92
wire_payload=$(cat)
payload=${wire_payload#*"<<'RKA_ADB_ROOT_PAYLOAD_7D4C2A91'"$'\n'}
[[ "$payload" != "$wire_payload" ]] || exit 93
payload=${payload%%$'\n'RKA_ADB_ROOT_PAYLOAD_7D4C2A91$'\n'*}
payload+=$'\n'
first_line=${payload%%$'\n'*}
read -r set_marker dash_marker mode _remote_arguments <<< "$first_line"
[[ "$set_marker" = set && "$dash_marker" = -- && -n "$mode" ]] || exit 93
printf '%s shell su 0 sh %s\n' "$serial" "${first_line#set -- }" >> "$RKA_FAKE_LOG"
if [ "$mode" = cleanup-probe ]; then
    printf '%s PROBE_CLEANUP_ROLLBACK\n' "$serial" >> "$RKA_FAKE_LOG"
fi
if [ "$mode" = preflight ] && [ "${RKA_FAKE_INCOMPATIBLE:-}" = "$serial" ]; then
    printf '%s\n' 'RESULT=INCOMPATIBLE reason=KSUD_VERSION'
    exit 0
fi
if [ "$mode" = network ] && [ "${RKA_FAKE_FAIL_NETWORK:-}" = "$serial" ]; then
    exit 1
fi
if [ "$mode" = deploy ] && [ "${RKA_FAKE_FAIL_DEPLOY:-}" = "$serial" ]; then
    exit 1
fi

mkdir -p "$root"/{data/adb/modules,data/adb/modules_update,data/adb/teesimulator-rka,data/adb/ksu/bin,data/local/tmp,data/system,dev,etc,proc,shim,tmp,usr,bin,lib,lib64,run}
chmod 700 "$root/data/adb/teesimulator-rka"
if [ "${RKA_FAKE_FIRST_INSTALL:-false}" = true ] && [ ! -e "$root/data/adb/modules/tricky_store" ] && [ ! -e "$root/data/adb/modules_update/tricky_store" ]; then
    rm -rf "$root/data/adb/modules" "$root/data/adb/modules_update"
    case "${RKA_FAKE_NEXT_MUTATION:-}" in
        layout-one-parent) mkdir -p "$root/data/adb/modules" ;;
        layout-file) : > "$root/data/adb/modules" ;;
        layout-symlink) ln -s /data/adb/elsewhere "$root/data/adb/modules" ;;
        layout-hidden-mount) : > "$root/data/adb/teesimulator-rka/.bound" ;;
    esac
fi

write_shim() {
    local name=$1
    shift
    printf '%s\n' '#!/bin/sh' "$@" > "$root/shim/$name"
    chmod 700 "$root/shim/$name"
}

write_shim id 'if [ "${1-}" = -u ]; then printf "0\n"; else /usr/bin/id "$@"; fi'
write_shim chown 'exit 0'
write_shim rm '
if [ "${RKA_FAKE_NEXT_MUTATION:-}" = probe-cleanup-failure ] && [ "${2-}" != "" ]; then
  case "${@: -1}" in /data/adb/teesimulator-rka/probes/*.manager-appid) exit 0 ;; esac
fi
exec /usr/bin/rm "$@"'
write_shim ksud '
case "${1-} ${2-}" in
  "--version ") printf "%s\n" "3.2.5-12-g824f2f23 (uapi: 2)" ;;
  "module --help"|"sepolicy --help"|"sepolicy check"|"sepolicy apply") exit 0 ;;
  "module install")
    if [ "${RKA_FAKE_FAULT:-}" = install-only-modules-parent ]; then mkdir -p /data/adb/modules; exit 1; fi
    if [ "${RKA_FAKE_FAULT:-}" = install-only-update-parent ]; then mkdir -p /data/adb/modules_update; exit 1; fi
    rm -rf /data/adb/modules_update/tricky_store
    mkdir -p /data/adb/modules_update/tricky_store
    /usr/bin/unzip -q "$3" -d /data/adb/modules_update/tricky_store
    ;;
  *) exit 1 ;;
esac'
if [ "${RKA_FAKE_KSU_PROFILE:-legacy}" = ksu-next-dual ]; then
    cat > "$root/data/adb/ksud" <<'EOF'
#!/bin/sh
case "${1-} ${2-}" in
  "--version ")
    if [ "${RKA_FAKE_NEXT_MUTATION:-}" = version-drift ]; then printf '%s\n' 'ksud 3.3.1 (uapi: 2)'; else printf '%s\n' 'ksud 3.3.0 (uapi: 2)'; fi ;;
  "module help")
    printf '%s\n' 'Commands:' '  install' '  restore' '  uninstall' '  enable' '  disable' '  action' '  metamodule' '  list' '  config'
    [ "${RKA_FAKE_NEXT_MUTATION:-}" = help-drift ] || printf '%s\n' '  help' ;;
  "sepolicy help") printf '%s\n' 'Commands:' '  patch' '  apply' '  check' '  help' ;;
  "sepolicy check"|"sepolicy apply") exit 0 ;;
  "module install")
    if [ "${RKA_FAKE_FAULT:-}" = install-only-modules-parent ]; then mkdir -p /data/adb/modules; exit 1; fi
    if [ "${RKA_FAKE_FAULT:-}" = install-only-update-parent ]; then mkdir -p /data/adb/modules_update; exit 1; fi
    rm -rf /data/adb/modules_update/tricky_store
    mkdir -p /data/adb/modules/tricky_store /data/adb/modules_update/tricky_store
    : > /data/adb/modules/tricky_store/update
    /usr/bin/unzip -q "$3" -d /data/adb/modules_update/tricky_store ;;
  *) exit 1 ;;
esac
EOF
    chmod 755 "$root/data/adb/ksud"
    ln -sfn /data/adb/ksud "$root/data/adb/ksu/bin/ksud"
fi
write_shim sha256sum '
if [ "${1-}" = /proc/sys/kernel/random/boot_id ] && [ "${RKA_FAKE_NEXT_MUTATION:-}" = boot-drift ] && [ -f /data/adb/teesimulator-rka/.boot-drift ]; then
  printf "%s  %s\n" bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb "$1"
elif [ "${1-}" = /data/adb/ksud ]; then
  if [ "${RKA_FAKE_NEXT_MUTATION:-}" = binary-drift ]; then digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; else digest=f4359553a597955956b97e86277e08bc426f644de0dba5ff13da562fba29c55d; fi
  printf "%s  %s\n" "$digest" "$1"
elif [ "${1-}" = /shim/ksud ]; then
  printf "%s  %s\n" a75099ef6dd9eb5f528df2fdf1aaa2eaa080af3df70b6c69216d28778a8c66c9 "$1"
else
  exec /usr/bin/sha256sum "$@"
fi'
write_shim cmd '
if [ "${RKA_FAKE_KSU_PROFILE:-legacy}" = ksu-next-dual ]; then
  printf "%s\n" com.rifsxd.ksunext/.ui.MainActivity
else
  printf "%s\n" me.weishu.kernelsu/.ui.MainActivity
fi'
write_shim dumpsys '
if [ "${1-} ${2-}" = "package com.rifsxd.ksunext" ]; then
  if [ "${RKA_FAKE_NEXT_MUTATION:-}" = uid-mismatch ]; then package_uid=10125; else package_uid=10123; fi
  printf "%s\n" "versionName=v3.3.0" "versionCode=33214" "  userId=$package_uid"
  [ "${RKA_FAKE_NEXT_MUTATION:-}" = signing-wrong ] || printf "%s\n" "  signingDetails=SigningDetails{fixture-donor}"
  if [ "${RKA_FAKE_NEXT_MUTATION:-}" = component-wrong ]; then exported=false; else exported=true; fi
  printf "%s\n" "  activity com.rifsxd.ksunext/.ui.MainActivity exported=$exported" "  activity com.rifsxd.ksunext/.ui.webui.WebUIActivity exported=false"
  exit 0
fi
if [ "${1-} ${2-}" = "package org.example.headless" ]; then
  printf "%s\n" "versionName=fixture" "versionCode=1" "  userId=10124" "  signingDetails=SigningDetails{fixture-candidate}"
  exit 0
fi
if [ "${1-} ${2-}" = "package me.weishu.kernelsu" ]; then
  printf "%s\n" "versionName=v3.2.5-12-g824f2f23" "versionCode=32537"
  exit 0
fi
[ "${1-} ${2-} ${3-}" = "activity -a services" ] || exit 1
if [ "${RKA_FAKE_KSU_PROFILE:-legacy}" = ksu-next-dual ]; then
  client="201:com.rifsxd.ksunext/u0a123"
else
  client="201:me.weishu.kernelsu/u0a123"
fi
case "${RKA_FAKE_WEBUI_OWNER:-}" in
  wrong) client="211:com.example.unrelated/u0a124" ;;
  missing) client= ;;
esac
printf "%s\n" \
  "ACTIVITY MANAGER SERVICES (dumpsys activity services)" \
  "  * ServiceRecord{aaa u0 com.google.android.webview/org.chromium.content.app.SandboxedProcessService0:0}" \
  "    packageName=com.google.android.webview" \
  "    processName=com.google.android.webview:sandboxed_process0" \
  "    isolatedProc=ProcessRecord{bbb 301:com.google.android.webview:sandboxed_process0/u0i1}" \
  "    Bindings:"
if [ -n "$client" ]; then
  printf "      * Client AppBindRecord{ddd ProcessRecord{ccc %s}}\n" "$client"
fi
if [ "${RKA_FAKE_WEBUI_OWNER:-}" = ambiguous ]; then
  printf "%s\n" \
    "  * ServiceRecord{ddd u0 com.google.android.webview/org.chromium.content.app.SandboxedProcessService0:1}" \
    "    packageName=com.google.android.webview" \
    "    processName=com.google.android.webview:sandboxed_process0" \
    "    isolatedProc=ProcessRecord{eee 302:com.google.android.webview:sandboxed_process0/u0i2}" \
    "    Bindings:" \
    "      * Client AppBindRecord{ggg ProcessRecord{fff 201:${client#*:}}}"
fi'
write_shim pidof '
case "${1-}" in
  ksud) printf "101\n" ;;
  me.weishu.kernelsu) printf "201\n" ;;
  com.rifsxd.ksunext) printf "201\n" ;;
  com.google.android.webview:sandboxed_process0)
    if [ "${RKA_FAKE_WEBUI_OWNER:-}" = ambiguous ]; then printf "301 302\n"; else printf "301\n"; fi ;;
  webview_zygote)
    case "${RKA_FAKE_ZYGOTE:-}" in
      ambiguous) printf "700 701\n" ;;
      missing) exit 1 ;;
      *) printf "700\n" ;;
    esac ;;
  *) exit 1 ;;
esac'
write_shim ip '
case "$RKA_FAKE_SERIAL" in
  DONOR_A) printf "1: tailscale0 inet 127.0.0.1/32 scope global tailscale0\n" ;;
  *) printf "1: tailscale0 inet 127.0.0.2/32 scope global tailscale0\n" ;;
esac'
write_shim ping 'exit 0'
write_shim logcat 'exit 0'
write_shim strings 'exit 1'
write_shim toybox 'exit 0'
write_shim timeout 'shift; exec "$@"'
write_shim lsattr 'printf "%s %s\n" ---------------------- "${@: -1}"'
write_shim awk '
last=
for value in "$@"; do last=$value; done
if [ "$last" = /data/system/packages.list ]; then
  case " $* " in
    *"(\$2 % 100000) == appid"*)
      if [ -n "${RKA_FAKE_MANAGER_MATCH:-}" ]; then
        printf "%s\n" "$RKA_FAKE_MANAGER_MATCH"
        exit 0
      fi ;;
  esac
fi
if [ "$last" = /proc/1/mountinfo ]; then
  if [ -f /data/adb/teesimulator-rka/.bound ]; then
    case " $* " in *print*) printf "77|/\n" ;; esac
    exit 0
  fi
  exit 1
fi
case "$last" in
  /proc/201/status)
    case " $* " in *Uid:*) printf "10123\n" ;; *PPid:*) printf "1\n" ;; *) exit 1 ;; esac
    exit 0 ;;
  /proc/301/status)
    case " $* " in *Uid:*) printf "99001\n" ;; *PPid:*) printf "700\n" ;; *) exit 1 ;; esac
    exit 0 ;;
  /proc/302/status)
    case " $* " in *Uid:*) printf "99002\n" ;; *PPid:*) printf "700\n" ;; *) exit 1 ;; esac
    exit 0 ;;
  /proc/700/status)
    case " $* " in *Uid:*) printf "1053\n" ;; *PPid:*) printf "1\n" ;; *) exit 1 ;; esac
    exit 0 ;;
esac
exec /usr/bin/awk "$@"'
write_shim stat '
last=
for value in "$@"; do last=$value; done
case "$last" in
  /data/adb/teesimulator-rka/probes/*.manager-appid)
    if [ "${1-}" = -c ] && [ "${2-}" = %u:%g:%a ]; then printf "0:0:700\n"; exit 0; fi ;;
  /data/adb/ksud)
    if [ "${1-}" = -c ] && [ "${2-}" = %u:%g:%a ]; then printf "0:0:755\n"; exit 0; fi ;;
  /data/adb/ksu/.metadata/ksud.provenance)
    if [ "${1-}" = -c ] && [ "${2-}" = %u:%a ]; then printf "0:600\n"; exit 0; fi ;;
  /data/adb/modules/tricky_store/module.prop|/data/adb/modules_update/tricky_store/module.prop)
    if [ -f /data/adb/teesimulator-rka/.bound ] && [ "${RKA_NSENTER:-}" = 1 ] && [ "$last" = /data/adb/modules/tricky_store/module.prop ]; then
      exec /usr/bin/stat -c %d:%i /data/adb/modules_update/tricky_store/module.prop
    fi ;;
  /data/adb/modules/tricky_store)
    if [ ! -f /data/adb/teesimulator-rka/.bound ] && [ "$(cat /data/adb/teesimulator-rka/run/supervisor.state 2>/dev/null)" = STOPPED ]; then
      if [ "${RKA_FAKE_FAULT:-}" = active-hash ]; then exit 1; fi
      if [ "${RKA_FAKE_FAULT:-}" = active-metadata ]; then
        if [ -f /data/adb/teesimulator-rka/.active-hash-complete ]; then exit 1; fi
        : > /data/adb/teesimulator-rka/.active-hash-complete
      fi
    fi ;;
esac
exec /usr/bin/stat "$@"'
write_shim ls '
if [ "${1-}" = -Zd ] && [ "${2-}" = /data/adb/ksud ]; then
  printf "u:object_r:ksu_file:s0 %s\n" "$2"
else
  exec /usr/bin/ls "$@"
fi'
write_shim cp '
if [ "${RKA_FAKE_FAULT:-}" = active-copy ] && [ "${1-}" = -a ] && [ "${2-}" = /data/adb/modules/tricky_store ]; then exit 1; fi
exec /usr/bin/cp "$@"'
write_shim mount '
if [ "${1-}" = --bind ]; then
  rm -rf /data/adb/teesimulator-rka/active-underlay
  mv "$3" /data/adb/teesimulator-rka/active-underlay
  cp -a "$2" "$3"
  : > /data/adb/teesimulator-rka/.bound
  exit 0
fi
exit 1'
write_shim umount '
rm -rf /data/adb/modules/tricky_store
mv /data/adb/teesimulator-rka/active-underlay /data/adb/modules/tricky_store
rm -f /data/adb/teesimulator-rka/.bound
[ "${RKA_FAKE_FAULT:-}" != after-unmount ] || exit 1
exit 0'
write_shim nsenter '
while [ $# -gt 0 ]; do
  case "$1" in -t) shift 2 ;; -m) shift ;; --) shift; break ;; *) break ;; esac
done
RKA_NSENTER=1 exec "$@"'
write_shim readlink '
case "${1-}" in
  /proc/*/ns/mnt) pid=${1#/proc/}; pid=${pid%/ns/mnt}; printf "mnt:[402653%s]\n" "$pid" ;;
  *) exec /usr/bin/readlink "$@" ;;
esac'
write_shim cat '
case "${1-}" in
  /proc/201/cmdline)
    if [ "${RKA_FAKE_KSU_PROFILE:-legacy}" = ksu-next-dual ]; then printf "com.rifsxd.ksunext\\0"; else printf "me.weishu.kernelsu\\0"; fi ;;
  /proc/301/cmdline|/proc/302/cmdline) printf "com.google.android.webview:sandboxed_process0\\0" ;;
  *) exec /usr/bin/cat "$@" ;;
esac'
write_shim head '
if [ "${1-}" = -c ]; then
  path=${3-}
  case "$path" in
    /proc/301/status)
      if [ "${RKA_FAKE_ZYGOTE:-}" = wrong-parent ]; then parent=701; else parent=700; fi
      printf "Name:\tcom.google.android.webview:sandboxed_process0\nUid:\t99001\t99001\t99001\t99001\nPPid:\t%s\n" "$parent"
      exit 0 ;;
    /proc/302/status)
      printf "Name:\tcom.google.android.webview:sandboxed_process0\nUid:\t99002\t99002\t99002\t99002\nPPid:\t700\n"
      exit 0 ;;
    /proc/700/status)
      if [ "${RKA_FAKE_ZYGOTE:-}" = invalid-identity ]; then name=not_zygote uid=1054; else name=webview_zygote uid=1053; fi
      printf "Name:\t%s\nUid:\t%s\t%s\t%s\t%s\nPPid:\t1\n" "$name" "$uid" "$uid" "$uid" "$uid"
      exit 0 ;;
    /proc/700/cmdline)
      if [ "${RKA_FAKE_ZYGOTE:-}" = invalid-identity ]; then printf "not_zygote\0"; else printf "webview_zygote\0"; fi
      exit 0 ;;
  esac
fi
exec /usr/bin/head "$@"'
mkdir -p "$root/data/adb/ksu/.metadata"
cat > "$root/data/adb/ksu/.metadata/ksud.provenance" <<'EOF'
version=1
ksud_version=3.2.5-12-g824f2f23 (uapi: 2)
ksud_sha256=a75099ef6dd9eb5f528df2fdf1aaa2eaa080af3df70b6c69216d28778a8c66c9
source_commit=824f2f235d37dac7f06b31869a138ee7a9309a43
module_cli=true
sepolicy_cli=true
EOF
chmod 600 "$root/data/adb/ksu/.metadata/ksud.provenance"

if [ "${RKA_FAKE_KSU_PROFILE:-legacy}" = ksu-next-dual ]; then
    if [ "$serial" = DONOR_A ]; then
        printf 'com.rifsxd.ksunext 10123 0 /data/user/0/com.rifsxd.ksunext default:targetSdkVersion=36 none 0 0 1\n' > "$root/data/system/packages.list"
    else
        printf 'org.example.headless 10124 0 /data/user/0/org.example.headless default:targetSdkVersion=36 none 0 0 1\n' > "$root/data/system/packages.list"
    fi
    case "${RKA_FAKE_NEXT_MUTATION:-}" in
        appid-ambiguous) printf 'org.example.second 110123 0 /data/user/0/org.example.second default none 0 0 1\n' >> "$root/data/system/packages.list" ;;
        packages-malicious) printf '../evil 10123\n' >> "$root/data/system/packages.list" ;;
    esac
fi

manager_match=
case "${RKA_FAKE_NEXT_MUTATION:-}" in
    match-whitespace) manager_match='com.rifsxd bad|10123' ;;
    match-newline) manager_match='com.rifsxd.ksunext|10123
org.example.second|10123' ;;
    match-metachar) manager_match='com.rifsxd.$(touch /tmp/rka-manager-executed)|10123' ;;
    match-malformed) manager_match='com.rifsxd.ksunext|' ;;
    match-extra) manager_match='com.rifsxd.ksunext|10123|extra' ;;
esac

if [ "${RKA_FAKE_NEXT_MUTATION:-}" = android-shell-parser ]; then
    case "$wire_payload" in
        *'package=${matches%%|*}; package_uid=${matches#*|}'*)
            printf "manager-probe: unexpected '.'\n" >&2
            exit 2 ;;
    esac
fi

printf '%s\n' "$wire_payload" | bwrap \
    --bind "$root" / \
    --ro-bind /usr /usr \
    --ro-bind /bin /bin \
    --ro-bind /lib /lib \
    --ro-bind /lib64 /lib64 \
    --ro-bind /etc /etc \
    --ro-bind "$RKA_FAKE_DEVICE_ROOT" /devices \
    --ro-bind "$RKA_FAKE_TLS_ROOT" /tls-fixture \
    --proc /proc \
    --dev /dev \
    --unshare-all \
    --share-net \
    --setenv PATH "$([ "${RKA_FAKE_KSU_PROFILE:-legacy}" = ksu-next-dual ] && printf /data/adb/ksu/bin:/shim:/usr/bin:/bin || printf /shim:/usr/bin:/bin)" \
    --setenv RKA_FAKE_SERIAL "$serial" \
    --setenv RKA_FAKE_KSU_PROFILE "${RKA_FAKE_KSU_PROFILE:-legacy}" \
    --setenv RKA_FAKE_FIRST_INSTALL "${RKA_FAKE_FIRST_INSTALL:-false}" \
    --setenv RKA_FAKE_SYSTEM_OPENSSL "${RKA_FAKE_SYSTEM_OPENSSL:-true}" \
    --setenv RKA_FAKE_NEXT_MUTATION "${RKA_FAKE_NEXT_MUTATION:-}" \
    --setenv RKA_FAKE_MANAGER_MATCH "$manager_match" \
    --setenv RKA_FAKE_MISMATCH_PIN "$([ "${RKA_FAKE_MISMATCH_SERIAL:-}" = "$serial" ] && printf true || printf false)" \
    --setenv RKA_FAKE_TLS_PROTOCOL "${RKA_FAKE_TLS_PROTOCOL:-TLS1.3}" \
    --setenv RKA_FAKE_PROBE_STATUS "${RKA_FAKE_PROBE_STATUS:-}" \
    --setenv RKA_FAKE_FAULT "${RKA_FAKE_FAULT:-}" \
    --setenv RKA_FAKE_WEBUI_OWNER "${RKA_FAKE_WEBUI_OWNER:-}" \
    --setenv RKA_FAKE_ZYGOTE "${RKA_FAKE_ZYGOTE:-}" \
    /bin/sh
