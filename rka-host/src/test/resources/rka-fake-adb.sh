#!/bin/bash
set -euo pipefail

serial=$2
shift 2
device="$RKA_FAKE_DEVICE_ROOT/$serial"
root="$device/root"

if [ "${1-}" = push ]; then
    printf '%s %s\n' "$serial" "$*" >> "$RKA_FAKE_LOG"
    if [ "${RKA_FAKE_PROTECTED_PUSH_DENIED:-}" = "$serial" ] && [[ "$3" = /data/adb/* ]]; then
        printf 'adb: error: failed to copy: Permission denied\n' >&2
        exit 1
    fi
    mkdir -p "$root${3%/*}"
    cp "$2" "$root$3"
    if [ "${RKA_FAKE_UPLOAD_FAULT:-}" = truncate ] && [[ "$3" = /data/local/tmp/rka-adb-upload-* ]]; then
        printf 'truncated\n' >> "$root$3"
    fi
    if [ "${RKA_FAKE_NEXT_MUTATION:-}" = probe-hash-mismatch ] && [[ "$3" = /data/local/tmp/rka-adb-upload-*-probe ]]; then
        printf 'corrupt\n' >> "$root$3"
    fi
    exit 0
fi

if [ "${1-}" = shell ] && [ "${2-}" = cat ] && [ "${3-}" = /proc/sys/kernel/random/boot_id ]; then
    printf 'fixture-%s-boot\n' "$serial"
    exit 0
fi
if [ "${1-}" = shell ] && [ "${2-}" = cat ] && [ "${3-}" = /proc/uptime ]; then
    mkdir -p "$device"
    uptime_file="$device/uptime-sample"
    uptime_sample=12345
    [ ! -f "$uptime_file" ] || uptime_sample=$(cat "$uptime_file")
    uptime_sample=$((uptime_sample + 1))
    printf '%s\n' "$uptime_sample" > "$uptime_file"
    printf '%s.%02d 1.0\n' "$((uptime_sample / 100))" "$((uptime_sample % 100))"
    exit 0
fi
if [ "${1-}" = shell ] && [ "${2-}" = getprop ] && [ "${3-}" = ro.build.version.release ]; then
    printf 'MISLEADING_SUCCESS_STDOUT\n'
    printf 'controlled failure remains visible\n' >&2
    exit 19
fi

[[ "$#" -eq 4 && "$1" = shell && "$2" = su && "$3" = 0 && "$4" = sh ]] || exit 92
wire_payload=$(cat)
if [[ "$wire_payload" == *"<<'RKA_ROOT_SCRIPT_89C4B517'"* ]]; then
    script_payload=${wire_payload#*"<<'RKA_ROOT_SCRIPT_89C4B517'"$'\n'}
    [[ "$script_payload" != "$wire_payload" ]] || exit 93
    script_payload=${script_payload%%$'\n'RKA_ROOT_SCRIPT_89C4B517$'\n'*}
    fixed=$(printf '%s\n' "$script_payload" | sed -n '/^set -- /p' | head -1)
    read -r _ _ action sentinel_id _ <<< "$fixed"
    phase=ROOT_AUTHORITATIVE
    samples=2
    [ "$action" != start ] || samples=1
    [ "$action" != stop ] || phase=STOPPED
    printf 'sentinel_id=%s action=%s phase=%s samples=%s\n' "$sentinel_id" "$action" "$phase" "$samples"
    printf '%s shell su 0 sh %s\n' "$serial" "${fixed#set -- }" >> "$RKA_FAKE_LOG"
    exit 0
fi
[[ "$wire_payload" != exec\ 3\<\<* ]] || exit 93
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
if [ "$mode" = deploy ] && [ "${RKA_FAKE_CORRUPT_ARCHIVE_SERIAL:-}" = "$serial" ]; then
    printf 'corrupt\n' >> "$root/data/adb/teesimulator-rka/upload/role-neutral-release.zip"
fi
if [ "$mode" = deploy ] && [ "${RKA_FAKE_CORRUPT_SOURCE_SERIAL:-}" = "$serial" ]; then
    printf '%040d\n' 0 > "$root/data/adb/teesimulator-rka/upload/role-neutral-release.zip.source-sha"
fi

mkdir -p "$root"/{data/adb/modules,data/adb/modules_update,data/adb/teesimulator-rka,data/adb/ksu/bin,data/local/tmp,data/system,dev,etc,proc,shim,tmp,usr,bin,lib,lib64,run}
chmod 700 "$root/data/adb/teesimulator-rka"
if [ "${RKA_FAKE_FIRST_INSTALL:-false}" = true ] && [ ! -e "$root/data/adb/modules/tricky_store" ] && [ ! -e "$root/data/adb/modules_update/tricky_store" ]; then
    rm -rf "$root/data/adb/modules" "$root/data/adb/modules_update"
    case "${RKA_FAKE_NEXT_MUTATION:-}" in
        layout-one-parent) mkdir -p "$root/data/adb/modules" ;;
        layout-target-file) mkdir -p "$root/data/adb/modules" "$root/data/adb/modules_update"; printf malformed > "$root/data/adb/modules/tricky_store" ;;
        layout-file) : > "$root/data/adb/modules" ;;
        layout-symlink) ln -s /data/adb/elsewhere "$root/data/adb/modules" ;;
        layout-hidden-mount) : > "$root/data/adb/teesimulator-rka/.bound" ;;
    esac
    case "${RKA_FAKE_FIRST_INSTALL_PARENTS:-absent}" in
        empty) mkdir -p "$root/data/adb/modules" "$root/data/adb/modules_update" ;;
        mixed)
            mkdir -p "$root/data/adb/modules" "$root/data/adb/modules_update"
            if [ "$serial" = CANDIDATE_B ]; then : > "$root/data/adb/modules/unrelated"; fi
            ;;
    esac
fi
if [ "${RKA_FAKE_KSU_PROFILE:-legacy}" = ksu-next-dual ] && [ "${RKA_FAKE_FIRST_INSTALL:-false}" != true ] && [ ! -e "$root/data/adb/modules/tricky_store/module.prop" ]; then
    mkdir -p "$root/data/adb/modules/tricky_store"
    printf 'id=tricky_store\nversion=prior\n' > "$root/data/adb/modules/tricky_store/module.prop"
    chmod 644 "$root/data/adb/modules/tricky_store/module.prop"
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
set_perm() {
  [ "${RKA_FAKE_KSU_MODE_MUTATION:-}" != customize-failure ] || return 1
  chown "$2:$3" "$1" || return 1
  chmod "$4" "$1" || return 1
}
set_perm_recursive() {
  find "$1" -type d -exec chmod "$4" {} + || return 1
  find "$1" -type f -exec chmod "$5" {} + || return 1
}
abort() { exit 1; }
case "${1-} ${2-}" in
  "--version ") printf "%s\n" "3.2.5-12-g824f2f23 (uapi: 2)" ;;
  "module --help"|"sepolicy --help"|"sepolicy check"|"sepolicy apply") exit 0 ;;
  "module install")
    if [ "${RKA_FAKE_FAULT:-}" = install-only-modules-parent ]; then mkdir -p /data/adb/modules; exit 1; fi
    if [ "${RKA_FAKE_FAULT:-}" = install-only-update-parent ]; then mkdir -p /data/adb/modules_update; exit 1; fi
    rm -rf /data/adb/modules_update/tricky_store
    mkdir -p /data/adb/modules_update/tricky_store
    /usr/bin/unzip -q "$3" -d /data/adb/modules_update/tricky_store
    set_perm_recursive /data/adb/modules_update/tricky_store 0 0 0755 0644 || exit 1
    if [ -f /data/adb/modules_update/tricky_store/customize.sh ]; then
      MODPATH=/data/adb/modules_update/tricky_store
      . "$MODPATH/customize.sh" || exit 1
      rm -f "$MODPATH/customize.sh"
    fi
    ;;
  *) exit 1 ;;
esac'
if [ "${RKA_FAKE_KSU_PROFILE:-legacy}" = ksu-next-dual ]; then
cat > "$root/data/adb/ksud" <<'EOF'
#!/bin/sh
set_perm() {
  [ "${RKA_FAKE_KSU_MODE_MUTATION:-}" != customize-failure ] || return 1
  chown "$2:$3" "$1" || return 1
  chmod "$4" "$1" || return 1
}
set_perm_recursive() {
  find "$1" -type d -exec chmod "$4" {} + || return 1
  find "$1" -type f -exec chmod "$5" {} + || return 1
}
abort() { exit 1; }
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
    /usr/bin/unzip -q "$3" -d /data/adb/modules_update/tricky_store -x 'META-INF/*'
    set_perm_recursive /data/adb/modules_update/tricky_store 0 0 0755 0644 || exit 1
    if [ "${RKA_FAKE_KSU_MODE_MUTATION:-}" = customize-missing ]; then
      rm -f /data/adb/modules_update/tricky_store/customize.sh
    elif [ -f /data/adb/modules_update/tricky_store/customize.sh ]; then
      MODPATH=/data/adb/modules_update/tricky_store
      . "$MODPATH/customize.sh" || exit 1
      rm -f "$MODPATH/customize.sh"
    fi
    case "${RKA_FAKE_KSU_MODE_MUTATION:-}" in
      executable-mode) chmod 0644 /data/adb/modules_update/tricky_store/rka-control.sh ;;
      ordinary-mode) chmod 0755 /data/adb/modules_update/tricky_store/module.prop ;;
      directory-mode) chmod 0700 /data/adb/modules_update/tricky_store/webroot ;;
      symlink-type) rm -f /data/adb/modules_update/tricky_store/rka-control.sh; ln -s module.prop /data/adb/modules_update/tricky_store/rka-control.sh ;;
    esac
    if [ "${RKA_FAKE_FIRST_INSTALL:-false}" = true ]; then
      cp /data/adb/modules_update/tricky_store/module.prop /data/adb/modules/tricky_store/module.prop
    fi
    [ -e /data/adb/modules/tricky_store/update ] || : > /data/adb/modules/tricky_store/update
    case "${RKA_FAKE_NEXT_MUTATION:-}" in
      active-missing-module-prop) rm -f /data/adb/modules/tricky_store/module.prop ;;
      active-corrupt-module-prop) printf corrupt >> /data/adb/modules/tricky_store/module.prop ;;
      active-extra) : > /data/adb/modules/tricky_store/unexpected ;;
      active-module-prop-symlink) rm -f /data/adb/modules/tricky_store/module.prop; ln -s /data/adb/modules_update/tricky_store/module.prop /data/adb/modules/tricky_store/module.prop ;;
      active-missing-update) rm -f /data/adb/modules/tricky_store/update ;;
      active-update-symlink) rm -f /data/adb/modules/tricky_store/update; ln -s /data/adb/modules_update/tricky_store/module.prop /data/adb/modules/tricky_store/update ;;
      active-update-nonempty) printf marker > /data/adb/modules/tricky_store/update ;;
    esac ;;
  *) exit 1 ;;
esac
EOF
    chmod 755 "$root/data/adb/ksud"
    ln -sfn /data/adb/ksud "$root/data/adb/ksu/bin/ksud"
fi
write_shim sha256sum '
if [ "${RKA_FAKE_PACKAGE_RUNTIME:-}" = true ] && [ "${RKA_FAKE_REMOTE_MODE:-}" = manager-probe ]; then
  case "${1-}" in
    /data/adb/teesimulator-rka/probes/*.manager-appid)
      digest_line=$(/usr/bin/sha256sum "$1") || exit 1
      digest=${digest_line%% *}
      cat > "$1" <<PROBE
#!/bin/sh
case "\${RKA_FAKE_SERIAL:-}" in DONOR_A) printf "10123\\n" ;; CANDIDATE_B) printf "10124\\n" ;; *) exit 2 ;; esac
PROBE
      chmod 700 "$1"
      printf "%s  %s\\n" "$digest" "$1"
      exit 0 ;;
  esac
fi
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
if [ "${1-} ${2-}" = "package resolve-activity" ]; then
  if [ "${RKA_FAKE_KSU_PROFILE:-legacy}" = ksu-next-dual ]; then
    case "${RKA_FAKE_NEXT_MUTATION:-}" in
      component-wrong) exit 0 ;;
      activity-wrong) printf "%s\n" com.rifsxd.ksunext/.ui.OtherActivity ;;
      *) printf "%s\n" com.rifsxd.ksunext/.ui.MainActivity ;;
    esac
  else
    printf "%s\n" me.weishu.kernelsu/.ui.MainActivity
  fi
  exit 0
fi
if [ "${1-} ${2-} ${3-} ${4-} ${5-} ${6-}" = "package list packages -U --user 0" ]; then
  [ "$#" -eq 7 ] || exit 2
  case "${RKA_FAKE_SERIAL:-}:${7-}" in
    DONOR_A:com.rifsxd.ksunext) printf "package:com.rifsxd.ksunext uid:10123\n" ;;
    CANDIDATE_B:org.example.headless)
      case "${RKA_FAKE_NEXT_MUTATION:-}" in
        uid-source-zero) exit 0 ;;
        uid-source-multiple) printf "package:org.example.headless uid:10124\npackage:org.example.second uid:10124\n" ;;
        uid-source-wrong-modulo|uid-mismatch) printf "package:org.example.headless uid:10125\n" ;;
        uid-source-malformed) printf "package:org.example.headless uid:not-a-uid\n" ;;
        uid-source-extra) printf "package:org.example.headless uid:10124 extra\n" ;;
        uid-source-whitespace) printf " package:org.example.headless uid:10124\n" ;;
        uid-source-metachar) printf "%s\n" "package:org.example.\$(touch /tmp/rka-manager-uid-executed) uid:10124" ;;
        uid-source-mismatch) printf "package:org.example.other uid:10124\n" ;;
        *) printf "package:org.example.headless uid:10124\n" ;;
      esac ;;
    *) exit 2 ;;
  esac
  exit 0
fi
exit 2'
write_shim dumpsys '
if [ "${1-} ${2-}" = "package com.rifsxd.ksunext" ]; then
  package_uid=10123
  printf "%s\n" "versionName=v3.3.0" "versionCode=33214"
  if [ "${RKA_FAKE_NEXT_MUTATION:-}" = legacy-userid ]; then printf "  userId=%s\n" "$package_uid"; else printf "  appId=%s\n" "$package_uid"; fi
  [ "${RKA_FAKE_NEXT_MUTATION:-}" = signing-wrong ] || printf "%s\n" "  signingDetails=SigningDetails{fixture-donor}"
  exit 0
fi
if [ "${1-} ${2-}" = "package org.example.headless" ]; then
  printf "%s\n" "versionName=fixture" "versionCode=1"
  if [ "${RKA_FAKE_NEXT_MUTATION:-}" = legacy-userid ]; then printf "  userId=10124\n"; else printf "  appId=10124\n"; fi
  printf "%s\n" "  signingDetails=SigningDetails{fixture-candidate}"
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
  DONOR_A) endpoint=192.168.50.9; interface=wlan0 ;;
  *) endpoint=100.88.0.2; interface=tun0 ;;
esac
case "${RKA_FAKE_IP_MODE:-}" in
  donor-wlan-candidate-tun)
    if [ "$RKA_FAKE_SERIAL" = DONOR_A ]; then
      printf "7: wlan0    inet 192.168.50.9/24 scope global wlan0\\n"
    else
      printf "7: tun0    inet 100.88.0.2/32 scope global tun0\\n"
    fi
    ;;
  network-side-swap)
    if [ "$RKA_FAKE_SERIAL" = DONOR_A ]; then
      printf "7: tun0    inet 100.88.0.1/32 scope global tun0\\n"
    else
      printf "7: wlan0    inet 192.168.50.10/24 scope global wlan0\\n"
    fi
    ;;
  suffix) printf "7: %s@if8    inet %s/32 scope global %s\\n" "$interface" "$endpoint" "$interface" ;;
  multiple) printf "7: tun0    inet %s/32 scope global tun0\\n8: tun1    inet 100.88.0.3/32 scope global tun1\\n" "$endpoint" ;;
  special) printf "7: tun0    inet 127.0.0.1/32 scope global tun0\\n" ;;
  unspecified) printf "7: tun0    inet 0.0.0.0/32 scope global tun0\\n" ;;
  link-local) printf "7: tun0    inet 169.254.1.2/16 scope global tun0\\n" ;;
  multicast) printf "7: tun0    inet 224.0.0.1/32 scope global tun0\\n" ;;
  broadcast) printf "7: tun0    inet 255.255.255.255/32 scope global tun0\\n" ;;
  whitespace) printf "7: tun0    inet %s /32 scope global tun0\\n" "$endpoint" ;;
  malformed) printf "7: tun0    inet %s/32;touch /tmp/rka-network-pwn scope global tun0\\n" "$endpoint" ;;
  *) printf "7: %s    inet %s/32 scope global %s\\n" "$interface" "$endpoint" "$interface" ;;
esac'
write_shim ping 'exit 0'
write_shim logcat 'exit 0'
write_shim strings 'exit 1'
write_shim toybox '
if [ "${1-}" = touch ]; then shift; exec /usr/bin/touch "$@"; fi
exit 0'
write_shim unzip '
if [ "${RKA_FAKE_NEXT_MUTATION:-}" = busybox-unzip ]; then
  case "${1-}" in
    -Z*) printf "unzip: invalid option -- Z\\n" >&2; exit 2 ;;
  esac
fi
exec /usr/bin/unzip "$@"'
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
  /data/adb/teesimulator-rka/trust/transport-self.pem)
    if [ "${1-}" = -c ] && [ "${2-}" = %u:%a ]; then printf "0:600\n"; exit 0; fi ;;
  /data/adb/modules/tricky_store/module.prop|/data/adb/modules_update/tricky_store/module.prop)
    if [ -f /data/adb/teesimulator-rka/.bound ] && [ "${RKA_NSENTER:-}" = 1 ] && [ "$last" = /data/adb/modules/tricky_store/module.prop ]; then
      exec /usr/bin/stat -c %d:%i /data/adb/modules_update/tricky_store/module.prop
    fi
    if [ "${1-}" = -c ] && [ "${2-}" = %u:%g:%a ]; then
      if [ "$last" = /data/adb/modules_update/tricky_store/module.prop ]; then
        printf "0:0:%s\n" "$(/usr/bin/stat -c %a "$last")"
      else
        printf "0:0:644\n"
      fi
      exit 0
    fi ;;
  /data/adb/modules/tricky_store/update)
    if [ "${1-}" = -c ] && [ "${2-}" = %u:%g:%a ]; then
      case "${RKA_FAKE_NEXT_MUTATION:-}" in
        active-update-wrong-owner) printf "1000:0:644\n" ;;
        active-update-wrong-group) printf "0:1000:644\n" ;;
        active-update-unsafe-mode) printf "0:0:666\n" ;;
        *) printf "0:0:644\n" ;;
      esac
      exit 0
    fi ;;
  /data/adb/modules/tricky_store)
    if [ ! -f /data/adb/teesimulator-rka/.bound ] && [ "$(cat /data/adb/teesimulator-rka/run/supervisor.state 2>/dev/null)" = STOPPED ]; then
      if [ "${RKA_FAKE_FAULT:-}" = active-hash ]; then exit 1; fi
      if [ "${RKA_FAKE_FAULT:-}" = active-metadata ]; then
        if [ -f /data/adb/teesimulator-rka/.active-hash-complete ]; then exit 1; fi
        : > /data/adb/teesimulator-rka/.active-hash-complete
      fi
    fi ;;
  /data/adb/modules_update/tricky_store|/data/adb/modules_update/tricky_store/*)
    if [ "${1-}" = -c ] && [ "${2-}" = %u:%g:%a ]; then
      installed_mode=$(/usr/bin/stat -c %a "$last") || exit 1
      if [ "${RKA_FAKE_KSU_MODE_MUTATION:-}" = wrong-owner ] && [ "$last" = /data/adb/modules_update/tricky_store/rka-control.sh ]; then
        printf "1000:0:%s\n" "$installed_mode"
      else
        printf "0:0:%s\n" "$installed_mode"
      fi
      exit 0
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
write_shim mv '
source_path=
for value in "$@"; do
  case "$value" in /data/adb/teesimulator-rka/*/.rka-adb-upload.*) source_path=$value ;; esac
done
if [ "${RKA_FAKE_UPLOAD_FAULT:-}" = remote-nonzero ] && [ -n "$source_path" ]; then exit 1; fi
exec /usr/bin/mv "$@"'
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
if [ "${RKA_FAKE_PACKAGE_RUNTIME:-}" = true ]; then
  case "${1-}:${2-}" in
    */rka-control.sh:set-role)
      : > /data/adb/teesimulator-rka/.package-set-role-executed
      "$@" || exit 1
      exit 0 ;;
    */rka-sidecar:direct-identity)
      mkdir -p "$RKA_STATE_ROOT/secrets" "$RKA_STATE_ROOT/trust"
      cp "/tls-fixture/$RKA_FAKE_SERIAL/server.key" "$RKA_STATE_ROOT/secrets/transport.key"
      cp "/tls-fixture/$RKA_FAKE_SERIAL/server.pem" "$RKA_STATE_ROOT/trust/transport-self.pem"
      cp "/tls-fixture/$RKA_FAKE_SERIAL/server.pem" "$RKA_STATE_ROOT/trust/transport-trust.pem"
      cp "/tls-fixture/$RKA_FAKE_SERIAL/server.pin" "$RKA_STATE_ROOT/trust/transport.pin"
      printf "version=1\\nspki_sha256=%s\\n" "$(cat "/tls-fixture/$RKA_FAKE_SERIAL/server.pin")" > "$RKA_STATE_ROOT/trust/transport-identity.commit"
      chmod 600 "$RKA_STATE_ROOT/secrets/transport.key" "$RKA_STATE_ROOT/trust/transport-self.pem" "$RKA_STATE_ROOT/trust/transport-trust.pem" "$RKA_STATE_ROOT/trust/transport.pin" "$RKA_STATE_ROOT/trust/transport-identity.commit"
      printf "RESULT=IDENTITY spki_sha256=%s\\n" "$(cat "$RKA_STATE_ROOT/trust/transport.pin")"
      exit 0 ;;
    */rka-sidecar:direct-probe)
      profile_digest=$(/usr/bin/sha256sum "$RKA_PROFILE_PATH")
      profile_sha=${profile_digest%% *}
      epoch=$(/usr/bin/sed -n "3s/^profile_epoch=//p" "$RKA_PROFILE_PATH")
      pin=$(/usr/bin/sed -n "7s/^peer_spki_sha256=//p" "$RKA_PROFILE_PATH")
      pin_digest=$(printf %s "$pin" | /usr/bin/xxd -r -p | /usr/bin/sha256sum)
      pin_sha=${pin_digest%% *}
      printf "version=1\\nprotocol=TLSv1.3\\nprofile_sha256=%s\\nprofile_epoch=%s\\npeer_pin_sha256=%s\\ndial_mode=DONOR_DIALS\\ntransport=DIRECT\\n" "$profile_sha" "$epoch" "$pin_sha" > "$RKA_DIRECT_PROBE_RECEIPT_PATH"
      chmod 600 "$RKA_DIRECT_PROBE_RECEIPT_PATH"
      printf "RESULT=DIRECT protocol=TLSv1.3 profile_sha256=%s\\n" "$profile_sha"
      exit 0 ;;
    */rka-supervisor.sh:start)
      mkdir -p /data/adb/teesimulator-rka/run/pids
      printf "RUNNING\\n" > /data/adb/teesimulator-rka/run/supervisor.state
      printf "401 401 1\\n" > /data/adb/teesimulator-rka/run/pids/broker.pid
      printf "501 501 1\\n" > /data/adb/teesimulator-rka/run/pids/sidecar.pid
      exit 0 ;;
    */rka-supervisor.sh:stop)
      rm -rf /data/adb/teesimulator-rka/run/pids
      mkdir -p /data/adb/teesimulator-rka/run
      printf "STOPPED\\n" > /data/adb/teesimulator-rka/run/supervisor.state
      exit 0 ;;
    */rka-supervisor.sh:status)
      current=$(cat /data/adb/teesimulator-rka/run/supervisor.state 2>/dev/null || printf STOPPED)
      printf "state=%s\\nlegacy=STOPPED\\n" "$current"
      if [ -d /data/adb/teesimulator-rka/run/pids ]; then printf "broker=RUNNING\\nsidecar=RUNNING\\n"; else printf "broker=STOPPED\\nsidecar=STOPPED\\n"; fi
      exit 0 ;;
  esac
fi
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
        if [ "${RKA_FAKE_NEXT_MUTATION:-}" = appid-missing ]; then package_uid=10125; else package_uid=10124; fi
        printf 'org.example.headless %s 0 /data/user/0/org.example.headless default:targetSdkVersion=36 none 0 0 1\n' "$package_uid" > "$root/data/system/packages.list"
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

if [ "${RKA_FAKE_UPLOAD_FAULT:-}" = symlink-parent ] && [[ "$wire_payload" = *'/data/local/tmp/rka-adb-upload-'* ]]; then
    rm -rf "$root/data/adb/teesimulator-rka/probes"
    ln -s /tmp "$root/data/adb/teesimulator-rka/probes"
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
    --setenv RKA_FAKE_UPLOAD_FAULT "${RKA_FAKE_UPLOAD_FAULT:-}" \
    --setenv RKA_FAKE_KSU_MODE_MUTATION "${RKA_FAKE_KSU_MODE_MUTATION:-}" \
    --setenv RKA_FAKE_PACKAGE_RUNTIME "${RKA_FAKE_PACKAGE_RUNTIME:-false}" \
    --setenv RKA_FAKE_REMOTE_MODE "$mode" \
    /bin/sh
