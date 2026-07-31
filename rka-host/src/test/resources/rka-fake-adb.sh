#!/bin/bash
set -euo pipefail

serial=$2
shift 2
printf '%s %s\n' "$serial" "$*" >> "$RKA_FAKE_LOG"
device="$RKA_FAKE_DEVICE_ROOT/$serial"
root="$device/root"

if [ "${1-}" = push ]; then
    mkdir -p "$root${3%/*}"
    cp "$2" "$root$3"
    if [ "${RKA_FAKE_CORRUPT_ARCHIVE_SERIAL:-}" = "$serial" ] && [ "$3" = /data/adb/teesimulator-rka/upload/role-neutral-release.zip ]; then
        printf 'corrupt\n' >> "$root$3"
    fi
    if [ "${RKA_FAKE_CORRUPT_SOURCE_SERIAL:-}" = "$serial" ] && [ "$3" = /data/adb/teesimulator-rka/upload/role-neutral-release.zip.source-sha ]; then
        printf '%040d\n' 0 > "$root$3"
    fi
    exit 0
fi

if [[ " $* " == *" mkdir -p "* ]]; then
    mkdir -p "$root/data/adb/teesimulator-rka/upload"
    exit 0
fi

mode=${7-}
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

mkdir -p "$root"/{data/adb/modules,data/adb/modules_update,data/adb/teesimulator-rka,dev,etc,proc,shim,tmp,usr,bin,lib,lib64,run}
chmod 700 "$root/data/adb/teesimulator-rka"

write_shim() {
    local name=$1
    shift
    printf '%s\n' '#!/bin/sh' "$@" > "$root/shim/$name"
    chmod 700 "$root/shim/$name"
}

write_shim id 'if [ "${1-}" = -u ]; then printf "0\n"; else /usr/bin/id "$@"; fi'
write_shim ksud '
case "${1-} ${2-}" in
  "--version ") printf "%s\n" "3.2.5-12-g824f2f23 (uapi: 2)" ;;
  "module --help"|"sepolicy --help"|"sepolicy check"|"sepolicy apply") exit 0 ;;
  "module install")
    rm -rf /data/adb/modules_update/tricky_store
    mkdir -p /data/adb/modules_update/tricky_store
    /usr/bin/unzip -q "$3" -d /data/adb/modules_update/tricky_store
    ;;
  *) exit 1 ;;
esac'
write_shim sha256sum '
if [ "${1-}" = /shim/ksud ]; then
  printf "%s  %s\n" a75099ef6dd9eb5f528df2fdf1aaa2eaa080af3df70b6c69216d28778a8c66c9 "$1"
else
  exec /usr/bin/sha256sum "$@"
fi'
write_shim cmd 'printf "%s\n" me.weishu.kernelsu/.ui.MainActivity'
write_shim dumpsys '
if [ "${1-} ${2-}" = "package me.weishu.kernelsu" ]; then
  printf "%s\n" "versionName=v3.2.5-12-g824f2f23" "versionCode=32537"
  exit 0
fi
[ "${1-} ${2-} ${3-}" = "activity -a services" ] || exit 1
client="201:me.weishu.kernelsu/u0a123"
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
    "      * Client AppBindRecord{ggg ProcessRecord{fff 201:me.weishu.kernelsu/u0a123}}"
fi'
write_shim pidof '
case "${1-}" in
  ksud) printf "101\n" ;;
  me.weishu.kernelsu) printf "201\n" ;;
  com.google.android.webview:sandboxed_process0)
    if [ "${RKA_FAKE_WEBUI_OWNER:-}" = ambiguous ]; then printf "301 302\n"; else printf "301\n"; fi ;;
  *) exit 1 ;;
esac'
write_shim ip '
case "$RKA_FAKE_SERIAL" in
  DONOR_A) printf "1: tailscale0 inet 100.64.0.1/32 scope global tailscale0\n" ;;
  *) printf "1: tailscale0 inet 100.64.0.2/32 scope global tailscale0\n" ;;
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
  /proc/201/cmdline) printf "me.weishu.kernelsu\\0" ;;
  /proc/301/cmdline|/proc/302/cmdline) printf "com.google.android.webview:sandboxed_process0\\0" ;;
  *) exec /usr/bin/cat "$@" ;;
esac'
write_shim openssl '
if [ "${1-}" = s_client ]; then
  if [ "${RKA_FAKE_MISMATCH_PIN:-}" = true ]; then
    cat /data/adb/teesimulator-rka/trust/transport-self.pem
    exit 0
  fi
  endpoint=
  while [ $# -gt 0 ]; do
    if [ "$1" = -connect ]; then endpoint=${2%:*}; break; fi
    shift
  done
  case "$endpoint" in
    100.64.0.1) cat /devices/DONOR_A/root/data/adb/teesimulator-rka/trust/transport-self.pem ;;
    100.64.0.2) cat /devices/CANDIDATE_B/root/data/adb/teesimulator-rka/trust/transport-self.pem ;;
    *) exit 1 ;;
  esac
else
  exec /usr/bin/openssl "$@"
fi'

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

shift 7
exec bwrap \
    --bind "$root" / \
    --ro-bind /usr /usr \
    --ro-bind /bin /bin \
    --ro-bind /lib /lib \
    --ro-bind /lib64 /lib64 \
    --ro-bind /etc /etc \
    --ro-bind "$RKA_FAKE_DEVICE_ROOT" /devices \
    --proc /proc \
    --dev /dev \
    --unshare-all \
    --setenv PATH /shim:/usr/bin:/bin \
    --setenv RKA_FAKE_SERIAL "$serial" \
    --setenv RKA_FAKE_MISMATCH_PIN "$([ "${RKA_FAKE_MISMATCH_SERIAL:-}" = "$serial" ] && printf true || printf false)" \
    --setenv RKA_FAKE_FAULT "${RKA_FAKE_FAULT:-}" \
    --setenv RKA_FAKE_WEBUI_OWNER "${RKA_FAKE_WEBUI_OWNER:-}" \
    /bin/sh -s -- "$mode" "$@"
