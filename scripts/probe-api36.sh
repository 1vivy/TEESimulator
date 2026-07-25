#!/usr/bin/env bash
set -euo pipefail

# Host-only, read-only probe. It does not transfer files, write on the device,
# trace/inject processes, create keys, alter properties, or control services.
ADB=${ADB:-adb}
PROFILE=${PROFILE:-profiles/api36-arm64-qcom-default-v1.conf}
[[ -r "$PROFILE" ]] || { echo "STOP profile-missing"; exit 2; }

pass() { printf 'PASS %s\n' "$1"; }
stop() { printf 'STOP %s\n' "$1"; failed=1; }
shell() { "$ADB" shell "$@" 2>/dev/null | tr -d '\000\r'; }
root_read() { "$ADB" shell su -c "$1" 2>/dev/null | tr -d '\000\r'; }
failed=0

[[ $(shell getprop ro.build.version.sdk) == 36 ]] && pass api-36 || stop api
[[ $(shell getprop ro.product.cpu.abi) == arm64-v8a ]] && pass abi-arm64-v8a || stop abi
[[ $(shell getenforce) == Enforcing ]] && pass selinux-enforcing || stop selinux
[[ $(shell getprop ro.boot.verifiedbootstate) == green ]] && pass avb-green || stop avb

services=$(shell service list)
for instance in \
  android.hardware.security.keymint.IKeyMintDevice/default \
  android.hardware.security.keymint.IKeyMintDevice/strongbox \
  android.hardware.security.keymint.IRemotelyProvisionedComponent/default \
  android.hardware.security.keymint.IRemotelyProvisionedComponent/strongbox \
  android.hardware.security.keymint.IRemotelyProvisionedComponent/avf; do
  grep -Fq "$instance" <<<"$services" && pass "service-$instance" || stop "service-$instance"
done

pid1=$(shell pidof keystore2)
start1=$(root_read "stat -c %Y /proc/$pid1" || true)
maps1=$(root_read "sha256sum /proc/$pid1/maps" | awk '{print $1}' || true)
sleep 1
pid2=$(shell pidof keystore2)
start2=$(root_read "stat -c %Y /proc/$pid2" || true)
maps2=$(root_read "sha256sum /proc/$pid2/maps" | awk '{print $1}' || true)
[[ "$pid1" =~ ^[0-9]+$ && "$pid1" == "$pid2" ]] && pass keystore2-pid-stable || stop keystore2-pid
[[ -n "$start1" && "$start1" == "$start2" ]] && pass keystore2-start-stable || stop keystore2-start
[[ "$maps1" =~ ^[0-9a-f]{64}$ && "$maps1" == "$maps2" ]] && pass keystore2-maps-stable || stop keystore2-maps

context=$(root_read "cat /proc/$pid1/attr/current" || true)
[[ "$context" == "u:r:keystore:s0" ]] && pass keystore2-context || stop keystore2-context
grep -Eq '(^|[[:space:]])binder([[:space:]]|$)|/dev/binder' <<<"$(root_read "cat /proc/$pid1/mountinfo; ls -l /proc/$pid1/fd" || true)" \
  && pass binder-route || stop binder-route

maps=$(root_read "cat /proc/$pid1/maps" || true)
if grep -Eqi 'teesimulator|libinject|tricky.?store|keybox' <<<"$maps"; then
  stop competing-hook
else
  pass no-competing-hook
fi

# Presence is evidence only; this probe never invokes a restart.
if shell su -c 'command -v setprop >/dev/null && command -v start >/dev/null && command -v stop >/dev/null'; then
  pass controlled-restart-tools-available
else
  stop controlled-restart-tools
fi

# Stable AIDL version/hash and ELF build-id collection needs a profile-specific
# read-only helper. Do not guess: absence is a hard compatibility STOP.
stop stable-aidl-version-hash-unimplemented
stop elf-dependencies-build-id-unimplemented
stop selinux-injection-prerequisites-unproven

(( failed == 0 )) && { pass G1; exit 0; }
echo "STOP G1"
exit 1
