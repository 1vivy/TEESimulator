import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts/probe-api36.sh"


class ProbeApi36Tests(unittest.TestCase):
    def test_requires_explicit_serial_and_profile(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            fake_adb = Path(temporary_directory) / "adb"
            fake_adb.write_text("#!/usr/bin/env bash\nexit 0\n")
            fake_adb.chmod(0o755)

            completed = subprocess.run(
                [str(PROBE)],
                cwd=ROOT,
                env={**os.environ, "ADB": str(fake_adb)},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("STOP arguments-required", completed.stdout)
        self.assertEqual(json.loads(completed.stdout.splitlines()[-1])["verdict"], "STOP")

    def test_normalizes_enforcing_result_after_serial_scoped_adb_read(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            fake_adb = Path(temporary_directory) / "adb"
            fake_adb.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -s && "$2" == unit-serial && "$3" == shell ]] || exit 91
case "${*:4}" in
  *'getprop ro.build.version.sdk'*) printf '36\\n' ;;
  *'getprop ro.product.cpu.abi'*) printf 'arm64-v8a\\n' ;;
  *getenforce*) printf 'Enforcing\\n' ;;
  *'ro.boot.verifiedbootstate'*) printf 'green\\n' ;;
  *'pidof keystore2'*) printf '999\\n' ;;
  *'stat -c %Y'*) printf '1\\n' ;;
  *sha256sum*) printf '0000000000000000000000000000000000000000000000000000000000000000  maps\\n' ;;
  *'cat /proc/999/attr/current'*) printf 'u:r:keystore:s0\\n' ;;
esac
"""
            )
            fake_adb.chmod(0o755)
            completed = subprocess.run(
                [str(PROBE), "unit-serial", "profiles/api36-arm64-qcom-default-v1.conf"],
                cwd=ROOT,
                env={**os.environ, "ADB": str(fake_adb)},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stderr, "")
        self.assertIn("PASS selinux-enforcing", completed.stdout)
        self.assertNotIn("unit-serial", completed.stdout)
        self.assertEqual(json.loads(completed.stdout.splitlines()[-1])["verdict"], "STOP")

    def test_stops_when_a_direct_dependency_has_no_valid_build_id(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            fake_adb = Path(temporary_directory) / "adb"
            fake_adb.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -s && "$2" == unit-serial && "$3" == shell ]] || exit 91
dependencies=(liblog.so libbinder_ndk.so libc.so libm.so libdl.so libc++.so libcrypto.so libkeystore2_aaid.so libkeystore2_apc_compat.so libkeystore2_crypto.so libhidlbase.so libkm_compat_service.so libselinux.so libsqlite.so)
paths=(/system/lib64/liblog.so /system/lib64/libbinder_ndk.so /apex/com.android.runtime/lib64/bionic/libc.so /apex/com.android.runtime/lib64/bionic/libm.so /apex/com.android.runtime/lib64/bionic/libdl.so /system/lib64/libc++.so /system/lib64/libcrypto.so /system/lib64/libkeystore2_aaid.so /system/lib64/libkeystore2_apc_compat.so /system/lib64/libkeystore2_crypto.so /system/lib64/libhidlbase.so /system/lib64/libkm_compat_service.so /system/lib64/libselinux.so /system/lib64/libsqlite.so)
case "${*:4}" in
  *'getprop ro.build.version.sdk'*) printf '36\\n' ;;
  *'getprop ro.product.cpu.abi'*) printf 'arm64-v8a\\n' ;;
  *getenforce*) printf 'Enforcing\\n' ;;
  *'ro.boot.verifiedbootstate'*) printf 'green\\n' ;;
  *'pidof keystore2'*) printf '999\\n' ;;
  *'stat -c %Y'*) printf '1\\n' ;;
  *sha256sum*) printf '0000000000000000000000000000000000000000000000000000000000000000  maps\\n' ;;
  *'cat /proc/999/attr/current'*) printf 'u:r:keystore:s0\\n' ;;
  *'test -r /proc/999/maps'*) printf 'MAPS_READY'; printf '%s\\n' "${paths[@]}" ;;
  *'/system/bin/readelf -d -n /system/bin/keystore2'*) for dependency in "${dependencies[@]}"; do printf ' Shared library: [%s]\\n' "$dependency"; done; printf ' NT_GNU_BUILD_ID f4683bcbc097021e3085d8a223e5024f\\n' ;;
  *'/system/bin/readelf -d -n /system/lib64/liblog.so'*) printf ' no GNU build ID\\n' ;;
  *'/system/bin/readelf -d -n '*) printf ' NT_GNU_BUILD_ID 11111111111111111111111111111111\\n' ;;
esac
"""
            )
            fake_adb.chmod(0o755)
            completed = subprocess.run(
                [str(PROBE), "unit-serial", "profiles/api36-arm64-qcom-default-v1.conf"],
                cwd=ROOT,
                env={**os.environ, "ADB": str(fake_adb)},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("STOP elf-dependency-chain", completed.stdout)

    def test_passes_portable_elf_dependency_chain_with_32_and_40_hex_build_ids(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            profile = temporary_path / "portable.conf"
            profile.write_text(
                """SDK=36
ABI=arm64-v8a
SELINUX=enforcing
AVB_STATE=green
DEFAULT_INSTANCE=android.hardware.security.keymint.IKeyMintDevice/default
KEYMINT_DEFAULT_AIDL_VARIANTS=3:74a538630d5d90f732f361a2313cbb69b09eb047,4:a05c8079586139db45b0762a528cdd9745ad15ce
KEYSTORE_CONTEXT=u:r:keystore:s0
KERNELSU_DOMAIN=u:r:ksu:s0
MODULE_DIRECTORY=/data/adb/modules/teesimulator_api36_probe
MODULE_CONTEXT=u:object_r:adb_data_file:s0
MODULE_MODE=755
MODULE_OWNER=root:root
KEYSTORE2_DEPENDENCIES=liblog.so,libbinder_ndk.so,libc.so,libm.so,libdl.so,libc++.so,libcrypto.so,libkeystore2_aaid.so,libkeystore2_apc_compat.so,libkeystore2_crypto.so,libhidlbase.so,libkm_compat_service.so,libselinux.so,libsqlite.so
ELF_ALLOWED_PATH_PREFIXES=/system/lib64,/apex/com.android.runtime/lib64/bionic,/apex/com.android.i18n/lib64
"""
            )
            fake_adb = temporary_path / "adb"
            fake_adb.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -s && "$2" == unit-serial && "$3" == shell ]] || exit 91
dependencies=(liblog.so libbinder_ndk.so libc.so libm.so libdl.so libc++.so libcrypto.so libkeystore2_aaid.so libkeystore2_apc_compat.so libkeystore2_crypto.so libhidlbase.so libkm_compat_service.so libselinux.so libsqlite.so)
paths=(/system/lib64/liblog.so /system/lib64/libbinder_ndk.so /apex/com.android.runtime/lib64/bionic/libc.so /apex/com.android.runtime/lib64/bionic/libm.so /apex/com.android.runtime/lib64/bionic/libdl.so /system/lib64/libc++.so /system/lib64/libcrypto.so /system/lib64/libkeystore2_aaid.so /system/lib64/libkeystore2_apc_compat.so /system/lib64/libkeystore2_crypto.so /system/lib64/libhidlbase.so /system/lib64/libkm_compat_service.so /system/lib64/libselinux.so /system/lib64/libsqlite.so)
case "${*:4}" in
  *'getprop ro.build.version.sdk'*) printf '36\\n' ;;
  *'getprop ro.product.cpu.abi'*) printf 'arm64-v8a\\n' ;;
  *getenforce*) printf 'Enforcing\\n' ;;
  *'ro.boot.verifiedbootstate'*) printf 'green\\n' ;;
  *'service list'*) printf 'android.hardware.security.keymint.IKeyMintDevice/default\\n' ;;
  *'pidof keystore2'*) printf '999\\n' ;;
  *'stat -c %Y'*) printf '1\\n' ;;
  *sha256sum*) printf '0000000000000000000000000000000000000000000000000000000000000000  maps\\n' ;;
  *'cat /proc/999/attr/current'*) printf 'u:r:keystore:s0\\n' ;;
  *'cat /proc/999/mountinfo; ls -l /proc/999/fd'*) printf '/dev/binder\\n' ;;
  *'test -r /proc/999/maps'*) printf 'MAPS_READY'; printf '%s\\n' "${paths[@]}" ;;
  *'command -v setprop'*) printf 'TOOLS_READY\\n' ;;
  *'service call android.hardware.security.keymint.IKeyMintDevice/default 16777215'*) printf '00000000 00000003\\n' ;;
  *'service call android.hardware.security.keymint.IKeyMintDevice/default 16777214'*) printf '0x00000000: 00000000 00000000 00340037 00350061 00380033 00330036 00640030 00640035 00300039 00370066 00320033 00330066 00310036 00320061 00310033 00630033 00620062 00390036 00300062 00650039 00300062 00370034 00000000\\n' ;;
  *'/system/bin/readelf -d -n /system/bin/keystore2'*) for dependency in "${dependencies[@]}"; do printf ' Shared library: [%s]\\n' "$dependency"; done; printf ' NT_GNU_BUILD_ID 0123456789abcdef0123456789abcdef\\n' ;;
  *'/system/bin/readelf -d -n /system/lib64/libc++.so'*) printf ' NT_GNU_BUILD_ID 0123456789abcdef0123456789abcdef01234567\\n' ;;
  *'/system/bin/readelf -d -n '*) printf ' NT_GNU_BUILD_ID 0123456789abcdef0123456789abcdef\\n' ;;
  *'id -Z'*) printf 'u:r:ksu:s0\\n' ;;
  *'test -d /data/adb/modules/teesimulator_api36_probe'*) ;;
  *'command -v logcat'*) printf 'AVC_LOG_READY\\n' ;;
esac
"""
            )
            fake_adb.chmod(0o755)
            completed = subprocess.run(
                [str(PROBE), "unit-serial", str(profile)],
                cwd=ROOT,
                env={**os.environ, "ADB": str(fake_adb)},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("PASS stable-aidl-version", completed.stdout)
        self.assertIn("PASS stable-aidl-hash", completed.stdout)
        self.assertIn("PASS elf-dependency-chain", completed.stdout)
        self.assertIn("PASS module-absent-preinstall", completed.stdout)
        self.assertIn("PASS controlled-restart-tools-available", completed.stdout)
        self.assertNotIn("TOOLS_READY\n", completed.stdout)
        self.assertEqual(json.loads(completed.stdout.splitlines()[-1])["verdict"], "PASS")

    def test_stops_when_controlled_restart_tools_are_absent(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            fake_adb = Path(temporary_directory) / "adb"
            fake_adb.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -s && "$2" == unit-serial && "$3" == shell ]] || exit 91
case "${*:4}" in
  *'command -v setprop'*) ;;
esac
"""
            )
            fake_adb.chmod(0o755)
            completed = subprocess.run(
                [str(PROBE), "unit-serial", "profiles/api36-arm64-qcom-default-v1.conf"],
                cwd=ROOT,
                env={**os.environ, "ADB": str(fake_adb)},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("STOP controlled-restart-tools-available", completed.stdout)


if __name__ == "__main__":
    unittest.main()
