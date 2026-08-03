from __future__ import annotations

import os
from pathlib import Path
from subprocess import run
from tempfile import TemporaryDirectory
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PROBE_SCRIPT = REPOSITORY_ROOT / "scripts" / "rka-probe-synthetic-lease.sh"


class RkaSyntheticLeaseProbeTest(unittest.TestCase):
    def test_missing_arguments_fail_before_adb(self) -> None:
        result = run(
            ["bash", str(PROBE_SCRIPT)],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 64)
        self.assertEqual(
            result.stderr,
            "usage: rka-probe-synthetic-lease.sh --adb PATH --serial SERIAL\n",
        )

    def test_only_sanitized_fixed_receipt_crosses_adb(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            fake_adb = temporary / "adb"
            fake_adb.write_text(
                "#!/bin/sh\n"
                "cat >/dev/null\n"
                "printf '%s\\n' "
                "'synthetic_lease_probe_status=READY certificate_count=4 "
                f"spki_sha256={'ab' * 32} chain_sha256={'cd' * 32} "
                "leaf_ca=true leaf_key_cert_sign=true'\n",
                encoding="ascii",
            )
            os.chmod(fake_adb, 0o700)

            result = run(
                [
                    "bash",
                    str(PROBE_SCRIPT),
                    "--adb",
                    str(fake_adb),
                    "--serial",
                    "donor-1",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("synthetic_lease_probe_status=READY", result.stdout)
        self.assertNotIn("PRIVATE", result.stdout.upper())

    def test_script_uses_bounded_root_helper_and_never_reboots(self) -> None:
        source = PROBE_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("rka_adb_root_run", source)
        self.assertIn("synthetic-lease-probe", source)
        self.assertNotIn("reboot", source)
        self.assertNotIn("PRIVATE KEY", source)
        self.assertNotIn("pkcs8", source.lower())


if __name__ == "__main__":
    unittest.main()
