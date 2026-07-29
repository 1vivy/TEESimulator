from pathlib import Path
import subprocess
import tempfile
import unittest

from tests.test_g0_guards import GUARDS, ROOT


class PhysicalHarnessProtocolGuardTests(unittest.TestCase):
    def test_protocol_marked_test_sources_reject_raw_binder_and_custody(self) -> None:
        fixtures = (
            (
                "CrossDeviceParcelTest.kt",
                b"import org.matrix.teesimulator.twophone.WireDonorBackend\n"
                b"import android.os.Parcel\n",
                "raw-binder-cross-device-protocol",
            ),
            (
                "CrossDeviceIBinderTest.kt",
                b"import org.matrix.teesimulator.twophone.WireDonorBackend\n"
                b"import android.os.IBinder\n",
                "raw-binder-cross-device-protocol",
            ),
            (
                "CrossDevicePrivateKeyTest.kt",
                b"import org.matrix.teesimulator.twophone.WireDonorBackend\n"
                b"val privateKey = \"forbidden\"\n",
                "target-protocol-custody",
            ),
            (
                "CrossDeviceDonorAliasTest.kt",
                b"import org.matrix.teesimulator.twophone.WireDonorBackend\n"
                b"val donorAlias = \"forbidden\"\n",
                "target-protocol-custody",
            ),
        )
        for filename, payload, label in fixtures:
            with self.subTest(filename=filename):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    source_root = Path(temporary_directory)
                    fixture = (
                        source_root
                        / "physical-harness/src/test/kotlin/org/matrix/teesimulator/physicalharness"
                        / filename
                    )
                    fixture.parent.mkdir(parents=True)
                    fixture.write_bytes(payload)

                    # Given: a protocol-marked test source. When: G0 scans it. Then: named rejection.
                    completed = subprocess.run(
                        [str(GUARDS), "source", str(source_root)],
                        capture_output=True,
                        check=False,
                        cwd=ROOT,
                        text=True,
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertEqual(completed.stderr, f"FAIL {label}\n")
