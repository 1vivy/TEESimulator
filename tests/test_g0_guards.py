from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
GUARDS = ROOT / "scripts/g0-guards.sh"
VERIFY = ROOT / "scripts/verify.sh"


@dataclass(frozen=True, slots=True)
class SourceFixture:
    relative_path: str
    payload: bytes
    label: str


@dataclass(frozen=True, slots=True)
class PackageFixture:
    member_name: str
    label: str


class G0GuardTests(unittest.TestCase):
    def run_source_guard(self, source_root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(GUARDS), "source", str(source_root)],
            capture_output=True,
            check=False,
            cwd=ROOT,
            text=True,
        )

    def run_package_guard(self, package: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(GUARDS), "package", str(package)],
            capture_output=True,
            check=False,
            cwd=ROOT,
            text=True,
        )

    def assert_source_rejected(self, fixture: SourceFixture) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            source_root = Path(temporary_directory)
            source_path = source_root / fixture.relative_path
            source_path.parent.mkdir(parents=True)
            source_path.write_bytes(fixture.payload)

            # Given: one isolated source fixture. When: G0 scans it. Then: named rejection.
            completed = self.run_source_guard(source_root)
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(completed.stderr, f"FAIL {fixture.label}\n")

    def assert_package_rejected(self, fixture: PackageFixture) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            package = Path(temporary_directory) / "fixture.zip"
            with ZipFile(package, "w", compression=ZIP_DEFLATED) as archive:
                archive.writestr(fixture.member_name, b"fixture")

            # Given: one isolated ZIP fixture. When: G0 scans it. Then: named rejection.
            completed = self.run_package_guard(package)
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(completed.stderr, f"FAIL {fixture.label}\n")

    def test_g0_source_guard_accepts_clean_production_sources(self) -> None:
        # Given: the production tree. When: G0 scans sources. Then: it passes.
        completed = self.run_source_guard(ROOT)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "PASS g0-source-guards\n")

    def test_g0_source_guard_rejects_every_forbidden_source_fixture(self) -> None:
        fixtures = (
            SourceFixture("module/keybox.xml", b"fixture", "bundled-keybox"),
            SourceFixture(
                "module/private.txt",
                b"-----BEGIN EC PRIVATE KEY-----",
                "secret-or-forbidden-rkp",
            ),
            SourceFixture(
                "profiles/rkp.txt",
                b"remote_provisioning csr",
                "secret-or-forbidden-rkp",
            ),
            SourceFixture(
                "scripts/device\nidentifier.sh",
                b"ro." b"serialno\n",
                "device-identifier-collection",
            ),
            SourceFixture(
                "two-phone/raw\nbinder.kt",
                b"android.os.Parcel.obtain()\x00",
                "raw-binder-cross-device-protocol",
            ),
            SourceFixture(
                "two-phone/src/main/kotlin/org/matrix/teesimulator/twophone/Protocol.kt",
                b"privateKey",
                "target-protocol-custody",
            ),
            SourceFixture(
                "two-phone/src/main/kotlin/org/matrix/teesimulator/twophone/Routing.kt",
                b"donorAlias",
                "target-protocol-custody",
            ),
            SourceFixture(
                "physical-harness/src/main/kotlin/PrivateMaterial.kt",
                b"-----BEGIN EC PRIVATE KEY-----",
                "secret-or-forbidden-rkp",
            ),
            SourceFixture(
                "physical-harness/src/main/resources/keybox.xml",
                b"<Keybox />",
                "secret-or-forbidden-rkp",
            ),
            SourceFixture(
                "physical-harness/src/main/kotlin/RemoteProvisioning.kt",
                b"remote_provisioning certify",
                "secret-or-forbidden-rkp",
            ),
            SourceFixture(
                "physical-harness/src/main/kotlin/DeviceIdentifier.kt",
                b"ro." b"serialno\n",
                "device-identifier-collection",
            ),
            SourceFixture(
                "physical-harness/src/main/kotlin/CrossDeviceParcel.kt",
                b"import org.matrix.teesimulator.twophone.WireDonorBackend\n"
                b"import android.os.Parcel\n",
                "raw-binder-cross-device-protocol",
            ),
            SourceFixture(
                "physical-harness/src/main/kotlin/CrossDeviceCustody.kt",
                b"import org.matrix.teesimulator.twophone.WireDonorBackend\n"
                b"val privateKey = \"forbidden\"\n",
                "target-protocol-custody",
            ),
            SourceFixture(
                "signing/fixture-signer.p12",
                b"opaque PKCS12 fixture signing material",
                "committed-signing-material",
            ),
        )
        for fixture in fixtures:
            with self.subTest(path=fixture.relative_path):
                self.assert_source_rejected(fixture)

    def test_g0_package_guard_rejects_forbidden_and_malformed_members(self) -> None:
        fixtures = (
            PackageFixture("keybox.xml", "unsafe-package-content"),
            PackageFixture("nested/target.txt", "unsafe-package-content"),
            PackageFixture("nested/sepolicy.rule", "unsafe-package-content"),
            PackageFixture("nested/\nkeybox.xml", "unsafe-package-content"),
        )
        for fixture in fixtures:
            with self.subTest(member=fixture.member_name):
                self.assert_package_rejected(fixture)

    def test_g0_package_guard_rejects_invalid_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            package = Path(temporary_directory) / "not-a-zip.bin"
            package.write_bytes(b"not a zip\x00")

            # Given: malformed binary package input. When: G0 scans it. Then: named rejection.
            completed = self.run_package_guard(package)
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(completed.stderr, "FAIL invalid-package-input\n")

    def test_g0_source_guard_allows_android_service_binder_outside_wire_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            source_root = Path(temporary_directory)
            service = source_root / "physical-harness/src/main/kotlin/DonorService.kt"
            service.parent.mkdir(parents=True)
            service.write_bytes(b"import android.os.IBinder\n")

            # Given: Android lifecycle Binder only. When: G0 scans it. Then: it passes.
            completed = self.run_source_guard(source_root)
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "PASS g0-source-guards\n")

    def test_g0_source_guard_allows_local_tls_private_key_with_public_pin_utility(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            source_root = Path(temporary_directory)
            tls_identity = (
                source_root
                / "physical-harness/src/main/kotlin/PinnedJsseServerContext.kt"
            )
            tls_identity.parent.mkdir(parents=True)
            tls_identity.write_bytes(
                b"import org.matrix.teesimulator.twophone.SpkiPin\n"
                b"val privateKey = \"local-only\"\n"
            )

            # Given: local TLS identity code using a public pin utility. When: G0 scans it. Then: it passes.
            completed = self.run_source_guard(source_root)
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, "PASS g0-source-guards\n")

    def test_g0_source_guard_rejects_custody_tokens_in_wire_named_source(self) -> None:
        fixture = SourceFixture(
            "physical-harness/src/main/kotlin/WireProtocolSurface.kt",
            b"import org.matrix.teesimulator.twophone.WireDonorBackend\n"
            b"val privateKey = \"forbidden\"\nval donorAlias = \"forbidden\"\n",
            "target-protocol-custody",
        )

        # Given: a wire-named source. When: it carries custody tokens. Then: G0 rejects it.
        self.assert_source_rejected(fixture)

    def test_verify_gates_all_physical_harness_unit_variants(self) -> None:
        gradle_tasks = re.findall(r":physical-harness:[A-Za-z]+", VERIFY.read_text())
        self.assertIn(":physical-harness:test", gradle_tasks)
        self.assertNotIn(":physical-harness:testDebugUnitTest", gradle_tasks)

    def test_project_listing_detection_consumes_large_early_match_without_sigpipe(self) -> None:
        producer = (
            "printf '%s\\n' ':rka-fixture'; "
            "for index in $(seq 1 4096); do printf 'project-%s\\n' \"$index\"; done"
        )
        command = f'{{ {producer}; }} | "$1" project-list-has ":rka-fixture"'

        # Given: an early project match followed by large output. When: G0 tests it. Then: no SIGPIPE.
        completed = subprocess.run(
            ["bash", "-o", "pipefail", "-c", command, "g0-guard-pipe", str(GUARDS)],
            capture_output=True,
            check=False,
            cwd=ROOT,
            text=True,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")

    def test_native_bridge_cmake_does_not_publish_local_binder_or_utils_under_platform_names(
        self,
    ) -> None:
        cmake = (ROOT / "app/src/main/cpp/CMakeLists.txt").read_text()

        self.assertNotIn("add_library(utils ", cmake)
        self.assertNotIn("add_library(binder ", cmake)

    def test_native_bridge_cmake_allows_runtime_platform_binder_resolution(self) -> None:
        cmake = (ROOT / "app/src/main/cpp/CMakeLists.txt").read_text()

        self.assertIn("external/AOSP/android16/include_platform", cmake)
        self.assertIn("binder_ndk", cmake)
        self.assertIn("--allow-shlib-undefined", cmake)

    def test_native_bridge_refbase_stub_has_live_reference_accounting(self) -> None:
        stub = (ROOT / "app/src/main/cpp/stub/stub_utils.cpp").read_text()

        self.assertNotIn("void RefBase::incStrong(const void *id) const {}", stub)
        self.assertNotIn("void RefBase::decStrong(const void *id) const {}", stub)
        self.assertNotIn("return nullptr;", stub.split("RefBase::createWeak", 1)[1].split("}", 1)[0])
        self.assertNotIn("return nullptr;", stub.split("RefBase::getWeakRefs", 1)[1].split("}", 1)[0])
        self.assertNotIn("return false;", stub.split("attemptIncStrong", 1)[1].split("}", 1)[0])
        self.assertNotIn("return false;", stub.split("attemptIncWeak", 1)[1].split("}", 1)[0])
