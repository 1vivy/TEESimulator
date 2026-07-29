from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from tests.test_g0_guards import GUARDS, ROOT


class TargetProtocolCustodyGuardTests(unittest.TestCase):
    def assert_source_rejected(self, relative_path: Path, payload: bytes) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            source_root = Path(temporary_directory)
            source_path = source_root / relative_path
            source_path.parent.mkdir(parents=True)
            source_path.write_bytes(payload)

            completed = subprocess.run(
                [str(GUARDS), "source", str(source_root)],
                capture_output=True,
                check=False,
                cwd=ROOT,
                text=True,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(completed.stderr, "FAIL target-protocol-custody\n")

    def test_custody_rejects_every_two_phone_main_source_regardless_of_filename(self) -> None:
        source_root = ROOT / "two-phone/src/main"
        source_paths = tuple(sorted(source_root.rglob("*.kt")))
        source_names = {source_path.name for source_path in source_paths}
        required_names = {
            "BoundedWireFrameIo.kt",
            "InMemoryWireDonorBackend.kt",
            "Donor.kt",
            "DonorTransportHelloCodec.kt",
            "PublicProfileCodec.kt",
            "TargetResponseCorrelator.kt",
            "TransportStreamReads.kt",
        }
        self.assertTrue(required_names <= source_names)

        for source_path in source_paths:
            with self.subTest(source=source_path.name):
                self.assert_source_rejected(
                    source_path.relative_to(ROOT),
                    b"val privateKey = \"forbidden\"\nval donorAlias = \"forbidden\"\n",
                )

    def test_custody_rejects_semantically_equivalent_kotlin_package_references(self) -> None:
        references = (
            b"import org.matrix.teesimulator.twophone.*\n",
            b"import org.matrix.teesimulator.twophone.WireDonorBackend.Nested\n",
            b"val protocol = org.matrix.teesimulator.twophone.PublicProfileCodec\n",
            b" \timport \torg.matrix.teesimulator.twophone.Donor\n",
            b"import org.matrix.teesimulator.twophone.TargetResponseCorrelator;\n",
            b"import org.matrix.teesimulator.twophone.TransportStreamReads as Streams\n",
        )
        relative_path = Path(
            "physical-harness/src/main/kotlin/org/matrix/teesimulator/physicalharness/"
            "ProtocolReference.kt"
        )

        for reference in references:
            with self.subTest(reference=reference):
                self.assert_source_rejected(
                    relative_path,
                    reference
                    + b"val privateKey = \"forbidden\"\nval donorAlias = \"forbidden\"\n",
                )

    def test_custody_rejects_unterminated_fully_qualified_reference_in_real_tls_source(self) -> None:
        tls_source = (
            ROOT
            / "physical-harness/src/main/kotlin/org/matrix/teesimulator/physicalharness/"
            "PinnedJsseServerContext.kt"
        )
        source_bytes = tls_source.read_bytes().rstrip(b"\n")
        self.assertIn(b"SpkiPin", source_bytes)
        self.assertIn(b"privateKey", source_bytes)
        reference = b"\nval protocol = org.matrix.teesimulator.twophone.PublicProfileCodec"
        self.assertFalse(reference.endswith(b"\n"))

        for suffix in (b"", b"\n"):
            with self.subTest(final_newline=bool(suffix)):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    source_root = Path(temporary_directory)
                    source_path = source_root / tls_source.relative_to(ROOT)
                    source_path.parent.mkdir(parents=True)
                    source_path.write_bytes(source_bytes + reference + suffix)

                    completed = subprocess.run(
                        [str(GUARDS), "source", str(source_root)],
                        capture_output=True,
                        check=False,
                        cwd=ROOT,
                        text=True,
                    )

                    self.assertNotEqual(completed.returncode, 0)
                    self.assertEqual(completed.stderr, "FAIL target-protocol-custody\n")
