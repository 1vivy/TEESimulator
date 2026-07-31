from __future__ import annotations

import hashlib
from pathlib import Path
from subprocess import run
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZIP_DEFLATED, ZipFile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_MANIFEST = REPOSITORY_ROOT / "module" / "rka-runtime.manifest"
EXECUTABLE_ENTRIES = frozenset(
    {
        "daemon",
        "rka-control.sh",
        "rka-paths.sh",
        "rka-sidecar",
        "rka-supervisor.sh",
        "service.sh",
        "uninstall.sh",
    }
)
COMMON_ENTRIES = frozenset(
    {
        "daemon",
        "rka-sidecar",
        "rka-control.sh",
        "rka-paths.sh",
        "rka-profile.schema",
        "rka-role.conf",
        "rka-runtime.manifest",
        "rka-supervisor.sh",
        "sepolicy.rule",
        "service.sh",
        "uninstall.sh",
        "webroot/index.html",
        "webroot/app.js",
        "webroot/style.css",
        "licenses/LICENSE",
        "licenses/NOTICE",
        "META-INF/rka-artifacts.sha256",
        "META-INF/rka-source.sha256",
    }
)
FORBIDDEN_ENTRY_FRAGMENTS = frozenset(
    {"action", "customize", "diag", "keybox", "persistent_keys", "update.json"}
)
FORBIDDEN_TEXT = frozenset({"-----begin private key-----", "reboot", "device serial"})


class RkaPackageTest(unittest.TestCase):
    def test_role_neutral_runtime_manifest_declares_archive_contract(self) -> None:
        self.assertTrue(RUNTIME_MANIFEST.is_file(), "missing role-neutral runtime manifest")
        manifest = RUNTIME_MANIFEST.read_text(encoding="utf-8")

        self.assertIn("roles=LOCAL|DONOR|CANDIDATE", manifest)
        self.assertIn("sidecar_abi=arm64-v8a", manifest)
        self.assertNotIn("role=DONOR", manifest)
        self.assertNotIn("role=CANDIDATE", manifest)

    def test_generated_archives_have_exact_role_neutral_surface(self) -> None:
        archives = self.current_archives()

        self.assertEqual(set(archives), {"Debug", "Release"})
        for variant, archive in archives.items():
            with ZipFile(archive) as package:
                names = frozenset(package.namelist())
                self.assertTrue(COMMON_ENTRIES <= names)
                self.assertIn("service.apk" if variant == "Debug" else "classes.dex", names)
                self.assertFalse(
                    any(fragment in name for fragment in FORBIDDEN_ENTRY_FRAGMENTS for name in names)
                )
                self.assertFalse(any("profiles/" in name or "trust/" in name for name in names))
                self.assertEqual(package.read("rka-sidecar")[:20], b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\xb7\x00")
                self.assertIn("commit=", package.read("META-INF/rka-source.sha256").decode())
                self.assertTrue(package.read("META-INF/rka-artifacts.sha256").endswith(b"\n"))
                for entry in package.infolist():
                    if entry.is_dir():
                        continue
                    mode = entry.external_attr >> 16 & 0o777
                    expected = 0o755 if entry.filename in EXECUTABLE_ENTRIES else 0o644
                    self.assertEqual(mode, expected, entry.filename)
                    if entry.filename.endswith((".sh", ".conf", ".manifest", ".schema", ".html", ".js", ".css")):
                        text = package.read(entry.filename).decode("utf-8").lower()
                        self.assertFalse(any(token in text for token in FORBIDDEN_TEXT), entry.filename)

    def test_forbidden_fixture_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            fixture = Path(temporary_directory) / "fixture.zip"
            with ZipFile(fixture, "w", ZIP_DEFLATED) as package:
                package.writestr("keybox.xml", "-----BEGIN PRIVATE KEY-----")

            with ZipFile(fixture) as package:
                names = frozenset(package.namelist())
                self.assertTrue(
                    any(fragment in name for fragment in FORBIDDEN_ENTRY_FRAGMENTS for name in names)
                )

    def test_repeated_release_archives_are_byte_identical(self) -> None:
        release = self.current_archives()["Release"]
        first_hash = hashlib.sha256(release.read_bytes()).hexdigest()
        repeat_hash = (REPOSITORY_ROOT / "build" / "rka-release.sha256").read_text().split()[0]

        self.assertEqual(first_hash, repeat_hash)

    def current_archives(self) -> dict[str, Path]:
        commit_count = int(
            run(
            ["git", "rev-list", "HEAD", "--count"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
            ).stdout.strip()
        ) + 5
        archives: dict[str, Path] = {}
        for variant in ("Debug", "Release"):
            matches = list((REPOSITORY_ROOT / "out").glob(f"TEESimulator-RS-v6.0.1-{commit_count}-{variant}.zip"))
            self.assertEqual(len(matches), 1, variant)
            archives[variant] = matches[0]
        return archives


if __name__ == "__main__":
    unittest.main()
