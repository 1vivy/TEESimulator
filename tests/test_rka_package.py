from __future__ import annotations

import hashlib
import os
from pathlib import Path
from shutil import copy2
from subprocess import CompletedProcess, run
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_MANIFEST = REPOSITORY_ROOT / "module" / "rka-runtime.manifest"
FIXED_EPOCH = "1785486225"


class RkaPackageTest(unittest.TestCase):
    def test_production_validator_rejects_every_tampered_archive_class(self) -> None:
        release = self.current_archives()["Release"]
        mutations = {
            "secret": ("secrets/transport.key", b"secret"),
            "profile": ("profiles/active.conf", b"role=DONOR\n"),
            "trust": ("trust/transport.pem", b"trust"),
            "device_identity": ("device-id.txt", b"identity"),
            "legacy_keybox": ("keybox.xml", b"keybox"),
            "companion": ("companion.apk", b"companion"),
            "probe": ("probe-service.sh", b"probe"),
            "unexpected": ("unexpected.txt", b"unexpected"),
        }
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            for name, (entry, payload) in mutations.items():
                archive = temporary_root / f"{name}-Release.zip"
                self.copy_archive(release, archive, {entry: payload})
                result = self.run_validator(archive)
                self.assertNotEqual(result.returncode, 0, name)

            for name, payload in {
                "role_specific": {"rka-role.conf": b"version=1\nrole=DONOR\n"},
                "reboot": {"service.sh": b"#!/system/bin/sh\nreboot\n"},
                "deploy": {"service.sh": b"#!/system/bin/sh\nadb push\n"},
                "start_service": {"service.sh": b"#!/system/bin/sh\nstart-service\n"},
            }.items():
                archive = temporary_root / f"{name}-Release.zip"
                self.copy_archive(release, archive, payload)
                result = self.run_validator(archive)
                self.assertNotEqual(result.returncode, 0, name)

            missing = temporary_root / "missing-Release.zip"
            self.copy_archive(release, missing, {}, {"rka-sidecar"})
            self.assertNotEqual(self.run_validator(missing).returncode, 0)
            wrong_mode = temporary_root / "wrong-mode-Release.zip"
            self.copy_archive(release, wrong_mode, {"daemon": b"#!/system/bin/sh\n"}, modes={"daemon": 0o644})
            self.assertNotEqual(self.run_validator(wrong_mode).returncode, 0)

    def test_two_clean_fixed_epoch_release_builds_are_byte_identical(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            first = temporary_root / "first.zip"
            second = temporary_root / "second.zip"
            for destination in (first, second):
                result = run(
                    ["./gradlew", "clean", "zipRelease"],
                    cwd=REPOSITORY_ROOT,
                    check=False,
                    capture_output=True,
                    env=os.environ | {"SOURCE_DATE_EPOCH": FIXED_EPOCH},
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                copy2(self.current_archives()["Release"], destination)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())

    def test_manifest_webui_modes_and_hashes_exactly_match_release_archive(self) -> None:
        manifest = self.parse_manifest(RUNTIME_MANIFEST)
        release = self.current_archives()["Release"]
        source_webroot = {
            f"webroot/{path.relative_to(REPOSITORY_ROOT / 'module' / 'webroot').as_posix()}": path
            for path in (REPOSITORY_ROOT / "module" / "webroot").rglob("*")
            if path.is_file()
        }
        expected_entries = set(manifest["archive_entries"].split(",")) | set(source_webroot) | {"classes.dex"}
        expected_executables = set(manifest["archive_executables"].split(","))
        with ZipFile(release) as archive:
            relevant_entries = {
                info.filename
                for info in archive.infolist()
                if not info.is_dir() and not info.filename.startswith(("lib/", "META-INF/"))
            }
            self.assertEqual(relevant_entries, expected_entries)
            for name, source in source_webroot.items():
                info = archive.getinfo(name)
                self.assertEqual(archive.read(name), source.read_bytes(), name)
                self.assertEqual(info.external_attr >> 16 & 0o777, 0o644, name)
            for info in archive.infolist():
                if info.is_dir() or info.filename.startswith("lib/"):
                    continue
                expected_mode = 0o755 if info.filename in expected_executables else 0o644
                self.assertEqual(info.external_attr >> 16 & 0o777, expected_mode, info.filename)
            hashes = self.parse_hash_manifest(archive.read("META-INF/rka-artifacts.sha256"))
            self.assertEqual(set(hashes), {info.filename for info in archive.infolist() if not info.is_dir() and not info.filename.startswith("META-INF/")})
            for name, expected_hash in hashes.items():
                self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), expected_hash, name)

    def run_validator(self, archive: Path) -> CompletedProcess[str]:
        return run(
            ["./gradlew", "verifyRkaModuleArchive", f"-PrkaArchivePath={archive}"],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def copy_archive(
        self,
        source: Path,
        destination: Path,
        replacements: dict[str, bytes],
        removals: set[str] | None = None,
        modes: dict[str, int] | None = None,
    ) -> None:
        removed = removals or set()
        replacement_modes = modes or {}
        with ZipFile(source) as original, ZipFile(destination, "w", ZIP_DEFLATED) as copied:
            for info in original.infolist():
                if info.is_dir() or info.filename in removed:
                    continue
                payload = replacements.get(info.filename, original.read(info.filename))
                entry = ZipInfo(info.filename, info.date_time)
                entry.compress_type = ZIP_DEFLATED
                entry.create_system = info.create_system
                entry.external_attr = ((replacement_modes.get(info.filename, info.external_attr >> 16 & 0o777)) << 16) | 0o100000
                copied.writestr(entry, payload)
            for name, payload in replacements.items():
                if name not in original.namelist():
                    entry = ZipInfo(name)
                    entry.compress_type = ZIP_DEFLATED
                    entry.create_system = 3
                    entry.external_attr = (0o644 << 16) | 0o100000
                    copied.writestr(entry, payload)

    def current_archives(self) -> dict[str, Path]:
        count = int(run(["git", "rev-list", "HEAD", "--count"], cwd=REPOSITORY_ROOT, check=True, capture_output=True, text=True).stdout) + 5
        return {variant: REPOSITORY_ROOT / "out" / f"TEESimulator-RS-v6.0.1-{count}-{variant}.zip" for variant in ("Debug", "Release")}

    def parse_manifest(self, path: Path) -> dict[str, str]:
        return dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines())

    def parse_hash_manifest(self, payload: bytes) -> dict[str, str]:
        return {name: digest for digest, name in (line.split("  ", 1) for line in payload.decode().splitlines())}


if __name__ == "__main__":
    unittest.main()
