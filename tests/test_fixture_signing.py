from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts/bootstrap-fixture-signer.sh"
SIGN_RELEASE = ROOT / "scripts/sign-fixture-release-apk.sh"
VERIFY_APK = ROOT / "scripts/verify-fixture-apk.sh"
CREATE_PROVENANCE = ROOT / "scripts/create-fixture-provenance.sh"
SIGN_PROVENANCE = ROOT / "scripts/sign-fixture-provenance.sh"
VERIFY_PROVENANCE = ROOT / "scripts/verify-fixture-provenance.sh"
GRADLE = ROOT / "gradlew"
RELEASE_DIRECTORY = ROOT / "rka-fixture/build/outputs/apk/release"
UNSIGNED_APK = RELEASE_DIRECTORY / "rka-fixture-release-unsigned.apk"
SIGNED_APK = RELEASE_DIRECTORY / "rka-fixture-release.apk"
BUILD_TOOLS = Path(os.environ.get("ANDROID_HOME", ROOT / ".android-sdk")) / "build-tools/36.0.0"
FIXTURE_SIGNING_ENVIRONMENT = frozenset(
    (
        "TEESIM_FIXTURE_KEYSTORE",
        "TEESIM_FIXTURE_STORE_PASSWORD_FILE",
        "TEESIM_FIXTURE_KEY_ALIAS",
        "TEESIM_FIXTURE_KEY_PASSWORD_FILE",
        "TEESIM_AGENT_GPG_KEY",
    )
)


def run(
    command: list[str], environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    child_environment = os.environ.copy()
    child_environment.pop("GPG_TTY", None)
    if environment is not None:
        for name in FIXTURE_SIGNING_ENVIRONMENT:
            child_environment.pop(name, None)
        child_environment.update(environment)
    return subprocess.run(
        command,
        capture_output=True,
        check=False,
        cwd=ROOT,
        env=child_environment,
        stdin=subprocess.DEVNULL,
        text=True,
    )


def fixture_environment(state: Path, alias: str = "teesim-fixture") -> dict[str, str]:
    return {
        "TEESIM_FIXTURE_KEYSTORE": str(state / "fixture-signer.p12"),
        "TEESIM_FIXTURE_STORE_PASSWORD_FILE": str(state / "fixture-store-password"),
        "TEESIM_FIXTURE_KEY_ALIAS": alias,
        "TEESIM_FIXTURE_KEY_PASSWORD_FILE": str(state / "fixture-key-password"),
    }


def release_build(environment: dict[str, str], clean: bool = False) -> subprocess.CompletedProcess[str]:
    tasks = [":rka-fixture:assembleRelease"]
    if clean:
        tasks.insert(0, ":rka-fixture:clean")
    return run(
        [
            str(GRADLE),
            "--no-daemon",
            *tasks,
        ],
        environment,
    )


def fingerprint(home: Path) -> str:
    completed = run(
        ["gpg", "--batch", "--no-tty", "--with-colons", "--list-secret-keys"],
        {"GNUPGHOME": str(home)},
    )
    lines = [line.split(":")[9] for line in completed.stdout.splitlines() if line.startswith("fpr:")]
    if not lines:
        raise AssertionError("ephemeral GPG key was not created")
    return lines[0]


def generate_gpg_key(home: Path, identity: str, password_file: Path | None = None) -> str:
    command = ["gpg", "--batch", "--no-tty", "--pinentry-mode", "loopback"]
    if password_file is not None:
        command.extend(("--passphrase-file", str(password_file)))
    else:
        command.extend(("--passphrase-file", "/dev/null"))
    command.extend(("--quick-generate-key", identity, "rsa2048", "sign", "0"))
    completed = run(command, {"GNUPGHOME": str(home)})
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return fingerprint(home)


class FixtureReleaseFailureTests(unittest.TestCase):
    def test_release_assembly_rejects_missing_signing_configuration(self) -> None:
        # Given: all four signing paths are absent. When: release assembly runs. Then: typed failure.
        environment = os.environ.copy()
        for name in fixture_environment(Path("/unused")):
            environment.pop(name, None)
        with patch.dict(os.environ, fixture_environment(Path("/unexpected"))):
            completed = release_build(environment)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("FIXTURE_SIGNING_CONFIG_MISSING", completed.stdout + completed.stderr)


class FixtureSigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary_directory = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        cls.temporary_root = Path(cls.temporary_directory.name)
        cls.state = cls.temporary_root / "fixture-state"
        cls.environment = fixture_environment(cls.state)

        # Given: no signing implementation. When: the bootstrap contract is exercised. Then: it exists.
        if not BOOTSTRAP.is_file():
            raise AssertionError(f"missing bootstrap: {BOOTSTRAP}")
        completed = run([str(BOOTSTRAP), str(cls.state)])
        if completed.returncode != 0:
            raise AssertionError(completed.stderr)
        if completed.stdout != "PASS FIXTURE_SIGNER_BOOTSTRAPPED\n":
            raise AssertionError(completed.stdout)

        first = release_build(cls.environment, clean=True)
        if first.returncode != 0:
            raise AssertionError(first.stderr)
        shutil.copyfile(SIGNED_APK, cls.temporary_root / "first.apk")
        second = release_build(cls.environment, clean=True)
        if second.returncode != 0:
            raise AssertionError(second.stderr)
        shutil.copyfile(SIGNED_APK, cls.temporary_root / "second.apk")
        cls.manifest = cls.temporary_root / "fixture-provenance.json"
        cls.provenance_created = run([str(CREATE_PROVENANCE), str(cls.temporary_root / "first.apk"), str(cls.manifest)])
        if cls.provenance_created.returncode != 0:
            raise AssertionError(cls.provenance_created.stderr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary_directory.cleanup()

    def test_bootstrap_creates_private_state_without_secret_output(self) -> None:
        # Given: the bootstrap result. When: host-state modes are inspected. Then: every secret is private.
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        for path in (self.state / "fixture-signer.p12", *[Path(value) for key, value in self.environment.items() if key.endswith("PASSWORD_FILE")]):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        for path in (Path(self.environment["TEESIM_FIXTURE_STORE_PASSWORD_FILE"]), Path(self.environment["TEESIM_FIXTURE_KEY_PASSWORD_FILE"])):
            self.assertNotIn(path.read_text(), "PASS FIXTURE_SIGNER_BOOTSTRAPPED\n")

    def test_bootstrap_rejects_a_prompting_keytool_without_retaining_material(self) -> None:
        # Given: a keytool that requests input. When: bootstrap runs closed-stdin. Then: it cleans state and fails typed.
        fake_tools = self.temporary_root / "prompting-tools"
        fake_tools.mkdir()
        keytool = fake_tools / "keytool"
        keytool.write_text("#!/usr/bin/env bash\nprintf 'Enter keystore password:' >&2\nexit 1\n")
        keytool.chmod(0o755)
        failed_state = self.temporary_root / "prompting-state"
        prompting = run([str(BOOTSTRAP), str(failed_state)], {"PATH": f"{fake_tools}:{os.environ['PATH']}"})
        self.assertEqual(prompting.stderr, "FAIL INTERACTION_REQUIRED\n")
        self.assertFalse((failed_state / "fixture-signer.p12").exists())
        self.assertFalse((failed_state / "fixture-store-password").exists())
        self.assertFalse((failed_state / "fixture-key-password").exists())

    def test_release_apks_are_byte_identical_and_verify_by_artifact_and_signer(self) -> None:
        # Given: two clean release builds. When: their bytes and signer manifest are checked. Then: both match.
        first = self.temporary_root / "first.apk"
        second = self.temporary_root / "second.apk"
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(self.provenance_created.stderr, "")
        provenance = json.loads(self.manifest.read_text())
        self.assertEqual(provenance["artifact_sha256"], sha256(first.read_bytes()).hexdigest())
        verified = run(
            [
                str(VERIFY_APK),
                str(second),
                provenance["artifact_sha256"],
                provenance["signer_certificate_sha256"],
            ]
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(verified.stdout, "PASS FIXTURE_APK_VERIFIED\n")

    def test_wrong_signer_and_malformed_signing_inputs_have_typed_errors(self) -> None:
        # Given: a valid artifact plus malformed signing inputs. When: validation runs. Then: labels are distinct.
        missing = dict(self.environment)
        missing["TEESIM_FIXTURE_KEYSTORE"] = str(self.temporary_root / "missing.p12")
        missing_result = release_build(missing)
        self.assertIn("FIXTURE_SIGNING_KEYSTORE_MISSING", missing_result.stdout + missing_result.stderr)

        password = Path(self.environment["TEESIM_FIXTURE_STORE_PASSWORD_FILE"])
        password.chmod(0o644)
        try:
            permission_result = release_build(self.environment)
        finally:
            password.chmod(0o600)
        self.assertIn("FIXTURE_SIGNING_PASSWORD_FILE_PERMISSIONS", permission_result.stdout + permission_result.stderr)

        alias_result = release_build(fixture_environment(self.state, "wrong-alias"))
        self.assertIn("FIXTURE_SIGNING_ALIAS_INVALID", alias_result.stdout + alias_result.stderr)

        alternate_state = self.temporary_root / "alternate-state"
        bootstrapped = run([str(BOOTSTRAP), str(alternate_state)])
        self.assertEqual(bootstrapped.returncode, 0, bootstrapped.stderr)
        alternate = self.temporary_root / "alternate.apk"
        signed = run(
            [
                str(SIGN_RELEASE),
                "--input",
                str(UNSIGNED_APK),
                "--output",
                str(alternate),
                "--apksigner",
                str(BUILD_TOOLS / "apksigner"),
                "--zipalign",
                str(BUILD_TOOLS / "zipalign"),
            ],
            fixture_environment(alternate_state),
        )
        self.assertEqual(signed.returncode, 0, signed.stderr)
        provenance = json.loads(self.manifest.read_text())
        signer_mismatch = run(
            [
                str(VERIFY_APK),
                str(alternate),
                provenance["artifact_sha256"],
                provenance["signer_certificate_sha256"],
            ]
        )
        self.assertEqual(signer_mismatch.stderr, "FAIL SIGNER_MISMATCH\n")

    def test_detached_provenance_signature_rejects_key_and_content_failures(self) -> None:
        # Given: a canonical manifest and temporary GPG homes. When: signing and verification run. Then: typed results.
        no_key_home = self.temporary_root / "gpg-none"
        no_key_home.mkdir(mode=0o700)
        missing = run([str(SIGN_PROVENANCE), str(self.manifest)], {"GNUPGHOME": str(no_key_home)})
        self.assertEqual(missing.stderr, "FAIL GPG_KEY_MISSING\n")

        ambiguous_home = self.temporary_root / "gpg-ambiguous"
        ambiguous_home.mkdir(mode=0o700)
        generate_gpg_key(ambiguous_home, "one <one@example.invalid>")
        generate_gpg_key(ambiguous_home, "two <two@example.invalid>")
        ambiguous = run([str(SIGN_PROVENANCE), str(self.manifest)], {"GNUPGHOME": str(ambiguous_home)})
        self.assertEqual(ambiguous.stderr, "FAIL GPG_KEY_AMBIGUOUS\n")

        protected_home = self.temporary_root / "gpg-protected"
        protected_home.mkdir(mode=0o700)
        password = self.temporary_root / "gpg-password"
        password.write_text(os.urandom(32).hex())
        password.chmod(0o600)
        protected = generate_gpg_key(protected_home, "protected <protected@example.invalid>", password)
        protected_result = run(
            [str(SIGN_PROVENANCE), str(self.manifest)],
            {"GNUPGHOME": str(protected_home), "TEESIM_AGENT_GPG_KEY": protected},
        )
        self.assertEqual(protected_result.stderr, "FAIL GPG_KEY_PASSWORD_PROTECTED\n")

        signing_home = self.temporary_root / "gpg-signing"
        signing_home.mkdir(mode=0o700)
        selected = generate_gpg_key(signing_home, "signing <signing@example.invalid>")
        signed = run(
            [str(SIGN_PROVENANCE), str(self.manifest)],
            {"GNUPGHOME": str(signing_home), "TEESIM_AGENT_GPG_KEY": selected},
        )
        self.assertEqual(signed.returncode, 0, signed.stderr)
        signature = self.manifest.with_suffix(".json.asc")
        verified = run([str(VERIFY_PROVENANCE), str(self.manifest), str(signature)], {"GNUPGHOME": str(signing_home)})
        self.assertEqual(verified.stdout, f"PASS PROVENANCE_SIGNATURE_VERIFIED {selected}\n")

        self.manifest.write_text(self.manifest.read_text().replace('"schema_version":1', '"schema_version":2'))
        invalid = run([str(VERIFY_PROVENANCE), str(self.manifest), str(signature)], {"GNUPGHOME": str(signing_home)})
        self.assertEqual(invalid.stderr, "FAIL PROVENANCE_SIGNATURE_INVALID\n")


if __name__ == "__main__":
    unittest.main()
