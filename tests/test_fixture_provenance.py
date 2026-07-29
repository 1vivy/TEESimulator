from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SIGN_PROVENANCE = ROOT / "scripts/sign-fixture-provenance.sh"
VERIFY_PROVENANCE = ROOT / "scripts/verify-fixture-provenance.sh"


def run(command: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    child_environment = os.environ.copy()
    child_environment.pop("GPG_TTY", None)
    child_environment.pop("TEESIM_AGENT_GPG_KEY", None)
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


def generate_gpg_key(home: Path, identity: str) -> str:
    created = run(
        [
            "gpg",
            "--batch",
            "--no-tty",
            "--pinentry-mode",
            "loopback",
            "--passphrase-file",
            "/dev/null",
            "--quick-generate-key",
            identity,
            "rsa2048",
            "sign",
            "0",
        ],
        {"GNUPGHOME": str(home)},
    )
    if created.returncode != 0:
        raise AssertionError(created.stderr)
    for line in created.stdout.splitlines():
        if line.startswith("[GNUPG:] KEY_CREATED"):
            return line.split()[-1]
    listed = run(["gpg", "--batch", "--no-tty", "--with-colons", "--list-secret-keys"], {"GNUPGHOME": str(home)})
    fingerprints = [line.split(":")[9] for line in listed.stdout.splitlines() if line.startswith("fpr:")]
    if not fingerprints:
        raise AssertionError("ephemeral GPG key was not created")
    return fingerprints[-1]


class FixtureProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.temporary_root = Path(self.temporary_directory.name)
        self.manifest = self.temporary_root / "manifest.json"
        self.manifest.write_text('{"schema_version":1}\n')
        self.gpg_home = self.temporary_root / "gpg"
        self.gpg_home.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_verification_rejects_a_signature_from_a_non_selected_agent_key(self) -> None:
        # Given: two signing keys. When: the other key signs the manifest. Then: selected-key verification rejects it.
        selected = generate_gpg_key(self.gpg_home, "selected <selected@example.invalid>")
        other = generate_gpg_key(self.gpg_home, "other <other@example.invalid>")
        environment = {"GNUPGHOME": str(self.gpg_home), "TEESIM_AGENT_GPG_KEY": selected}
        signed = run([str(SIGN_PROVENANCE), str(self.manifest)], environment)
        self.assertEqual(signed.returncode, 0, signed.stderr)
        selected_signature = self.manifest.with_suffix(".json.asc")
        selected_verified = run([str(VERIFY_PROVENANCE), str(self.manifest), str(selected_signature)], environment)
        self.assertEqual(selected_verified.returncode, 0, selected_verified.stderr)

        other_signature = self.temporary_root / "other.json.asc"
        other_signed = run(
            [
                "gpg",
                "--batch",
                "--no-tty",
                "--pinentry-mode",
                "loopback",
                "--local-user",
                other,
                "--armor",
                "--detach-sign",
                "--output",
                str(other_signature),
                str(self.manifest),
            ],
            {"GNUPGHOME": str(self.gpg_home)},
        )
        self.assertEqual(other_signed.returncode, 0, other_signed.stderr)
        rejected = run([str(VERIFY_PROVENANCE), str(self.manifest), str(other_signature)], environment)
        self.assertEqual(rejected.stderr, "FAIL PROVENANCE_SIGNER_MISMATCH\n")

        selected_still_verified = run([str(VERIFY_PROVENANCE), str(self.manifest), str(selected_signature)], environment)
        self.assertEqual(selected_still_verified.returncode, 0, selected_still_verified.stderr)


if __name__ == "__main__":
    unittest.main()
