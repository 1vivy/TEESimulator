from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "scripts/verify-snapshot.sh"
TEMP_ROOT = Path("/tmp/opencode")
FIXTURE_SIGNING_ENVIRONMENT = (
    "TEESIM_FIXTURE_KEYSTORE",
    "TEESIM_FIXTURE_STORE_PASSWORD_FILE",
    "TEESIM_FIXTURE_KEY_ALIAS",
    "TEESIM_FIXTURE_KEY_PASSWORD_FILE",
)


class SnapshotVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(dir=TEMP_ROOT)
        self.fixture_root = Path(self.temporary_directory.name)
        self.source = self.fixture_root / "source with spaces\nand newlines"
        self.snapshot_root = self.fixture_root / "snapshot clones"
        self.source.mkdir()
        self.snapshot_root.mkdir()
        self._write_fixture_repository()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _run(self, *arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            arguments,
            capture_output=True,
            check=True,
            cwd=cwd,
        )

    def _write_fixture_repository(self) -> None:
        (self.source / ".gitignore").write_text("ignored-build/\n")
        (self.source / "tracked keep.txt").write_text("tracked\n")
        (self.source / "tracked deleted.txt").write_text("delete me\n")
        scripts = self.source / "scripts"
        scripts.mkdir()
        verify = scripts / "verify.sh"
        verify.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "git diff --quiet\n"
            "test -z \"$(git status --porcelain)\"\n"
            "git cat-file -e HEAD^\n"
            "test -L 'untracked link'\n"
            "test \"$(readlink -- 'untracked link')\" = 'untracked target'\n"
            "test -f $'untracked\\nfilename'\n"
            "test ! -e ignored-build/ignored.txt\n"
            "test ! -e .omo/evidence/excluded.txt\n"
            "for name in TEESIM_FIXTURE_KEYSTORE TEESIM_FIXTURE_STORE_PASSWORD_FILE TEESIM_FIXTURE_KEY_ALIAS TEESIM_FIXTURE_KEY_PASSWORD_FILE; do\n"
            "  test -n \"${!name:-}\"\n"
            "done\n"
            "test -f \"$TEESIM_FIXTURE_KEYSTORE\"\n"
            "test -f \"$TEESIM_FIXTURE_STORE_PASSWORD_FILE\"\n"
            "test -f \"$TEESIM_FIXTURE_KEY_PASSWORD_FILE\"\n"
            "case \"$TEESIM_FIXTURE_KEYSTORE\" in \"$PWD\"/*) exit 1 ;; esac\n"
            "if [[ -n \"${FIXTURE_READY_FIFO:-}\" ]]; then\n"
            "  printf ready >\"$FIXTURE_READY_FIFO\"\n"
            "  sleep 30\n"
            "fi\n"
            "printf 'PASS fixture-g0\\n'\n"
        )
        verify.chmod(0o755)
        bootstrap = scripts / "bootstrap-fixture-signer.sh"
        bootstrap.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "state=$1\n"
            "mkdir -m 700 -- \"$state\"\n"
            "printf fixture >\"$state/fixture-signer.p12\"\n"
            "printf fixture >\"$state/fixture-store-password\"\n"
            "printf fixture >\"$state/fixture-key-password\"\n"
            "chmod 600 -- \"$state/fixture-signer.p12\" \"$state/fixture-store-password\" \"$state/fixture-key-password\"\n"
            "printf 'PASS FIXTURE_SIGNER_BOOTSTRAPPED\\n'\n"
        )
        bootstrap.chmod(0o755)

        self._run("git", "init", "--initial-branch=main", str(self.source))
        self._run("git", "-C", str(self.source), "config", "user.name", "Fixture")
        self._run("git", "-C", str(self.source), "config", "user.email", "fixture@example.invalid")
        self._run("git", "-C", str(self.source), "config", "commit.gpgSign", "false")
        self._run("git", "-C", str(self.source), "add", "--", ".")
        self._run("git", "-C", str(self.source), "commit", "-m", "fixture")

        (self.source / "tracked deleted.txt").unlink()
        (self.source / "untracked target").write_text("untracked\n")
        (self.source / "untracked\nfilename").write_text("newline path\n")
        os.symlink("untracked target", self.source / "untracked link")
        (self.source / "ignored-build").mkdir()
        (self.source / "ignored-build/ignored.txt").write_text("ignored\n")
        evidence = self.source / ".omo/evidence"
        evidence.mkdir(parents=True)
        (evidence / "excluded.txt").write_text("excluded\n")

    def _source_identity(self) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
        git_directory = self._run(
            "git", "-C", str(self.source), "rev-parse", "--absolute-git-dir"
        ).stdout.strip()
        index = Path(os.fsdecode(git_directory)) / "index"
        return (
            self._run("git", "-C", str(self.source), "rev-parse", "HEAD").stdout,
            self._run("git", "-C", str(self.source), "status", "--porcelain=v1", "-z").stdout,
            sha256(index.read_bytes()).digest(),
            self._run("git", "-C", str(self.source), "show-ref", "--head").stdout,
            self._run("git", "-C", str(self.source), "reflog", "show", "--all").stdout,
            self._run("git", "-C", str(self.source), "ls-files", "-co", "--exclude-standard", "-z").stdout,
        )

    def _run_snapshot(self, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
        combined_environment = os.environ.copy()
        for name in FIXTURE_SIGNING_ENVIRONMENT:
            combined_environment.pop(name, None)
        combined_environment["VERIFY_SNAPSHOT_TMP_ROOT"] = str(self.snapshot_root)
        if environment is not None:
            combined_environment.update(environment)
        return subprocess.run(
            [str(SNAPSHOT), str(self.source)],
            capture_output=True,
            check=False,
            cwd=self.source,
            env=combined_environment,
        )

    def test_snapshot_wrapper_exists_before_exercising_its_contract(self) -> None:
        # Given: Todo 2 has no wrapper. When: its contract is requested. Then: it must exist.
        self.assertTrue(SNAPSHOT.is_file())

    def test_snapshot_wrapper_preserves_dirty_source_and_runs_clean_clone(self) -> None:
        # Given: malformed-path, symlink, deletion, ignored, and evidence fixture content.
        self.assertTrue(SNAPSHOT.is_file())
        source_before = self._source_identity()

        # When: the dirty fixture runs through the snapshot wrapper.
        completed = self._run_snapshot()

        # Then: only an exact clean clone verifies and the source identity remains unchanged.
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertIn(b"PASS git-directories-distinct\n", completed.stdout)
        self.assertIn(b"PASS snapshot-manifests-match\n", completed.stdout)
        self.assertIn(b"PASS FIXTURE_SIGNER_BOOTSTRAPPED\n", completed.stdout)
        self.assertIn(b"PASS fixture-g0\n", completed.stdout)
        self.assertIn(b"PASS snapshot-verified\n", completed.stdout)
        self.assertIn(b"PASS cleanup clone-removed\n", completed.stdout)
        self.assertEqual(source_before, self._source_identity())
        self.assertEqual(tuple(self.snapshot_root.glob("verify-snapshot.*")), ())

    def test_snapshot_wrapper_rejects_drift_after_manifest_capture(self) -> None:
        # Given: a fixture-only hook that mutates source after its manifest is captured.
        self.assertTrue(SNAPSHOT.is_file())
        hook = self.fixture_root / "mutate fixture source.sh"
        hook.write_text("#!/usr/bin/env bash\nprintf drift >\"$1/drifted after capture\"\n")
        hook.chmod(0o755)

        # When: the wrapper invokes the hook after capture.
        completed = self._run_snapshot({"VERIFY_SNAPSHOT_TEST_HOOK_AFTER_CAPTURE": str(hook)})

        # Then: it reports the exact drift label and still removes the disposable clone.
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"FAIL snapshot-drift\n")
        self.assertIn(b"PASS cleanup clone-removed\n", completed.stdout)
        self.assertEqual(tuple(self.snapshot_root.glob("verify-snapshot.*")), ())

    def test_snapshot_wrapper_rejects_clone_manifest_mismatch(self) -> None:
        # Given: a fixture-only hook that adds content after the clone copy.
        self.assertTrue(SNAPSHOT.is_file())
        hook = self.fixture_root / "mutate fixture clone.sh"
        hook.write_text("#!/usr/bin/env bash\nprintf mismatch >\"$1/clone mismatch\"\n")
        hook.chmod(0o755)

        # When: the copied clone changes before its manifest comparison.
        completed = self._run_snapshot({"VERIFY_SNAPSHOT_TEST_HOOK_AFTER_COPY": str(hook)})

        # Then: it rejects the exact manifest mismatch and removes the clone.
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"FAIL snapshot-mismatch\n")
        self.assertIn(b"PASS cleanup clone-removed\n", completed.stdout)
        self.assertEqual(tuple(self.snapshot_root.glob("verify-snapshot.*")), ())


if __name__ == "__main__":
    unittest.main()
