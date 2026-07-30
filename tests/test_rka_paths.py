from __future__ import annotations

import os
from pathlib import Path
from subprocess import CompletedProcess, run
from tempfile import TemporaryDirectory
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTROL_SCRIPT = REPOSITORY_ROOT / "module" / "rka-control.sh"


class RkaPathsTest(unittest.TestCase):
    def run_control(
        self, config_root: Path, state_root: Path, *arguments: str
    ) -> CompletedProcess[str]:
        return run(
            [
                "bash",
                str(CONTROL_SCRIPT),
                "--root",
                str(config_root),
                "--state-root",
                str(state_root),
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_donor_layout(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "teesimulator-rka"

            set_role = self.run_control(config_root, state_root, "set-role", "DONOR")
            result = self.run_control(config_root, state_root, "initialize")

            expected_directories = (
                state_root,
                state_root / "profiles",
                state_root / "secrets",
                state_root / "trust",
                state_root / "journal",
                state_root / "sidecar" / "sessions",
                state_root / "sidecar" / "replay",
                state_root / "sidecar" / "audit",
                state_root / "run" / "sockets",
                state_root / "run" / "pids",
                state_root / "staging",
                state_root / "quarantine",
                state_root / "test-keys",
            )

            self.assertEqual(set_role.returncode, 0)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "READY\n")
            self.assertTrue(all(path.is_dir() for path in expected_directories))
            self.assertTrue(all(os.stat(path).st_mode & 0o777 == 0o700 for path in expected_directories))
            self.assertEqual(
                (state_root / "profiles" / "active.conf").read_text(encoding="utf-8"),
                "version=1\nrole=DONOR\nprofile_epoch=0\n",
            )

    def test_mutation_states(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            result = self.run_control(
                temporary_root / "tricky_store",
                temporary_root / "teesimulator-rka",
                "mutation-states",
            )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            result.stdout,
            "RKP_KEY_GENERATING\n"
            "RKP_KEY_RECORDED\n"
            "CSR_PREPARED\n"
            "CSR_POSTING\n"
            "POST_AMBIGUOUS\n"
            "RKP_CERTIFIED\n"
            "APP_KEY_GENERATING\n"
            "APP_KEY_RECORDED\n"
            "EXPOSED\n"
            "TERMINAL\n"
            "DELETE\n",
        )

    def test_rejects_symlink(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "teesimulator-rka"
            self.assertEqual(self.run_control(config_root, state_root, "initialize").returncode, 0)
            target_path = temporary_root / "transport.key"
            target_path.write_text("not-a-key", encoding="utf-8")
            os.chmod(target_path, 0o600)
            (state_root / "secrets" / "unexpected-secret").symlink_to(target_path)

            result = self.run_control(config_root, state_root, "initialize")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "INERT_INVALID_CONFIG\n")

    def test_rejects_weak_mode(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "teesimulator-rka"
            self.assertEqual(self.run_control(config_root, state_root, "initialize").returncode, 0)
            secret_path = state_root / "secrets" / "unexpected-secret"
            secret_path.write_text("not-a-key", encoding="utf-8")
            os.chmod(secret_path, 0o644)

            result = self.run_control(config_root, state_root, "initialize")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "INERT_INVALID_CONFIG\n")

    def test_future_profile_version_fails_inert(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "teesimulator-rka"
            self.assertEqual(self.run_control(config_root, state_root, "initialize").returncode, 0)
            profile_path = state_root / "profiles" / "active.conf"
            profile_path.write_text(
                "version=2\nrole=LOCAL\nprofile_epoch=0\n", encoding="utf-8"
            )
            os.chmod(profile_path, 0o600)

            result = self.run_control(config_root, state_root, "initialize")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "INERT_INVALID_CONFIG\n")

    def test_path_traversal_fails_inert(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            result = self.run_control(
                temporary_root / "tricky_store",
                temporary_root / "teesimulator-rka" / ".." / "escaped",
                "initialize",
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "INERT_INVALID_CONFIG\n")

    def test_wipe_preserves_profile_and_deletes_runtime_state(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            config_root = temporary_root / "tricky_store"
            state_root = temporary_root / "teesimulator-rka"
            self.assertEqual(
                self.run_control(config_root, state_root, "set-role", "DONOR").returncode,
                0,
            )
            self.assertEqual(self.run_control(config_root, state_root, "initialize").returncode, 0)
            profile_path = state_root / "profiles" / "active.conf"
            profile_before_wipe = profile_path.read_text(encoding="utf-8")
            identity_path = state_root / "profiles" / "active-identity.conf"
            identity_path.write_text("identity=public\n", encoding="utf-8")
            os.chmod(identity_path, 0o600)
            identity_before_wipe = identity_path.read_text(encoding="utf-8")
            for path in (
                state_root / "sidecar" / "sessions" / "session",
                state_root / "test-keys" / "test-key",
                state_root / "quarantine" / "failed",
            ):
                path.write_text("temporary", encoding="utf-8")
                os.chmod(path, 0o600)

            result = self.run_control(config_root, state_root, "wipe")

            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "WIPED\n")
            self.assertEqual(profile_path.read_text(encoding="utf-8"), profile_before_wipe)
            self.assertEqual(identity_path.read_text(encoding="utf-8"), identity_before_wipe)
            self.assertFalse((state_root / "sidecar" / "sessions" / "session").exists())
            self.assertFalse((state_root / "test-keys" / "test-key").exists())
            self.assertFalse((state_root / "quarantine" / "failed").exists())
