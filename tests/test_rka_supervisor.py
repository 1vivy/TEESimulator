from __future__ import annotations

import os
from pathlib import Path
from subprocess import CompletedProcess, run
from tempfile import TemporaryDirectory
from time import monotonic, sleep
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SUPERVISOR = REPOSITORY_ROOT / "module" / "rka-supervisor.sh"
CUSTOMIZE = REPOSITORY_ROOT / "module" / "customize.sh"


class RkaSupervisorTest(unittest.TestCase):
    def command(
        self, root: Path, state: Path, *arguments: str, environment: dict[str, str] | None = None
    ) -> CompletedProcess[str]:
        child_environment = os.environ | {
            "RKA_CONTROL": str(REPOSITORY_ROOT / "module" / "rka-control.sh"),
            "RKA_DAEMON": str(root / "fake-child.sh"),
            "RKA_SIDECAR": str(root / "fake-child.sh"),
            "RKA_CHILD_LOG": str(root / "children.log"),
            "RKA_BACKOFF_BASE": "0",
        }
        if environment is not None:
            child_environment = child_environment | environment
        return run(
            ["sh", str(SUPERVISOR), "--root", str(root), "--state-root", str(state), *arguments],
            check=False,
            capture_output=True,
            env=child_environment,
            text=True,
        )

    def write_role(self, root: Path, role: str) -> None:
        path = root / "rka" / "role.conf"
        path.parent.mkdir(parents=True)
        path.write_text(f"version=1\nrole={role}\n", encoding="utf-8")
        os.chmod(path, 0o600)

    def write_profile(self, state: Path, role: str) -> None:
        path = state / "profiles" / "active.conf"
        path.parent.mkdir(parents=True)
        path.write_text(f"version=1\nrole={role}\nprofile_epoch=0\n", encoding="utf-8")
        os.chmod(path, 0o600)

    def fixture(self, role: str | None) -> tuple[TemporaryDirectory[str], Path, Path]:
        temporary = TemporaryDirectory()
        root = Path(temporary.name) / "root"
        state = Path(temporary.name) / "state"
        root.mkdir()
        child = root / "fake-child.sh"
        child.write_text(
            "#!/bin/sh\nprintf '%s %s\\n' \"$0\" \"$*\" >> \"$RKA_CHILD_LOG\"\n[ \"${RKA_CHILD_MODE:-hold}\" = crash ] && exit 7\ntrap 'printf term\\n >> \"$RKA_CHILD_LOG\"; exit 0' TERM INT\nwhile :; do sleep 1; done\n",
            encoding="utf-8",
        )
        child.chmod(0o755)
        if role is not None:
            self.write_role(root, role)
            if role not in {"LOCAL", "DISABLED"}:
                self.write_profile(state, role)
        return temporary, root, state

    def clean(self, root: Path, state: Path) -> None:
        self.command(root, state, "stop")

    def test_local_starts_only_legacy_process(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            result = self.command(root, state, "start")
            status = self.command(root, state, "status")
            self.assertEqual(result.returncode, 0)
            self.assertIn("legacy=RUNNING", status.stdout)
            self.assertNotIn("broker=RUNNING", status.stdout)
            self.assertNotIn("sidecar=RUNNING", status.stdout)
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_donor_process_graph(self) -> None:
        temporary, root, state = self.fixture("DONOR")
        try:
            self.assertEqual(self.command(root, state, "start").returncode, 0)
            status = self.command(root, state, "status")
            child_log = (root / "children.log").read_text(encoding="utf-8")
            self.assertIn("broker=RUNNING", status.stdout)
            self.assertIn("sidecar=RUNNING", status.stdout)
            self.assertNotIn("--rka-candidate", child_log)
            self.assertNotIn("legacy=RUNNING", status.stdout)
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_candidate_process_graph(self) -> None:
        temporary, root, state = self.fixture("CANDIDATE")
        try:
            self.assertEqual(self.command(root, state, "start").returncode, 0)
            child_log = (root / "children.log").read_text(encoding="utf-8")
            self.assertIn("--rka-role CANDIDATE", child_log)
            self.assertIn("candidate", child_log)
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_invalid_or_disabled_starts_nothing(self) -> None:
        temporary, root, state = self.fixture("DISABLED")
        try:
            result = self.command(root, state, "start")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "children.log").exists())
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_invalid_role_configuration_starts_nothing(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            os.chmod(root / "rka" / "role.conf", 0o644)
            result = self.command(root, state, "start")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "children.log").exists())
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_duplicate_start_is_idempotent(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            self.assertEqual(self.command(root, state, "start").returncode, 0)
            self.assertEqual(self.command(root, state, "start").returncode, 0)
            self.assertEqual(len(list((state / "run" / "pids").glob("*.pid"))), 1)
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_stale_or_reused_pid_record_is_removed_without_signal(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            record = state / "run" / "pids" / "legacy.pid"
            record.parent.mkdir(parents=True)
            record.write_text("1 1 1\n", encoding="utf-8")
            self.assertEqual(self.command(root, state, "stop").returncode, 0)
            self.assertFalse(record.exists())
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_child_death_restarts_and_stop_forwards_term(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            self.assertEqual(self.command(root, state, "start").returncode, 0)
            record = next((state / "run" / "pids").glob("legacy.pid"))
            prior_record = record.read_text(encoding="utf-8")
            run(["kill", "-TERM", "--", f"-{prior_record.split()[1]}"], check=True)
            deadline = monotonic() + 2
            while record.read_text(encoding="utf-8") == prior_record and monotonic() < deadline:
                sleep(0.02)
            self.assertNotEqual(record.read_text(encoding="utf-8"), prior_record)
            self.assertEqual(self.command(root, state, "stop").returncode, 0)
            self.assertIn("legacy=STOPPED", self.command(root, state, "status").stdout)
            self.assertIn("term", (root / "children.log").read_text(encoding="utf-8"))
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_rapid_crashes_reach_failed_cap(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            result = self.command(root, state, "start", environment={"RKA_CHILD_MODE": "crash"})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("state=FAILED_CRASH_CAP", self.command(root, state, "status").stdout)
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_forbidden_process_control_tokens_are_absent(self) -> None:
        source = SUPERVISOR.read_text(encoding="utf-8")
        for forbidden in ("killall", "pkill", "reboot", "keystore2", "rkpd", "classpath"):
            self.assertNotIn(forbidden, source.lower())

    def test_module_installer_ships_supervisor(self) -> None:
        source = CUSTOMIZE.read_text(encoding="utf-8")
        self.assertIn("rka-supervisor.sh", source)
        self.assertIn('chmod 755 "$MODPATH/rka-supervisor.sh"', source)
