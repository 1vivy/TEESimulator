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

    def write_direct_profile(self, state: Path, role: str, epoch: int = 0) -> None:
        path = state / "profiles" / "direct.conf"
        path.write_text(
            "version=1\n"
            f"role={role}\n"
            f"profile_epoch={epoch}\n"
            "peer_endpoint=192.0.2.44\n"
            f"peer_spki_sha256={'ab' * 32}\n"
            "transport=DIRECT\n",
            encoding="utf-8",
        )
        os.chmod(path, 0o600)

    def fixture(self, role: str | None) -> tuple[TemporaryDirectory[str], Path, Path]:
        temporary = TemporaryDirectory()
        root = Path(temporary.name) / "root"
        state = Path(temporary.name) / "state"
        root.mkdir()
        child = root / "fake-child.sh"
        child.write_text(
            "#!/bin/sh\nprintf '%s %s RKA_PROFILE_PATH=%s RKA_EXPECTED_PROFILE_EPOCH=%s RKA_PROFILE_RECEIPT_PATH=%s\\n' \"$0\" \"$*\" \"${RKA_PROFILE_PATH-}\" \"${RKA_EXPECTED_PROFILE_EPOCH-}\" \"${RKA_PROFILE_RECEIPT_PATH-}\" >> \"$RKA_CHILD_LOG\"\nif [ -n \"${RKA_PROFILE_RECEIPT_PATH-}\" ]; then profile_hash=$(sha256sum \"$RKA_PROFILE_PATH\" | awk '{print $1}'); printf 'version=1\\nprofile_sha256=%s\\nprofile_epoch=%s\\npeer_pin_sha256=%064d\\ntransport=DIRECT\\n' \"$profile_hash\" \"$RKA_EXPECTED_PROFILE_EPOCH\" 0 > \"$RKA_PROFILE_RECEIPT_PATH\"; chmod 600 \"$RKA_PROFILE_RECEIPT_PATH\"; fi\n[ \"${RKA_CHILD_MODE:-hold}\" = crash ] && exit 7\nif [ \"${RKA_CHILD_MODE:-hold}\" = crash-once ] && [ ! -e \"$RKA_CRASH_ONCE_FILE\" ]; then : > \"$RKA_CRASH_ONCE_FILE\"; sleep 1; exit 7; fi\ntrap 'printf term\\n >> \"$RKA_CHILD_LOG\"; exit 0' TERM INT\nwhile :; do sleep 1; done\n",
            encoding="utf-8",
        )
        child.chmod(0o755)
        if role is not None:
            self.write_role(root, role)
            if role not in {"LOCAL", "DISABLED"}:
                self.write_profile(state, role)
                self.write_direct_profile(state, role)
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

    def test_no_restart_during_generating(self) -> None:
        temporary, root, state = self.fixture("LOCAL")
        try:
            marker = state / "journal" / "mutation.state"
            marker.parent.mkdir(parents=True)
            marker.write_text("RKP_KEY_GENERATING\n", encoding="utf-8")
            result = self.command(root, state, "start", environment={"RKA_CHILD_MODE": "crash"})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "state=QUARANTINED_AMBIGUOUS_MUTATION",
                self.command(root, state, "status").stdout,
            )
            self.assertEqual((root / "children.log").read_text(encoding="utf-8").count("legacy"), 1)
        finally:
            self.clean(root, state)
            temporary.cleanup()

    def test_marker_matrix_quarantines_ambiguous_and_restarts_normal(self) -> None:
        quarantined = ("POST_AMBIGUOUS", "RKP_KEY_GENERATING", "APP_KEY_GENERATING", "malformed", "unreadable")
        normal = (None, "IDLE", "COMPLETED")
        for marker_value in quarantined + normal:
            temporary, root, state = self.fixture("LOCAL")
            try:
                if marker_value is not None:
                    marker = state / "journal" / "mutation.state"
                    marker.parent.mkdir(parents=True)
                    marker.write_text(f"{marker_value}\n", encoding="utf-8")
                    if marker_value == "unreadable":
                        os.chmod(marker, 0o000)
                crash_file = root / "crashed-once"
                self.assertEqual(
                    self.command(
                        root,
                        state,
                        "start",
                        environment={"RKA_CHILD_MODE": "crash-once", "RKA_CRASH_ONCE_FILE": str(crash_file)},
                    ).returncode,
                    0,
                )
                deadline = monotonic() + 3
                while "state=RUNNING" in self.command(root, state, "status").stdout and monotonic() < deadline:
                    sleep(0.02)
                status = self.command(root, state, "status").stdout
                launches = (root / "children.log").read_text(encoding="utf-8").count("legacy")
                if marker_value in quarantined:
                    self.assertIn("state=QUARANTINED_AMBIGUOUS_MUTATION", status)
                    self.assertEqual(launches, 1)
                else:
                    self.assertIn("legacy=RUNNING", status)
                    self.assertEqual(launches, 2)
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
        self.assertIn("rka-sidecar", source)
