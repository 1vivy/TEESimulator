from __future__ import annotations

import os
from pathlib import Path
import signal
from subprocess import Popen, run
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / "module" / "rka-control.sh"
SUPERVISOR = ROOT / "module" / "rka-supervisor.sh"


class FailClosedRuntimeTest(unittest.TestCase):
    def test_recovery_ready_requires_a_new_process_generation(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            config = base / "module"
            state = base / "state"
            self.assertEqual(self.control(config, state, "set-role", "DONOR").returncode, 0)
            self.assertEqual(self.control(config, state, "initialize").returncode, 0)
            profile = state / "profiles" / "recovery.conf"
            profile.write_text(
                "version=1\n"
                "keystore2_name=keystore2\n"
                "keystore2_executable=/system/bin/keystore2\n"
                "keystore2_restart=keystore2\n"
                "rkpd_name=rkpd\n"
                "rkpd_executable=/system/bin/rkpd\n"
                "rkpd_restart=rkpd\n"
                "rkpd_property_one=persist.rkpd.a\n"
                "rkpd_property_two=persist.rkpd.b\n",
                encoding="ascii",
            )
            profile.chmod(0o600)
            proc = base / "proc"
            self.write_process(proc, 42, 777, "/system/bin/keystore2")
            self.write_process(proc, 43, 888, "/system/bin/keystore2")
            current = base / "current-pid"
            current.write_text("42\n", encoding="ascii")
            pidof = base / "pidof"
            pidof.write_text("#!/bin/sh\ncat \"$RKA_CURRENT_PID\"\n", encoding="ascii")
            pidof.chmod(0o700)
            environment = {
                "RKA_CURRENT_PID": str(current),
                "RKA_RECOVERY_PIDOF": str(pidof),
                "RKA_RECOVERY_PROC_ROOT": str(proc),
            }

            stale = self.control(
                config,
                state,
                "recover-exact",
                "ready",
                "keystore2",
                "100",
                "42",
                "777",
                environment=environment,
            )
            current.write_text("43\n", encoding="ascii")
            replaced = self.control(
                config,
                state,
                "recover-exact",
                "ready",
                "keystore2",
                "100",
                "42",
                "777",
                environment=environment,
            )

        self.assertNotEqual(stale.returncode, 0)
        self.assertEqual(replaced.returncode, 0, replaced.stderr)
        self.assertEqual(replaced.stdout, "READY\n")

    def test_status_degrades_a_running_marker_without_its_live_graph(self) -> None:
        with TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "module"
            state = base / "state"
            root.mkdir()
            profile = state / "profiles" / "active.conf"
            profile.parent.mkdir(parents=True)
            profile.write_text("version=1\nrole=LOCAL\nprofile_epoch=0\n", encoding="ascii")
            profile.chmod(0o600)
            marker = state / "run" / "supervisor.state"
            marker.parent.mkdir(parents=True)
            marker.write_text("RUNNING\n", encoding="ascii")
            marker.chmod(0o600)

            result = self.supervisor(root, state, "status")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("state=NOT_READY\n", result.stdout)
        self.assertIn("legacy=STOPPED\n", result.stdout)

    def test_stop_refuses_to_forget_a_live_unverifiable_generation(self) -> None:
        process = Popen(["sleep", "30"], start_new_session=True)
        try:
            with TemporaryDirectory() as directory:
                base = Path(directory)
                root = base / "module"
                state = base / "state"
                root.mkdir()
                pids = state / "run" / "pids"
                pids.mkdir(parents=True)
                marker = state / "run" / "supervisor.state"
                marker.write_text("RUNNING\n", encoding="ascii")
                marker.chmod(0o600)
                facts = Path(f"/proc/{process.pid}/stat").read_text(encoding="ascii")
                fields = facts[facts.rfind(")") + 2 :].split()
                record = pids / "legacy.pid"
                record.write_text(
                    f"{process.pid} {fields[2]} {fields[19]}\n",
                    encoding="ascii",
                )
                record.chmod(0o600)

                result = self.supervisor(root, state, "stop")

                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(record.is_file())
                self.assertEqual(marker.read_text(encoding="ascii"), "STOPPING\n")
                self.assertIsNone(process.poll())
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)

    @staticmethod
    def write_process(proc: Path, pid: int, start: int, executable: str) -> None:
        process = proc / str(pid)
        process.mkdir(parents=True)
        process.joinpath("stat").write_text(
            f"{pid} (keystore2) S 1 {pid} {pid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {start} 0\n",
            encoding="ascii",
        )
        process.joinpath("exe").symlink_to(executable)

    @staticmethod
    def control(
        root: Path,
        state: Path,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ):
        return run(
            ["sh", str(CONTROL), "--root", str(root), "--state-root", str(state), *arguments],
            capture_output=True,
            check=False,
            env=os.environ | (environment or {}),
            text=True,
        )

    @staticmethod
    def supervisor(root: Path, state: Path, *arguments: str):
        return run(
            ["sh", str(SUPERVISOR), "--root", str(root), "--state-root", str(state), *arguments],
            capture_output=True,
            check=False,
            env=os.environ
            | {"RKA_SOCKET_CONTEXT": "?", "RKA_SOCKET_DIRECTORY_CONTEXT": "?"},
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
