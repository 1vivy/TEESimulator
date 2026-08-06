from __future__ import annotations

import hashlib
import os
from pathlib import Path
import signal
import socket
from subprocess import Popen, run
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
SUPERVISOR = ROOT / "module" / "rka-supervisor.sh"


class RuntimeEvidenceStatusTest(unittest.TestCase):
    def test_running_status_requires_current_receipt_and_socket(self) -> None:
        for candidate in (None, "candidate-a"):
            for missing in ("receipt", "socket"):
                with self.subTest(candidate=candidate, missing=missing):
                    self.assert_status_degrades(candidate, missing)

    def assert_status_degrades(self, candidate: str | None, missing: str) -> None:
        processes: list[Popen[bytes]] = []
        listener: socket.socket | None = None
        try:
            with TemporaryDirectory() as directory:
                base = Path(directory)
                root = base / "module"
                state = base / "state"
                root.mkdir()
                profile = self.write_profiles(state, candidate)
                run_directory = state / "run"
                pids = run_directory / "pids"
                sockets = run_directory / "sockets"
                pids.mkdir(parents=True)
                sockets.mkdir()
                sockets.chmod(0o700)
                suffix = f"-{candidate}" if candidate else ""
                marker = run_directory / f"supervisor{suffix}.state"
                marker.write_text("RUNNING\n", encoding="ascii")
                marker.chmod(0o600)
                for name in (f"broker{suffix}", f"sidecar{suffix}"):
                    process = Popen(["sleep", "30"], start_new_session=True)
                    processes.append(process)
                    self.write_record(pids / f"{name}.pid", process.pid)
                receipt = run_directory / f"direct-profile{suffix}.receipt"
                receipt.write_text(
                    "version=1\n"
                    f"profile_sha256={hashlib.sha256(profile.read_bytes()).hexdigest()}\n"
                    "profile_epoch=0\n"
                    f"peer_pin_sha256={'cd' * 32}\n"
                    "dial_mode=DONOR_DIALS\n"
                    "transport=DIRECT\n",
                    encoding="ascii",
                )
                receipt.chmod(0o600)
                socket_path = sockets / f"broker{suffix}.sock"
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(str(socket_path))
                socket_path.chmod(0o600)

                baseline = self.status(root, state, candidate)
                self.assertIn("state=RUNNING\n", baseline.stdout)
                if missing == "receipt":
                    receipt.unlink()
                else:
                    socket_path.unlink()
                degraded = self.status(root, state, candidate)

                self.assertEqual(degraded.returncode, 0, degraded.stderr)
                self.assertIn("state=NOT_READY\n", degraded.stdout)
        finally:
            if listener is not None:
                listener.close()
            for process in processes:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=5)

    def test_aggregate_multi_candidate_status_uses_candidate_graphs(self) -> None:
        processes: list[Popen[bytes]] = []
        listeners: list[socket.socket] = []
        try:
            with TemporaryDirectory() as directory:
                base = Path(directory)
                root = base / "module"
                state = base / "state"
                root.mkdir()
                run_directory = state / "run"
                pids = run_directory / "pids"
                sockets = run_directory / "sockets"
                pids.mkdir(parents=True)
                sockets.mkdir()
                sockets.chmod(0o700)
                marker = run_directory / "supervisor.state"
                marker.write_text("RUNNING\n", encoding="ascii")
                marker.chmod(0o600)
                candidate_b_receipt: Path | None = None
                candidate_b_receipt_contents = ""
                candidate_b_socket: Path | None = None
                for candidate in ("candidate-a", "candidate-b"):
                    profile = self.write_profiles(state, candidate)
                    for kind in ("broker", "sidecar"):
                        process = Popen(["sleep", "30"], start_new_session=True)
                        processes.append(process)
                        self.write_record(pids / f"{kind}-{candidate}.pid", process.pid)
                    candidate_marker = run_directory / f"supervisor-{candidate}.state"
                    candidate_marker.write_text("RUNNING\n", encoding="ascii")
                    candidate_marker.chmod(0o600)
                    receipt = run_directory / f"direct-profile-{candidate}.receipt"
                    receipt_contents = (
                        "version=1\n"
                        f"profile_sha256={hashlib.sha256(profile.read_bytes()).hexdigest()}\n"
                        "profile_epoch=0\n"
                        f"peer_pin_sha256={'cd' * 32}\n"
                        "dial_mode=DONOR_DIALS\n"
                        "transport=DIRECT\n"
                    )
                    receipt.write_text(receipt_contents, encoding="ascii")
                    receipt.chmod(0o600)
                    socket_path = sockets / f"broker-{candidate}.sock"
                    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    listener.bind(str(socket_path))
                    socket_path.chmod(0o600)
                    listeners.append(listener)
                    if candidate == "candidate-b":
                        candidate_b_receipt = receipt
                        candidate_b_receipt_contents = receipt_contents
                        candidate_b_socket = socket_path

                baseline = self.status(root, state, None)
                self.assertIn("state=RUNNING\n", baseline.stdout)
                if candidate_b_receipt is None or candidate_b_socket is None:
                    raise AssertionError("candidate-b evidence was not created")
                candidate_b_receipt.unlink()
                missing_receipt = self.status(root, state, None)
                self.assertIn("state=NOT_READY\n", missing_receipt.stdout)
                candidate_b_receipt.write_text(candidate_b_receipt_contents, encoding="ascii")
                candidate_b_receipt.chmod(0o600)
                candidate_b_socket.unlink()
                missing_socket = self.status(root, state, None)
                self.assertIn("state=NOT_READY\n", missing_socket.stdout)
        finally:
            for listener in listeners:
                listener.close()
            for process in processes:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=5)

    @staticmethod
    def write_profiles(state: Path, candidate: str | None) -> Path:
        profiles = state / "profiles"
        profiles.mkdir(parents=True, exist_ok=True)
        active = profiles / "active.conf"
        active.write_text("version=1\nrole=DONOR\nprofile_epoch=0\n", encoding="ascii")
        active.chmod(0o600)
        profile = (
            profiles / "direct.conf"
            if candidate is None
            else profiles / "direct.d" / f"{candidate}.conf"
        )
        profile.parent.mkdir(parents=True, exist_ok=True)
        profile.write_text(
            "version=2\n"
            "role=DONOR\n"
            "profile_epoch=0\n"
            "dial_mode=DONOR_DIALS\n"
            "dial_endpoint=100.64.0.2\n"
            "listen_interface=100.64.0.1\n"
            f"peer_spki_sha256={'ab' * 32}\n"
            "transport=DIRECT\n",
            encoding="ascii",
        )
        profile.chmod(0o600)
        return profile

    @staticmethod
    def write_record(path: Path, pid: int) -> None:
        facts = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = facts[facts.rfind(")") + 2 :].split()
        path.write_text(f"{pid} {fields[2]} {fields[19]}\n", encoding="ascii")
        path.chmod(0o600)

    @staticmethod
    def status(root: Path, state: Path, candidate: str | None):
        arguments = [
            "sh",
            str(SUPERVISOR),
            "--root",
            str(root),
            "--state-root",
            str(state),
            "status",
        ]
        if candidate is not None:
            arguments.append(candidate)
        return run(
            arguments,
            capture_output=True,
            check=False,
            env=os.environ
            | {
                "RKA_DAEMON": str(root / "fake-daemon"),
                "RKA_SIDECAR": str(root / "fake-sidecar"),
                "RKA_SOCKET_CONTEXT": "?",
                "RKA_SOCKET_DIRECTORY_CONTEXT": "?",
            },
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
