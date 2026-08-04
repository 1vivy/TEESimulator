from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "rka-adb-stream-relay.py"
SPEC = importlib.util.spec_from_file_location("rka_adb_stream_relay", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
RELAY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RELAY
SPEC.loader.exec_module(RELAY)


class RkaAdbStreamRelayTest(unittest.TestCase):
    def write_pair(self, directory: Path) -> Path:
        path = directory / "device-pair.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "donor_serial": "donor-adb",
                    "candidate_serial": "candidate-adb",
                    "profile_sha256": "ab" * 32,
                }
            ),
            encoding="utf-8",
        )
        os.chmod(path, 0o600)
        return path

    def test_two_candidate_relays_run_concurrently(self) -> None:
        # Given
        pair = RELAY.DevicePair(
            donor_serial="donor-adb",
            candidate_serials=("candidate-a", "candidate-b"),
        )
        barrier = threading.Barrier(2)
        completed = threading.Event()

        def bridge(_adb: str, session: RELAY.RelaySession) -> RELAY.BridgeStats:
            barrier.wait(timeout=1)
            if session.candidate_serial == "candidate-a":
                raise RELAY.RelayFailure("CANDIDATE_ROUTE_UNAVAILABLE")
            completed.set()
            return RELAY.BridgeStats(donor_bytes=11, candidate_bytes=22, donor_tls_record=True)

        # When
        with mock.patch.object(RELAY, "candidate_address", return_value="127.0.0.1"):
            with mock.patch.object(RELAY, "bridge_once", side_effect=bridge):
                outcomes = RELAY.run_relays_once("fake-adb", pair)

        # Then
        self.assertTrue(completed.is_set())
        self.assertEqual(len(outcomes), 2)
        self.assertIsNone(outcomes[0].stats)
        self.assertEqual(outcomes[1].stats.donor_bytes, 11)
        self.assertEqual(outcomes[1].stats.candidate_bytes, 22)

    def test_reads_private_pair_without_logging_identifiers(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            pair = RELAY.read_device_pair(self.write_pair(Path(temporary_directory)))

        self.assertEqual(pair.donor_serial, "donor-adb")
        self.assertEqual(pair.candidate_serial, "candidate-adb")
        rendered = RELAY.BridgeStats(123, 456, True).render(789)
        self.assertNotIn(pair.donor_serial, rendered)
        self.assertNotIn(pair.candidate_serial, rendered)
        self.assertNotIn("100.", rendered)

    def test_rejects_non_private_or_linked_pair_file(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            pair_path = self.write_pair(directory)
            os.chmod(pair_path, 0o644)
            with self.assertRaisesRegex(RELAY.RelayFailure, "PAIR_FILE_UNSAFE"):
                RELAY.read_device_pair(pair_path)

            os.chmod(pair_path, 0o600)
            linked_path = directory / "linked-pair.json"
            linked_path.symlink_to(pair_path)
            with self.assertRaisesRegex(RELAY.RelayFailure, "PAIR_FILE_UNSAFE"):
                RELAY.read_device_pair(linked_path)

    @mock.patch.object(RELAY.subprocess, "run")
    def test_reads_candidate_route_from_root_direct_profile(
        self, run_mock: mock.Mock
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"100.64.0.8\n"
        )

        address = RELAY.candidate_address("adb-custom", "candidate-adb")

        self.assertEqual(address, "100.64.0.8")
        command = run_mock.call_args.args[0]
        self.assertEqual(
            command,
            ["adb-custom", "-s", "candidate-adb", "shell", "su", "0", "sh"],
        )
        self.assertIn(b"listen_interface=", run_mock.call_args.kwargs["input"])

    @mock.patch.object(RELAY.subprocess, "Popen")
    def test_donor_uses_shell_tty_disabled_stream_not_exec_out(
        self, popen_mock: mock.Mock
    ) -> None:
        process = object()
        popen_mock.return_value = process

        self.assertIs(RELAY.donor_listener("adb", "donor-adb"), process)

        command = popen_mock.call_args.args[0]
        self.assertEqual(
            command,
            [
                "adb",
                "-s",
                "donor-adb",
                "shell",
                "-T",
                "toybox",
                "nc",
                "-l",
                "-p",
                "37373",
            ],
        )
        self.assertNotIn("exec-out", command)


if __name__ == "__main__":
    unittest.main()
