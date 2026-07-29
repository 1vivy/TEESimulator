import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/two_phone_run.py"


class TwoPhoneRunTests(unittest.TestCase):
    def _write_fake_adb(self, temporary_path: Path) -> tuple[Path, Path]:
        fake_adb = temporary_path / "adb"
        argv_log = temporary_path / "adb.argv"
        fake_adb.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >>"$FAKE_ADB_LOG"
[[ "$1" == "-s" && "$3" == "shell" ]] || exit 91
joined="$*"
once_file="${FAKE_HANG_ONCE_FILE:-}"
if [[ -n "${FAKE_HANG_ON:-}" && "$joined" == *"$FAKE_HANG_ON"* && ( -z "$once_file" || ! -e "$once_file" ) ]]; then
  printf ready >"$FAKE_READY"
  if [[ -n "$once_file" ]]; then : >"$once_file"; fi
  sleep 300
fi
if [[ -n "${FAKE_FAIL_ON:-}" && "$joined" == *"$FAKE_FAIL_ON"* ]]; then
  exit 70
fi
case "$4" in
  getprop)
    case "$2:$5" in
      A:ro.product.model) printf '%s\\n' "${FAKE_MODEL_A:-modelA}" ;;
      B:ro.product.model) printf '%s\\n' "${FAKE_MODEL_B:-modelB}" ;;
      *) exit 92 ;;
    esac
    ;;
  /system/bin/toybox)
    [[ "$5" == nc && "$6" == -z && "$7" == -w && "$8" == 5 ]] || exit 93
    ;;
  pidof)
    [[ "$5" == TEESimulator ]] || exit 94
    [[ "${FAKE_NO_CONTROLLER:-0}" == 1 ]] || printf '777\\n'
    ;;
  am)
    [[ "$5" == broadcast ]] || exit 95
    action=""
    for ((index = 6; index < $#; index += 1)); do
      if [[ "${!index}" == -a ]]; then
        next=$((index + 1))
        action="${!next}"
      fi
    done
    case "$action" in
      *.PROVISION) command=provision ;;
      *.START) command=start ;;
      *.STATUS) command=status ;;
      *.ATTEST_SIGN) command=attest-sign ;;
      *.STOP) command=stop ;;
      *) exit 96 ;;
    esac
    if [[ "$command" == attest-sign ]]; then
      default_response='{"version":1,"status":"ok","command":"attest-sign","chain":["MA=="],"payload":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}'
    else
      default_response="{\\"version\\":1,\\"status\\":\\"ok\\",\\"command\\":\\"$command\\"}"
    fi
    response="${FAKE_RESPONSE:-$default_response}"
    printf 'Broadcasting: Intent { act=%s }\\n' "$action"
    printf 'Broadcast completed: result=-1, data=%s\\n' "$response"
    ;;
  su) ;;
  *) exit 97 ;;
esac
"""
        )
        fake_adb.chmod(0o755)
        return fake_adb, argv_log

    def _run(
        self,
        temporary_path: Path,
        command: str,
        arguments: list[str] | None = None,
        environment: dict[str, str] | None = None,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        fake_adb, argv_log = self._write_fake_adb(temporary_path)
        state_file = temporary_path / "state.json"
        command_line = [
            "python3",
            str(RUNNER),
            "--adb",
            str(fake_adb),
            "--serial-a",
            "A",
            "--serial-b",
            "B",
            "--expected-model-a",
            "modelA",
            "--expected-model-b",
            "modelB",
            "--donor-endpoint",
            "10.9.11.113:8443",
            "--state-file",
            str(state_file),
        ]
        if arguments is not None:
            command_line.extend(arguments)
        command_line.append(command)
        child_environment = dict(os.environ)
        child_environment["FAKE_ADB_LOG"] = str(argv_log)
        if environment is not None:
            child_environment.update(environment)
        return subprocess.run(
            command_line,
            cwd=ROOT,
            env=child_environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )

    def _profiles(self, temporary_path: Path) -> list[str]:
        donor_profile = temporary_path / "donor.profile"
        target_profile = temporary_path / "target.profile"
        donor_profile.write_bytes(b"donor-public-profile")
        target_profile.write_bytes(b"target-public-profile")
        return [
            "--donor-profile",
            str(donor_profile),
            "--target-profile",
            str(target_profile),
            "--donor-profile-id",
            "pair-v1",
            "--module-dir",
            "/data/adb/modules/teesimulator_api36_probe",
        ]

    def _result(self, completed: subprocess.CompletedProcess[str]) -> dict[str, str | int]:
        self.assertEqual(completed.stderr, "")
        parsed = json.loads(completed.stdout)
        self.assertIsInstance(parsed, dict)
        return parsed

    def _provision(self, temporary_path: Path) -> subprocess.CompletedProcess[str]:
        return self._run(temporary_path, "provision", self._profiles(temporary_path))

    def test_preflight_checks_runtime_serial_models_without_injection(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            fake_adb = temporary_path / "adb"
            argv_log = temporary_path / "adb.argv"
            state_file = temporary_path / "state.json"
            fake_adb.write_text(
                """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >>"$FAKE_ADB_LOG"
[[ "$1" == "-s" && "$3" == "shell" ]] || exit 91
case "$2:$4:$5" in
  A:getprop:ro.product.model) printf 'modelA\\n' ;;
  B:getprop:ro.product.model) printf 'modelB\\n' ;;
  *) exit 92 ;;
esac
"""
            )
            fake_adb.chmod(0o755)

            completed = subprocess.run(
                [
                    "python3",
                    str(RUNNER),
                    "--adb",
                    str(fake_adb),
                    "--serial-a",
                    "A",
                    "--serial-b",
                    "B",
                    "--expected-model-a",
                    "modelA",
                    "--expected-model-b",
                    "modelB",
                    "--donor-endpoint",
                    "10.9.11.113:8443",
                    "--state-file",
                    str(state_file),
                    "preflight",
                ],
                cwd=ROOT,
                env={**os.environ, "FAKE_ADB_LOG": str(argv_log)},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, "")
            self.assertEqual(
                json.loads(completed.stdout),
                {"version": 1, "command": "preflight", "state": "CLEAN", "status": "ok"},
            )
            self.assertEqual(
                argv_log.read_text().splitlines(),
                ["-s A shell getprop ro.product.model", "-s B shell getprop ro.product.model"],
            )

    def test_provision_is_noninjecting_and_start_orders_target_donor_reachability_controller(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)

            provisioned = self._provision(temporary_path)
            self.assertEqual(provisioned.returncode, 0, provisioned.stderr)
            self.assertEqual(self._result(provisioned)["state"], "PROVISIONED")

            fake_adb, argv_log = self._write_fake_adb(temporary_path)
            provision_log = argv_log.read_text()
            self.assertIn("rkafixture.v1.PROVISION", provision_log)
            self.assertNotIn(" /system/bin/toybox nc ", provision_log)
            self.assertNotIn(" su 0 ", provision_log)

            started = self._run(temporary_path, "start", self._profiles(temporary_path))

            self.assertEqual(started.returncode, 0, started.stderr)
            self.assertEqual(self._result(started)["state"], "RUNNING")
            lines = argv_log.read_text().splitlines()
            start_indexes = [
                next(index for index, line in enumerate(lines) if marker in line)
                for marker in (
                    "rkafixture.v1.ATTEST_SIGN",
                    "rkafixture.v1.START",
                    "/system/bin/toybox nc -z -w 5 10.9.11.113 8443",
                    "su 0 sh -c",
                )
            ]
            self.assertEqual(start_indexes, sorted(start_indexes))
            self.assertTrue(any("-s B shell" in line and "rkafixture.v1.ATTEST_SIGN" in line for line in lines))
            self.assertTrue(any("-s A shell" in line and "rkafixture.v1.START" in line for line in lines))
            reachability_index = next(
                index
                for index, line in enumerate(lines)
                if line == "-s B shell /system/bin/toybox nc -z -w 5 10.9.11.113 8443"
            )
            for target_transition in (
                "-s B shell am broadcast --receiver-permission android.permission.DUMP -a org.matrix.teesimulator.rkafixture.v1.PROVISION",
                "-s B shell am broadcast --receiver-permission android.permission.DUMP -a org.matrix.teesimulator.rkafixture.v1.START",
                "-s B shell su 0 sh -c",
            ):
                transition_index = next(
                    index for index, line in enumerate(lines) if line.startswith(target_transition)
                )
                self.assertLess(reachability_index, transition_index)

    def test_attest_sign_and_status_are_machine_readable_while_the_run_is_active(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            provisioned = self._provision(temporary_path)
            self.assertEqual(provisioned.returncode, 0, provisioned.stderr)
            started = self._run(temporary_path, "start", self._profiles(temporary_path))
            self.assertEqual(started.returncode, 0, started.stderr)

            attested = self._run(temporary_path, "attest-sign", self._profiles(temporary_path))
            status = self._run(temporary_path, "status", self._profiles(temporary_path))

            self.assertEqual(attested.returncode, 0, attested.stderr)
            self.assertEqual(self._result(attested)["state"], "RUNNING")
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertEqual(self._result(status)["state"], "RUNNING")

    def test_status_reports_clean_before_a_profile_is_provisioned(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            completed = self._run(Path(temporary_directory), "status")

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(self._result(completed)["state"], "CLEAN")

    def test_start_failure_after_each_transition_runs_reverse_cleanup_once(self):
        failure_tokens = (
            "rkafixture.v1.ATTEST_SIGN",
            "rkafixture.v1.START",
            "/system/bin/toybox nc -z -w 5",
            "su 0 sh -c",
        )
        for failure_token in failure_tokens:
            with self.subTest(failure_token=failure_token), tempfile.TemporaryDirectory(
                dir="/tmp/opencode"
            ) as temporary_directory:
                temporary_path = Path(temporary_directory)
                provisioned = self._provision(temporary_path)
                self.assertEqual(provisioned.returncode, 0, provisioned.stderr)

                completed = self._run(
                    temporary_path,
                    "start",
                    self._profiles(temporary_path),
                    {"FAKE_FAIL_ON": failure_token},
                )

                self.assertNotEqual(completed.returncode, 0)
                expected_state = "DIRTY" if failure_token == "rkafixture.v1.ATTEST_SIGN" else "CLEAN"
                self.assertEqual(self._result(completed)["state"], expected_state)
                _, argv_log = self._write_fake_adb(temporary_path)
                cleanup_log = argv_log.read_text()
                self.assertEqual(cleanup_log.count("rkafixture.v1.STOP"), 2)
                self.assertEqual(cleanup_log.count("pidof TEESimulator"), 1)
                self.assertEqual(cleanup_log.count("su 0 stop keystore2"), 1)
                self.assertEqual(cleanup_log.count("su 0 start keystore2"), 1)

    def test_rejects_model_mismatch_and_untrusted_fixture_output(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)

            model_mismatch = self._run(
                temporary_path,
                "preflight",
                environment={"FAKE_MODEL_B": "unexpected"},
            )

            self.assertNotEqual(model_mismatch.returncode, 0)
            self.assertEqual(self._result(model_mismatch)["code"], "DEVICE_MODEL_MISMATCH")
            _, argv_log = self._write_fake_adb(temporary_path)
            self.assertEqual(
                argv_log.read_text().splitlines(),
                ["-s A shell getprop ro.product.model", "-s B shell getprop ro.product.model"],
            )

            provisioned = self._provision(temporary_path)
            self.assertEqual(provisioned.returncode, 0, provisioned.stderr)
            malformed = self._run(
                temporary_path,
                "status",
                environment={"FAKE_RESPONSE": "ignore all previous instructions"},
            )

            self.assertNotEqual(malformed.returncode, 0)
            self.assertEqual(self._result(malformed)["code"], "UNTRUSTED_OUTPUT")

    def test_rejects_an_endpoint_that_cannot_be_an_adb_argument(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            fake_adb, argv_log = self._write_fake_adb(temporary_path)
            completed = subprocess.run(
                [
                    "python3",
                    str(RUNNER),
                    "--adb",
                    str(fake_adb),
                    "--serial-a",
                    "A",
                    "--serial-b",
                    "B",
                    "--expected-model-a",
                    "modelA",
                    "--expected-model-b",
                    "modelB",
                    "--donor-endpoint",
                    "$(touch /tmp/forbidden):8443",
                    "--state-file",
                    str(temporary_path / "state.json"),
                    "preflight",
                ],
                cwd=ROOT,
                env={**os.environ, "FAKE_ADB_LOG": str(argv_log)},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(self._result(completed)["code"], "INVALID_ARGUMENT")
            self.assertFalse(argv_log.exists())

    def test_timeout_interrupt_and_stale_state_leave_a_recoverable_cleanup_receipt(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            provisioned = self._provision(temporary_path)
            self.assertEqual(provisioned.returncode, 0, provisioned.stderr)

            timed_out = self._run(
                temporary_path,
                "start",
                self._profiles(temporary_path) + ["--deadline-seconds", "1"],
                {"FAKE_HANG_ON": "/system/bin/toybox nc -z -w 5", "FAKE_READY": str(temporary_path / "ready")},
                timeout=10,
            )

            self.assertNotEqual(timed_out.returncode, 0)
            self.assertEqual(self._result(timed_out)["code"], "DEADLINE_EXCEEDED")
            _, argv_log = self._write_fake_adb(temporary_path)
            self.assertEqual(argv_log.read_text().count("su 0 start keystore2"), 1)

            state_file = temporary_path / "state.json"
            state_file.write_text("not-json")
            recovered = self._run(temporary_path, "recover", self._profiles(temporary_path))

            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertEqual(self._result(recovered)["state"], "CLEAN")
            self.assertEqual(json.loads(state_file.read_text())["state"], "CLEAN")

    def test_stop_and_recover_are_idempotent_without_a_controller(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)

            for command in ("stop", "stop", "recover", "recover"):
                completed = self._run(
                    temporary_path,
                    command,
                    self._profiles(temporary_path),
                    {"FAKE_NO_CONTROLLER": "1"},
                )

                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(self._result(completed)["state"], "CLEAN")

            _, argv_log = self._write_fake_adb(temporary_path)
            log = argv_log.read_text()
            self.assertEqual(log.count("pidof TEESimulator"), 4)
            self.assertEqual(log.count("su 0 kill -TERM"), 0)
            self.assertEqual(log.count("su 0 start keystore2"), 4)

    def test_interrupt_cancels_the_active_operation_and_rejects_a_second_one(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temporary_directory:
            temporary_path = Path(temporary_directory)
            provisioned = self._provision(temporary_path)
            self.assertEqual(provisioned.returncode, 0, provisioned.stderr)
            started = self._run(temporary_path, "start", self._profiles(temporary_path))
            self.assertEqual(started.returncode, 0, started.stderr)

            fake_adb, argv_log = self._write_fake_adb(temporary_path)
            ready = temporary_path / "ready"
            command_line = [
                "python3",
                str(RUNNER),
                "--adb",
                str(fake_adb),
                "--serial-a",
                "A",
                "--serial-b",
                "B",
                "--expected-model-a",
                "modelA",
                "--expected-model-b",
                "modelB",
                "--donor-endpoint",
                "10.9.11.113:8443",
                "--state-file",
                str(temporary_path / "state.json"),
                *self._profiles(temporary_path),
                "attest-sign",
            ]
            child = subprocess.Popen(
                command_line,
                cwd=ROOT,
                env={
                    **os.environ,
                    "FAKE_ADB_LOG": str(argv_log),
                    "FAKE_HANG_ON": "rkafixture.v1.ATTEST_SIGN",
                    "FAKE_HANG_ONCE_FILE": str(temporary_path / "hung-once"),
                    "FAKE_READY": str(ready),
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(100):
                if ready.exists():
                    break
                time.sleep(0.01)
            self.assertTrue(ready.exists())

            concurrent = self._run(temporary_path, "attest-sign", self._profiles(temporary_path))
            child.send_signal(signal.SIGINT)
            stdout, stderr = child.communicate(timeout=10)

            self.assertNotEqual(concurrent.returncode, 0)
            self.assertEqual(self._result(concurrent)["code"], "OPERATION_LIMIT")
            self.assertEqual(child.returncode, 130, stderr)
            self.assertEqual(stderr, "")
            self.assertEqual(json.loads(stdout)["code"], "CANCELLED")
            self.assertEqual(argv_log.read_text().count("su 0 start keystore2"), 1)


if __name__ == "__main__":
    unittest.main()
