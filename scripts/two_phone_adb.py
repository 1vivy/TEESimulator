from __future__ import annotations

import base64
from dataclasses import dataclass
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import time
from typing import Final
from typing import assert_never

from two_phone_fixture import FixtureCommand, FixtureRequest, FixtureResult, action, parse_fixture
from two_phone_types import Endpoint, ErrorCode, RunError


MAX_ADB_OUTPUT_BYTES: Final = 1_048_576
@dataclass(frozen=True, slots=True)
class Deadline:
    expires_at: float

    @classmethod
    def after(cls, seconds: int) -> Deadline:
        return cls(time.monotonic() + seconds)

    def timeout(self) -> float:
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0:
            raise RunError(ErrorCode.DEADLINE_EXCEEDED)
        return remaining


class AdbClient:
    def __init__(self, adb: Path) -> None:
        self._adb = adb

    def check_model(self, serial: str, expected_model: str, deadline: Deadline) -> None:
        actual_model = self._single_line(self._run(serial, ("getprop", "ro.product.model"), deadline))
        if actual_model != expected_model:
            raise RunError(ErrorCode.DEVICE_MODEL_MISMATCH)

    def reachable_from_b(self, serial_b: str, endpoint: Endpoint, deadline: Deadline) -> None:
        self._run(
            serial_b,
            ("/system/bin/toybox", "nc", "-z", "-w", "5", endpoint.host, str(endpoint.port)),
            deadline,
        )

    def fixture(self, request: FixtureRequest, deadline: Deadline) -> FixtureResult:
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode("ascii")
        arguments = [
            "am",
            "broadcast",
            "--receiver-permission",
            "android.permission.DUMP",
            "-a",
            action(request.command),
            "--ei",
            "version",
            "1",
            "--es",
            "nonce",
            nonce,
            "--es",
            "metadata",
            f'{{"roles":["{request.role}"]}}',
        ]
        if request.profile is not None:
            arguments.extend(("--es", "profile", base64.b64encode(request.profile).decode("ascii")))
        if request.profile_id is not None:
            arguments.extend(("--es", "profileId", request.profile_id))
        if request.challenge is not None:
            arguments.extend(("--es", "challenge", base64.b64encode(request.challenge).decode("ascii")))
        return parse_fixture(request.command, self._run(request.serial, tuple(arguments), deadline))

    def start_controller(self, serial_b: str, module_dir: str, deadline: Deadline) -> None:
        self._run(
            serial_b,
            (
                "su",
                "0",
                "sh",
                "-c",
                'exec "$1/daemon" "$1" >/dev/null 2>&1 &',
                "sh",
                module_dir,
            ),
            deadline,
        )

    def close_controller(self, serial_b: str, deadline: Deadline) -> None:
        output = self._run(serial_b, ("pidof", "TEESimulator"), deadline)
        pids = output.split()
        if not pids:
            return
        if len(pids) != 1 or re.fullmatch(r"[1-9][0-9]{0,8}", pids[0]) is None:
            raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
        self._run(serial_b, ("su", "0", "kill", "-TERM", pids[0]), deadline)

    def restart_keystore2(self, serial_b: str, deadline: Deadline) -> None:
        self._run(serial_b, ("su", "0", "stop", "keystore2"), deadline)
        self._run(serial_b, ("su", "0", "start", "keystore2"), deadline)

    def keystore2_pid(self, serial_b: str, deadline: Deadline) -> str:
        output = self._run(serial_b, ("pidof", "keystore2"), deadline)
        pid = self._single_line(output)
        if re.fullmatch(r"[1-9][0-9]{0,8}", pid) is None:
            raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
        return pid

    def service_listing(self, serial_b: str, deadline: Deadline) -> tuple[str, ...]:
        lines = self._run(serial_b, ("service", "list"), deadline).splitlines()
        if len(lines) > 512 or any(not 1 <= len(line) <= 512 or "\x00" in line for line in lines):
            raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
        return tuple(lines)

    def keystore2_maps(self, serial_b: str, pid: str, deadline: Deadline) -> str:
        if re.fullmatch(r"[1-9][0-9]{0,8}", pid) is None:
            raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
        return self._run(serial_b, ("su", "0", "cat", f"/proc/{pid}/maps"), deadline)

    def _run(self, serial: str, remote: tuple[str, ...], deadline: Deadline) -> str:
        command = (str(self._adb), "-s", serial, "shell", *remote)
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                start_new_session=True,
            )
        except OSError as failure:
            raise RunError(ErrorCode.ADB_COMMAND_FAILED) from failure
        try:
            stdout, _ = process.communicate(timeout=deadline.timeout())
        except subprocess.TimeoutExpired as failure:
            self._kill_process_group(process)
            process.communicate()
            raise RunError(ErrorCode.DEADLINE_EXCEEDED) from failure
        except KeyboardInterrupt:
            self._kill_process_group(process)
            process.communicate()
            raise
        if process.returncode != 0:
            raise RunError(ErrorCode.ADB_COMMAND_FAILED)
        if len(stdout) > MAX_ADB_OUTPUT_BYTES:
            raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
        try:
            return stdout.decode("utf-8")
        except UnicodeDecodeError as failure:
            raise RunError(ErrorCode.UNTRUSTED_OUTPUT) from failure

    def _single_line(self, output: str) -> str:
        lines = output.splitlines()
        if len(lines) != 1 or not 1 <= len(lines[0]) <= 128:
            raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
        return lines[0]

    def _kill_process_group(self, process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
