from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Final
from typing import assert_never

from two_phone_lifecycle import Terminal, TwoPhoneRun
from two_phone_types import (
    Command,
    ErrorCode,
    RunConfig,
    RunError,
    RunState,
    parse_endpoint,
    parse_model,
    parse_module_dir,
    parse_serial,
    read_profiles,
)


TERMINAL_VERSION: Final = 1
DEFAULT_STATE_NAME: Final = "two-phone-run-v1.json"


class TerminalArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RunError(ErrorCode.INVALID_ARGUMENT)


def parser() -> TerminalArgumentParser:
    result = TerminalArgumentParser(add_help=False)
    result.add_argument("--adb", required=True)
    result.add_argument("--serial-a", required=True)
    result.add_argument("--serial-b", required=True)
    result.add_argument("--expected-model-a", required=True)
    result.add_argument("--expected-model-b", required=True)
    result.add_argument("--donor-endpoint", required=True)
    result.add_argument("--state-file")
    result.add_argument("--donor-profile")
    result.add_argument("--target-profile")
    result.add_argument("--donor-profile-id")
    result.add_argument("--module-dir")
    result.add_argument("--deadline-seconds", type=int, default=120)
    result.add_argument("command", choices=tuple(command.value for command in Command))
    return result


def parse_config(arguments: list[str]) -> tuple[RunConfig, Command]:
    namespace = parser().parse_args(arguments)
    if namespace.deadline_seconds < 1 or namespace.deadline_seconds > 120:
        raise RunError(ErrorCode.INVALID_ARGUMENT)
    state_path = namespace.state_file
    if state_path is None:
        state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
        state_path = state_home / "teesimulator" / DEFAULT_STATE_NAME
    config = RunConfig(
        adb=Path(namespace.adb),
        serial_a=parse_serial(namespace.serial_a),
        serial_b=parse_serial(namespace.serial_b),
        model_a=parse_model(namespace.expected_model_a),
        model_b=parse_model(namespace.expected_model_b),
        endpoint=parse_endpoint(namespace.donor_endpoint),
        state_file=Path(state_path),
        deadline_seconds=namespace.deadline_seconds,
        module_dir=parse_module_dir(namespace.module_dir),
        profiles=read_profiles(
            None if namespace.donor_profile is None else Path(namespace.donor_profile),
            None if namespace.target_profile is None else Path(namespace.target_profile),
            namespace.donor_profile_id,
        ),
    )
    return config, Command(namespace.command)


def terminal_json(terminal: Terminal) -> str:
    record: dict[str, int | str] = {
        "version": TERMINAL_VERSION,
        "command": terminal.command.value,
        "state": terminal.state.value,
        "status": "ok" if terminal.code is None else "error",
    }
    if terminal.code is not None:
        record["code"] = terminal.code.value
    encoded = json.dumps(record, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > 1_024:
        raise RuntimeError("terminal JSON exceeded its contract")
    return encoded


def failure(command: Command, code: ErrorCode) -> Terminal:
    return Terminal(command, RunState.CLEAN, code)


def main(arguments: list[str]) -> int:
    command = Command.PREFLIGHT
    try:
        config, command = parse_config(arguments)
        terminal = TwoPhoneRun(config).execute(command)
    except KeyboardInterrupt:
        terminal = failure(command, ErrorCode.CANCELLED)
    except RunError as error:
        terminal = failure(command, error.code)
    print(terminal_json(terminal))
    if terminal.code is None:
        return 0
    match terminal.code:
        case ErrorCode.CANCELLED:
            return 130
        case (
            ErrorCode.INVALID_ARGUMENT
            | ErrorCode.ADB_COMMAND_FAILED
            | ErrorCode.DEADLINE_EXCEEDED
            | ErrorCode.DEVICE_MODEL_MISMATCH
            | ErrorCode.FIXTURE_ERROR
            | ErrorCode.OPERATION_LIMIT
            | ErrorCode.STALE_STATE
            | ErrorCode.UNTRUSTED_OUTPUT
            | ErrorCode.READINESS_FAILED
            | ErrorCode.ATTESTATION_VERIFICATION_FAILED
        ):
            return 1
        case unreachable:
            assert_never(unreachable)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
