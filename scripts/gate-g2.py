from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Final
from typing import assert_never

from two_phone_attestation import load_trust_anchors
from two_phone_g2 import GateConfig, GateG2, GateTerminal
from two_phone_types import ErrorCode, RunError, RunState, parse_model, parse_module_dir, parse_serial


TERMINAL_VERSION: Final = 1
DEFAULT_STATE_NAME: Final = "gate-g2-v1.json"


class GateArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RunError(ErrorCode.INVALID_ARGUMENT)


def parser() -> GateArgumentParser:
    result = GateArgumentParser(add_help=True)
    result.add_argument("--adb", required=True)
    result.add_argument("--serial-b", required=True)
    result.add_argument("--expected-model-b", required=True)
    result.add_argument("--module-dir", required=True)
    result.add_argument("--trust-anchor", action="append", required=True)
    result.add_argument("--state-file")
    result.add_argument("--deadline-seconds", type=int, default=120)
    result.add_argument("--readiness-seconds", type=int, default=2)
    return result


def parse_config(arguments: list[str]) -> GateConfig:
    namespace = parser().parse_args(arguments)
    if not 1 <= namespace.deadline_seconds <= 120 or not 1 <= namespace.readiness_seconds <= 30:
        raise RunError(ErrorCode.INVALID_ARGUMENT)
    state_path = namespace.state_file
    if state_path is None:
        state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
        state_path = state_home / "teesimulator" / DEFAULT_STATE_NAME
    module_dir = parse_module_dir(namespace.module_dir)
    if module_dir is None:
        raise RunError(ErrorCode.INVALID_ARGUMENT)
    return GateConfig(
        Path(namespace.adb),
        parse_serial(namespace.serial_b),
        parse_model(namespace.expected_model_b),
        module_dir,
        Path(state_path),
        namespace.deadline_seconds,
        namespace.readiness_seconds,
        load_trust_anchors(tuple(Path(path) for path in namespace.trust_anchor)),
    )


def terminal_json(terminal: GateTerminal) -> str:
    record: dict[str, bool | int | str] = {
        "version": TERMINAL_VERSION,
        "gate": "G2",
        "verdict": "PASS" if terminal.code is None else "STOP",
        "attempts": terminal.attempts,
        "proofs": terminal.proofs,
        "pidChanged": terminal.pid_changed,
        "servicesReady": terminal.services_ready,
        "hookAbsent": terminal.hook_absent,
        "cleanup": terminal.cleanup.value,
    }
    if terminal.code is not None:
        record["code"] = terminal.code.value
    encoded = json.dumps(record, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > 1_024:
        raise RuntimeError("terminal JSON exceeded its contract")
    return encoded


def failure(code: ErrorCode) -> GateTerminal:
    return GateTerminal(code, 0, 0, False, False, False, RunState.DIRTY)


def main(arguments: list[str]) -> int:
    try:
        terminal = GateG2(parse_config(arguments)).execute()
    except KeyboardInterrupt:
        terminal = failure(ErrorCode.CANCELLED)
    except RunError as failure_error:
        terminal = failure(failure_error.code)
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
