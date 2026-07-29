from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from two_phone_adb import AdbClient, Deadline
from two_phone_fixture import FixtureCommand, FixtureRequest
from two_phone_types import ErrorCode, RunError, RunState


@dataclass(frozen=True, slots=True)
class CleanupPlan:
    serial_b: str
    native_proof: Callable[[Deadline], None]
    serial_a: str | None = None


@dataclass(frozen=True, slots=True)
class CleanupReceipt:
    state: RunState
    first_error: ErrorCode | None


class CleanupExecutor:
    def __init__(self, adb: AdbClient, plan: CleanupPlan) -> None:
        self._adb = adb
        self._plan = plan

    def run(self) -> CleanupReceipt:
        deadline = Deadline.after(10)
        first_error: ErrorCode | None = None
        actions: list[Callable[[], None]] = [
            lambda: self._adb.fixture(
                FixtureRequest(self._plan.serial_b, FixtureCommand.STOP, "TARGET"), deadline
            ),
            lambda: self._adb.close_controller(self._plan.serial_b, deadline),
        ]
        if self._plan.serial_a is not None:
            actions.append(
                lambda: self._adb.fixture(
                    FixtureRequest(self._plan.serial_a, FixtureCommand.STOP, "DONOR"), deadline
                )
            )
        actions.extend(
            (
                lambda: self._adb.restart_keystore2(self._plan.serial_b, deadline),
                lambda: self._plan.native_proof(deadline),
            )
        )
        for action in actions:
            try:
                action()
            except RunError as failure:
                if first_error is None:
                    first_error = failure.code
        state = RunState.CLEAN if first_error is None else RunState.DIRTY
        return CleanupReceipt(state, first_error)
