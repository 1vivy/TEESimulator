from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import assert_never

from two_phone_adb import AdbClient, Deadline
from two_phone_cleanup import CleanupExecutor, CleanupPlan, CleanupReceipt
from two_phone_fixture import FixtureCommand, FixtureRequest
from two_phone_state import StateStore
from two_phone_types import Command, ErrorCode, RunConfig, RunError, RunState, StoredState


@dataclass(frozen=True, slots=True)
class Terminal:
    command: Command
    state: RunState
    code: ErrorCode | None


class TwoPhoneRun:
    def __init__(self, config: RunConfig) -> None:
        self._config = config
        self._adb = AdbClient(config.adb)
        self._store = StateStore(config.state_file)

    def execute(self, command: Command) -> Terminal:
        try:
            with self._store.lock():
                return self._execute_locked(command)
        except RunError as failure:
            return Terminal(command, RunState.CLEAN, failure.code)

    def _execute_locked(self, command: Command) -> Terminal:
        match command:
            case Command.PREFLIGHT:
                self._verify_devices(Deadline.after(self._config.deadline_seconds))
                return Terminal(command, RunState.CLEAN, None)
            case (
                Command.PROVISION
                | Command.START
                | Command.ATTEST_SIGN
                | Command.STATUS
                | Command.STOP
                | Command.RECOVER
            ):
                return self._execute_transition(command)
            case unreachable:
                assert_never(unreachable)

    def _execute_transition(self, command: Command) -> Terminal:
        try:
            self._verify_devices(Deadline.after(self._config.deadline_seconds))
            match command:
                case Command.PROVISION:
                    return self._provision(command)
                case Command.START:
                    return self._start(command)
                case Command.ATTEST_SIGN:
                    return self._attest_sign(command)
                case Command.STATUS:
                    return self._status(command)
                case Command.STOP | Command.RECOVER:
                    return self._stop(command)
        except KeyboardInterrupt:
            receipt = self._cleanup()
            return Terminal(command, receipt.state, ErrorCode.CANCELLED)
        except RunError as failure:
            receipt = self._cleanup()
            return Terminal(command, receipt.state, failure.code)

    def _provision(self, command: Command) -> Terminal:
        profiles = self._profiles()
        deadline = Deadline.after(self._config.deadline_seconds)
        self._adb.fixture(
            FixtureRequest(self._config.serial_a, FixtureCommand.PROVISION, "DONOR", profile=profiles.donor),
            deadline,
        )
        self._store.write(StoredState(RunState.PROVISIONED, self._config.fingerprint, profiles.fingerprint, False))
        return Terminal(command, RunState.PROVISIONED, None)

    def _start(self, command: Command) -> Terminal:
        profiles = self._profiles()
        if self._config.module_dir is None:
            raise RunError(ErrorCode.INVALID_ARGUMENT)
        state = self._compatible_state(profiles.fingerprint)
        match state.state:
            case RunState.PROVISIONED:
                if state.active_operation:
                    raise RunError(ErrorCode.STALE_STATE)
            case RunState.CLEAN | RunState.RUNNING | RunState.DIRTY:
                raise RunError(ErrorCode.STALE_STATE)
            case unreachable:
                assert_never(unreachable)
        deadline = Deadline.after(self._config.deadline_seconds)
        self._adb.fixture(
            FixtureRequest(
                self._config.serial_b,
                FixtureCommand.ATTEST_SIGN,
                "TARGET",
                challenge=secrets.token_bytes(32),
            ),
            deadline,
        )
        self._adb.fixture(
            FixtureRequest(self._config.serial_a, FixtureCommand.START, "DONOR", profile_id=profiles.donor_id),
            deadline,
        )
        self._adb.reachable_from_b(self._config.serial_b, self._config.endpoint, deadline)
        self._adb.fixture(
            FixtureRequest(self._config.serial_b, FixtureCommand.PROVISION, "TARGET", profile=profiles.target),
            deadline,
        )
        self._adb.fixture(
            FixtureRequest(self._config.serial_b, FixtureCommand.START, "TARGET", profile_id=profiles.donor_id),
            deadline,
        )
        self._adb.start_controller(self._config.serial_b, self._config.module_dir, deadline)
        self._store.write(StoredState(RunState.RUNNING, self._config.fingerprint, profiles.fingerprint, False))
        return Terminal(command, RunState.RUNNING, None)

    def _attest_sign(self, command: Command) -> Terminal:
        profiles = self._profiles()
        state = self._compatible_state(profiles.fingerprint)
        match state.state:
            case RunState.RUNNING:
                if state.active_operation:
                    raise RunError(ErrorCode.OPERATION_LIMIT)
            case RunState.CLEAN | RunState.PROVISIONED | RunState.DIRTY:
                raise RunError(ErrorCode.OPERATION_LIMIT)
            case unreachable:
                assert_never(unreachable)
        self._store.write(StoredState(RunState.RUNNING, self._config.fingerprint, profiles.fingerprint, True))
        self._adb.fixture(
            FixtureRequest(
                self._config.serial_b,
                FixtureCommand.ATTEST_SIGN,
                "TARGET",
                challenge=secrets.token_bytes(32),
            ),
            Deadline.after(self._config.deadline_seconds),
        )
        self._store.write(StoredState(RunState.RUNNING, self._config.fingerprint, profiles.fingerprint, False))
        return Terminal(command, RunState.RUNNING, None)

    def _status(self, command: Command) -> Terminal:
        state = self._compatible_state(None)
        self._adb.fixture(
            FixtureRequest(self._config.serial_b, FixtureCommand.STATUS, "TARGET"),
            Deadline.after(self._config.deadline_seconds),
        )
        return Terminal(command, state.state, None)

    def _stop(self, command: Command) -> Terminal:
        receipt = self._cleanup()
        return Terminal(command, receipt.state, receipt.first_error)

    def _cleanup(self) -> CleanupReceipt:
        def native_proof(deadline: Deadline) -> None:
            self._adb.fixture(
                FixtureRequest(
                    self._config.serial_b,
                    FixtureCommand.ATTEST_SIGN,
                    "TARGET",
                    challenge=secrets.token_bytes(32),
                ),
                deadline,
            )

        receipt = CleanupExecutor(
            self._adb,
            CleanupPlan(self._config.serial_b, native_proof, self._config.serial_a),
        ).run()
        profiles = self._config.profiles
        profile_fingerprint = "" if profiles is None else profiles.fingerprint
        self._store.write(StoredState(receipt.state, self._config.fingerprint, profile_fingerprint, False))
        return receipt

    def _verify_devices(self, deadline: Deadline) -> None:
        self._adb.check_model(self._config.serial_a, self._config.model_a, deadline)
        self._adb.check_model(self._config.serial_b, self._config.model_b, deadline)

    def _profiles(self):
        profiles = self._config.profiles
        if profiles is None:
            raise RunError(ErrorCode.INVALID_ARGUMENT)
        return profiles

    def _compatible_state(self, profile_fingerprint: str | None) -> StoredState:
        state = self._store.load()
        match state.state:
            case RunState.CLEAN:
                if state.fingerprint == "":
                    return state
            case RunState.PROVISIONED | RunState.RUNNING | RunState.DIRTY:
                pass
            case unreachable:
                assert_never(unreachable)
        if state.fingerprint != self._config.fingerprint:
            raise RunError(ErrorCode.STALE_STATE)
        if profile_fingerprint is not None and state.profile_fingerprint != profile_fingerprint:
            raise RunError(ErrorCode.STALE_STATE)
        return state
