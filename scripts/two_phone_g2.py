from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import secrets
import time
from typing import Final

from two_phone_adb import AdbClient, Deadline
from two_phone_attestation import TrustAnchor, verify_native_proof
from two_phone_cleanup import CleanupExecutor, CleanupPlan, CleanupReceipt
from two_phone_fixture import FixtureCommand, FixtureRequest
from two_phone_state import StateStore
from two_phone_types import ErrorCode, RunError, RunState, StoredState


EXPECTED_SERVICES: Final = (
    "android.system.keystore2.IKeystoreService/default",
    "android.hardware.security.keymint.IKeyMintDevice/default",
)
MAX_RESTART_ATTEMPTS: Final = 2
POLL_SECONDS: Final = 0.05


@dataclass(frozen=True, slots=True)
class GateConfig:
    adb: Path
    serial_b: str
    model_b: str
    module_dir: str
    state_file: Path
    deadline_seconds: int
    readiness_seconds: int
    trust_anchors: tuple[TrustAnchor, ...]

    @property
    def fingerprint(self) -> str:
        encoded = f"{self.serial_b}\x00{self.model_b}\x00{self.module_dir}".encode() + b"".join(anchor.der for anchor in self.trust_anchors)
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class KeystoreSnapshot:
    pid: str
    maps_digest: str
    services_digest: str
    services_ready: bool
    hook_absent: bool


@dataclass(frozen=True, slots=True)
class GateTerminal:
    code: ErrorCode | None
    attempts: int
    proofs: int
    pid_changed: bool
    services_ready: bool
    hook_absent: bool
    cleanup: RunState


class GateG2:
    def __init__(self, config: GateConfig) -> None:
        self._config = config
        self._adb = AdbClient(config.adb)
        self._store = StateStore(config.state_file)

    def execute(self) -> GateTerminal:
        try:
            with self._store.lock():
                return self._execute_locked()
        except RunError as failure:
            return GateTerminal(failure.code, 0, 0, False, False, False, RunState.DIRTY)

    def _execute_locked(self) -> GateTerminal:
        code: ErrorCode | None = None
        attempts = 0
        proofs = 0
        pid_changed = False
        services_ready = False
        hook_absent = False
        try:
            self._check_state()
            deadline = Deadline.after(self._config.deadline_seconds)
            self._adb.check_model(self._config.serial_b, self._config.model_b, deadline)
            self._baseline(deadline)
            first_challenge = self._native_proof(deadline)
            proofs += 1
            before = self._stable_snapshot(deadline)
            after: KeystoreSnapshot | None = None
            for attempt in range(MAX_RESTART_ATTEMPTS):
                attempts = attempt + 1
                self._adb.restart_keystore2(self._config.serial_b, deadline)
                after = self._wait_for_readiness(before, deadline)
                if after is not None:
                    break
            if after is None:
                raise RunError(ErrorCode.READINESS_FAILED)
            pid_changed = after.pid != before.pid
            services_ready = after.services_ready
            hook_absent = after.hook_absent
            second_challenge = self._native_proof(deadline)
            proofs += 1
            if second_challenge == first_challenge:
                raise RunError(ErrorCode.ATTESTATION_VERIFICATION_FAILED)
        except KeyboardInterrupt:
            code = ErrorCode.CANCELLED
        except RunError as failure:
            code = failure.code
        receipt = self._cleanup()
        if receipt.state is RunState.CLEAN:
            proofs += 1
        if code is None:
            code = receipt.first_error
        self._store.write(StoredState(receipt.state, self._config.fingerprint, "g2", False))
        return GateTerminal(code, attempts, proofs, pid_changed, services_ready, hook_absent, receipt.state)

    def _check_state(self) -> None:
        state = self._store.load()
        if state.state is not RunState.CLEAN:
            raise RunError(ErrorCode.STALE_STATE)
        if state.fingerprint not in ("", self._config.fingerprint):
            raise RunError(ErrorCode.STALE_STATE)

    def _baseline(self, deadline: Deadline) -> None:
        self._adb.fixture(FixtureRequest(self._config.serial_b, FixtureCommand.STOP, "TARGET"), deadline)
        self._adb.close_controller(self._config.serial_b, deadline)
        snapshot = self._stable_snapshot(deadline)
        if not snapshot.services_ready or not snapshot.hook_absent:
            raise RunError(ErrorCode.READINESS_FAILED)

    def _native_proof(self, deadline: Deadline) -> bytes:
        challenge = secrets.token_bytes(32)
        result = self._adb.fixture(
            FixtureRequest(
                self._config.serial_b,
                FixtureCommand.ATTEST_SIGN,
                "TARGET",
                challenge=challenge,
            ),
            deadline,
        )
        if result.proof is None:
            raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
        verify_native_proof(result.proof, challenge, self._config.trust_anchors)
        return challenge

    def _stable_snapshot(self, deadline: Deadline) -> KeystoreSnapshot:
        first = self._snapshot(deadline)
        second = self._snapshot(deadline)
        if first != second:
            raise RunError(ErrorCode.READINESS_FAILED)
        return first

    def _snapshot(self, deadline: Deadline) -> KeystoreSnapshot:
        pid = self._adb.keystore2_pid(self._config.serial_b, deadline)
        maps = self._adb.keystore2_maps(self._config.serial_b, pid, deadline)
        services = self._adb.service_listing(self._config.serial_b, deadline)
        maps_lower = maps.lower()
        hook_absent = self._config.module_dir.lower() not in maps_lower and re.search(
            r"teesimulator|libinject|tricky.?store|keybox", maps_lower
        ) is None
        service_text = "\n".join(services)
        return KeystoreSnapshot(
            pid,
            hashlib.sha256(maps.encode()).hexdigest(),
            hashlib.sha256(service_text.encode()).hexdigest(),
            all(any(expected in service for service in services) for expected in EXPECTED_SERVICES),
            hook_absent,
        )

    def _wait_for_readiness(self, before: KeystoreSnapshot, deadline: Deadline) -> KeystoreSnapshot | None:
        readiness = Deadline.after(self._config.readiness_seconds)
        while True:
            candidate = self._stable_snapshot(deadline)
            if candidate.pid != before.pid and candidate.services_ready and candidate.hook_absent:
                return candidate
            try:
                remaining = readiness.timeout()
            except RunError as failure:
                if failure.code is ErrorCode.DEADLINE_EXCEEDED:
                    return None
                raise
            time.sleep(min(POLL_SECONDS, remaining))

    def _cleanup(self) -> CleanupReceipt:
        def native_proof(deadline: Deadline) -> None:
            self._native_proof(deadline)

        receipt = CleanupExecutor(self._adb, CleanupPlan(self._config.serial_b, native_proof)).run()
        if receipt.state is RunState.DIRTY:
            return receipt
        try:
            snapshot = self._stable_snapshot(Deadline.after(10))
            if snapshot.services_ready and snapshot.hook_absent:
                return receipt
            return CleanupReceipt(RunState.DIRTY, ErrorCode.READINESS_FAILED)
        except RunError as failure:
            return CleanupReceipt(RunState.DIRTY, failure.code)
