from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import tempfile
from typing import TextIO

from two_phone_types import ErrorCode, RunError, RunState, StoredState


STATE_VERSION = 1
MAX_STATE_BYTES = 4_096


class StateLock:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._handle: TextIO | None = None

    def __enter__(self) -> StateLock:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._handle = self._path.open("a", encoding="utf-8")
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as failure:
            self._handle.close()
            self._handle = None
            raise RunError(ErrorCode.OPERATION_LIMIT) from failure
        return self

    def __exit__(self, exception_type, exception, traceback) -> bool:
        handle = self._handle
        if handle is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()
            self._handle = None
        return False


class StateStore:
    def __init__(self, path: Path) -> None:
        self._path = path

    def lock(self) -> StateLock:
        return StateLock(self._path.with_suffix(self._path.suffix + ".lock"))

    def load(self) -> StoredState:
        if not self._path.exists():
            return StoredState(RunState.CLEAN, "", "", False)
        try:
            raw = self._path.read_bytes()
            if not 1 <= len(raw) <= MAX_STATE_BYTES:
                raise RunError(ErrorCode.STALE_STATE)
            parsed = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as failure:
            raise RunError(ErrorCode.STALE_STATE) from failure
        match parsed:
            case dict() as record:
                return self._record(record)
            case _:
                raise RunError(ErrorCode.STALE_STATE)

    def write(self, state: StoredState) -> None:
        payload = json.dumps(
            {
                "version": STATE_VERSION,
                "state": state.state.value,
                "fingerprint": state.fingerprint,
                "profileFingerprint": state.profile_fingerprint,
                "activeOperation": state.active_operation,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self._path.parent,
            delete=False,
        ) as temporary:
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        temporary_path.chmod(0o600)
        os.replace(temporary_path, self._path)

    def _record(self, record) -> StoredState:
        expected = {"version", "state", "fingerprint", "profileFingerprint", "activeOperation"}
        if set(record) != expected or record.get("version") != STATE_VERSION:
            raise RunError(ErrorCode.STALE_STATE)
        fingerprint = record.get("fingerprint")
        profile_fingerprint = record.get("profileFingerprint")
        active_operation = record.get("activeOperation")
        state_value = record.get("state")
        if (
            type(fingerprint) is not str
            or type(profile_fingerprint) is not str
            or type(active_operation) is not bool
            or type(state_value) is not str
        ):
            raise RunError(ErrorCode.STALE_STATE)
        try:
            state = RunState(state_value)
        except ValueError as failure:
            raise RunError(ErrorCode.STALE_STATE) from failure
        return StoredState(state, fingerprint, profile_fingerprint, active_operation)
