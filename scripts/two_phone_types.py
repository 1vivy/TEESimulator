from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from typing import Final


MAX_PROFILE_BYTES: Final = 1_048_576
SERIAL_PATTERN: Final = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
MODEL_PATTERN: Final = re.compile(r"[^\x00-\x1f]{1,128}\Z")
MODULE_PATTERN: Final = re.compile(r"/data/adb/modules/[A-Za-z0-9._-]{1,64}\Z")
HOST_PATTERN: Final = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")


class Command(StrEnum):
    PREFLIGHT = "preflight"
    PROVISION = "provision"
    START = "start"
    ATTEST_SIGN = "attest-sign"
    STATUS = "status"
    STOP = "stop"
    RECOVER = "recover"


class RunState(StrEnum):
    CLEAN = "CLEAN"
    PROVISIONED = "PROVISIONED"
    RUNNING = "RUNNING"
    DIRTY = "DIRTY"


class ErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    ADB_COMMAND_FAILED = "ADB_COMMAND_FAILED"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    DEVICE_MODEL_MISMATCH = "DEVICE_MODEL_MISMATCH"
    FIXTURE_ERROR = "FIXTURE_ERROR"
    OPERATION_LIMIT = "OPERATION_LIMIT"
    STALE_STATE = "STALE_STATE"
    UNTRUSTED_OUTPUT = "UNTRUSTED_OUTPUT"
    CANCELLED = "CANCELLED"
    READINESS_FAILED = "READINESS_FAILED"
    ATTESTATION_VERIFICATION_FAILED = "ATTESTATION_VERIFICATION_FAILED"


@dataclass(frozen=True, slots=True)
class RunError(Exception):
    code: ErrorCode

    def __str__(self) -> str:
        return self.code.value


@dataclass(frozen=True, slots=True)
class Endpoint:
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class ProfileBundle:
    donor: bytes
    target: bytes
    donor_id: str

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.donor + self.target + self.donor_id.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class RunConfig:
    adb: Path
    serial_a: str
    serial_b: str
    model_a: str
    model_b: str
    endpoint: Endpoint
    state_file: Path
    deadline_seconds: int
    module_dir: str | None
    profiles: ProfileBundle | None

    @property
    def fingerprint(self) -> str:
        encoded = json.dumps(
            {
                "serialA": self.serial_a,
                "serialB": self.serial_b,
                "modelA": self.model_a,
                "modelB": self.model_b,
                "endpoint": f"{self.endpoint.host}:{self.endpoint.port}",
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class StoredState:
    state: RunState
    fingerprint: str
    profile_fingerprint: str
    active_operation: bool


def parse_endpoint(raw: str) -> Endpoint:
    host, separator, port_text = raw.rpartition(":")
    if separator == "" or host == "" or port_text == "":
        raise RunError(ErrorCode.INVALID_ARGUMENT)
    if host.startswith("[") and host.endswith("]"):
        candidate = host[1:-1]
        try:
            ipaddress.IPv6Address(candidate)
        except ipaddress.AddressValueError as failure:
            raise RunError(ErrorCode.INVALID_ARGUMENT) from failure
        host = candidate
    elif not HOST_PATTERN.fullmatch(host):
        try:
            ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError as failure:
            raise RunError(ErrorCode.INVALID_ARGUMENT) from failure
    if not port_text.isdecimal():
        raise RunError(ErrorCode.INVALID_ARGUMENT)
    port = int(port_text)
    if port < 1 or port > 65_535:
        raise RunError(ErrorCode.INVALID_ARGUMENT)
    return Endpoint(host, port)


def parse_serial(raw: str) -> str:
    if SERIAL_PATTERN.fullmatch(raw) is None:
        raise RunError(ErrorCode.INVALID_ARGUMENT)
    return raw


def parse_model(raw: str) -> str:
    if MODEL_PATTERN.fullmatch(raw) is None:
        raise RunError(ErrorCode.INVALID_ARGUMENT)
    return raw


def parse_module_dir(raw: str | None) -> str | None:
    if raw is None:
        return None
    if MODULE_PATTERN.fullmatch(raw) is None:
        raise RunError(ErrorCode.INVALID_ARGUMENT)
    return raw


def read_profiles(donor_path: Path | None, target_path: Path | None, profile_id: str | None) -> ProfileBundle | None:
    if donor_path is None and target_path is None and profile_id is None:
        return None
    if donor_path is None or target_path is None or profile_id is None:
        raise RunError(ErrorCode.INVALID_ARGUMENT)
    if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", profile_id) is None:
        raise RunError(ErrorCode.INVALID_ARGUMENT)
    try:
        donor = donor_path.read_bytes()
        target = target_path.read_bytes()
    except OSError as failure:
        raise RunError(ErrorCode.INVALID_ARGUMENT) from failure
    if not donor or not target or len(donor) > MAX_PROFILE_BYTES or len(target) > MAX_PROFILE_BYTES:
        raise RunError(ErrorCode.INVALID_ARGUMENT)
    return ProfileBundle(donor, target, profile_id)
