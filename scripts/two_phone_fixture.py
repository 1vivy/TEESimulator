from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from enum import StrEnum
import json
import re
from typing import Final
from typing import assert_never

from two_phone_types import ErrorCode, RunError


MAX_FIXTURE_LINES: Final = 2
FIXTURE_PACKAGE: Final = "org.matrix.teesimulator.rkafixture"
FIXTURE_RESULT: Final = re.compile(r"Broadcast completed: result=(-1|1), data=(.+)\Z")


class FixtureCommand(StrEnum):
    PROVISION = "PROVISION"
    START = "START"
    STATUS = "STATUS"
    ATTEST_SIGN = "ATTEST_SIGN"
    STOP = "STOP"


class FixtureStatus(StrEnum):
    OK = "ok"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class FixtureProof:
    certificate_chain_der: tuple[bytes, ...]
    payload: bytes
    signature: bytes


@dataclass(frozen=True, slots=True)
class FixtureResult:
    command: FixtureCommand
    proof: FixtureProof | None


@dataclass(frozen=True, slots=True)
class FixtureRequest:
    serial: str
    command: FixtureCommand
    role: str
    profile: bytes | None = None
    profile_id: str | None = None
    challenge: bytes | None = None


def parse_fixture(expected: FixtureCommand, output: str) -> FixtureResult:
    lines = output.splitlines()
    if not 1 <= len(lines) <= MAX_FIXTURE_LINES:
        raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
    match = FIXTURE_RESULT.fullmatch(lines[-1])
    if match is None:
        raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
    record = _json_record(match.group(2))
    status = _status(record.get("status"))
    match status:
        case FixtureStatus.ERROR:
            if match.group(1) != "1" or set(record) != {"version", "status", "code"}:
                raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
            if record.get("version") != 1 or not _error_code(record.get("code")):
                raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
            raise RunError(ErrorCode.FIXTURE_ERROR)
        case FixtureStatus.OK:
            if match.group(1) != "-1":
                raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
        case unreachable:
            assert_never(unreachable)
    if record.get("version") != 1 or record.get("command") != expected.value.lower().replace("_", "-"):
        raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
    match expected:
        case FixtureCommand.ATTEST_SIGN:
            proof = _proof(record)
            expected_fields = {"version", "status", "command", "chain", "payload", "signature"}
        case FixtureCommand.PROVISION | FixtureCommand.START | FixtureCommand.STATUS | FixtureCommand.STOP:
            proof = None
            expected_fields = {"version", "status", "command"}
        case unreachable:
            assert_never(unreachable)
    if set(record) != expected_fields:
        raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
    return FixtureResult(expected, proof)


def action(command: FixtureCommand) -> str:
    match command:
        case FixtureCommand.PROVISION:
            return f"{FIXTURE_PACKAGE}.v1.PROVISION"
        case FixtureCommand.START:
            return f"{FIXTURE_PACKAGE}.v1.START"
        case FixtureCommand.STATUS:
            return f"{FIXTURE_PACKAGE}.v1.STATUS"
        case FixtureCommand.ATTEST_SIGN:
            return f"{FIXTURE_PACKAGE}.v1.ATTEST_SIGN"
        case FixtureCommand.STOP:
            return f"{FIXTURE_PACKAGE}.v1.STOP"
        case unreachable:
            assert_never(unreachable)


def _proof(record) -> FixtureProof:
    chain = record.get("chain")
    if type(chain) is not list or not 1 <= len(chain) <= 8:
        raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
    certificates: list[bytes] = []
    for certificate in chain:
        if type(certificate) is not str or not 1 <= len(certificate) <= 87_384:
            raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
        certificates.append(_base64(certificate))
    payload = record.get("payload")
    signature = record.get("signature")
    if type(payload) is not str or type(signature) is not str:
        raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
    decoded_payload = _base64(payload)
    decoded_signature = _base64(signature)
    if len(decoded_payload) != 32 or not 8 <= len(decoded_signature) <= 1_024:
        raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
    return FixtureProof(tuple(certificates), decoded_payload, decoded_signature)


def _json_record(encoded: str):
    try:
        parsed = json.loads(encoded)
        if type(parsed) is str:
            parsed = json.loads(parsed)
    except json.JSONDecodeError as failure:
        raise RunError(ErrorCode.UNTRUSTED_OUTPUT) from failure
    match parsed:
        case dict() as record:
            return record
        case _:
            raise RunError(ErrorCode.UNTRUSTED_OUTPUT)


def _base64(encoded: str) -> bytes:
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as failure:
        raise RunError(ErrorCode.UNTRUSTED_OUTPUT) from failure


def _status(value) -> FixtureStatus:
    if type(value) is not str:
        raise RunError(ErrorCode.UNTRUSTED_OUTPUT)
    try:
        return FixtureStatus(value)
    except ValueError as failure:
        raise RunError(ErrorCode.UNTRUSTED_OUTPUT) from failure


def _error_code(value) -> bool:
    return type(value) is str and re.fullmatch(r"[A-Z0-9_]{1,64}", value) is not None
