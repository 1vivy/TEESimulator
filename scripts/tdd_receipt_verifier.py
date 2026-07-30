from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Final

ENVIRONMENT_FAILURES: Final = re.compile(
    r"SDK location not found|Compilation error|Could not resolve all files|"
    r"Execution failed for task ':[^']*compile|A problem occurred starting process",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class Receipt:
    label: str
    fields: dict[str, str]
    raw: bytes


@dataclass(frozen=True, slots=True)
class CommandLog:
    command: str
    exit_code: int
    captured_epoch: int
    output: str


@dataclass(frozen=True, slots=True)
class ReceiptContext:
    repository: Path
    evidence: Path
    task: int
    receipt: Receipt


@dataclass(frozen=True, slots=True)
class TaskEvidence:
    repository: Path
    evidence: Path
    task: int
    red: Receipt
    green: Receipt


class ReceiptError(Exception):
    __slots__ = ("code", "detail")

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(code, detail)
        self.code = code
        self.detail = detail

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


def parse_receipt(raw: bytes, label: str) -> Receipt:
    fields: dict[str, str] = {}
    for line in raw.decode("utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key:
            continue
        if key in fields:
            raise ReceiptError("DUPLICATE_FIELD", f"{label}: {key}")
        fields[key] = value
    return Receipt(label, fields, raw)


def required(receipt: Receipt, key: str, expected: str | None = None) -> str:
    value = receipt.fields.get(key)
    if value is None or value == "":
        raise ReceiptError("INVALID_RECEIPT", f"{receipt.label}: missing {key}")
    if expected is not None and value != expected:
        raise ReceiptError(
            "INVALID_RECEIPT",
            f"{receipt.label}: {key} expected {expected!r}, got {value!r}",
        )
    return value


def git(repository: Path, *arguments: str) -> str:
    process = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode:
        raise ReceiptError("GIT_OBJECT_INVALID", " ".join(arguments))
    return process.stdout.strip()


def git_blob(repository: Path, blob: str) -> bytes:
    process = subprocess.run(
        ["git", "cat-file", "-p", blob],
        cwd=repository,
        check=False,
        capture_output=True,
    )
    if process.returncode:
        raise ReceiptError("GIT_OBJECT_INVALID", blob)
    return process.stdout


def commit_metadata(repository: Path, commit: str) -> tuple[str, str, int]:
    git(repository, "cat-file", "-e", f"{commit}^{{commit}}")
    fields = git(repository, "show", "-s", "--format=%P%x00%T%x00%ct", commit).split("\0")
    if len(fields) != 3:
        raise ReceiptError("GIT_OBJECT_INVALID", commit)
    return fields[0], fields[1], int(fields[2])


def changed_paths(repository: Path, parent: str, child: str) -> frozenset[str]:
    output = git(
        repository,
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "-r",
        parent,
        child,
    )
    return frozenset(output.splitlines()) if output else frozenset()


def is_test_path(path: str) -> bool:
    normalized = f"/{path.lower()}/"
    return (
        "/src/test/" in normalized
        or "/src/androidtest/" in normalized
        or normalized.startswith("/tests/")
    )


def read_log(context: ReceiptContext, prefix: str) -> CommandLog:
    receipt = context.receipt
    relative = required(receipt, f"{prefix}_LOG")
    if PurePath(relative).is_absolute() or ".." in PurePath(relative).parts:
        raise ReceiptError("LOG_PATH_INVALID", relative)
    path = context.evidence / relative
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ReceiptError("LOG_MISSING", str(path)) from error
    digest = hashlib.sha256(raw).hexdigest()
    if digest != required(receipt, f"{prefix}_LOG_SHA256"):
        raise ReceiptError("LOG_DIGEST_MISMATCH", str(path))
    blob = required(receipt, f"{prefix}_LOG_BLOB")
    if git_blob(context.repository, blob) != raw:
        raise ReceiptError("LOG_BLOB_MISMATCH", str(path))
    header, marker, output = raw.decode("utf-8").partition("--- OUTPUT ---\n")
    if not marker:
        raise ReceiptError("LOG_FORMAT_INVALID", str(path))
    values = parse_receipt(header.encode(), str(path)).fields
    try:
        return CommandLog(
            values["COMMAND"],
            int(values["EXIT_CODE"]),
            int(values["CAPTURED_AT_EPOCH"]),
            output,
        )
    except (KeyError, ValueError) as error:
        raise ReceiptError("LOG_FORMAT_INVALID", str(path)) from error


def verify_red(context: ReceiptContext) -> str:
    repository = context.repository
    receipt = context.receipt
    required(receipt, "SCHEMA_VERSION", "2")
    required(receipt, "TASK", str(context.task))
    required(receipt, "PHASE", "RED")
    base = required(receipt, "BASE_COMMIT")
    _, base_tree, _ = commit_metadata(repository, base)
    if base_tree != required(receipt, "BASE_TREE"):
        raise ReceiptError("BASE_TREE_MISMATCH", base)
    state = required(receipt, "STATE_COMMIT")
    state_parents, state_tree, state_epoch = commit_metadata(repository, state)
    if state_parents != base:
        raise ReceiptError("RED_BASE_ANCESTRY_INVALID", state)
    if state_tree != required(receipt, "STATE_TREE"):
        raise ReceiptError("RED_TREE_MISMATCH", state)
    paths = changed_paths(repository, base, state)
    if not paths or any(not is_test_path(path) for path in paths):
        raise ReceiptError("RED_PRODUCTION_DIFF", ",".join(sorted(paths)))
    if int(required(receipt, "CAPTURED_AT_EPOCH")) != state_epoch:
        raise ReceiptError("RED_TIMESTAMP_MISMATCH", state)
    required(receipt, "FAILURE_CLASS")
    required(receipt, "COMPILATION_OR_ENVIRONMENT_FAILURE", "false")
    log = read_log(context, "COMMAND")
    command = required(receipt, "COMMAND")
    if (
        log.command != command
        or log.exit_code != int(required(receipt, "COMMAND_EXIT_CODE"))
        or log.captured_epoch != state_epoch
    ):
        raise ReceiptError("RED_COMMAND_MISMATCH", receipt.label)
    if log.exit_code == 0:
        raise ReceiptError("INVALID_RED_EXIT", receipt.label)
    if ENVIRONMENT_FAILURES.search(log.output):
        raise ReceiptError("RED_ENVIRONMENT_FAILURE", receipt.label)
    pattern = required(receipt, "EXPECTED_FAILURE_REGEX")
    try:
        matched = re.search(pattern, log.output)
    except re.error as error:
        raise ReceiptError("FAILURE_PATTERN_INVALID", pattern) from error
    if not matched:
        raise ReceiptError("RED_WRONG_FAILURE_CAUSE", receipt.label)
    return command


def verify_green(evidence: TaskEvidence, red_command: str) -> None:
    repository = evidence.repository
    red = evidence.red
    green = evidence.green
    required(green, "SCHEMA_VERSION", "2")
    required(green, "TASK", str(evidence.task))
    required(green, "PHASE", "GREEN")
    task_commit = required(green, "TASK_COMMIT")
    parent = required(green, "TASK_PARENT")
    actual_parents, _, task_epoch = commit_metadata(repository, task_commit)
    if actual_parents != parent:
        raise ReceiptError("TASK_PARENT_MISMATCH", task_commit)
    base = required(red, "BASE_COMMIT")
    git(repository, "merge-base", "--is-ancestor", base, parent)
    red_epoch = int(required(red, "CAPTURED_AT_EPOCH"))
    captured_epoch = int(required(green, "CAPTURED_AT_EPOCH"))
    if not red_epoch < task_epoch <= captured_epoch:
        raise ReceiptError("TDD_ORDER_INVALID", green.label)
    if hashlib.sha256(red.raw).hexdigest() != required(green, "RED_RECEIPT_SHA256"):
        raise ReceiptError("RED_RECEIPT_DIGEST_MISMATCH", green.label)
    required(green, "RED_STATE_COMMIT", required(red, "STATE_COMMIT"))
    required(green, "RED_COMMAND", red_command)
    replay = read_log(
        ReceiptContext(repository, evidence.evidence, evidence.task, green),
        "RED_REPLAY",
    )
    if (
        replay.command != red_command
        or replay.exit_code != 0
        or replay.exit_code != int(required(green, "RED_REPLAY_EXIT_CODE"))
        or replay.captured_epoch != captured_epoch
    ):
        raise ReceiptError("RED_REPLAY_INVALID", green.label)
    changed = changed_paths(repository, parent, task_commit)
    production = frozenset(path for path in changed if not is_test_path(path))
    declared = frozenset(required(green, "PRODUCTION_PATHS").split(","))
    if not production or production != declared:
        raise ReceiptError("GREEN_PRODUCTION_DIFF_MISMATCH", ",".join(sorted(production)))
    red_paths = changed_paths(repository, base, required(red, "STATE_COMMIT"))
    if not red_paths.issubset(changed):
        raise ReceiptError("GREEN_TEST_DIFF_MISMATCH", green.label)


def verify_task(evidence: TaskEvidence) -> None:
    red_context = ReceiptContext(
        evidence.repository,
        evidence.evidence,
        evidence.task,
        evidence.red,
    )
    verify_green(evidence, verify_red(red_context))


def verify_evidence(repository: Path, evidence: Path, tasks: tuple[int, ...]) -> None:
    for task in tasks:
        red_path = evidence / f"task-{task}-red.txt"
        green_path = evidence / f"task-{task}-green.txt"
        try:
            red_raw = red_path.read_text(encoding="utf-8")
            green_raw = green_path.read_text(encoding="utf-8")
        except OSError as error:
            raise ReceiptError("MISSING_RECEIPT", str(error.filename)) from error
        verify_task(
            TaskEvidence(
                repository,
                evidence,
                task,
                parse_receipt(red_raw.encode(), f"task-{task}-red.txt"),
                parse_receipt(green_raw.encode(), f"task-{task}-green.txt"),
            )
        )
