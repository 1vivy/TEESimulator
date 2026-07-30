from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from tdd_receipt_verifier import ReceiptError, TaskEvidence, parse_receipt, verify_task


@dataclass(frozen=True, slots=True)
class Fixture:
    repository: Path
    evidence: Path
    base: str
    red_state: str
    task_commit: str
    red_log: Path
    green_log: Path


class VerifyTddReceiptsTest(unittest.TestCase):
    def test_valid_git_backed_receipts_pass(self) -> None:
        fixture = create_fixture()
        self.addCleanup(shutil.rmtree, fixture.repository)

        verify_task(task_evidence(fixture))

    def test_forged_red_timestamp_is_rejected(self) -> None:
        fixture = create_fixture()
        self.addCleanup(shutil.rmtree, fixture.repository)
        red = red_receipt(fixture).replace(
            "CAPTURED_AT_EPOCH=100",
            "CAPTURED_AT_EPOCH=999",
        )

        with self.assertRaisesRegex(ReceiptError, "RED_TIMESTAMP_MISMATCH"):
            verify_task(task_evidence(fixture, red))

    def test_production_path_hidden_as_test_diff_is_rejected(self) -> None:
        fixture = create_fixture(red_path="src/main/Production.kt")
        self.addCleanup(shutil.rmtree, fixture.repository)

        with self.assertRaisesRegex(ReceiptError, "RED_PRODUCTION_DIFF"):
            verify_task(task_evidence(fixture))

    def test_environment_failure_cannot_be_claimed_as_named_cause(self) -> None:
        fixture = create_fixture(red_output="SDK location not found")
        self.addCleanup(shutil.rmtree, fixture.repository)
        red = red_receipt(fixture).replace(
            "EXPECTED_FAILURE_REGEX=missing topology",
            "EXPECTED_FAILURE_REGEX=SDK location not found",
        )

        with self.assertRaisesRegex(ReceiptError, "RED_ENVIRONMENT_FAILURE"):
            verify_task(task_evidence(fixture, red))

    def test_forged_failure_cause_is_rejected(self) -> None:
        fixture = create_fixture(red_output="some unrelated assertion failed")
        self.addCleanup(shutil.rmtree, fixture.repository)

        with self.assertRaisesRegex(ReceiptError, "RED_WRONG_FAILURE_CAUSE"):
            verify_task(task_evidence(fixture))

    def test_duplicate_receipt_field_is_rejected(self) -> None:
        fixture = create_fixture()
        self.addCleanup(shutil.rmtree, fixture.repository)
        red = red_receipt(fixture) + "\nTASK=1"

        with self.assertRaisesRegex(ReceiptError, "DUPLICATE_FIELD"):
            task_evidence(fixture, red)


def create_fixture(
    red_path: str = "src/test/ContractTest.kt",
    red_output: str = "missing topology",
) -> Fixture:
    repository = Path(tempfile.mkdtemp(prefix="receipt-repository-"))
    evidence = repository / "evidence"
    evidence.mkdir()
    run_git(repository, "init", "--quiet")
    run_git(repository, "config", "user.name", "Receipt Test")
    run_git(repository, "config", "user.email", "receipt@example.invalid")
    run_git(repository, "config", "commit.gpgsign", "false")
    (repository / "README").write_text("base\n", encoding="utf-8")
    run_git(repository, "add", "README")
    run_git(repository, "commit", "--quiet", "-m", "base")
    base = run_git(repository, "rev-parse", "HEAD")

    path = repository / red_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("test\n", encoding="utf-8")
    run_git(repository, "add", red_path)
    red_tree = run_git(repository, "write-tree")
    red_state = commit_tree(repository, red_tree, base, 100, "red state")
    run_git(repository, "reset", "--quiet", "--hard", base)

    production = repository / "src/main/Behavior.kt"
    production.parent.mkdir(parents=True, exist_ok=True)
    production.write_text("behavior\n", encoding="utf-8")
    test_path = repository / "src/test/ContractTest.kt"
    test_path.parent.mkdir(parents=True, exist_ok=True)
    test_path.write_text("test\n", encoding="utf-8")
    run_git(repository, "add", "src")
    commit(repository, 200, "task")
    task_commit = run_git(repository, "rev-parse", "HEAD")

    red_log = evidence / "red.log"
    green_log = evidence / "green.log"
    write_log(red_log, "run-red", 1, 100, red_output)
    write_log(green_log, "run-red", 0, 201, "tests passed")
    return Fixture(repository, evidence, base, red_state, task_commit, red_log, green_log)


def red_receipt(fixture: Fixture) -> str:
    return "\n".join(
        (
            "SCHEMA_VERSION=2",
            "TASK=1",
            "PHASE=RED",
            f"BASE_COMMIT={fixture.base}",
            f"BASE_TREE={run_git(fixture.repository, 'rev-parse', fixture.base + '^{tree}')}",
            f"STATE_COMMIT={fixture.red_state}",
            f"STATE_TREE={run_git(fixture.repository, 'rev-parse', fixture.red_state + '^{tree}')}",
            "CAPTURED_AT_EPOCH=100",
            "COMMAND=run-red",
            f"COMMAND_LOG={fixture.red_log.name}",
            f"COMMAND_LOG_SHA256={sha256(fixture.red_log)}",
            f"COMMAND_LOG_BLOB={run_git(fixture.repository, 'hash-object', '-w', fixture.red_log)}",
            "COMMAND_EXIT_CODE=1",
            "EXPECTED_FAILURE_REGEX=missing topology",
            "FAILURE_CLASS=PLAN_APPROVED_MISSING_TOPOLOGY",
            "COMPILATION_OR_ENVIRONMENT_FAILURE=false",
        )
    )


def green_receipt(fixture: Fixture) -> str:
    red = red_receipt(fixture)
    parent = run_git(fixture.repository, "rev-parse", fixture.task_commit + "^")
    return "\n".join(
        (
            "SCHEMA_VERSION=2",
            "TASK=1",
            "PHASE=GREEN",
            f"TASK_COMMIT={fixture.task_commit}",
            f"TASK_PARENT={parent}",
            "CAPTURED_AT_EPOCH=201",
            f"RED_RECEIPT_SHA256={hashlib.sha256(red.encode()).hexdigest()}",
            f"RED_STATE_COMMIT={fixture.red_state}",
            "RED_COMMAND=run-red",
            f"RED_REPLAY_LOG={fixture.green_log.name}",
            f"RED_REPLAY_LOG_SHA256={sha256(fixture.green_log)}",
            f"RED_REPLAY_LOG_BLOB={run_git(fixture.repository, 'hash-object', '-w', fixture.green_log)}",
            "RED_REPLAY_EXIT_CODE=0",
            "PRODUCTION_PATHS=src/main/Behavior.kt",
        )
    )


def task_evidence(fixture: Fixture, red: str | None = None) -> TaskEvidence:
    red_raw = red or red_receipt(fixture)
    return TaskEvidence(
        fixture.repository,
        fixture.evidence,
        1,
        parse_receipt(red_raw.encode(), "task-1-red.txt"),
        parse_receipt(green_receipt(fixture).encode(), "task-1-green.txt"),
    )


def write_log(path: Path, command: str, exit_code: int, epoch: int, output: str) -> None:
    path.write_text(
        f"COMMAND={command}\nEXIT_CODE={exit_code}\nCAPTURED_AT_EPOCH={epoch}\n--- OUTPUT ---\n{output}\n",
        encoding="utf-8",
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def commit(repository: Path, epoch: int, message: str) -> None:
    environment = os.environ | {
        "GIT_AUTHOR_DATE": f"@{epoch} +0000",
        "GIT_COMMITTER_DATE": f"@{epoch} +0000",
    }
    subprocess.run(
        ["git", "commit", "--quiet", "-m", message],
        cwd=repository,
        env=environment,
        check=True,
    )


def commit_tree(repository: Path, tree: str, parent: str, epoch: int, message: str) -> str:
    environment = os.environ | {
        "GIT_AUTHOR_DATE": f"@{epoch} +0000",
        "GIT_COMMITTER_DATE": f"@{epoch} +0000",
    }
    return subprocess.run(
        ["git", "commit-tree", tree, "-p", parent, "-m", message],
        cwd=repository,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def run_git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


if __name__ == "__main__":
    unittest.main()
