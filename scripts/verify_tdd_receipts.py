#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv (if not installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run directly (no venv, no pip install needed):
#      uv run scripts/verify_tdd_receipts.py --plan PLAN --evidence EVIDENCE
# 3. Or make executable and run:
#      chmod +x scripts/verify_tdd_receipts.py && ./scripts/verify_tdd_receipts.py --plan PLAN --evidence EVIDENCE
# ──────────────────

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from tdd_receipt_verifier import (
    ReceiptError,
    Receipt,
    TaskEvidence,
    parse_receipt,
    verify_task,
)

TASK_PATTERN: Final = re.compile(r"^- \[[ x]\] ((?:\d+)|(?:F[1-5]))\.", re.MULTILINE)
EXPECTED_TASKS: Final = tuple(str(value) for value in range(1, 29)) + tuple(
    f"F{value}" for value in range(1, 6)
)


@dataclass(frozen=True, slots=True)
class CliArgs:
    plan: Path
    evidence: Path
    tasks: tuple[str, ...] | None


def parse_args(arguments: list[str]) -> CliArgs:
    if len(arguments) not in {4, 6} or len(arguments) % 2:
        raise ReceiptError("USAGE", "expected --plan PLAN --evidence DIR [--tasks LIST]")
    values = dict(zip(arguments[::2], arguments[1::2], strict=True))
    if set(values) not in ({"--plan", "--evidence"}, {"--plan", "--evidence", "--tasks"}):
        raise ReceiptError("USAGE", "expected --plan PLAN --evidence DIR [--tasks LIST]")
    raw_tasks = values.get("--tasks")
    tasks = tuple(raw_tasks.split(",")) if raw_tasks else None
    return CliArgs(Path(values["--plan"]), Path(values["--evidence"]), tasks)


def plan_tasks(plan: Path) -> tuple[str, ...]:
    try:
        text = plan.read_text(encoding="utf-8")
    except OSError as error:
        raise ReceiptError("PLAN_UNREADABLE", str(plan)) from error
    tasks = tuple(TASK_PATTERN.findall(text))
    if tasks != EXPECTED_TASKS:
        raise ReceiptError("PLAN_TASK_SET_INVALID", f"found tasks {tasks}")
    return tasks


def main() -> int:
    try:
        args = parse_args(sys.argv[1:])
        available = plan_tasks(args.plan)
        tasks = args.tasks or available
        if not tasks or not set(tasks).issubset(available):
            raise ReceiptError("TASK_SELECTION_INVALID", str(tasks))
        for task in tasks:
            red_path = args.evidence / f"task-{task}-red.txt"
            green_path = args.evidence / f"task-{task}-green.txt"
            try:
                red = red_path.read_bytes()
                green = green_path.read_bytes()
            except OSError as error:
                raise ReceiptError("MISSING_RECEIPT", str(error.filename)) from error
            task_number = int(task) if task.isdigit() else 28 + int(task[1:])
            parsed_red = parse_receipt(red, red_path.name)
            parsed_green = parse_receipt(green, green_path.name)
            normalized_red = Receipt(
                parsed_red.label,
                parsed_red.fields | {"TASK": str(task_number)},
                parsed_red.raw,
            )
            normalized_green = Receipt(
                parsed_green.label,
                parsed_green.fields | {"TASK": str(task_number)},
                parsed_green.raw,
            )
            verify_task(
                TaskEvidence(
                    Path.cwd(),
                    args.evidence,
                    task_number,
                    normalized_red,
                    normalized_green,
                )
            )
    except (ReceiptError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    print("TDD_RECEIPTS_VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
