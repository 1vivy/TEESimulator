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

from tdd_receipt_verifier import ReceiptError, verify_evidence

TASK_PATTERN: Final = re.compile(r"^- \[ \] (\d+)\.", re.MULTILINE)


@dataclass(frozen=True, slots=True)
class CliArgs:
    plan: Path
    evidence: Path
    tasks: tuple[int, ...] | None


def parse_args(arguments: list[str]) -> CliArgs:
    if len(arguments) not in {4, 6} or len(arguments) % 2:
        raise ReceiptError("USAGE", "expected --plan PLAN --evidence DIR [--tasks LIST]")
    values = dict(zip(arguments[::2], arguments[1::2], strict=True))
    if set(values) not in ({"--plan", "--evidence"}, {"--plan", "--evidence", "--tasks"}):
        raise ReceiptError("USAGE", "expected --plan PLAN --evidence DIR [--tasks LIST]")
    raw_tasks = values.get("--tasks")
    tasks = tuple(int(value) for value in raw_tasks.split(",")) if raw_tasks else None
    return CliArgs(Path(values["--plan"]), Path(values["--evidence"]), tasks)


def plan_tasks(plan: Path) -> tuple[int, ...]:
    try:
        text = plan.read_text(encoding="utf-8")
    except OSError as error:
        raise ReceiptError("PLAN_UNREADABLE", str(plan)) from error
    tasks = tuple(int(match) for match in TASK_PATTERN.findall(text))
    if tasks != tuple(range(1, 28)):
        raise ReceiptError("PLAN_TASK_SET_INVALID", f"found tasks {tasks}")
    return tasks


def main() -> int:
    try:
        args = parse_args(sys.argv[1:])
        available = plan_tasks(args.plan)
        tasks = args.tasks or available
        if not tasks or not set(tasks).issubset(available):
            raise ReceiptError("TASK_SELECTION_INVALID", str(tasks))
        verify_evidence(Path.cwd(), args.evidence, tasks)
    except (ReceiptError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    print("TDD_RECEIPTS_VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
