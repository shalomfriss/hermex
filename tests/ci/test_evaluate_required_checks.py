"""Behavior tests for the required-check aggregate evaluator."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest


_EVALUATOR = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "ci"
    / "evaluate_required_checks.py"
)


def _run(
    results: dict[str, str], output_path: Path
) -> subprocess.CompletedProcess[str]:
    needs = {name: {"result": result} for name, result in results.items()}
    return subprocess.run(
        [sys.executable, str(_EVALUATOR), "--output", str(output_path)],
        input=json.dumps(needs),
        capture_output=True,
        text=True,
        check=False,
    )


def test_success_and_intentional_skips_are_accepted(tmp_path: Path) -> None:
    output_path = tmp_path / "github-output"

    result = _run({"tests": "success", "docs": "skipped"}, output_path)

    assert result.returncode == 0, result.stderr
    assert "All checks passed (or were skipped)" in result.stdout
    assert json.loads(output_path.read_text().removeprefix("needs-json=")) == {
        "tests": "success",
        "docs": "skipped",
    }


@pytest.mark.parametrize(
    "dependency_result",
    ["failure", "cancelled", "timed_out", "action_required", "stale"],
)
def test_every_non_passing_dependency_result_fails_closed(
    dependency_result: str, tmp_path: Path
) -> None:
    output_path = tmp_path / "github-output"

    result = _run({"tests": "success", "required-lane": dependency_result}, output_path)

    assert result.returncode == 1
    assert f"❌ required-lane: {dependency_result}" in result.stdout
    assert "::error::1 required job(s) did not pass: required-lane" in result.stdout
    assert "All checks passed" not in result.stdout
