from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[2] / "scripts" / "ci" / "check_disk_headroom.py"
SPEC = importlib.util.spec_from_file_location("check_disk_headroom", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_headroom_accepts_exact_minimum() -> None:
    minimum = 10 * 1024**3
    assert MODULE.evaluate_headroom(minimum, minimum) is None


def test_headroom_rejects_below_minimum_with_actionable_message() -> None:
    minimum = 10 * 1024**3
    message = MODULE.evaluate_headroom(minimum - 1, minimum)

    assert message is not None
    assert "ENOSPC" in message
    assert "10.00 GiB required" in message
    assert "completed worktrees" in message


@pytest.mark.parametrize("minimum", ["nan", "inf", "-inf", "0", "-1"])
def test_cli_rejects_non_positive_or_non_finite_minimum(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    minimum: str,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), f"--minimum-gib={minimum}", "--path", str(SCRIPT.parent)],
    )

    with pytest.raises(SystemExit) as exc_info:
        MODULE.main()

    assert exc_info.value.code == 2
    assert "--minimum-gib must be greater than zero" in capsys.readouterr().err
