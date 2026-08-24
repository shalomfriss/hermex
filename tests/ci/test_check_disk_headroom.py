from __future__ import annotations

import importlib.util
from pathlib import Path


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
