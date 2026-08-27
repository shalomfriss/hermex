#!/usr/bin/env python3
"""Fail local integration work before low disk headroom becomes ENOSPC."""

from __future__ import annotations

import argparse
import math
import shutil
from pathlib import Path

GIB = 1024**3
DEFAULT_MINIMUM_GIB = 10.0


def evaluate_headroom(free_bytes: int, minimum_bytes: int) -> str | None:
    """Return an actionable error when free space is below the floor."""
    if free_bytes >= minimum_bytes:
        return None
    free_gib = free_bytes / GIB
    minimum_gib = minimum_bytes / GIB
    return (
        "capacity preflight failed before ENOSPC: "
        f"{free_gib:.2f} GiB available; {minimum_gib:.2f} GiB required. "
        "Remove dependency trees only from clean completed worktrees, prune "
        "completed worktrees after preserving their refs, or clear rebuildable "
        "package caches. Never clean active workspaces or deployment state."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--minimum-gib", type=float, default=DEFAULT_MINIMUM_GIB)
    parser.add_argument("--path", type=Path, default=Path.cwd())
    args = parser.parse_args()
    if not math.isfinite(args.minimum_gib) or args.minimum_gib <= 0:
        parser.error("--minimum-gib must be greater than zero")

    free_bytes = shutil.disk_usage(args.path).free
    minimum_bytes = int(args.minimum_gib * GIB)
    error = evaluate_headroom(free_bytes, minimum_bytes)
    if error:
        print(f"error: {error}")
        return 1
    print(
        "capacity preflight passed: "
        f"{free_bytes / GIB:.2f} GiB available; "
        f"{args.minimum_gib:.2f} GiB required"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
