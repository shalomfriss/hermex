#!/usr/bin/env python3
"""Evaluate the results consumed by the required CI aggregate job."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


def evaluate(needs: dict[str, dict[str, Any]], output_path: Path) -> int:
    """Print dependency results, write the compact output, and return an exit code."""
    compact = {name: info["result"] for name, info in needs.items()}
    print(f"needs-json={json.dumps(compact)}")
    with output_path.open("a", encoding="utf-8") as output:
        output.write(f"needs-json={json.dumps(compact)}\n")

    rejected: list[str] = []
    for name, info in sorted(needs.items()):
        result = info["result"]
        accepted = result in ("success", "skipped")
        icon = "✅" if accepted else "❌"
        print(f"{icon} {name}: {result}")
        if not accepted:
            rejected.append(name)

    if rejected:
        print(
            f"::error::{len(rejected)} required job(s) did not pass: "
            f"{', '.join(rejected)}"
        )
        return 1

    print("All checks passed (or were skipped)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    return evaluate(json.load(sys.stdin), args.output)


if __name__ == "__main__":
    raise SystemExit(main())
