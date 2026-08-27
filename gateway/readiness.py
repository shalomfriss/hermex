"""Bounded, non-destructive readiness probes for authenticated health surfaces."""

from __future__ import annotations

import shutil
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import yaml

from gateway.disk_status import classify_disk_pressure
from hermes_cli.config_defaults import DEFAULT_CONFIG
from hermes_constants import get_hermes_home


_DISK_DEGRADED_PERCENT = 90.0
_BYTES_PER_MB = 1024 * 1024
_BYTES_PER_GB = 1024 * 1024 * 1024
_DEFAULT_DISK_MIN_FREE_GB = float(DEFAULT_CONFIG["readiness"]["disk_min_free_gb"])


def _check(status: str, detail: str | None = None, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"status": status}
    if detail:
        result["detail"] = detail
    result.update(extra)
    return result


def _probe_state_db(home: Path) -> dict[str, Any]:
    path = home / "state.db"
    if not path.exists():
        return _check("ok", "not initialized")
    try:
        # A readiness probe must never compete with normal state writers. A
        # read-only schema query still catches unreadable/corrupt databases
        # without taking a write reservation on every health poll.
        # ``closing(...)`` is required: sqlite3's connection context manager
        # only commits/rolls back — it never closes, so a bare ``with
        # sqlite3.connect(...)`` leaks one connection (and its fds) per
        # health poll in the long-running gateway (#69678/#69567 bug class).
        uri = f"file:{path.as_posix()}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=1.0)) as conn:
            conn.execute("PRAGMA query_only = ON")
            conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
        return _check("ok")
    except Exception as exc:
        return _check("degraded", type(exc).__name__)


def _probe_config(home: Path) -> dict[str, Any]:
    path = home / "config.yaml"
    if not path.exists():
        return _check("ok", "using defaults")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if raw is not None and not isinstance(raw, dict):
            return _check("degraded", "top level is not a mapping")
        return _check("ok")
    except Exception as exc:
        return _check("degraded", f"invalid config ({type(exc).__name__})")


def _disk_min_free_bytes(home: Path) -> int:
    """Resolve the absolute readiness floor from config.yaml, fail-safe."""
    value: Any = _DEFAULT_DISK_MIN_FREE_GB
    try:
        raw = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8")) or {}
        readiness = raw.get("readiness") if isinstance(raw, dict) else None
        if isinstance(readiness, dict):
            value = readiness.get("disk_min_free_gb", value)
    except Exception:
        pass
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        value = _DEFAULT_DISK_MIN_FREE_GB
    return int(float(value) * _BYTES_PER_GB)


def _probe_disk(home: Path) -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(home)
        used_pct = round((usage.used / usage.total) * 100, 1) if usage.total else 0.0
        minimum_free = _disk_min_free_bytes(home)
        degraded = used_pct >= _DISK_DEGRADED_PERCENT or usage.free < minimum_free
        pressure = classify_disk_pressure(
            usage.free // _BYTES_PER_MB,
            usage.total // _BYTES_PER_MB,
        )
        if degraded and pressure == "ok":
            pressure = "elevated"
        return _check(
            "degraded" if degraded else "ok",
            used_percent=used_pct,
            free_bytes=usage.free,
            minimum_free_bytes=minimum_free,
            pressure=pressure,
        )
    except Exception as exc:
        return _check("degraded", type(exc).__name__)


def _probe_gateway(runtime_status: dict[str, Any]) -> dict[str, Any]:
    state = str(runtime_status.get("gateway_state") or "unknown")
    platforms = runtime_status.get("platforms")
    connected = 0
    configured = 0
    if isinstance(platforms, dict):
        configured = len(platforms)
        connected = sum(
            1
            for value in platforms.values()
            if isinstance(value, dict)
            and str(value.get("state") or value.get("status") or "").lower()
            in {"connected", "running", "ok"}
        )
    status = "ok" if state in {"running", "draining"} else "degraded"
    return _check(status, state=state, connected_platforms=connected, platforms=configured)


def collect_runtime_readiness(
    *,
    configured_model: str,
    runtime_status: dict[str, Any] | None,
    active_api_runs: int = 0,
    process_completion_queue_depth: int = 0,
    active_delegations: int = 0,
) -> dict[str, Any]:
    """Return bounded readiness diagnostics without mutating runtime state.

    The detailed health endpoint is authenticated. Even there, probes expose
    status and counts only: never config values, credentials, paths, commands,
    queue payloads, or exception messages.
    """
    home = get_hermes_home()
    runtime = runtime_status if isinstance(runtime_status, dict) else {}
    checks = {
        "state_db": _probe_state_db(home),
        "config": _probe_config(home),
        "model": _check("ok" if str(configured_model or "").strip() else "degraded"),
        "disk": _probe_disk(home),
        "gateway": _probe_gateway(runtime),
        "background_queues": _check(
            "ok",
            active_api_runs=max(0, int(active_api_runs)),
            process_completions=max(0, int(process_completion_queue_depth)),
            active_delegations=max(0, int(active_delegations)),
        ),
    }
    overall = "ok" if all(item.get("status") == "ok" for item in checks.values()) else "degraded"
    return {"status": overall, "checks": checks}


__all__ = ["collect_runtime_readiness"]
