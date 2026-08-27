from __future__ import annotations

import json
import os
import sqlite3
import shutil
from pathlib import Path

import gateway.readiness as readiness
from gateway.readiness import collect_runtime_readiness


def test_collect_runtime_readiness_reports_healthy_local_runtime(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text(
        "model:\n  provider: openrouter\n  model: test/model\n",
        encoding="utf-8",
    )
    with sqlite3.connect(home / "state.db") as conn:
        conn.execute("CREATE TABLE probe (id INTEGER PRIMARY KEY)")
    monkeypatch.setenv("HERMES_HOME", str(home))
    total = 100 * 1024**3
    free = 20 * 1024**3
    monkeypatch.setattr(
        readiness.shutil,
        "disk_usage",
        lambda _path: shutil._ntuple_diskusage(  # type: ignore[attr-defined]
            total=total, used=total - free, free=free
        ),
    )

    result = collect_runtime_readiness(
        configured_model="test/model",
        runtime_status={
            "gateway_state": "running",
            "platforms": {"telegram": {"state": "connected"}},
            "updated_at": "2026-07-09T00:00:00Z",
        },
        active_api_runs=2,
    )

    assert result["status"] == "ok"
    assert result["checks"]["state_db"]["status"] == "ok"
    assert result["checks"]["config"]["status"] == "ok"
    assert result["checks"]["model"]["status"] == "ok"
    assert result["checks"]["gateway"]["status"] == "ok"
    assert result["checks"]["background_queues"]["active_api_runs"] == 2
    assert result["checks"]["disk"]["status"] == "ok"


def test_collect_runtime_readiness_degrades_on_invalid_config_and_stopped_gateway(
    tmp_path, monkeypatch
):
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text("model: [unterminated", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(home))

    result = collect_runtime_readiness(
        configured_model="",
        runtime_status={"gateway_state": "stopped", "platforms": {}},
    )

    assert result["status"] == "degraded"
    assert result["checks"]["config"]["status"] == "degraded"
    assert result["checks"]["model"]["status"] == "degraded"
    assert result["checks"]["gateway"]["status"] == "degraded"
    # Readiness is diagnostic data, not an exception or a destructive repair.
    assert (home / "config.yaml").read_text(encoding="utf-8") == "model: [unterminated"


def test_collect_runtime_readiness_degrades_below_staging_disk_headroom(
    tmp_path, monkeypatch
):
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text(
        "readiness:\n  disk_min_free_gb: 10\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    total = 20 * 1024**3
    free = 9 * 1024**3
    monkeypatch.setattr(
        readiness.shutil,
        "disk_usage",
        lambda _path: shutil._ntuple_diskusage(  # type: ignore[attr-defined]
            total=total, used=total - free, free=free
        ),
    )

    result = collect_runtime_readiness(
        configured_model="test/model",
        runtime_status={"gateway_state": "running", "platforms": {}},
    )

    disk = result["checks"]["disk"]
    assert result["status"] == "degraded"
    assert disk["status"] == "degraded"
    assert disk["pressure"] == "elevated"
    assert disk["minimum_free_bytes"] == 10 * 1024**3


def test_collect_runtime_readiness_uses_conservative_default_disk_headroom(
    tmp_path, monkeypatch
):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    total = 5 * 1024**3
    free = 2 * 1024**3
    monkeypatch.setattr(
        readiness.shutil,
        "disk_usage",
        lambda _path: shutil._ntuple_diskusage(  # type: ignore[attr-defined]
            total=total, used=total - free, free=free
        ),
    )

    result = collect_runtime_readiness(
        configured_model="test/model",
        runtime_status={"gateway_state": "running", "platforms": {}},
    )

    disk = result["checks"]["disk"]
    assert disk["status"] == "ok"
    assert disk["minimum_free_bytes"] == 1024**3


