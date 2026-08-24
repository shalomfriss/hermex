"""Deployment-topology contract for process-local dashboard auth state."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any


class TopologyError(ValueError):
    """The configured deployment cannot safely route process-local auth state."""


def _positive_int(value: object, *, name: str) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError) as exc:
        raise TopologyError(f"{name} must be a positive integer") from exc
    if parsed < 1:
        raise TopologyError(f"{name} must be a positive integer")
    return parsed


def validate_topology(
    config: Mapping[str, Any] | None,
    *,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Validate the only safe layouts for pending codes and WS tickets.

    A single process needs no coordination. Multiple replicas are supported
    only when an operator explicitly declares and verifies proxy stickiness;
    this keeps each browser's REST, WS-upgrade, and reconnect requests on the
    process that owns its pending codes and one-shot tickets. In-process
    multi-worker launchers cannot provide that guarantee and are rejected.
    """
    raw = dict(config or {})
    environment = os.environ if env is None else env
    replicas = _positive_int(raw.get("replicas", 1), name="dashboard.topology.replicas")
    backend = str(raw.get("state_backend") or "process_local").strip().lower()
    if backend != "process_local":
        raise TopologyError(
            f"unsupported state backend {backend!r}; only process_local is implemented"
        )

    for variable in ("WEB_CONCURRENCY", "UVICORN_WORKERS"):
        value = environment.get(variable)
        if value in (None, ""):
            continue
        workers = _positive_int(value, name=variable)
        if workers > 1:
            raise TopologyError(
                f"{variable}={workers} is unsupported: dashboard auth tickets and "
                "native pending codes are process-local; run one worker per replica"
            )

    if replicas == 1:
        return {
            "status": "ok",
            "replicas": 1,
            "state_backend": backend,
            "routing": "single_replica",
        }
    if raw.get("sticky_routing_verified") is not True:
        raise TopologyError(
            "multiple replicas with process-local auth state require explicitly "
            "verified sticky routing for HTTP and every WebSocket surface"
        )
    if raw.get("native_flow_affinity_verified") is not True:
        raise TopologyError(
            "multiple replicas also require verified native desktop affinity: "
            "the browser callback and subsequent native token exchange must "
            "reach the same replica"
        )
    return {
        "status": "ok",
        "replicas": replicas,
        "state_backend": backend,
        "routing": "verified_sticky",
    }


def topology_readiness(
    config: Mapping[str, Any] | None,
    *,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Readiness-shaped validation that never raises or exposes config values."""
    try:
        return validate_topology(config, env=env)
    except TopologyError as exc:
        raw = dict(config or {})
        try:
            replicas = max(1, int(raw.get("replicas", 1)))
        except (TypeError, ValueError):
            replicas = 1
        return {
            "status": "degraded",
            "replicas": replicas,
            "state_backend": str(raw.get("state_backend") or "process_local"),
            "detail": str(exc),
        }


__all__ = ["TopologyError", "topology_readiness", "validate_topology"]
