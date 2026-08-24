from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from hermes_cli.dashboard_auth.topology import (
    TopologyError,
    topology_readiness,
    validate_topology,
)


def test_single_replica_process_local_topology_is_ready():
    result = validate_topology({"replicas": 1, "state_backend": "process_local"}, env={})

    assert result == {
        "status": "ok",
        "replicas": 1,
        "state_backend": "process_local",
        "routing": "single_replica",
    }


def test_multi_replica_process_local_state_requires_verified_sticky_routing():
    with pytest.raises(TopologyError, match="sticky routing"):
        validate_topology(
            {"replicas": 2, "state_backend": "process_local"},
            env={},
        )

    result = validate_topology(
        {
            "replicas": 2,
            "state_backend": "process_local",
            "sticky_routing_verified": True,
            "native_flow_affinity_verified": True,
        },
        env={},
    )
    assert result["status"] == "ok"
    assert result["routing"] == "verified_sticky"


def test_multi_worker_process_is_rejected_even_if_replica_stickiness_is_verified():
    with pytest.raises(TopologyError, match="WEB_CONCURRENCY=2"):
        validate_topology(
            {
                "replicas": 2,
                "state_backend": "process_local",
                "sticky_routing_verified": True,
                "native_flow_affinity_verified": True,
            },
            env={"WEB_CONCURRENCY": "2"},
        )


def test_unknown_shared_state_backend_is_rejected_until_implemented():
    with pytest.raises(TopologyError, match="unsupported state backend"):
        validate_topology({"replicas": 2, "state_backend": "redis"}, env={})


def test_multi_replica_requires_native_desktop_exchange_affinity():
    with pytest.raises(TopologyError, match="native desktop"):
        validate_topology(
            {
                "replicas": 2,
                "state_backend": "process_local",
                "sticky_routing_verified": True,
            },
            env={},
        )


def test_readiness_is_loudly_degraded_instead_of_raising():
    result = topology_readiness(
        {"replicas": 3, "state_backend": "process_local"}, env={}
    )

    assert result["status"] == "degraded"
    assert result["replicas"] == 3
    assert "sticky routing" in result["detail"]


def test_public_readiness_endpoint_fails_for_unsupported_topology(monkeypatch):
    from hermes_cli.dashboard_auth import public_paths
    from hermes_cli.web_server import app

    monkeypatch.setattr(
        app.state,
        "auth_topology",
        {"status": "degraded", "detail": "unsupported topology"},
        raising=False,
    )
    response = TestClient(app).get("/api/ready")

    assert "/api/ready" in public_paths.PUBLIC_API_PATHS
    assert response.status_code == 503
    assert response.json()["topology"]["status"] == "degraded"
