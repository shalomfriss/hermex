"""Public dashboard metadata and response-security contracts."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from hermes_cli import web_server
from hermes_cli.dashboard_auth import clear_providers, register_provider
from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider


_REQUIRED_HEADERS = {
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
}


@pytest.fixture
def gated_client():
    clear_providers()
    register_provider(StubAuthProvider())
    previous = {
        key: getattr(web_server.app.state, key, None)
        for key in ("bound_host", "bound_port", "auth_required")
    }
    web_server.app.state.bound_host = "dashboard.example.test"
    web_server.app.state.bound_port = 443
    web_server.app.state.auth_required = True
    client = TestClient(
        web_server.app,
        base_url="https://dashboard.example.test",
    )
    try:
        yield client
    finally:
        clear_providers()
        for key, value in previous.items():
            setattr(web_server.app.state, key, value)


def _login(client: TestClient) -> None:
    start = client.get("/auth/login?provider=stub", follow_redirects=False)
    assert start.status_code == 302
    state = start.headers["location"].split("state=")[1]
    callback = client.get(
        f"/auth/callback?code=stub_code&state={state}",
        follow_redirects=False,
    )
    assert callback.status_code == 302


def test_anonymous_liveness_schemas_are_exact_and_metadata_free(gated_client):
    assert gated_client.get("/api/health").json() == {"ok": True}
    assert gated_client.get("/api/status").json() == {
        "ok": True,
        "auth_required": True,
    }
    assert gated_client.get("/api/status?profile=customer-a").json() == {
        "ok": True,
        "auth_required": True,
    }


def test_authenticated_status_retains_full_operator_inventory(gated_client):
    _login(gated_client)

    response = gated_client.get("/api/status")

    assert response.status_code == 200
    body = response.json()
    assert body["auth_required"] is True
    assert "gateway_running" in body
    assert "components" in body
    assert "profiles" in body
    assert "disk" in body
    assert "hermes_home" in body


@pytest.mark.parametrize(
    "path",
    [
        "/api/config/defaults",
        "/api/config/schema",
        "/api/model/info",
        "/api/dashboard/themes",
        "/api/dashboard/plugins",
    ],
)
def test_inventory_manifests_require_authentication(gated_client, path):
    response = gated_client.get(path, follow_redirects=False)

    assert response.status_code == 401
    assert response.json()["error"] == "unauthenticated"


@pytest.mark.parametrize("path", ["/login", "/api/health", "/api/not-a-route"])
def test_security_headers_cover_html_api_and_error_responses(gated_client, path):
    response = gated_client.get(path, follow_redirects=False)

    assert _REQUIRED_HEADERS <= set(response.headers)
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["permissions-policy"] == (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
        "serial=(), bluetooth=(), browsing-topics=()"
    )
    assert "no-store" in response.headers["cache-control"]


def test_hsts_is_only_emitted_for_https():
    previous_host = getattr(web_server.app.state, "bound_host", None)
    previous_required = getattr(web_server.app.state, "auth_required", None)
    web_server.app.state.bound_host = None
    web_server.app.state.auth_required = False
    try:
        http = TestClient(web_server.app, base_url="http://127.0.0.1")
        https = TestClient(web_server.app, base_url="https://127.0.0.1")

        spoofed = http.get(
            "/api/health", headers={"X-Forwarded-Proto": "https"}
        )
        proxied_https = https.get(
            "/api/health", headers={"X-Forwarded-Proto": "https"}
        )
        assert "strict-transport-security" not in spoofed.headers
        assert proxied_https.headers["strict-transport-security"] == (
            "max-age=31536000; includeSubDomains"
        )
    finally:
        web_server.app.state.bound_host = previous_host
        web_server.app.state.auth_required = previous_required


def test_unknown_asset_directory_is_safe_404(gated_client):
    response = gated_client.get("/assets/", follow_redirects=False)

    assert response.status_code == 404
    assert _REQUIRED_HEADERS <= set(response.headers)
