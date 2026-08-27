"""Adversarial secret-redaction tests for dashboard-auth failures."""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from hermes_cli import web_server
from hermes_cli.dashboard_auth import clear_providers, register_provider
from hermes_cli.dashboard_auth.base import (
    AccessDeniedError,
    InvalidCodeError,
    ProviderError,
)
from hermes_cli.dashboard_auth.cookies import SESSION_AT_COOKIE
from hermes_cli.dashboard_auth.refresh_binding import mint_refresh_binding
from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider


SECRET_CANARIES = (
    "client-secret-canary",
    "refresh-token-canary",
    "access-token-canary",
    "id-token-canary",
    "authorization-code-canary",
    "session-cookie-canary",
    "control-canary",
)
REFLECTED_FAILURE = (
    "client_secret=client-secret-canary refresh_token=refresh-token-canary "
    "access_token=access-token-canary id_token=id-token-canary "
    "code=authorization-code-canary cookie=session-cookie-canary\n"
    "second-line\r\x1b[31mcontrol-canary"
)


class _ReflectingProvider(StubAuthProvider):
    name = "reflecting"
    display_name = "Reflecting provider"

    def verify_session(self, *, access_token: str):
        raise ProviderError(REFLECTED_FAILURE)

    def refresh_session(self, *, refresh_token: str, access_token: str = ""):
        raise ProviderError(REFLECTED_FAILURE)


class _DenyingProvider(_ReflectingProvider):
    name = "denying"

    def verify_session(self, *, access_token: str):
        raise AccessDeniedError(
            "group_required", details={"raw_claims": REFLECTED_FAILURE}
        )


class _InvalidCodeProvider(_ReflectingProvider):
    name = "invalid-code"

    def complete_login(self, **kwargs):
        raise InvalidCodeError(REFLECTED_FAILURE)


class _StartFailureProvider(_ReflectingProvider):
    name = "start-failure"

    def __init__(self):
        super().__init__()
        self.error = ProviderError(
            REFLECTED_FAILURE, classification="client-secret-canary"
        )

    def start_login(self, *, redirect_uri: str):
        raise self.error


@pytest.fixture
def gated_client(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
    clear_providers()
    register_provider(_ReflectingProvider())
    previous = (
        getattr(web_server.app.state, "bound_host", None),
        getattr(web_server.app.state, "bound_port", None),
        getattr(web_server.app.state, "auth_required", None),
    )
    web_server.app.state.bound_host = "auth.example.test"
    web_server.app.state.bound_port = 443
    web_server.app.state.auth_required = True
    client = TestClient(web_server.app, base_url="https://auth.example.test")
    yield client, tmp_path / ".hermes"
    clear_providers()
    (
        web_server.app.state.bound_host,
        web_server.app.state.bound_port,
        web_server.app.state.auth_required,
    ) = previous


@pytest.mark.parametrize("path", ["/api/auth/me", "/"])
def test_provider_secrets_do_not_reach_logs_audit_http_or_ui(
    gated_client, caplog, path
):
    client, hermes_home = gated_client
    client.cookies.set(SESSION_AT_COOKIE, "presented-token")

    with caplog.at_level(logging.WARNING):
        response = client.get(path, follow_redirects=False)

    assert response.status_code == 503
    ordinary_logs = "\n".join(record.getMessage() for record in caplog.records)
    audit_path = hermes_home / "logs" / "dashboard-auth.log"
    audit_logs = audit_path.read_text() if audit_path.exists() else ""
    assert "reference AUTH-" in ordinary_logs
    if path.startswith("/api/"):
        assert response.json()["reference_id"] in ordinary_logs
    for canary in SECRET_CANARIES:
        assert canary not in response.text
        assert canary not in ordinary_logs
        assert canary not in audit_logs


def test_auth_failures_keep_401_403_503_classification(gated_client):
    client, _hermes_home = gated_client

    assert client.get("/api/auth/me").status_code == 401

    clear_providers()
    register_provider(_DenyingProvider())
    client.cookies.set(SESSION_AT_COOKIE, "presented-token")
    denied = client.get("/api/auth/me")
    assert denied.status_code == 403
    assert denied.json()["error"] == "access_denied"
    for canary in SECRET_CANARIES:
        assert canary not in denied.text

    clear_providers()
    register_provider(_ReflectingProvider())
    unavailable = client.get("/api/auth/me")
    assert unavailable.status_code == 503
    assert unavailable.json()["error"] == "provider_unavailable"


def test_invalid_code_exception_text_stays_out_of_400(gated_client):
    client, _hermes_home = gated_client
    clear_providers()
    register_provider(_InvalidCodeProvider())
    started = client.get(
        "/auth/login?provider=invalid-code", follow_redirects=False
    )
    state = started.headers["location"].split("state=")[1]

    response = client.get(
        f"/auth/callback?code=reflected&state={state}",
        follow_redirects=False,
    )

    assert response.status_code == 400
    for canary in SECRET_CANARIES:
        assert canary not in response.text


def test_start_login_preserves_safe_reference_without_logging_text(
    gated_client, caplog
):
    client, _hermes_home = gated_client
    clear_providers()
    provider = _StartFailureProvider()
    register_provider(provider)

    with caplog.at_level(logging.WARNING):
        response = client.get(
            "/auth/login?provider=start-failure", follow_redirects=False
        )

    assert response.status_code == 503
    assert provider.error.reference_id in response.text
    assert provider.error.reference_id in caplog.text
    for canary in SECRET_CANARIES:
        assert canary not in response.text
        assert canary not in caplog.text


def test_native_refresh_provider_secret_stays_out_of_503(gated_client):
    client, _hermes_home = gated_client
    refresh_token = "presented-refresh"

    response = client.post(
        "/auth/native/refresh",
        json={
            "access_token": "prior-id-token",
            "refresh_token": refresh_token,
            "refresh_binding": mint_refresh_binding(
                provider="reflecting", refresh_token=refresh_token
            ),
            "provider": "reflecting",
        },
    )

    assert response.status_code == 503
    for canary in SECRET_CANARIES:
        assert canary not in response.text


def test_oauth_callback_allowlists_error_and_drops_description(gated_client):
    client, hermes_home = gated_client
    started = client.get("/auth/login?provider=reflecting", follow_redirects=False)
    assert started.status_code == 302

    response = client.get(
        "/auth/callback",
        params={
            "error": REFLECTED_FAILURE,
            "error_description": REFLECTED_FAILURE,
        },
    )

    assert response.status_code == 400
    audit_logs = (hermes_home / "logs" / "dashboard-auth.log").read_text()
    for canary in SECRET_CANARIES:
        assert canary not in response.text
        assert canary not in audit_logs
