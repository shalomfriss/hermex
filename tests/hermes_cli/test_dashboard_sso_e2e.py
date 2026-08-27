from __future__ import annotations

import base64
import hashlib
import http.server
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from hermes_cli import web_server
from hermes_cli.dashboard_auth import clear_providers, register_provider
from hermes_cli.dashboard_auth.cookies import (
    SESSION_AT_COOKIE,
    SESSION_RT_COOKIE,
    _resolved_name,
)
from hermes_cli.dashboard_auth.ws_tickets import TicketInvalid, consume_ticket
from plugins.dashboard_auth.self_hosted import SelfHostedOIDCProvider


@dataclass
class OIDCState:
    private_pem: str
    jwk: dict[str, Any]
    issuer: str = ""
    next_mode: str = "ok"
    groups: list[str] = field(default_factory=lambda: ["hermes-admins"])
    codes: dict[str, dict[str, str]] = field(default_factory=dict)
    revoked: list[str] = field(default_factory=list)

    def mint(self, *, nonce: str = "", mode: str = "ok") -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": "hermes-dashboard",
            "sub": "enterprise-user-1",
            "email": "alice@example.com",
            "email_verified": True,
            "name": "Alice Enterprise",
            "tid": "tenant-a",
            "groups": list(self.groups),
            "auth_time": now,
            "iat": now,
            "exp": now + 900,
        }
        if nonce:
            claims["nonce"] = "wrong-nonce" if mode == "wrong_nonce" else nonce
        if mode == "wrong_audience":
            claims["aud"] = ["hermes-dashboard", "other-api"]
            claims["azp"] = "other-client"
        if mode == "denied_group":
            claims["groups"] = ["viewers"]
        if mode == "stale_auth":
            claims["auth_time"] = now - 10_000
        return jwt.encode(
            claims,
            self.private_pem,
            algorithm="RS256",
            headers={"kid": self.jwk["kid"]},
        )


class OIDCHandler(http.server.BaseHTTPRequestHandler):
    server: "OIDCHTTPServer"

    def log_message(self, format, *args):
        return

    def _json(self, status: int, body: dict[str, Any]):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        state = self.server.state
        parsed = urlparse(self.path)
        if parsed.path == "/.well-known/openid-configuration":
            self._json(
                200,
                {
                    "issuer": state.issuer,
                    "authorization_endpoint": f"{state.issuer}/authorize",
                    "token_endpoint": f"{state.issuer}/token",
                    "jwks_uri": f"{state.issuer}/jwks",
                    "revocation_endpoint": f"{state.issuer}/revoke",
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "token_endpoint_auth_methods_supported": ["none"],
                },
            )
            return
        if parsed.path == "/jwks":
            self._json(200, {"keys": [state.jwk]})
            return
        if parsed.path == "/authorize":
            query = parse_qs(parsed.query)
            code = secrets.token_urlsafe(18)
            state.codes[code] = {
                "nonce": query.get("nonce", [""])[0],
                "mode": state.next_mode,
            }
            location = (
                f"{query['redirect_uri'][0]}?"
                f"{urlencode({'code': code, 'state': query['state'][0]})}"
            )
            self.send_response(302)
            self.send_header("location", location)
            self.end_headers()
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        state = self.server.state
        length = int(self.headers.get("content-length", "0"))
        form = parse_qs(self.rfile.read(length).decode())
        if self.path == "/token":
            grant = form.get("grant_type", [""])[0]
            if grant == "authorization_code":
                record = state.codes.pop(form.get("code", [""])[0], None)
                if record is None:
                    self._json(400, {"error": "invalid_grant"})
                    return
                token = state.mint(nonce=record["nonce"], mode=record["mode"])
            elif grant == "refresh_token":
                token = state.mint()
            else:
                self._json(400, {"error": "unsupported_grant_type"})
                return
            self._json(
                200,
                {
                    "id_token": token,
                    "token_type": "Bearer",
                    "refresh_token": "refresh-enterprise-user-1",
                },
            )
            return
        if self.path == "/revoke":
            state.revoked.append(form.get("token", [""])[0])
            self._json(200, {})
            return
        self._json(404, {"error": "not_found"})


class OIDCHTTPServer(http.server.ThreadingHTTPServer):
    state: OIDCState


class OIDCFixture:
    def __init__(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        numbers = key.public_key().public_numbers()

        def b64uint(value: int) -> str:
            size = (value.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()

        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "enterprise-test-key",
            "n": b64uint(numbers.n),
            "e": b64uint(numbers.e),
        }
        self.server = OIDCHTTPServer(("127.0.0.1", 0), OIDCHandler)
        self.server.state = OIDCState(private_pem=private_pem, jwk=jwk)
        port = self.server.server_address[1]
        self.server.state.issuer = f"http://127.0.0.1:{port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.stopped = False

    @property
    def state(self) -> OIDCState:
        return self.server.state

    def stop(self):
        if self.stopped:
            return
        self.stopped = True
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@pytest.fixture
def oidc_app():
    oidc = OIDCFixture()
    provider = SelfHostedOIDCProvider(
        issuer=oidc.state.issuer,
        client_id="hermes-dashboard",
        scopes="openid profile email groups offline_access",
        authorization={
            "require_email": True,
            "require_verified_email": True,
            "allowed_email_domains": ["example.com"],
            "required_groups": ["hermes-admins"],
            "allowed_tenants": ["tenant-a"],
            "require_mfa": False,
            "max_auth_age_seconds": 300,
        },
    )
    clear_providers()
    register_provider(provider)
    previous = (
        getattr(web_server.app.state, "bound_host", None),
        getattr(web_server.app.state, "bound_port", None),
        getattr(web_server.app.state, "auth_required", None),
    )
    web_server.app.state.bound_host = "fly-app.fly.dev"
    web_server.app.state.bound_port = 443
    web_server.app.state.auth_required = True
    client = TestClient(
        web_server.app,
        base_url="https://fly-app.fly.dev",
        follow_redirects=False,
    )
    yield oidc, provider, client
    client.close()
    clear_providers()
    (
        web_server.app.state.bound_host,
        web_server.app.state.bound_port,
        web_server.app.state.auth_required,
    ) = previous
    oidc.stop()


def _finish_idp_redirect(client: TestClient, authorize_url: str):
    idp = httpx.get(authorize_url, follow_redirects=False)
    assert idp.status_code == 302
    callback = urlparse(idp.headers["location"])
    return client.get(
        f"{callback.path}?{callback.query}", follow_redirects=False
    )


def _browser_login(client: TestClient):
    started = client.get(
        "/auth/login?provider=self-hosted", follow_redirects=False
    )
    assert started.status_code == 302
    return _finish_idp_redirect(client, started.headers["location"])


def test_real_http_browser_login_me_ws_ticket_and_logout(oidc_app):
    oidc, _provider, client = oidc_app

    document = client.get("/", follow_redirects=False)
    assert document.status_code == 302
    assert document.headers["location"].startswith("/auth/login")

    callback = _browser_login(client)
    assert callback.status_code == 302
    assert callback.headers["location"] == "/"

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["user_id"] == "enterprise-user-1"
    assert me.json()["org_id"] == "tenant-a"

    ticket_response = client.post("/api/auth/ws-ticket")
    assert ticket_response.status_code == 200
    ticket = ticket_response.json()["ticket"]
    assert consume_ticket(ticket)["user_id"] == "enterprise-user-1"
    with pytest.raises(TicketInvalid):
        consume_ticket(ticket)

    logged_out = client.post("/auth/logout", follow_redirects=False)
    assert logged_out.status_code == 302
    assert oidc.state.revoked == ["refresh-enterprise-user-1"]


@pytest.mark.parametrize(
    "mode, expected_status",
    [
        ("wrong_nonce", 400),
        ("wrong_audience", 400),
        ("denied_group", 403),
        ("stale_auth", 403),
    ],
)
def test_real_http_callback_fails_closed_for_protocol_and_policy(mode, expected_status, oidc_app):
    oidc, _provider, client = oidc_app
    oidc.state.next_mode = mode

    response = _browser_login(client)

    assert response.status_code == expected_status
    assert "id_token" not in response.text.lower()
    assert "hermes-admins" not in response.text


def test_refresh_group_removal_denies_and_provider_outage_is_503(oidc_app):
    oidc, provider, client = oidc_app
    assert _browser_login(client).status_code == 302
    refresh_token = client.cookies.get(
        _resolved_name(SESSION_RT_COOKIE, use_https=True, prefix="")
    )
    assert refresh_token

    oidc.state.groups = ["viewers"]
    denied = client.post(
        "/auth/native/refresh",
        json={"provider": "self-hosted", "refresh_token": refresh_token},
    )
    assert denied.status_code == 403
    assert denied.json()["error"] == "access_denied"

    oidc.state.groups = ["hermes-admins"]
    provider._jwks_client = None
    oidc.stop()
    outage = client.get(
        "/api/auth/me",
        headers={
            "Authorization": (
                "Bearer "
                + str(
                    client.cookies.get(
                        _resolved_name(SESSION_AT_COOKIE, use_https=True, prefix="")
                    )
                )
            )
        },
    )
    assert outage.status_code == 503
    assert outage.json()["error"] == "provider_unavailable"
    assert outage.json()["retryable"] is True
    assert outage.json()["reference_id"].startswith("AUTH-")


def test_real_http_desktop_native_flow_is_cookie_free(oidc_app):
    _oidc, _provider, client = oidc_app
    verifier = base64.urlsafe_b64encode(b"desktop-verifier-material-0123456789abcdef").rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    loopback = "http://127.0.0.1:53999/callback"

    started = client.get(
        "/auth/native/authorize",
        params={
            "provider": "self-hosted",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": loopback,
            "state": "desktop-state",
        },
    )
    assert started.status_code == 302
    callback = _finish_idp_redirect(client, started.headers["location"])
    assert callback.status_code == 302
    assert callback.headers["location"].startswith(loopback)
    assert "hermes_session_at" not in callback.headers.get("set-cookie", "")

    loopback_query = parse_qs(urlparse(callback.headers["location"]).query)
    redeemed = client.post(
        "/auth/native/token",
        json={"code": loopback_query["code"][0], "code_verifier": verifier},
    )
    assert redeemed.status_code == 200
    tokens = redeemed.json()
    assert tokens["provider"] == "self-hosted"

    me = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["user_id"] == "enterprise-user-1"
