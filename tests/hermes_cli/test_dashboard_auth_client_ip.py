"""Trusted reverse-proxy client-IP contract for dashboard authentication."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from hermes_cli.dashboard_auth.client_ip import (
    client_ip,
    parse_trusted_proxy_networks,
)


def _request(
    peer: str,
    *,
    forwarded_for: str = "",
    forwarded_proto: str = "",
    trusted_proxies: tuple = (),
) -> Request:
    headers = []
    if forwarded_for:
        headers.append((b"x-forwarded-for", forwarded_for.encode("ascii")))
    if forwarded_proto:
        headers.append((b"x-forwarded-proto", forwarded_proto.encode("ascii")))
    app = SimpleNamespace(
        state=SimpleNamespace(dashboard_trusted_proxy_networks=trusted_proxies)
    )
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/auth/password-login",
            "raw_path": b"/auth/password-login",
            "query_string": b"",
            "headers": headers,
            "client": (peer, 42000),
            "server": ("dashboard.example", 443),
            "app": app,
        }
    )


def _trusted(*values: str) -> tuple:
    return parse_trusted_proxy_networks(values)


def test_untrusted_peer_cannot_spoof_forwarded_for():
    request = _request("198.51.100.9", forwarded_for="203.0.113.44")

    assert client_ip(request) == "198.51.100.9"


def test_scalar_trusted_proxy_config_fails_closed():
    assert parse_trusted_proxy_networks("0.0.0.0/0") == ()


def test_trusted_append_proxy_resolves_single_hop():
    request = _request(
        "10.0.0.3",
        forwarded_for="203.0.113.44",
        trusted_proxies=_trusted("10.0.0.0/8"),
    )

    assert client_ip(request) == "203.0.113.44"


def test_trusted_append_proxy_resolves_multi_hop_right_to_left():
    request = _request(
        "10.0.0.3",
        forwarded_for="203.0.113.44, 10.0.0.1, 10.0.0.2",
        trusted_proxies=_trusted("10.0.0.0/8"),
    )

    assert client_ip(request) == "203.0.113.44"


def test_first_untrusted_hop_from_right_is_the_safe_boundary():
    request = _request(
        "10.0.0.3",
        forwarded_for="192.0.2.7, 198.51.100.8, 10.0.0.2",
        trusted_proxies=_trusted("10.0.0.0/8"),
    )

    assert client_ip(request) == "198.51.100.8"


@pytest.mark.parametrize(
    "forwarded_for",
    [
        "203.0.113.44, not-an-ip",
        "203.0.113.44,,10.0.0.2",
        ",".join(["10.0.0.1"] * 33),
        "1" * 4097,
    ],
)
def test_malformed_or_oversized_forwarded_chain_falls_back_to_peer(forwarded_for):
    request = _request(
        "10.0.0.3",
        forwarded_for=forwarded_for,
        trusted_proxies=_trusted("10.0.0.0/8"),
    )

    assert client_ip(request) == "10.0.0.3"


def test_ipv4_mapped_ipv6_normalizes_to_the_ipv4_bucket():
    direct = _request("::ffff:192.0.2.9")
    forwarded = _request(
        "10.0.0.3",
        forwarded_for="::ffff:192.0.2.9",
        trusted_proxies=_trusted("10.0.0.0/8"),
    )

    assert client_ip(direct) == client_ip(forwarded) == "192.0.2.9"


def test_routes_middleware_and_token_auth_use_the_same_canonical_ip():
    from hermes_cli.dashboard_auth import middleware, routes, token_auth

    request = _request(
        "10.0.0.3",
        forwarded_for="::ffff:192.0.2.9, 10.0.0.2",
        trusted_proxies=_trusted("10.0.0.0/8"),
    )

    assert {
        routes._client_ip(request),
        middleware._client_ip(request),
        token_auth._client_ip(request),
    } == {"192.0.2.9"}


def test_forwarded_proto_uses_the_same_trusted_peer_boundary():
    from hermes_cli import web_server

    async def read_scheme(request):
        return request.scope["scheme"]

    trusted = _request(
        "10.0.0.3",
        forwarded_proto="http",
        trusted_proxies=_trusted("10.0.0.0/8"),
    )
    untrusted = _request("198.51.100.9", forwarded_proto="http")

    assert asyncio.run(
        web_server._trusted_forwarded_proto_middleware(trusted, read_scheme)
    ) == "http"
    assert asyncio.run(
        web_server._trusted_forwarded_proto_middleware(untrusted, read_scheme)
    ) == "https"


def test_password_rate_limit_and_audit_share_unspoofable_canonical_ip(monkeypatch):
    from hermes_cli.dashboard_auth import clear_providers, register_provider
    from hermes_cli.dashboard_auth import routes
    from tests.hermes_cli.test_dashboard_auth_password_login import PasswordProvider

    clear_providers()
    register_provider(PasswordProvider())
    routes._reset_password_rate_limit()
    events = []
    monkeypatch.setattr(routes, "audit_log", lambda event, **fields: events.append(fields))
    body = routes._PasswordLoginBody(
        provider="testpw", username="admin", password="wrong"
    )

    try:
        for attempt in range(11):
            request = _request(
                "198.51.100.9",
                forwarded_for=f"203.0.113.{attempt + 1}",
            )
            with pytest.raises(HTTPException) as exc:
                asyncio.run(routes.auth_password_login(request, body))
            assert exc.value.status_code == (429 if attempt == 10 else 401)

        assert {event["ip"] for event in events} == {"198.51.100.9"}
        assert events[-1]["reason"] == "rate_limited"
    finally:
        routes._reset_password_rate_limit()
        clear_providers()


def test_native_pending_capacity_uses_trusted_chain_canonical_ip(monkeypatch):
    from hermes_cli.dashboard_auth import clear_providers, native_flow, register_provider
    from hermes_cli.dashboard_auth import routes
    from tests.hermes_cli.test_dashboard_auth_password_login import PasswordProvider

    clear_providers()
    register_provider(PasswordProvider())
    native_flow._reset_for_tests()
    events = []
    monkeypatch.setattr(routes, "audit_log", lambda event, **fields: events.append(fields))

    try:
        for attempt in range(9):
            request = _request(
                "10.0.0.3",
                forwarded_for="203.0.113.44, 10.0.0.2",
                trusted_proxies=_trusted("10.0.0.0/8"),
            )
            if attempt < 8:
                response = asyncio.run(
                    routes.auth_native_authorize(
                        request,
                        provider="testpw",
                        code_challenge=f"challenge-{attempt}",
                        code_challenge_method="S256",
                        redirect_uri="http://127.0.0.1:45678/callback",
                        state=f"state-{attempt}",
                    )
                )
                assert response.status_code == 302
            else:
                with pytest.raises(HTTPException) as exc:
                    asyncio.run(
                        routes.auth_native_authorize(
                            request,
                            provider="testpw",
                            code_challenge=f"challenge-{attempt}",
                            code_challenge_method="S256",
                            redirect_uri="http://127.0.0.1:45678/callback",
                            state=f"state-{attempt}",
                        )
                    )
                assert exc.value.status_code == 503
                assert "too many pending" in exc.value.detail

        assert {event["ip"] for event in events} == {"203.0.113.44"}
    finally:
        native_flow._reset_for_tests()
        clear_providers()
