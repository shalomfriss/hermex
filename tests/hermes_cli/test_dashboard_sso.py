from __future__ import annotations

import argparse
import base64
import json
import threading
from unittest.mock import MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from hermes_cli import dashboard_sso
from hermes_cli.subcommands.dashboard import build_dashboard_parser

ISSUER = "https://idp.example.com/oauth2/default"
DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
    "jwks_uri": f"{ISSUER}/jwks",
    "id_token_signing_alg_values_supported": ["RS256", "ES256"],
}


def _config(self_hosted=None, public_url=""):
    return {
        "dashboard": {
            "public_url": public_url,
            "oauth": {"self_hosted": self_hosted or {}},
        }
    }


def _response(body, status=200):
    response = MagicMock(spec=httpx.Response)
    response.status_code = status
    response.json.return_value = body
    response.headers = {"content-type": "application/json"}
    response.text = json.dumps(body)
    return response


class _StreamResponse:
    def __init__(self, body, *, status=200, chunks=None):
        self.status_code = status
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self._chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def iter_bytes(self, chunk_size=None):
        _ = chunk_size
        return iter(self._chunks or [self._body])


@pytest.fixture(scope="module")
def valid_jwks():
    public_numbers = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).public_key().public_numbers()

    def encoded(value):
        size = (value.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "preflight-test-key",
                "n": encoded(public_numbers.n),
                "e": encoded(public_numbers.e),
            }
        ]
    }


def test_parser_dispatches_nested_sso_without_changing_existing_forms():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    dashboard_handler = object()
    register_handler = object()
    sso_handler = object()
    rotate_handler = object()
    build_dashboard_parser(
        subparsers,
        cmd_dashboard=dashboard_handler,
        cmd_dashboard_register=register_handler,
        cmd_dashboard_sso_check=sso_handler,
        cmd_dashboard_refresh_binding_rotate=rotate_handler,
    )

    bare = parser.parse_args(["dashboard"])
    register = parser.parse_args(["dashboard", "register"])
    sso = parser.parse_args(
        ["dashboard", "sso", "check", "--json", "--public-url", "https://h.example"]
    )
    rotate = parser.parse_args(["dashboard", "sso", "rotate-refresh-binding-key"])

    assert bare.func is dashboard_handler
    assert register.func is register_handler
    assert sso.func is sso_handler
    assert sso.json is True
    assert sso.public_url == "https://h.example"
    assert rotate.func is rotate_handler


@pytest.mark.parametrize(
    "self_hosted, expected",
    [
        ({"issuer": "", "client_id": "client"}, "issuer"),
        ({"issuer": ISSUER, "client_id": ""}, "client_id"),
        (
            {
                "issuer": ISSUER,
                "client_id": "client",
                "authorization": {"required_groups": "admins"},
            },
            "policy",
        ),
        ({"issuer": "http://remote.example", "client_id": "client"}, "https"),
    ],
)
def test_invalid_or_missing_configuration_fails_without_discovery(self_hosted, expected):
    with patch("hermes_cli.config.load_config", return_value=_config(self_hosted)), patch.object(
        dashboard_sso.httpx, "get"
    ) as get:
        result = dashboard_sso.check_sso()

    assert result["ready"] is False
    assert expected in " ".join(result["errors"])
    get.assert_not_called()


def test_discovery_transport_failure_and_issuer_mismatch_are_reported():
    configured = {"issuer": ISSUER, "client_id": "client"}
    request = httpx.Request("GET", f"{ISSUER}/.well-known/openid-configuration")
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx,
        "get",
        side_effect=httpx.ConnectError("offline", request=request),
    ):
        offline = dashboard_sso.check_sso(public_url="https://hermes.example.com")
    assert offline["ready"] is False
    assert "unreachable" in " ".join(offline["errors"])
    assert offline["checks"]["discovery"]["code"] == "discovery_unreachable"

    mismatched = {**DISCOVERY, "issuer": "https://other.example"}
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get", return_value=_response(mismatched)
    ):
        result = dashboard_sso.check_sso(public_url="https://hermes.example.com")
    assert result["ready"] is False
    assert "issuer mismatch" in " ".join(result["errors"])
    assert result["checks"]["discovery"]["code"] == "discovery_issuer_mismatch"


def test_invalid_authorization_policy_has_a_policy_specific_result():
    configured = {
        "issuer": ISSUER,
        "client_id": "client",
        "authorization": {"required_groups": "admins"},
    }
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get"
    ) as get:
        result = dashboard_sso.check_sso(public_url="https://hermes.example.com")

    assert result["ready"] is False
    assert result["checks"]["configuration"]["ok"] is True
    assert result["checks"]["policy"]["code"] == "policy_invalid"
    get.assert_not_called()


@pytest.mark.parametrize(
    "issuer",
    [
        "https://issuer-secret@idp.example.com",
        "https://idp.example.com:not-a-port",
        "https://idp.example.com/tenant?token=issuer-secret",
    ],
    ids=["userinfo", "invalid-port", "query"],
)
def test_malformed_issuer_authority_is_rejected_secret_safely(issuer):
    configured = {"issuer": issuer, "client_id": "client"}
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get"
    ) as get:
        result = dashboard_sso.check_sso(public_url="https://hermes.example.com")

    assert result["ready"] is False
    assert result["checks"]["configuration"]["code"] == "configuration_invalid"
    assert result["issuer"] == ""
    assert "issuer-secret" not in json.dumps(result)
    assert "not-a-port" not in json.dumps(result)
    get.assert_not_called()


@pytest.mark.parametrize(
    "discovery, expected",
    [
        ({key: value for key, value in DISCOVERY.items() if key != "jwks_uri"}, "missing"),
        (
            {**DISCOVERY, "id_token_signing_alg_values_supported": ["HS256"]},
            "algorithm",
        ),
    ],
)
def test_discovery_requires_endpoints_and_signing_algorithm_intersection(
    discovery, expected
):
    configured = {"issuer": ISSUER, "client_id": "client"}
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get", return_value=_response(discovery)
    ):
        result = dashboard_sso.check_sso(public_url="https://hermes.example.com")

    assert result["ready"] is False
    assert expected in " ".join(result["errors"])


def test_missing_public_callback_fails_closed_with_distinct_check_results():
    configured = {"issuer": ISSUER, "client_id": "client"}
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get", return_value=_response(DISCOVERY)
    ):
        result = dashboard_sso.check_sso()

    assert result["ready"] is False
    assert result["callback_complete"] is False
    assert result["checks"]["configuration"]["ok"] is True
    assert result["checks"]["callback"]["code"] == "callback_missing"
    assert "public URL" in " ".join(result["errors"])


def test_non_loopback_http_callback_is_rejected_before_discovery():
    configured = {"issuer": ISSUER, "client_id": "client"}
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get"
    ) as get:
        result = dashboard_sso.check_sso(public_url="http://dashboard.example.com")

    assert result["ready"] is False
    assert result["callback_complete"] is False
    assert result["checks"]["callback"]["code"] == "callback_insecure"
    assert "HTTPS" in " ".join(result["errors"])
    get.assert_not_called()


@pytest.mark.parametrize(
    "public_url",
    [
        "https://callback-secret@dashboard.example.com",
        "https://dashboard.example.com:not-a-port",
    ],
    ids=["userinfo", "invalid-port"],
)
def test_malformed_callback_urls_fail_without_leaking_details(public_url):
    configured = {"issuer": ISSUER, "client_id": "client"}
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get"
    ) as get:
        result = dashboard_sso.check_sso(public_url=public_url)

    assert result["ready"] is False
    assert result["callback_complete"] is False
    assert result["checks"]["callback"]["code"] == "callback_invalid"
    assert "callback-secret" not in json.dumps(result)
    assert "not-a-port" not in json.dumps(result)
    get.assert_not_called()


def test_unreachable_jwks_fails_with_a_jwks_specific_result():
    configured = {"issuer": ISSUER, "client_id": "client"}
    request = httpx.Request("GET", DISCOVERY["jwks_uri"])
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get", return_value=_response(DISCOVERY)
    ), patch.object(
        dashboard_sso.httpx,
        "stream",
        side_effect=httpx.ConnectError("secret-bearing transport detail", request=request),
    ):
        result = dashboard_sso.check_sso(public_url="https://hermes.example.com")

    assert result["ready"] is False
    assert result["checks"]["discovery"]["ok"] is True
    assert result["checks"]["jwks"]["code"] == "jwks_unreachable"
    assert "JWKS endpoint is unreachable" in result["errors"]
    assert "secret-bearing" not in json.dumps(result)


def test_jwks_stream_enforces_an_overall_deadline():
    stream = _StreamResponse(b"", chunks=[b'{"keys": []}'])
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    errors = []
    fetch_jwks = getattr(dashboard_sso, "_fetch_jwks_document")
    jwks_error = getattr(dashboard_sso, "_JWKSError")
    caller = None

    def delayed_stream(*_args, **_kwargs):
        entered.set()
        release.wait()
        return stream

    def fetch():
        try:
            fetch_jwks(DISCOVERY["jwks_uri"])
        except jwks_error as exc:
            errors.append(exc)
        finally:
            finished.set()

    try:
        with patch.object(
            dashboard_sso.httpx, "stream", side_effect=delayed_stream
        ), patch.object(dashboard_sso, "_JWKS_TIMEOUT_SECONDS", 0.01):
            caller = threading.Thread(target=fetch)
            caller.start()
            assert entered.wait(2)
            assert finished.wait(2)
    finally:
        release.set()
        if caller is not None:
            caller.join(timeout=2)

    assert [error.code for error in errors] == ["jwks_timeout"]


@pytest.mark.parametrize(
    "jwks, discovery, expected_code",
    [
        (b"not-json", DISCOVERY, "jwks_malformed"),
        (
            {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256"}]},
            DISCOVERY,
            "jwks_malformed",
        ),
        ({"keys": []}, DISCOVERY, "jwks_empty"),
        ({"keys": [{"kty": "oct", "use": "sig", "alg": "HS256"}]}, DISCOVERY, "jwks_wrong_kty"),
        ({"keys": [{"kty": "RSA", "use": "enc", "alg": "RS256"}]}, DISCOVERY, "jwks_wrong_use"),
        ({"keys": [{"kty": "RSA", "use": "sig", "alg": "HS256"}]}, DISCOVERY, "jwks_wrong_alg"),
        (
            {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS512"}]},
            {**DISCOVERY, "id_token_signing_alg_values_supported": ["RS256"]},
            "jwks_no_algorithm_intersection",
        ),
        (b"x" * (1024 * 1024 + 1), DISCOVERY, "jwks_too_large"),
    ],
    ids=[
        "malformed-json",
        "malformed-key-material",
        "empty",
        "wrong-kty",
        "wrong-use",
        "wrong-alg",
        "no-intersection",
        "too-large",
    ],
)
def test_jwks_failures_are_bounded_and_classified(jwks, discovery, expected_code):
    configured = {"issuer": ISSUER, "client_id": "client"}
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get", return_value=_response(discovery)
    ), patch.object(
        dashboard_sso.httpx, "stream", return_value=_StreamResponse(jwks)
    ):
        result = dashboard_sso.check_sso(public_url="https://hermes.example.com")

    assert result["ready"] is False
    assert result["checks"]["jwks"]["code"] == expected_code
    assert len(" ".join(result["errors"])) < 500


def test_valid_public_and_confidential_reports_are_safe(monkeypatch, valid_jwks):
    configured = {
        "issuer": ISSUER,
        "client_id": "hermes-dashboard",
        "scopes": "openid profile email groups",
        "authorization": {
            "require_verified_email": True,
            "required_groups": ["admins"],
        },
    }
    monkeypatch.delenv("HERMES_DASHBOARD_OIDC_CLIENT_SECRET", raising=False)
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get", return_value=_response(DISCOVERY)
    ), patch.object(
        dashboard_sso.httpx, "stream", return_value=_StreamResponse(valid_jwks)
    ):
        public = dashboard_sso.check_sso(public_url="https://hermes.example.com/root")
    assert public["ready"] is True
    assert public["client_mode"] == "public"
    assert public["callback_url"] == "https://hermes.example.com/root/auth/callback"
    assert public["signing_algorithms"] == ["ES256", "RS256"]
    assert set(public["policy_categories"]) == {"verified_email", "groups"}
    assert all(check["ok"] for check in public["checks"].values())
    assert public["checks"]["jwks"]["usable_signing_keys"] == 1
    assert all("client_secret" not in key for key in public)

    monkeypatch.setenv("HERMES_DASHBOARD_OIDC_CLIENT_SECRET", "super-secret")
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get", return_value=_response(DISCOVERY)
    ), patch.object(
        dashboard_sso.httpx, "stream", return_value=_StreamResponse(valid_jwks)
    ):
        confidential = dashboard_sso.check_sso(public_url="http://127.0.0.1:9119")
    assert confidential["ready"] is True
    assert confidential["client_mode"] == "confidential"
    assert confidential["callback_complete"] is True
    assert "super-secret" not in json.dumps(confidential)


def test_discovered_endpoint_userinfo_is_rejected_without_exposure(valid_jwks):
    configured = {"issuer": ISSUER, "client_id": "client"}
    discovery = {
        **DISCOVERY,
        "jwks_uri": "https://transport-secret@idp.example.com/jwks",
    }
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get", return_value=_response(discovery)
    ), patch.object(
        dashboard_sso.httpx, "stream", return_value=_StreamResponse(valid_jwks)
    ):
        result = dashboard_sso.check_sso(public_url="https://hermes.example.com")

    assert result["ready"] is False
    assert result["checks"]["discovery"] == {
        "ok": False,
        "code": "discovery_endpoint_policy",
    }
    assert "transport-secret" not in json.dumps(result)


def test_json_command_has_stable_exit_codes_and_never_prints_secret(
    monkeypatch, capsys, valid_jwks
):
    monkeypatch.setenv("HERMES_DASHBOARD_OIDC_CLIENT_SECRET", "super-secret")
    good = {
        "issuer": ISSUER,
        "client_id": "client",
    }
    args = argparse.Namespace(json=True, public_url="https://hermes.example.com")
    with patch("hermes_cli.config.load_config", return_value=_config(good)), patch.object(
        dashboard_sso.httpx, "get", return_value=_response(DISCOVERY)
    ), patch.object(
        dashboard_sso.httpx, "stream", return_value=_StreamResponse(valid_jwks)
    ):
        dashboard_sso.cmd_dashboard_sso_check(args)
    output = capsys.readouterr().out
    assert json.loads(output)["ready"] is True
    assert "super-secret" not in output

    with patch("hermes_cli.config.load_config", return_value=_config({})):
        with pytest.raises(SystemExit) as excinfo:
            dashboard_sso.cmd_dashboard_sso_check(args)
    assert excinfo.value.code == 1


def test_human_command_distinguishes_each_preflight_check(capsys, valid_jwks):
    configured = {"issuer": ISSUER, "client_id": "client"}
    args = argparse.Namespace(json=False, public_url="https://hermes.example.com")
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get", return_value=_response(DISCOVERY)
    ), patch.object(
        dashboard_sso.httpx, "stream", return_value=_StreamResponse(valid_jwks)
    ):
        dashboard_sso.cmd_dashboard_sso_check(args)

    output = capsys.readouterr().out
    for category in ("configuration", "discovery", "jwks", "callback", "policy"):
        assert f"{category}: PASS" in output
