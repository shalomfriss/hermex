from __future__ import annotations

import argparse
import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

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


def test_parser_dispatches_nested_sso_without_changing_existing_forms():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    dashboard_handler = object()
    register_handler = object()
    sso_handler = object()
    build_dashboard_parser(
        subparsers,
        cmd_dashboard=dashboard_handler,
        cmd_dashboard_register=register_handler,
        cmd_dashboard_sso_check=sso_handler,
    )

    bare = parser.parse_args(["dashboard"])
    register = parser.parse_args(["dashboard", "register"])
    sso = parser.parse_args(
        ["dashboard", "sso", "check", "--json", "--public-url", "https://h.example"]
    )

    assert bare.func is dashboard_handler
    assert register.func is register_handler
    assert sso.func is sso_handler
    assert sso.json is True
    assert sso.public_url == "https://h.example"


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
            "required_groups",
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
        offline = dashboard_sso.check_sso()
    assert offline["ready"] is False
    assert "unreachable" in " ".join(offline["errors"])

    mismatched = {**DISCOVERY, "issuer": "https://other.example"}
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get", return_value=_response(mismatched)
    ):
        result = dashboard_sso.check_sso()
    assert result["ready"] is False
    assert "issuer mismatch" in " ".join(result["errors"])


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


def test_valid_public_and_confidential_reports_are_safe(monkeypatch):
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
    ):
        public = dashboard_sso.check_sso(public_url="https://hermes.example.com/root")
    assert public["ready"] is True
    assert public["client_mode"] == "public"
    assert public["callback_url"] == "https://hermes.example.com/root/auth/callback"
    assert public["signing_algorithms"] == ["ES256", "RS256"]
    assert set(public["policy_categories"]) == {"verified_email", "groups"}
    assert all("client_secret" not in key for key in public)

    monkeypatch.setenv("HERMES_DASHBOARD_OIDC_CLIENT_SECRET", "super-secret")
    with patch("hermes_cli.config.load_config", return_value=_config(configured)), patch.object(
        dashboard_sso.httpx, "get", return_value=_response(DISCOVERY)
    ):
        confidential = dashboard_sso.check_sso()
    assert confidential["ready"] is True
    assert confidential["client_mode"] == "confidential"
    assert confidential["callback_complete"] is False
    assert "super-secret" not in json.dumps(confidential)


def test_json_command_has_stable_exit_codes_and_never_prints_secret(monkeypatch, capsys):
    monkeypatch.setenv("HERMES_DASHBOARD_OIDC_CLIENT_SECRET", "super-secret")
    good = {
        "issuer": ISSUER,
        "client_id": "client",
    }
    args = argparse.Namespace(json=True, public_url="https://hermes.example.com")
    with patch("hermes_cli.config.load_config", return_value=_config(good)), patch.object(
        dashboard_sso.httpx, "get", return_value=_response(DISCOVERY)
    ):
        dashboard_sso.cmd_dashboard_sso_check(args)
    output = capsys.readouterr().out
    assert json.loads(output)["ready"] is True
    assert "super-secret" not in output

    with patch("hermes_cli.config.load_config", return_value=_config({})):
        with pytest.raises(SystemExit) as excinfo:
            dashboard_sso.cmd_dashboard_sso_check(args)
    assert excinfo.value.code == 1
