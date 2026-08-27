"""Read-only enterprise dashboard SSO preflight diagnostics."""
from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import urlparse

import httpx

from hermes_cli.dashboard_auth.prefix import _normalise_public_url
from plugins.dashboard_auth.self_hosted import (
    _ALLOWED_ID_TOKEN_ALGS,
    SelfHostedOIDCProvider,
)


def _configured_self_hosted() -> tuple[dict[str, Any], str]:
    from hermes_cli.config import load_config

    config = load_config()
    dashboard = config.get("dashboard") if isinstance(config, dict) else {}
    dashboard = dashboard if isinstance(dashboard, dict) else {}
    oauth = dashboard.get("oauth")
    oauth = oauth if isinstance(oauth, dict) else {}
    self_hosted = oauth.get("self_hosted")
    self_hosted = self_hosted if isinstance(self_hosted, dict) else {}
    return self_hosted, str(dashboard.get("public_url") or "")


def _resolve(env_name: str, configured: Any) -> str:
    override = os.environ.get(env_name, "").strip()
    return override or str(configured or "").strip()


def _policy_categories(provider: SelfHostedOIDCProvider) -> list[str]:
    policy = provider._authorization_policy
    categories: list[str] = []
    if policy.require_email:
        categories.append("email")
    if policy.require_verified_email:
        categories.append("verified_email")
    if policy.allowed_email_domains:
        categories.append("email_domains")
    if policy.required_groups:
        categories.append("groups")
    if policy.required_roles:
        categories.append("roles")
    if policy.allowed_tenants:
        categories.append("tenant")
    if policy.allowed_acr_values:
        categories.append("acr")
    if policy.require_mfa:
        categories.append("mfa")
    if policy.max_auth_age_seconds:
        categories.append("auth_age")
    return categories


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def check_sso(*, public_url: str | None = None) -> dict[str, Any]:
    """Validate OIDC configuration and discovery without login or writes."""
    result: dict[str, Any] = {
        "ready": False,
        "provider": "self-hosted",
        "issuer": "",
        "client_mode": "public",
        "scopes": [],
        "endpoint_origins": {},
        "signing_algorithms": [],
        "callback_url": None,
        "callback_complete": False,
        "policy_categories": [],
        "errors": [],
    }
    errors: list[str] = result["errors"]
    try:
        configured, configured_public_url = _configured_self_hosted()
        issuer = _resolve("HERMES_DASHBOARD_OIDC_ISSUER", configured.get("issuer"))
        client_id = _resolve(
            "HERMES_DASHBOARD_OIDC_CLIENT_ID", configured.get("client_id")
        )
        scopes = (
            _resolve("HERMES_DASHBOARD_OIDC_SCOPES", configured.get("scopes"))
            or "openid profile email"
        )
        client_secret = _resolve(
            "HERMES_DASHBOARD_OIDC_CLIENT_SECRET", configured.get("client_secret")
        )
        if not issuer:
            errors.append("issuer is required")
        if not client_id:
            errors.append("client_id is required")
        if errors:
            return result

        provider = SelfHostedOIDCProvider(
            issuer=issuer,
            client_id=client_id,
            scopes=scopes,
            client_secret=client_secret,
            authorization=configured.get("authorization", {}),
        )
        result["issuer"] = provider._issuer
        result["client_mode"] = "confidential" if client_secret else "public"
        result["scopes"] = scopes.split()
        result["policy_categories"] = _policy_categories(provider)

        selected_public_url = public_url
        if selected_public_url is None:
            env_public = os.environ.get("HERMES_DASHBOARD_PUBLIC_URL", "").strip()
            selected_public_url = env_public or configured_public_url
        normalized_public_url = _normalise_public_url(selected_public_url)
        if selected_public_url and not normalized_public_url:
            errors.append("public URL must be an absolute http(s) URL")
            return result
        if normalized_public_url:
            callback_url = f"{normalized_public_url}/auth/callback"
            provider._validate_redirect_uri(callback_url)
            result["callback_url"] = callback_url
            result["callback_complete"] = True

        discovery = provider._get_discovery()
        endpoints = {
            "authorization": discovery["authorization_endpoint"],
            "token": discovery["token_endpoint"],
            "jwks": discovery["jwks_uri"],
        }
        if discovery.get("revocation_endpoint"):
            endpoints["revocation"] = discovery["revocation_endpoint"]
        result["endpoint_origins"] = {
            name: _origin(value) for name, value in endpoints.items()
        }

        advertised = discovery.get("id_token_signing_alg_values_supported") or []
        allowed = set(_ALLOWED_ID_TOKEN_ALGS)
        if advertised:
            allowed.intersection_update(str(value) for value in advertised)
        result["signing_algorithms"] = sorted(allowed)
        if not allowed:
            errors.append(
                "no allowed ID-token signing algorithm intersects with discovery"
            )
            return result
        result["ready"] = True
        return result
    except Exception as exc:  # normalized below; command never traces
        # Keep diagnostics useful but bounded. Provider code already redacts token
        # material and this command never handles tokens or authorization codes.
        errors.append(str(exc)[:500])
        return result


def cmd_dashboard_sso_check(args) -> None:
    result = check_sso(public_url=getattr(args, "public_url", None))
    if getattr(args, "json", False):
        print(json.dumps(result, sort_keys=True))
    else:
        status = "READY" if result["ready"] else "NOT READY"
        print(f"Dashboard SSO: {status}")
        print(f"  Provider: {result['provider']}")
        if result["issuer"]:
            print(f"  Issuer: {result['issuer']}")
        print(f"  Client mode: {result['client_mode']}")
        if result["callback_url"]:
            print(f"  Callback: {result['callback_url']}")
        else:
            print("  Callback: incomplete (set --public-url or dashboard.public_url)")
        if result["signing_algorithms"]:
            print(f"  Signing algorithms: {', '.join(result['signing_algorithms'])}")
        for error in result["errors"]:
            print(f"  Error: {error}")
    if not result["ready"]:
        raise SystemExit(1)
