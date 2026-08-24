"""Read-only enterprise dashboard SSO preflight diagnostics."""
from __future__ import annotations

import json
import os
import queue
import threading
from typing import Any
from urllib.parse import urlparse

import httpx

from hermes_cli.dashboard_auth.prefix import _normalise_public_url
from plugins.dashboard_auth.self_hosted import (
    _ALLOWED_ID_TOKEN_ALGS,
    SelfHostedOIDCProvider,
)

_JWKS_TIMEOUT_SECONDS = 5.0
_JWKS_MAX_BYTES = 1024 * 1024
_EC_ALGORITHMS_BY_CURVE = {
    "P-256": "ES256",
    "P-384": "ES384",
    "P-521": "ES512",
}


class _JWKSError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fetch_jwks_document_sync(url: str) -> Any:
    try:
        with httpx.stream(
            "GET",
            url,
            headers={"Accept": "application/json"},
            timeout=_JWKS_TIMEOUT_SECONDS,
            follow_redirects=False,
        ) as response:
            if response.status_code != 200:
                raise _JWKSError("jwks_unreachable", "JWKS endpoint is unreachable")
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes(chunk_size=64 * 1024):
                size += len(chunk)
                if size > _JWKS_MAX_BYTES:
                    raise _JWKSError(
                        "jwks_too_large", "JWKS response exceeds the 1 MiB limit"
                    )
                chunks.append(chunk)
            body = b"".join(chunks)
    except httpx.RequestError as exc:
        raise _JWKSError("jwks_unreachable", "JWKS endpoint is unreachable") from exc
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _JWKSError("jwks_malformed", "JWKS response is malformed") from exc


def _fetch_jwks_document(url: str) -> Any:
    result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def fetch() -> None:
        try:
            result_queue.put((True, _fetch_jwks_document_sync(url)))
        except Exception as exc:
            result_queue.put((False, exc))

    threading.Thread(target=fetch, name="sso-jwks-preflight", daemon=True).start()
    try:
        success, value = result_queue.get(timeout=_JWKS_TIMEOUT_SECONDS)
    except queue.Empty as exc:
        raise _JWKSError(
            "jwks_timeout", "JWKS fetch exceeded the 5-second deadline"
        ) from exc
    if not success:
        raise value
    return value


def _compatible_key_algorithms(key: dict[str, Any]) -> set[str]:
    if key.get("kty") == "RSA":
        return {alg for alg in _ALLOWED_ID_TOKEN_ALGS if alg.startswith("RS")}
    if key.get("kty") == "EC":
        algorithm = _EC_ALGORITHMS_BY_CURVE.get(str(key.get("crv") or ""))
        return {algorithm} if algorithm else set()
    return set()


def _validate_jwks_document(payload: Any, allowed: set[str]) -> int:
    if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
        raise _JWKSError("jwks_malformed", "JWKS response is malformed")
    keys = payload["keys"]
    if not keys:
        raise _JWKSError("jwks_empty", "JWKS contains no keys")

    asymmetric = [
        key for key in keys if isinstance(key, dict) and key.get("kty") in {"RSA", "EC"}
    ]
    if not asymmetric:
        raise _JWKSError(
            "jwks_wrong_kty", "JWKS contains no RSA or EC signing keys"
        )
    signing = [
        key
        for key in asymmetric
        if str(key.get("use") or "sig") == "sig"
        and (
            "key_ops" not in key
            or (
                isinstance(key.get("key_ops"), list)
                and "verify" in key["key_ops"]
            )
        )
    ]
    if not signing:
        raise _JWKSError("jwks_wrong_use", "JWKS contains no keys usable for signing")

    import jwt

    saw_wrong_alg = False
    saw_no_intersection = False
    saw_malformed = False
    usable = 0
    all_supported = set(_ALLOWED_ID_TOKEN_ALGS)
    for key in signing:
        compatible = _compatible_key_algorithms(key)
        declared = str(key.get("alg") or "")
        if declared:
            if declared not in all_supported or declared not in compatible:
                saw_wrong_alg = True
                continue
            candidates = {declared} & allowed
        else:
            candidates = compatible & allowed
        if not candidates:
            saw_no_intersection = True
            continue
        parsed = False
        for algorithm in candidates:
            try:
                jwt.PyJWK.from_dict(key, algorithm=algorithm)
            except (ValueError, jwt.PyJWTError):
                continue
            parsed = True
            usable += 1
            break
        if not parsed:
            saw_malformed = True
    if usable:
        return usable
    if saw_malformed:
        raise _JWKSError("jwks_malformed", "JWKS signing key material is malformed")
    if saw_no_intersection:
        raise _JWKSError(
            "jwks_no_algorithm_intersection",
            "JWKS signing keys do not intersect the allowed discovery algorithms",
        )
    if saw_wrong_alg:
        raise _JWKSError(
            "jwks_wrong_alg", "JWKS contains no key with a compatible signing algorithm"
        )
    raise _JWKSError("jwks_malformed", "JWKS contains no usable signing keys")


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


def _configured_topology() -> dict[str, Any]:
    from hermes_cli.config import load_config

    dashboard = (load_config().get("dashboard") or {})
    topology = dashboard.get("topology") if isinstance(dashboard, dict) else {}
    return topology if isinstance(topology, dict) else {}


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
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"{parsed.scheme}://{host}{port}"


def _is_secure_public_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" or (
        parsed.scheme == "http"
        and (parsed.hostname or "").lower() in {"localhost", "127.0.0.1", "::1"}
    )


def _has_valid_public_authority(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.username is not None or parsed.password is not None:
        return False
    try:
        parsed.port
    except ValueError:
        return False
    return bool(parsed.hostname)


def _has_valid_issuer_authority(url: str) -> bool:
    parsed = urlparse(url)
    return (
        _has_valid_public_authority(url)
        and not parsed.query
        and not parsed.fragment
    )


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
        "checks": {
            name: {"ok": False, "code": "not_checked"}
            for name in ("configuration", "discovery", "jwks", "callback", "policy")
        },
        "topology": {},
        "errors": [],
    }
    errors: list[str] = result["errors"]
    checks: dict[str, dict[str, Any]] = result["checks"]
    try:
        from hermes_cli.dashboard_auth.topology import topology_readiness

        result["topology"] = topology_readiness(_configured_topology())
        if result["topology"]["status"] != "ok":
            errors.append(result["topology"]["detail"])
            return result
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
            checks["configuration"] = {
                "ok": False,
                "code": "configuration_invalid",
            }
            return result
        if not _has_valid_issuer_authority(issuer):
            errors.append("OIDC issuer URL authority is invalid")
            checks["configuration"] = {
                "ok": False,
                "code": "configuration_invalid",
            }
            return result
        try:
            provider = SelfHostedOIDCProvider(
                issuer=issuer,
                client_id=client_id,
                scopes=scopes,
                client_secret=client_secret,
                authorization={},
            )
        except Exception as exc:
            if "https" in str(exc).lower():
                errors.append("OIDC issuer must use https except loopback")
            else:
                errors.append("OIDC configuration is invalid")
            checks["configuration"] = {
                "ok": False,
                "code": "configuration_invalid",
            }
            return result
        checks["configuration"] = {"ok": True, "code": "configuration_valid"}
        try:
            provider = SelfHostedOIDCProvider(
                issuer=issuer,
                client_id=client_id,
                scopes=scopes,
                client_secret=client_secret,
                authorization=configured.get("authorization", {}),
            )
        except Exception:
            errors.append("OIDC authorization policy is invalid")
            checks["policy"] = {"ok": False, "code": "policy_invalid"}
            return result
        result["issuer"] = provider._issuer
        result["client_mode"] = "confidential" if client_secret else "public"
        result["scopes"] = scopes.split()
        result["policy_categories"] = _policy_categories(provider)
        checks["policy"] = {"ok": True, "code": "policy_valid"}

        selected_public_url = public_url
        if selected_public_url is None:
            env_public = os.environ.get("HERMES_DASHBOARD_PUBLIC_URL", "").strip()
            selected_public_url = env_public or configured_public_url
        normalized_public_url = _normalise_public_url(selected_public_url)
        if not selected_public_url:
            errors.append(
                "public URL is required to construct the production OAuth callback"
            )
            checks["callback"] = {"ok": False, "code": "callback_missing"}
            return result
        if selected_public_url and not normalized_public_url:
            errors.append("public URL must be an absolute http(s) URL")
            checks["callback"] = {"ok": False, "code": "callback_invalid"}
            return result
        if not _has_valid_public_authority(normalized_public_url):
            errors.append("public URL authority is invalid")
            checks["callback"] = {"ok": False, "code": "callback_invalid"}
            return result
        if not _is_secure_public_url(normalized_public_url):
            errors.append(
                "public callback URL must use HTTPS except for explicit loopback development"
            )
            checks["callback"] = {"ok": False, "code": "callback_insecure"}
            return result
        if normalized_public_url:
            callback_url = f"{normalized_public_url}/auth/callback"
            provider._validate_redirect_uri(callback_url)
            result["callback_url"] = callback_url
            result["callback_complete"] = True
            checks["callback"] = {"ok": True, "code": "callback_valid"}

        try:
            discovery = provider._get_discovery()
        except Exception as exc:
            detail = str(exc).lower()
            if "unreachable" in detail:
                code = "discovery_unreachable"
                message = "OIDC discovery is unreachable"
            elif "issuer mismatch" in detail:
                code = "discovery_issuer_mismatch"
                message = "OIDC discovery issuer mismatch"
            elif "missing" in detail:
                code = "discovery_incomplete"
                message = "OIDC discovery is missing required endpoints"
            elif "https" in detail:
                code = "discovery_endpoint_policy"
                message = "OIDC discovery endpoints must use HTTPS except loopback"
            else:
                code = "discovery_invalid"
                message = "OIDC discovery validation failed"
            checks["discovery"] = {"ok": False, "code": code}
            errors.append(message)
            return result
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
            checks["discovery"] = {
                "ok": False,
                "code": "discovery_no_algorithm_intersection",
            }
            return result
        checks["discovery"] = {"ok": True, "code": "discovery_valid"}
        try:
            jwks = _fetch_jwks_document(discovery["jwks_uri"])
            usable_keys = _validate_jwks_document(jwks, allowed)
        except _JWKSError as exc:
            checks["jwks"] = {"ok": False, "code": exc.code}
            errors.append(str(exc))
            return result
        checks["jwks"] = {
            "ok": True,
            "code": "jwks_valid",
            "usable_signing_keys": usable_keys,
        }
        result["ready"] = True
        return result
    except Exception:  # normalized below; command never traces or leaks details
        errors.append("SSO preflight failed unexpectedly")
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
        for category, check in result["checks"].items():
            check_status = "PASS" if check["ok"] else "FAIL"
            print(f"  {category}: {check_status} ({check['code']})")
        for error in result["errors"]:
            print(f"  Error: {error}")
    if not result["ready"]:
        raise SystemExit(1)
