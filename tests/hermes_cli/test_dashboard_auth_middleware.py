"""End-to-end behavioural tests for the dashboard auth gate.

Uses ``StubAuthProvider`` so the OAuth round trip can complete in-process
without any external IDP.  Exercises:

  * `/api/status` keeps a minimal public shape while its inventory is gated
  * `/` redirects to /login when no cookie present
  * `/api/auth/providers` is the public bootstrap endpoint
  * `/login` renders HTML listing all providers
  * /assets/* still passes through unauthenticated
  * Full /auth/login → /auth/callback → / round trip with the stub
  * Invalid / missing cookies return 401 (api) or 302 (html)
  * Zero-providers + gate-on fails closed
"""
from __future__ import annotations

import pytest
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from fastapi.testclient import TestClient

from hermes_cli import web_server
from hermes_cli.dashboard_auth import (
    LoginStart,
    Session,
    clear_providers,
    get_provider,
    register_provider,
)
from hermes_cli.dashboard_auth.cookies import (
    SESSION_AT_COOKIE,
    SESSION_PROVIDER_COOKIE,
    SESSION_RT_COOKIE,
)
from hermes_cli.dashboard_auth.refresh_binding import mint_refresh_binding
from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider


@pytest.fixture
def gated_app():
    """Configure web_server.app for gated mode + register the stub provider."""
    clear_providers()
    register_provider(StubAuthProvider())
    prev_host = getattr(web_server.app.state, "bound_host", None)
    prev_port = getattr(web_server.app.state, "bound_port", None)
    prev_required = getattr(web_server.app.state, "auth_required", None)
    web_server.app.state.bound_host = "fly-app.fly.dev"
    web_server.app.state.bound_port = 443
    web_server.app.state.auth_required = True
    # Use https base_url so cookies pick up Secure flag and host_header
    # matches the bound interface.
    client = TestClient(web_server.app, base_url="https://fly-app.fly.dev")
    yield client
    clear_providers()
    web_server.app.state.bound_host = prev_host
    web_server.app.state.bound_port = prev_port
    web_server.app.state.auth_required = prev_required


# ---------------------------------------------------------------------------
# Allowlist (public) routes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "next_value",
    [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "../../etc/passwd",
        "canary\r\nSet-Cookie: injected=1",
    ],
)
def test_empty_provider_login_page_is_safe_through_real_route(
    gated_app, next_value
):
    clear_providers()

    response = gated_app.get("/login", params={"next": next_value})

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "no-store" in response.headers["cache-control"]
    assert "Sign-in unavailable" in response.text
    assert "username/password provider" in response.text
    assert "OAuth provider" in response.text
    assert "--insecure" not in response.text
    assert next_value not in response.text


def test_gated_status_is_public(gated_app):
    """``/api/status`` MUST be public under the OAuth gate.

    Regression guard for the wildcard-subdomain rollout: NAS
    (``fly-provider.ts`` ``getInstanceRuntimeStatus``) hits
    ``/api/status`` without a cookie as its sole liveness probe. A 401
    here surfaces every healthy agent as STARTING/down in the portal
    UI. The endpoint returns only an ok bit + auth-gate boolean
    (no version, provider, host, or component inventory), so it stays in the shared
    ``PUBLIC_API_PATHS`` allowlist under both the legacy ``_SESSION_TOKEN``
    gate and the OAuth gate.

    The body reports only whether the gate is required.
    """
    r = gated_app.get("/api/status")
    assert r.status_code == 200, (
        f"Expected 200, got {r.status_code}: {r.text}"
    )
    assert r.json() == {"ok": True, "auth_required": True}


@pytest.mark.parametrize("path", [
    "/api/health",
])
def test_other_public_api_paths_are_public_under_gate(gated_app, path):
    """The minimal health route must bypass the gate.

    Accept any non-auth-failure status: 200 when the route succeeds,
    or any route-specific error (e.g. 400 / 404 / 500 from a missing
    dependency) — but NEVER 401, and NEVER a 302 to ``/login``.
    """
    r = gated_app.get(path, follow_redirects=False)
    assert r.status_code != 401, (
        f"{path} returned 401 under the OAuth gate — should be public"
    )
    if r.status_code == 302:
        location = r.headers.get("location", "")
        assert "/login" not in location, (
            f"{path} redirected to {location} — should be public, "
            "not bounced to /login"
        )


# ---------------------------------------------------------------------------
# OAuth round trip
# ---------------------------------------------------------------------------




def _complete_stub_login(client) -> None:
    """Walk the stub OAuth round trip so ``client`` carries a valid session.

    TestClient persists Set-Cookie across calls, so after this returns the
    client's cookie jar holds ``hermes_session_at`` / ``hermes_session_rt``
    and subsequent gated requests authenticate.
    """
    r1 = client.get("/auth/login?provider=stub", follow_redirects=False)
    assert r1.status_code == 302
    state = r1.headers["location"].split("state=")[1]
    r2 = client.get(
        f"/auth/callback?code=stub_code&state={state}",
        follow_redirects=False,
    )
    assert r2.status_code == 302


def test_callback_forwards_nonce_without_breaking_legacy_provider(gated_app):
    class NonceAwareProvider(StubAuthProvider):
        name = "nonce-aware"

        def __init__(self):
            super().__init__()
            self.received_nonce = ""

        def start_login(self, *, redirect_uri: str) -> LoginStart:
            login = super().start_login(redirect_uri=redirect_uri)
            parsed = urlparse(login.redirect_url)
            query = parse_qs(parsed.query)
            query["nonce"] = ["nonce-from-provider"]
            redirect_url = urlunparse(
                parsed._replace(query=urlencode(query, doseq=True))
            )
            payload = login.cookie_payload["hermes_session_pkce"]
            return LoginStart(
                redirect_url=redirect_url,
                cookie_payload={
                    "hermes_session_pkce": f"{payload};nonce=nonce-from-provider"
                },
            )

        def complete_login(
            self,
            *,
            code,
            state,
            code_verifier,
            redirect_uri,
            nonce="",
        ):
            self.received_nonce = nonce
            return super().complete_login(
                code=code,
                state=state,
                code_verifier=code_verifier,
                redirect_uri=redirect_uri,
            )

    clear_providers()
    provider = NonceAwareProvider()
    register_provider(provider)

    started = gated_app.get(
        "/auth/login?provider=nonce-aware", follow_redirects=False
    )
    query = parse_qs(urlparse(started.headers["location"]).query)
    completed = gated_app.get(
        "/auth/callback",
        params={"code": query["code"][0], "state": query["state"][0]},
        follow_redirects=False,
    )

    assert completed.status_code == 302
    assert provider.received_nonce == "nonce-from-provider"

    # The original four-keyword provider remains a valid external contract.
    clear_providers()
    register_provider(StubAuthProvider())
    _complete_stub_login(gated_app)


def test_gated_require_token_endpoint_accepts_cookie_session(gated_app):
    """Regression: ``_require_token`` endpoints must work under the OAuth gate.

    In gated mode the legacy ``_SESSION_TOKEN`` is NOT injected into the SPA
    (it authenticates with the session cookie). Endpoints that call
    ``_require_token`` directly — plugin install/enable/disable,
    ``/api/dashboard/plugins/hub``, and others — used to re-check the absent
    token and 401 every cookie-authenticated request, making them permanently
    unreachable behind the gate (the dashboard surfaced a
    ``401: {"detail":"Unauthorized"}`` popup on plugin install). The fix makes
    ``_require_token`` defer to the gate, which has already verified the cookie
    and attached ``request.state.session`` before the handler runs.

    We POST a deliberately invalid plugin identifier: a passing auth layer
    lets the request reach the handler, which rejects the identifier with a
    400. The assertion is simply "not 401" — proving auth succeeded without
    coupling to the validation message.
    """
    _complete_stub_login(gated_app)
    r = gated_app.post(
        "/api/dashboard/agent-plugins/install",
        json={"identifier": "definitely not a valid identifier",
              "force": False, "enable": False},
    )
    assert r.status_code != 401, (
        "A _require_token endpoint 401'd a cookie-authenticated request under "
        f"the OAuth gate (the install-popup bug). Body: {r.text}"
    )
    # And specifically: it reached the handler's own validation.
    assert r.status_code == 400, (
        f"Expected the install handler's 400 (bad identifier), got "
        f"{r.status_code}: {r.text}"
    )


# A representative spread of the OTHER ``_require_token`` endpoints (there are
# 14 in total). The install popup was just the reported symptom; the same bug
# made API-key reveal, provider validation, the OAuth-provider connect flow,
# and the rest of plugin management unreachable behind the gate. Each entry is
# (method, path, json_body); we assert only that a logged-in request is NOT
# 401'd — i.e. it cleared the auth layer and reached the handler. The
# handler's own status (400/404/429/etc.) is route-specific and not asserted.
_GATED_REQUIRE_TOKEN_ROUTES = [
    ("get", "/api/dashboard/plugins/hub", None),
    ("post", "/api/env/reveal", {"key": "NONEXISTENT_ENV_VAR_FOR_TEST"}),
    ("post", "/api/providers/validate", {"key": "OPENAI_API_KEY", "value": ""}),
    ("delete", "/api/providers/oauth/__not_a_real_provider__", None),
    ("post", "/api/dashboard/agent-plugins/__nope__/enable", None),
]


def test_login_non_interactive_provider_returns_404_not_500(gated_app):
    """Regression: a token-only provider (drain) has no login flow, so
    /auth/login?provider=drain-secret must 404 (not 500 on start_login) and it
    must not appear in the /api/auth/providers bootstrap.
    """
    import secrets

    import plugins.dashboard_auth.drain as drain_plugin

    register_provider(
        drain_plugin.DrainSecretProvider(secret=secrets.token_urlsafe(48))
    )

    r = gated_app.get(
        "/auth/login?provider=drain-secret&next=%2F", follow_redirects=False
    )
    assert r.status_code == 404, (
        f"drain-secret login should 404, not 500: {r.status_code} {r.text}"
    )

    bootstrap = gated_app.get("/api/auth/providers")
    assert bootstrap.status_code == 200
    names = {p["name"] for p in bootstrap.json()["providers"]}
    assert "drain-secret" not in names
    assert "stub" in names


def test_callback_invalid_code_returns_400(gated_app):
    r1 = gated_app.get("/auth/login?provider=stub", follow_redirects=False)
    state = r1.headers["location"].split("state=")[1]
    r2 = gated_app.get(
        f"/auth/callback?code=BAD_CODE&state={state}",
        follow_redirects=False,
    )
    assert r2.status_code == 400


# ---------------------------------------------------------------------------
# Cookie validation
# ---------------------------------------------------------------------------


def test_invalid_cookie_returns_401_on_api(gated_app):
    gated_app.cookies.set(SESSION_AT_COOKIE, "garbage-not-a-real-token")
    r = gated_app.get("/api/sessions")
    assert r.status_code == 401




# ---------------------------------------------------------------------------
# Identity probe
# ---------------------------------------------------------------------------


def test_api_auth_me_returns_session_after_login(gated_app):
    r1 = gated_app.get("/auth/login?provider=stub", follow_redirects=False)
    state = r1.headers["location"].split("state=")[1]
    gated_app.get(
        f"/auth/callback?code=stub_code&state={state}",
        follow_redirects=False,
    )
    r = gated_app.get("/api/auth/me")
    assert r.status_code == 200
    body = r.json()
    assert body["user_id"] == "stub-user-1"
    assert body["email"] == "stub@example.test"
    assert body["display_name"] == "Stub User"
    assert body["provider"] == "stub"
    assert body["org_id"] == "stub-org-1"
    assert "expires_at" in body


def test_api_auth_me_requires_auth(gated_app):
    # No cookies.
    r = gated_app.get("/api/auth/me")
    assert r.status_code == 401


def test_provider_bootstrap_exposes_only_safe_authorization_metadata(gated_app):
    import plugins.dashboard_auth.self_hosted as oidc_plugin

    clear_providers()
    register_provider(
        oidc_plugin.SelfHostedOIDCProvider(
            issuer="https://idp.example.com",
            client_id="hermes-dashboard",
            authorization={
                "allowed_email_domains": ["secret-customer.example"],
                "required_groups": ["secret-admin-group"],
            },
        )
    )

    response = gated_app.get("/api/auth/providers")

    assert response.status_code == 200
    assert response.json() == {
        "providers": [
            {
                "name": "self-hosted",
                "display_name": "Self-Hosted OIDC",
                "supports_password": False,
                "auth_type": "oidc",
                "policy_enforced": True,
            }
        ]
    }
    assert "secret-customer.example" not in response.text
    assert "secret-admin-group" not in response.text


def test_logout_invalidates_session_until_subsequent_login(gated_app):
    _complete_stub_login(gated_app)
    assert gated_app.get("/api/auth/me").status_code == 200

    logout = gated_app.post("/auth/logout", follow_redirects=True)

    assert logout.status_code == 200
    assert logout.url.path == "/login"
    assert len(logout.history) == 1
    prefixed_deletions = [
        cookie
        for cookie in logout.history[0].headers.get_list("set-cookie")
        if cookie.startswith("__Host-") or cookie.startswith("__Secure-")
    ]
    assert prefixed_deletions
    assert all("Secure" in cookie for cookie in prefixed_deletions)
    assert gated_app.get("/api/auth/me").status_code == 401
    deep_link = gated_app.get("/sessions", follow_redirects=False)
    assert deep_link.status_code == 302
    assert deep_link.headers["location"].startswith(("/login", "/auth/login"))

    _complete_stub_login(gated_app)
    assert gated_app.get("/api/auth/me").status_code == 200


def test_logout_clears_session_when_provider_revocation_fails(
    gated_app, monkeypatch
):
    _complete_stub_login(gated_app)
    provider = get_provider("stub")
    assert provider is not None

    def _revoke_failure(*, refresh_token: str) -> None:
        raise RuntimeError("simulated provider outage")

    monkeypatch.setattr(provider, "revoke_session", _revoke_failure)

    logout = gated_app.post("/auth/logout", follow_redirects=False)

    assert logout.status_code == 302
    assert gated_app.get("/api/auth/me").status_code == 401


# ---------------------------------------------------------------------------
# Zero-providers fail-closed
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# Multi-provider verify: a ProviderError from one provider must not abort the
# chain when another provider can verify the token.
# ---------------------------------------------------------------------------


class _UnreachableProvider(StubAuthProvider):
    """A provider whose IDP is unreachable: verify_session always raises.

    Models the real-world bug — a self-hosted-OIDC session hits the ``nous``
    provider first, which tries to reach Nous Portal's JWKS; if that's
    unreachable ``nous`` raises ProviderError. The gate must keep trying the
    remaining providers rather than 503-ing the whole request.
    """

    name = "unreachable"
    display_name = "Unreachable IdP (test only)"

    def verify_session(self, *, access_token: str):
        from hermes_cli.dashboard_auth.base import ProviderError

        raise ProviderError("simulated: IDP/JWKS unreachable")

    def refresh_session(self, *, refresh_token: str):
        from hermes_cli.dashboard_auth.base import ProviderError

        raise ProviderError("simulated: IDP/JWKS unreachable")


class _DenyingProvider(StubAuthProvider):
    name = "denying"
    display_name = "Denying IdP (test only)"

    @staticmethod
    def _deny():
        from hermes_cli.dashboard_auth import AccessDeniedError

        raise AccessDeniedError(
            "group_required", details={"raw_claims": "must-not-leak"}
        )

    def complete_login(self, **kwargs):
        self._deny()

    def verify_session(self, *, access_token: str):
        self._deny()

    def refresh_session(self, *, refresh_token: str):
        self._deny()


class _PriorIdentityRefreshProvider(StubAuthProvider):
    name = "prior-identity"
    display_name = "Prior identity refresh (test only)"

    def __init__(self):
        super().__init__()
        self.seen_access_token = None

    def verify_session(self, *, access_token: str):
        return None

    def refresh_session(self, *, refresh_token: str, access_token: str = ""):
        import time

        self.seen_access_token = access_token
        return Session(
            user_id="refreshed-user",
            email="refreshed@example.com",
            display_name="Refreshed User",
            org_id="",
            provider=self.name,
            expires_at=int(time.time()) + 300,
            access_token=access_token,
            refresh_token="rotated-refresh",
        )


class _ProactiveRefreshProvider(_PriorIdentityRefreshProvider):
    name = "proactive-refresh"

    def __init__(self):
        super().__init__()
        self.refresh_calls = 0

    def verify_session(self, *, access_token: str):
        import time

        return Session(
            user_id="verified-user",
            email="verified@example.com",
            display_name="Verified User",
            org_id="",
            provider=self.name,
            expires_at=int(time.time()) + 30,
            access_token=access_token,
            refresh_token="",
        )

    def refresh_session(self, *, refresh_token: str, access_token: str = ""):
        import time

        self.refresh_calls += 1
        self.seen_access_token = access_token
        return Session(
            user_id="verified-user",
            email="verified@example.com",
            display_name="Verified User",
            org_id="",
            provider=self.name,
            expires_at=int(time.time()) + 30,
            access_token=access_token,
            refresh_token="rotated-refresh",
        )


class _ProactiveRefreshOutageProvider(_ProactiveRefreshProvider):
    name = "proactive-refresh-outage"

    def refresh_session(self, *, refresh_token: str, access_token: str = ""):
        from hermes_cli.dashboard_auth import ProviderError

        raise ProviderError("refresh endpoint unavailable")


def _mint_stub_at(stub: StubAuthProvider) -> str:
    """Mint a valid access-token cookie value from a StubAuthProvider via its
    own login round trip (so the HMAC signature matches what verify expects)."""
    ls = stub.start_login(redirect_uri="https://fly-app.fly.dev/auth/callback")
    state = dict(
        seg.split("=", 1)
        for seg in ls.cookie_payload["hermes_session_pkce"].split(";")
        if "=" in seg
    )["state"]
    verifier = dict(
        seg.split("=", 1)
        for seg in ls.cookie_payload["hermes_session_pkce"].split(";")
        if "=" in seg
    )["verifier"]
    session = stub.complete_login(
        code="stub_code",
        state=state,
        code_verifier=verifier,
        redirect_uri="https://fly-app.fly.dev/auth/callback",
    )
    return session.access_token


def _bind_refresh_cookie(client: TestClient, *, provider: str, token: str) -> None:
    client.cookies.set(SESSION_RT_COOKIE, token)
    client.cookies.set(
        SESSION_PROVIDER_COOKIE,
        mint_refresh_binding(provider=provider, refresh_token=token),
    )


@pytest.fixture
def _gated_state():
    """Bare gated app-state setup WITHOUT registering any provider, so each
    test controls provider registration order itself. Yields a factory that
    builds the TestClient after providers are registered."""
    clear_providers()
    prev_host = getattr(web_server.app.state, "bound_host", None)
    prev_port = getattr(web_server.app.state, "bound_port", None)
    prev_required = getattr(web_server.app.state, "auth_required", None)
    web_server.app.state.bound_host = "fly-app.fly.dev"
    web_server.app.state.bound_port = 443
    web_server.app.state.auth_required = True

    def _client() -> TestClient:
        return TestClient(web_server.app, base_url="https://fly-app.fly.dev")

    yield _client
    clear_providers()
    web_server.app.state.bound_host = prev_host
    web_server.app.state.bound_port = prev_port
    web_server.app.state.auth_required = prev_required




def test_all_providers_unreachable_returns_503(_gated_state):
    """If NO provider can verify the token AND at least one was unreachable,
    surface 503 (transient outage) rather than forcing a needless re-login."""
    register_provider(_UnreachableProvider())
    client = _gated_state()
    # Any non-empty cookie — the unreachable provider raises before parsing.
    client.cookies.set(SESSION_AT_COOKIE, "some-opaque-token")
    r = client.get("/api/auth/me")
    assert r.status_code == 503
    assert r.json()["error"] == "provider_unavailable"
    assert r.json()["retryable"] is True
    assert r.json()["reference_id"].startswith("AUTH-")


def test_refresh_receives_prior_identity_token_when_provider_supports_it(
    _gated_state,
):
    provider = _PriorIdentityRefreshProvider()
    register_provider(provider)
    client = _gated_state()
    client.cookies.set(SESSION_AT_COOKIE, "previous-verified-id-token")
    _bind_refresh_cookie(client, provider=provider.name, token="refresh-token")

    response = client.get("/api/auth/me")

    assert response.status_code == 200
    assert provider.seen_access_token == "previous-verified-id-token"


def test_near_expiry_session_refreshes_while_prior_identity_is_still_valid(
    _gated_state,
):
    provider = _ProactiveRefreshProvider()
    register_provider(provider)
    client = _gated_state()
    client.cookies.set(SESSION_AT_COOKIE, "still-valid-id-token")
    _bind_refresh_cookie(client, provider=provider.name, token="refresh-token")

    response = client.get("/api/auth/me")

    assert response.status_code == 200
    assert provider.seen_access_token == "still-valid-id-token"
    assert "rotated-refresh" in response.headers.get("set-cookie", "")

    second_response = client.get("/api/auth/me")

    assert second_response.status_code == 200
    assert provider.refresh_calls == 1


def test_proactive_refresh_outage_serves_still_valid_session(_gated_state):
    provider = _ProactiveRefreshOutageProvider()
    register_provider(provider)
    client = _gated_state()
    client.cookies.set(SESSION_AT_COOKIE, "still-valid-id-token")
    _bind_refresh_cookie(client, provider=provider.name, token="refresh-token")

    response = client.get("/api/auth/me")

    assert response.status_code == 200
    assert response.json()["user_id"] == "verified-user"


def test_access_denial_is_terminal_for_cookie_bearer_and_refresh(_gated_state):
    denying = _DenyingProvider()
    accepting = StubAuthProvider()
    register_provider(denying)
    register_provider(accepting)
    access_token = _mint_stub_at(accepting)

    cookie_client = _gated_state()
    cookie_client.cookies.set(SESSION_AT_COOKIE, access_token)
    cookie_response = cookie_client.get("/api/auth/me")
    assert cookie_response.status_code == 403
    denial = cookie_response.json()
    assert denial["error"] == "access_denied"
    assert denial["detail"] == "Your account is not authorized for this dashboard."
    assert denial["reference_id"].startswith("AUTH-")
    assert "raw_claims" not in cookie_response.text
    assert "group_required" not in cookie_response.text
    assert "Max-Age=0" in cookie_response.headers["set-cookie"]

    bearer_client = _gated_state()
    bearer_response = bearer_client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert bearer_response.status_code == 403

    refresh_client = _gated_state()
    _bind_refresh_cookie(
        refresh_client,
        provider=denying.name,
        token="recognized-refresh-token",
    )
    refresh_response = refresh_client.get("/api/auth/me")
    assert refresh_response.status_code == 403
    assert "Max-Age=0" in refresh_response.headers["set-cookie"]


def test_access_denial_returns_generic_html_for_document_load(_gated_state):
    register_provider(_DenyingProvider())
    client = _gated_state()
    client.cookies.set(SESSION_AT_COOKIE, "recognized-access-token")

    response = client.get("/", headers={"Accept": "text/html"})

    assert response.status_code == 403
    assert "not authorized" in response.text
    assert 'role="alert"' in response.text
    assert "Support reference: AUTH-" in response.text
    assert "group_required" not in response.text
    assert "raw_claims" not in response.text


def test_callback_access_denial_clears_transient_and_session_cookies(_gated_state):
    register_provider(_DenyingProvider())
    client = _gated_state()

    started = client.get("/auth/login?provider=denying", follow_redirects=False)
    query = parse_qs(urlparse(started.headers["location"]).query)
    completed = client.get(
        "/auth/callback",
        params={"code": query["code"][0], "state": query["state"][0]},
        follow_redirects=False,
    )

    assert completed.status_code == 403
    assert "not authorized" in completed.text
    assert "group_required" not in completed.text
    assert "raw_claims" not in completed.text
    assert "Max-Age=0" in completed.headers["set-cookie"]


