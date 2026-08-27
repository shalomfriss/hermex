"""Auth-gate middleware for the dashboard.

Engaged when ``app.state.auth_required is True``. The gate's job:

  1. Allow a small set of routes through unauthenticated (login page,
     ``/auth/*`` OAuth round trip, ``/api/auth/providers``, static
     assets).
  2. For everything else, demand a valid session cookie and attach the
     verified :class:`Session` to ``request.state.session``.
  3. On HTML routes, redirect missing/invalid cookies to ``/login``.
     On ``/api/*`` routes, return 401 JSON.

The middleware is a no-op when ``auth_required`` is False (loopback
mode); the legacy ``_SESSION_TOKEN`` ``auth_middleware`` handles those
binds.
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
import inspect
import logging
import secrets
import threading
from typing import Awaitable, Callable

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from hermes_cli.dashboard_auth import list_session_providers
from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
from hermes_cli.dashboard_auth.base import (
    AccessDeniedError,
    DashboardAuthProvider,
    ProviderError,
    RefreshExpiredError,
)
from hermes_cli.dashboard_auth.cookies import (
    clear_sso_attempt_cookie,
    read_session_cookies,
    read_session_provider,
    read_sso_attempt_cookie,
    set_session_provider_cookie,
    set_sso_attempt_cookie,
)
from hermes_cli.dashboard_auth.client_ip import client_ip
from hermes_cli.dashboard_auth.public_paths import PUBLIC_API_PATHS

_log = logging.getLogger(__name__)

_REFRESH_EARLY_SECONDS = 60
_REFRESH_STATE_MAX = 1024
_refresh_state_lock = threading.Lock()
_refreshed_identities: OrderedDict[str, int] = OrderedDict()

# Prefixes that bypass the auth gate. Match via ``path == prefix`` or
# ``path.startswith(prefix)`` — so ``/assets/`` (with trailing slash)
# matches ``/assets/foo.css`` but not ``/assetsleak``. Auth-bootstrap
# (login page, OAuth round trip, provider listing) and static asset
# mounts go here.
_GATE_PUBLIC_PREFIXES: tuple[str, ...] = (
    "/auth/login",
    "/auth/callback",
    "/auth/native/authorize",
    "/auth/native/token",
    "/auth/native/refresh",
    "/auth/password-login",
    "/auth/logout",
    "/login",
    "/api/auth/providers",
    "/api/mcp/oauth/callback/",
    "/assets/",
    "/favicon.ico",
    "/ds-assets/",
    "/fonts/",
    "/fonts-terminal/",
)


def _path_is_public(path: str) -> bool:
    """True if ``path`` bypasses the OAuth auth gate.

    Two sources of public-ness:

    * :data:`PUBLIC_API_PATHS` — the shared ``/api/*`` allowlist that
      the legacy ``_SESSION_TOKEN`` middleware also honours. Matched
      exactly (no prefix expansion) so adding ``/api/status`` doesn't
      accidentally expose ``/api/status/secret-extension``.
    * :data:`_GATE_PUBLIC_PREFIXES` — auth-bootstrap routes and static
      mounts. Prefix-matched so ``/assets/foo.css`` lights up via
      ``/assets/``.
    """
    if path in PUBLIC_API_PATHS:
        return True
    return any(
        path == prefix or path.startswith(prefix)
        for prefix in _GATE_PUBLIC_PREFIXES
    )


def _client_ip(request: Request) -> str:
    """Compatibility alias for the shared trusted-proxy resolver."""
    return client_ip(request)


def _ordered_session_providers(
    provider_hint: str | None,
) -> list[DashboardAuthProvider]:
    """Prefer the hinted provider without making the hint authoritative.

    The cookie can outlive a provider rename/removal or become stale after a
    deployment change. A stable sort moves a matching provider to the front
    while preserving registration order for every remaining candidate; an
    unknown hint therefore leaves the normal scan unchanged.
    """
    providers = list_session_providers()
    if provider_hint:
        providers.sort(key=lambda provider: provider.name != provider_hint)
    return providers


def _unauth_response(request: Request, *, reason: str) -> Response:
    """API routes → 401 JSON with ``login_url``; HTML routes → 302 → /login.

    The JSON envelope carries a ``login_url`` field with a ``next=`` query
    string so the SPA's global 401 handler can drop the user back where
    they were after re-auth. The contract is intentionally simple so any
    fetch-wrapper can implement the redirect without parsing details:

        if response.status === 401 && body.error in ("unauthenticated",
                                                       "session_expired"):
            window.location.assign(body.login_url);

    HTML redirects also carry the ``next=`` query string so direct
    navigation to ``/sessions`` (etc.) without a cookie comes back to
    ``/sessions`` after login.

    Under a reverse proxy with ``X-Forwarded-Prefix: /hermes``, the
    ``login_url`` is prefixed (``/hermes/login?next=...``) so the
    browser's window.location.assign / Location: follow lands on the
    proxied login page rather than the bare ``/login`` (which the
    proxy doesn't route to the dashboard).
    """
    from hermes_cli.dashboard_auth.prefix import prefix_from_request

    path = request.url.path
    next_param = _safe_next_target(request)
    prefix = prefix_from_request(request)
    login_url = (
        f"{prefix}/login?next={next_param}" if next_param
        else f"{prefix}/login"
    )

    if path.startswith("/api/"):
        # API routes never get redirects: the browser fetch() API would
        # follow a 302 into the cross-origin OAuth dance opaquely. Return
        # 401 with a structured envelope so the SPA can full-page-navigate
        # to login_url.
        error_code = (
            "session_expired"
            if reason == "invalid_or_expired_session"
            else "unauthenticated"
        )
        return JSONResponse(
            {
                "error": error_code,
                "detail": "Unauthorized",
                "reason": reason,
                "login_url": login_url,
            },
            status_code=401,
        )
    return RedirectResponse(url=login_url, status_code=302)


def access_denied_response(
    request: Request,
    *,
    error: AccessDeniedError,
    provider: str = "",
    clear_cookies: bool = False,
) -> Response:
    """Return the one generic 403 shape used by every dashboard-auth lane."""
    provider = provider or error.provider
    audit_log(
        AuditEvent.ACCESS_DENIED,
        provider=provider,
        reason=error.reason,
        ip=_client_ip(request),
    )
    detail = "Your account is not authorized for this dashboard."
    reference_id = f"AUTH-{secrets.token_hex(4).upper()}"
    path = request.url.path
    if path.startswith("/api/") or path.startswith("/auth/native/"):
        response: Response = JSONResponse(
            {
                "error": "access_denied",
                "detail": detail,
                "reference_id": reference_id,
            },
            status_code=403,
        )
    else:
        response = HTMLResponse(
            f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access denied — Hermes Agent</title>
<style>
html,body{{min-height:100%;margin:0;background:#170d02;color:#fff;font:16px/1.6 system-ui,sans-serif}}
body{{display:grid;place-items:center;padding:1.25rem;box-sizing:border-box}}
main{{max-width:36rem;border:1px solid #ffac02;padding:clamp(1.5rem,6vw,3rem)}}
h1{{font-size:clamp(2rem,8vw,3rem);line-height:1.1;margin:0 0 1rem;color:#ffbf3f}}
.ref{{font-family:ui-monospace,monospace;color:#ffd98a;margin-top:1.5rem}}
</style></head><body><main role="alert" aria-live="assertive">
<h1>Access denied</h1><p>{detail}</p>
<p>Contact your organization’s administrator if you believe this is an error.</p>
<p class="ref">Support reference: {reference_id}</p>
</main></body></html>""",
            status_code=403,
        )
    if clear_cookies:
        from hermes_cli.dashboard_auth.cookies import clear_session_cookies
        from hermes_cli.dashboard_auth.prefix import prefix_from_request

        clear_session_cookies(response, prefix=prefix_from_request(request))
    return response


def provider_outage_response(request: Request, provider: str) -> Response:
    """Return a retryable outage without exposing provider internals."""
    reference_id = f"AUTH-{secrets.token_hex(4).upper()}"
    _log.warning(
        "dashboard-auth: provider %r unavailable (reference %s)",
        provider,
        reference_id,
    )
    detail = "The sign-in provider is temporarily unavailable."
    path = request.url.path
    if (
        path.startswith("/api/")
        or path.startswith("/auth/native/")
        or path == "/auth/password-login"
    ):
        return JSONResponse(
            {
                "error": "provider_unavailable",
                "detail": detail,
                "reference_id": reference_id,
                "retryable": True,
            },
            status_code=503,
        )
    from hermes_cli.dashboard_auth.prefix import prefix_from_request

    retry_url = f"{prefix_from_request(request)}/login"
    return HTMLResponse(
        f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign-in temporarily unavailable — Hermes Agent</title>
<style>html,body{{min-height:100%;margin:0;background:#170d02;color:#fff;font:16px/1.6 system-ui,sans-serif}}body{{display:grid;place-items:center;padding:1.25rem}}main{{max-width:36rem;border:1px solid #ffac02;padding:clamp(1.5rem,6vw,3rem)}}h1,a{{color:#ffbf3f}}a{{display:inline-block;min-height:44px;padding:.75rem 1rem;border:2px solid currentColor;font-weight:700}}.ref{{font-family:ui-monospace,monospace;color:#ffd98a}}</style>
</head><body><main role="alert" aria-live="assertive"><h1>Sign-in temporarily unavailable</h1>
<p>{detail} Your existing session has not been cleared.</p>
<p><a href="{retry_url}">Retry sign-in</a></p>
<p class="ref">Support reference: {reference_id}</p></main></body></html>""",
        status_code=503,
    )


def _auto_sso_response(request: Request) -> Response | None:
    """Maybe auto-initiate the portal OAuth redirect on an unauth HTML load.

    Returns a 302 → ``/auth/login`` (the existing OAuth-initiation route)
    when ALL of the following hold, else ``None`` (caller falls back to the
    ordinary ``/login`` interstitial):

      * the request is an HTML document navigation, not an ``/api/*`` fetch
        (a fetch() would follow the 302 into the cross-origin OAuth dance
        opaquely — same reason ``_unauth_response`` never redirects APIs);
      * exactly ONE interactive provider is registered — with two or more we
        can't pick for the user, so the ``/login`` chooser must render; with
        zero there's nothing to redirect to;
      * that provider is OAuth-style, not a password form provider. Password
        providers must render ``/login`` so the user can enter credentials;
      * the one-shot loop-guard marker is ABSENT. Its presence means we
        already bounced to the portal once and came back still
        unauthenticated (no portal session) — auto-redirecting again would
        ping-pong, so we fall through to ``/login`` and clear the marker.

    The portal ``/oauth/authorize`` auto-approves any current member of the
    dashboard's org and is a silent 302 when the user already holds a portal
    session, so for the common case (clicked a dashboard link while signed
    in to the portal) this removes the interstitial CLICK entirely. It
    removes a click, not a security check: the redirect lands on
    ``/auth/login`` which runs the unchanged PKCE auth-code flow.
    """
    path = request.url.path
    # APIs never auto-redirect (see _unauth_response). Only document loads.
    if path.startswith("/api/"):
        return None

    # Already bounced once and still no session → portal has no session for
    # this user. Stop here, clear the marker, let /login render.
    if read_sso_attempt_cookie(request):
        from hermes_cli.dashboard_auth.prefix import prefix_from_request
        resp = _unauth_response(request, reason="no_cookie")
        clear_sso_attempt_cookie(resp, prefix=prefix_from_request(request))
        return resp

    # list_session_providers() already filters on supports_session=True, so
    # token-only credentials (drain/service providers) are never candidates.
    providers = list_session_providers()
    if len(providers) != 1:
        # Zero → nothing to redirect to. Two+ → user must choose at /login.
        return None

    from hermes_cli.dashboard_auth.prefix import prefix_from_request

    provider = providers[0]
    if getattr(provider, "supports_password", False):
        return None

    prefix = prefix_from_request(request)
    next_param = _safe_next_target(request)
    from urllib.parse import quote
    auth_login = f"{prefix}/auth/login?provider={quote(provider.name, safe='')}"
    if next_param:
        auth_login = f"{auth_login}&next={next_param}"

    resp = RedirectResponse(url=auth_login, status_code=302)
    # Drop the one-shot marker so a return trip that's STILL unauthenticated
    # (portal had no session) trips the guard above next time instead of
    # looping. Detect HTTPS for the Secure flag the same way the auth routes
    # do; bind Path via the active prefix.
    from hermes_cli.dashboard_auth.cookies import detect_https
    set_sso_attempt_cookie(
        resp, use_https=detect_https(request), prefix=prefix,
    )
    audit_log(
        AuditEvent.LOGIN_START,
        provider=provider.name,
        reason="auto_sso",
        ip=_client_ip(request),
    )
    return resp


def _safe_next_target(request: Request) -> str:
    """Build the URL-encoded ``next`` query value, or empty string.

    Only same-origin relative paths are accepted; absolute URLs or
    ``//evil.com`` open-redirect attempts are silently dropped. The empty
    string return means the caller produces a bare ``/login`` URL — fine,
    user lands at the dashboard root after re-auth.
    """
    path = request.url.path
    # Reject anything that doesn't start with "/" or starts with "//"
    # (protocol-relative URL — would open-redirect to an attacker host).
    if not path or not path.startswith("/") or path.startswith("//"):
        return ""
    # Don't redirect back to the auth routes themselves — that loops.
    if any(
        path == p or path.startswith(p)
        for p in ("/login", "/auth/", "/api/auth/")
    ):
        return ""
    # Reject ALL ``/api/*`` paths. The 401-envelope code path fires for
    # any unauthenticated SPA fetch (e.g. ``GET /api/analytics/models``
    # from ModelsPage), and the SPA's global 401 handler full-page
    # navigates to ``login_url``. After the OAuth round trip the user
    # would land on the API URL and see raw JSON instead of the
    # dashboard. SPA routes survive (they don't start with ``/api/``);
    # the SPA's own ``sessionStorage["hermes.lastLocation"]`` fallback
    # in ``web/src/lib/api.ts`` covers the deep-link case.
    if path == "/api" or path.startswith("/api/"):
        return ""
    # Preserve query string if present (e.g. /sessions?page=2).
    query = request.url.query
    target = f"{path}?{query}" if query else path
    # urlencode the whole thing as a single value.
    from urllib.parse import quote
    return quote(target, safe="")


def _extract_bearer(request: Request) -> str:
    """Return the ``Authorization: Bearer <token>`` value, or ""."""
    auth = request.headers.get("authorization", "")
    parts = auth.split(" ", 1)
    if len(parts) == 2 and parts[0].strip().lower() == "bearer":
        return parts[1].strip()
    return ""


def _verify_bearer(request: Request, *, access_token: str):
    """Verify a native-app bearer access token via the session-provider stack.

    Returns the :class:`Session` on success, or ``None`` if no provider
    recognises the token (expired/invalid/unknown). Mirrors the cookie path's
    verify loop, including the "one provider unreachable ⇒ don't force
    re-login" semantics: a transient IDP outage returns a 503 rather than a
    401, so the desktop retries instead of dropping the user to full re-login.
    Unlike the cookie path there is no server-side refresh — the desktop owns
    its refresh token and rotates via ``/auth/native/refresh``.
    """
    unreachable_provider: str | None = None
    for provider in list_session_providers():
        try:
            session = provider.verify_session(access_token=access_token)
        except AccessDeniedError as e:
            e.provider = provider.name
            raise
        except ProviderError as e:
            _log.warning(
                "dashboard-auth: provider %r unreachable during bearer verify: %s",
                provider.name, e,
            )
            if unreachable_provider is None:
                unreachable_provider = provider.name
            continue
        if session is not None:
            return session
    if unreachable_provider is not None:
        # Signal transient outage to the caller via a sentinel exception the
        # middleware turns into 503. Raising keeps the "don't logout on a
        # flaky IDP" contract identical to the cookie path.
        raise ProviderError(unreachable_provider)
    return None


async def gated_auth_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Engaged only when ``app.state.auth_required is True``.

    No-op pass-through in loopback mode so the legacy auth_middleware can
    handle those binds via ``_SESSION_TOKEN``.
    """
    if not getattr(request.app.state, "auth_required", False):
        return await call_next(request)

    # A request already authenticated by the token-auth seam (a service caller
    # on a registered token route) carries ``token_authenticated`` — it is NOT
    # a cookie session and must not be bounced to /login. Pass it through; the
    # seam already attached ``request.state.token_principal``.
    if getattr(request.state, "token_authenticated", False):
        return await call_next(request)

    path = request.url.path
    if _path_is_public(path):
        # ``/api/status`` has a deliberately tiny anonymous representation and
        # a full authenticated representation. If credentials are present,
        # verify them through the normal path so the handler can distinguish
        # the two without duplicating provider/session logic. Truly anonymous
        # probes still bypass auth, as do all other public bootstrap routes.
        if path != "/api/status":
            return await call_next(request)
        public_at, public_rt = read_session_cookies(request)
        if not _extract_bearer(request) and not public_at and not public_rt:
            return await call_next(request)

    # RFC 8252 native-app bearer path (goal: no session cookies). The desktop
    # authenticates REST with ``Authorization: Bearer <access_token>`` — the
    # SAME provider-minted access token the cookie flow stores in
    # ``hermes_session_at``. Verify it with the identical ``verify_session``
    # provider stack and attach the Session; on success we're done, with no
    # cookie set or read. A missing/expired/invalid bearer falls through to
    # the cookie path (a request may legitimately carry neither). Token
    # rotation for this path is the desktop's job via /auth/native/refresh —
    # the gate never sets a cookie here, so the transparent cookie-rotation
    # below must not run for a bearer caller.
    bearer = _extract_bearer(request)
    if bearer:
        try:
            bearer_session = _verify_bearer(request, access_token=bearer)
        except AccessDeniedError as e:
            return access_denied_response(
                request, error=e, clear_cookies=True
            )
        except ProviderError as e:
            # At least one provider's IDP/JWKS was unreachable and none
            # verified the token — transient outage, not bad credentials.
            return provider_outage_response(request, str(e))
        if bearer_session is not None:
            request.state.session = bearer_session
            return await call_next(request)
        # A bearer was presented but didn't verify (expired/invalid/unknown).
        # Return the structured 401 so the desktop knows to refresh or
        # re-login, rather than falling through to the cookie/login redirect.
        return _unauth_response(request, reason="invalid_or_expired_session")

    at, _rt = read_session_cookies(request)
    provider_hint = read_session_provider(request)
    if not at and not _rt:
        # Neither token present — no session at all. Nothing to verify or
        # refresh. Before falling back to the /login interstitial, try to
        # silently bounce the user through the portal OAuth flow: the portal
        # auto-approves org members and 302s straight back when they already
        # hold a portal session, so the interstitial click is pure friction
        # for the common case. The one-shot loop-guard inside _auto_sso_response
        # prevents a ping-pong when the portal genuinely has no session.
        auto = _auto_sso_response(request)
        if auto is not None:
            return auto
        return _unauth_response(request, reason="no_cookie")

    # Try every registered provider's verify_session in turn. Providers
    # MUST return None for tokens they don't recognise (not raise). This
    # lets multiple providers stack — the first one that recognises a
    # token wins.
    #
    # When the access-token cookie is absent but a refresh-token cookie is
    # present, skip verification and go straight to the refresh path below.
    # This is the COMMON expiry case, not an edge case: the access-token
    # cookie is set with ``Max-Age = access_token_expires_in`` (~15 min), so
    # the browser EVICTS it the moment the token lapses, while the
    # refresh-token cookie lives for 30 days. From that point the browser
    # sends only ``hermes_session_rt``. If we bailed on ``not at`` here we'd
    # bounce the user to /login on every expiry despite holding a perfectly
    # good refresh token — defeating the whole transparent-refresh feature.
    session = None
    if at:
        # Try every registered provider's verify_session in turn. A provider
        # that doesn't recognise the token returns None and we move on; the
        # first provider that returns a Session wins.
        #
        # A provider may instead raise ProviderError (its IDP/JWKS is
        # unreachable, so it can neither confirm nor deny the token). With
        # multiple providers stacked, that MUST NOT abort the chain — the
        # token may belong to a *different*, reachable provider. (Concretely:
        # a self-hosted-OIDC session hits the `nous` provider first, which
        # tries to reach Nous Portal's JWKS; if that's unreachable it raises,
        # but the `self-hosted` provider can still verify the token.) So we
        # remember the unreachable error and keep going. Only if NO provider
        # verifies the token AND at least one was unreachable do we surface a
        # 503 — distinguishing "transient IDP outage" (don't force re-login)
        # from "token genuinely invalid" (fall through to refresh/relogin).
        unreachable_provider: str | None = None
        for provider in _ordered_session_providers(provider_hint):
            try:
                session = provider.verify_session(access_token=at)
            except AccessDeniedError as e:
                return access_denied_response(
                    request,
                    error=e,
                    provider=provider.name,
                    clear_cookies=True,
                )
            except ProviderError as e:
                _log.warning(
                    "dashboard-auth: provider %r unreachable during verify: %s",
                    provider.name, e,
                )
                audit_log(
                    AuditEvent.SESSION_VERIFY_FAILURE,
                    provider=provider.name,
                    reason="provider_unreachable",
                    ip=_client_ip(request),
                )
                if unreachable_provider is None:
                    unreachable_provider = provider.name
                continue
            if session is not None:
                break
        if session is None and unreachable_provider is not None:
            # No provider could verify the token and at least one couldn't be
            # reached — treat as a transient outage rather than forcing a
            # re-login through a (possibly also-unreachable) refresh.
            return provider_outage_response(request, unreachable_provider)

    if session is None:
        # Access token is expired/invalid. Before forcing re-login, try to
        # rotate it using the refresh token (if the session cookie carries
        # one). On success we re-set the rotated cookies on the response and
        # serve the request transparently; only after every provider rejects
        # the RT do we fall through to clear-and-relogin.
        try:
            refreshed = _attempt_refresh(
                request,
                refresh_token=_rt,
                access_token=at,
                provider_hint=provider_hint,
            )
        except AccessDeniedError as e:
            return access_denied_response(
                request, error=e, clear_cookies=True
            )
        except ProviderError as e:
            # At least one provider could not confirm or reject the RT, and no
            # other provider refreshed it. Preserve the cookies and surface a
            # transient outage instead of turning uncertainty into a logout.
            return provider_outage_response(request, str(e))
        if refreshed is not None:
            new_session, refreshing_provider = refreshed
            return await _serve_refreshed_session(
                request,
                call_next,
                session=new_session,
                provider=refreshing_provider,
            )

        audit_log(
            AuditEvent.SESSION_VERIFY_FAILURE,
            reason="no_provider_recognises",
            ip=_client_ip(request),
        )
        response = _unauth_response(request, reason="invalid_or_expired_session")
        # Clear the dead cookies so the browser doesn't keep sending them.
        # Refresh already failed (or there was no RT), so the only correct
        # next step is full re-auth via /login. Importing locally avoids a
        # cycle with cookies → middleware at module load. Pass the active
        # prefix so the deletion's Path matches the set-Path (otherwise
        # the browser ignores it).
        from hermes_cli.dashboard_auth.cookies import clear_session_cookies
        from hermes_cli.dashboard_auth.prefix import prefix_from_request
        clear_session_cookies(response, prefix=prefix_from_request(request))
        return response

    # Refresh while the verified identity is still valid. OIDC permits a
    # refresh response to omit id_token, so this short window lets providers
    # safely retain and re-check the prior identity instead of discovering the
    # omission only after the browser has evicted the expired ID-token cookie.
    if (
        _rt
        and (int(session.expires_at) - _now_seconds()) <= _REFRESH_EARLY_SECONDS
        and not _identity_was_refreshed(at)
    ):
        try:
            refreshed = _attempt_refresh(
                request,
                refresh_token=_rt,
                access_token=at,
                provider_hint=provider_hint or session.provider,
            )
        except AccessDeniedError as e:
            return access_denied_response(
                request, error=e, clear_cookies=True
            )
        except ProviderError:
            # The current identity already verified. A proactive refresh
            # outage must not turn a still-valid request into 503 or logout.
            refreshed = None
        if refreshed is not None:
            new_session, refreshing_provider = refreshed
            return await _serve_refreshed_session(
                request,
                call_next,
                session=new_session,
                provider=refreshing_provider,
            )

    request.state.session = session
    response = await call_next(request)
    if not provider_hint and session.provider:
        from hermes_cli.dashboard_auth.cookies import detect_https
        from hermes_cli.dashboard_auth.prefix import prefix_from_request

        set_session_provider_cookie(
            response,
            provider=session.provider,
            use_https=detect_https(request),
            prefix=prefix_from_request(request),
        )
    return response


def _expires_in_seconds(session) -> int:
    """Seconds until the access token's ``exp``, floored at 60.

    Mirrors the auth-route's ``max(60, exp - now)`` so the access-token
    cookie's Max-Age tracks the token lifetime even on a slightly skewed
    clock. ``time`` imported locally to keep the module's import surface
    minimal.
    """
    import time

    return max(60, int(session.expires_at) - int(time.time()))


def _now_seconds() -> int:
    import time

    return int(time.time())


async def _serve_refreshed_session(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
    *,
    session,
    provider: str,
) -> Response:
    """Serve the request and persist a successful token rotation."""
    request.state.session = session
    response = await call_next(request)
    from hermes_cli.dashboard_auth.cookies import detect_https, set_session_cookies
    from hermes_cli.dashboard_auth.prefix import prefix_from_request

    set_session_cookies(
        response,
        access_token=session.access_token,
        refresh_token=session.refresh_token,
        access_token_expires_in=_expires_in_seconds(session),
        use_https=detect_https(request),
        prefix=prefix_from_request(request),
        provider=provider,
    )
    audit_log(
        AuditEvent.REFRESH_SUCCESS,
        provider=provider,
        user_id=session.user_id,
        ip=_client_ip(request),
    )
    return response


def _token_digest(token: str | None) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def _identity_was_refreshed(access_token: str) -> bool:
    if not access_token:
        return False
    now = _now_seconds()
    key = _token_digest(access_token)
    with _refresh_state_lock:
        expires_at = _refreshed_identities.get(key)
        if expires_at is None:
            return False
        if expires_at <= now:
            _refreshed_identities.pop(key, None)
            return False
        _refreshed_identities.move_to_end(key)
        return True


def _mark_identity_refreshed(access_token: str, *, expires_at: int) -> None:
    if not access_token:
        return
    key = _token_digest(access_token)
    with _refresh_state_lock:
        _refreshed_identities[key] = expires_at
        _refreshed_identities.move_to_end(key)
        while len(_refreshed_identities) > _REFRESH_STATE_MAX:
            _refreshed_identities.popitem(last=False)


def _refresh_session_with_prior_identity(
    provider: DashboardAuthProvider, *, refresh_token: str, access_token: str
):
    """Refresh while preserving compatibility with narrow third-party plugins."""
    parameters = inspect.signature(provider.refresh_session).parameters.values()
    supports_prior_identity = any(
        parameter.name == "access_token"
        or parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )
    kwargs = {"refresh_token": refresh_token}
    if supports_prior_identity:
        kwargs["access_token"] = access_token
    return provider.refresh_session(**kwargs)


def _attempt_refresh(
    request: Request,
    *,
    refresh_token,
    access_token: str = "",
    provider_hint: str | None = None,
):
    """Try to rotate an expired session via the refresh token.

    The provider hint only changes candidate order. ``RefreshExpiredError``
    rejects the token for that candidate, but cannot prove ownership because
    providers such as Basic raise it for foreign opaque tokens too. Likewise,
    ``ProviderError`` only makes that candidate unavailable. Both are audited
    and the remaining providers are tried. Returns ``None`` only when there is
    no RT or every reachable provider rejects it. If no provider succeeds and
    at least one raised ``ProviderError``, re-raises with that provider's name
    so the caller can return 503 without clearing potentially valid cookies.
    """
    if not refresh_token:
        return None
    providers = _ordered_session_providers(provider_hint)
    return _attempt_refresh_locked(
        request,
        providers=providers,
        refresh_token=refresh_token,
        access_token=access_token,
    )


def _attempt_refresh_locked(
    request: Request,
    *,
    providers,
    refresh_token: str,
    access_token: str,
):
    unavailable_provider: str | None = None
    for provider in providers:
        try:
            new_session = _refresh_session_with_prior_identity(
                provider,
                refresh_token=refresh_token,
                access_token=access_token,
            )
        except AccessDeniedError as e:
            e.provider = provider.name
            raise
        except RefreshExpiredError:
            audit_log(
                AuditEvent.REFRESH_FAILURE,
                provider=provider.name,
                reason="refresh_expired",
                ip=_client_ip(request),
            )
            continue
        except ProviderError as e:
            _log.warning(
                "dashboard-auth: provider %r unreachable during refresh: %s",
                provider.name, e,
            )
            audit_log(
                AuditEvent.REFRESH_FAILURE,
                provider=provider.name,
                reason="provider_unreachable",
                ip=_client_ip(request),
            )
            if unavailable_provider is None:
                unavailable_provider = provider.name
            continue
        if new_session is not None:
            _mark_identity_refreshed(
                access_token,
                expires_at=int(new_session.expires_at),
            )
            return new_session, provider.name
    if unavailable_provider is not None:
        raise ProviderError(unavailable_provider)
    return None
