"""Abstract base + dataclasses + exceptions for dashboard auth providers."""
from __future__ import annotations

import logging
import re
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class Session:
    """A verified identity. Returned by ``complete_login`` and ``verify_session``.

    All fields are mandatory. Providers that don't have a concept of orgs
    should set ``org_id`` to an empty string. ``access_token`` and
    ``refresh_token`` are opaque to Hermes — provider-specific.
    """

    user_id: str
    email: str
    display_name: str
    org_id: str
    provider: str
    expires_at: int  # unix seconds; the access_token's exp claim
    access_token: str
    refresh_token: str


@dataclass(frozen=True)
class TokenPrincipal:
    """A verified non-interactive (service-to-service) caller.

    The token analog of :class:`Session`. Where a ``Session`` represents an
    interactive human identity behind a session cookie, a ``TokenPrincipal``
    represents a machine/service caller that authenticated by presenting a
    bearer token in the ``Authorization`` request header on a single
    request — no login, no cookie, no refresh.

    Returned by :meth:`DashboardAuthProvider.verify_token` and attached to
    ``request.state.token_principal`` by the token-auth middleware seam so a
    route handler can see *who* called it.

    Fields:
      * ``principal`` — stable identifier for the caller (e.g. the provider
        name, a service account id, or an agent id). Opaque to the seam.
      * ``provider`` — the ``name`` of the provider that verified the token.
      * ``scopes`` — capability strings this principal is authorised for.
        Empty tuple means "unscoped" (the provider vouches for the caller but
        attaches no capability list); a route MAY enforce a required scope.
    """

    principal: str
    provider: str
    scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class LoginStart:
    """First leg of the OAuth round trip.

    ``redirect_url`` is the URL the browser must navigate to (e.g. the
    Portal's ``/oauth/authorize``). ``cookie_payload`` is a dict of cookie
    name → serialised value that the auth route will ``Set-Cookie`` on the
    response. Used for PKCE state, CSRF nonces, etc. Cookies set here MUST
    be HttpOnly + Secure (when over HTTPS) + SameSite=Lax with a TTL ≤ 10
    minutes (the login lifetime).
    """

    redirect_url: str
    cookie_payload: dict[str, str]


_SAFE_DIAGNOSTIC_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_REFERENCE_RE = re.compile(r"^AUTH-[A-F0-9]{8}$")
_SAFE_PROVIDER_CLASSIFICATIONS = frozenset(
    {
        "backing_store_unreachable",
        "endpoint_unreachable",
        "provider_exception",
        "provider_unavailable",
        "upstream_http_error",
        "upstream_http_1xx",
        "upstream_http_2xx",
        "upstream_http_3xx",
        "upstream_http_4xx",
        "upstream_http_5xx",
    }
)
_SAFE_OAUTH_ERROR_CODES = frozenset(
    {
        "access_denied",
        "invalid_client",
        "invalid_grant",
        "invalid_request",
        "invalid_scope",
        "login_required",
        "server_error",
        "temporarily_unavailable",
        "unauthorized_client",
        "unsupported_grant_type",
        "unsupported_response_type",
    }
)


def safe_oauth_error_code(value: object) -> str:
    """Return an explicitly allowlisted OAuth error classification."""
    return value if isinstance(value, str) and value in _SAFE_OAUTH_ERROR_CODES else "provider_error"


def _safe_provider_classification(value: object) -> str:
    return (
        value
        if isinstance(value, str) and value in _SAFE_PROVIDER_CLASSIFICATIONS
        else "provider_unavailable"
    )


class ProviderError(Exception):
    """IDP unreachable, network error, or other transient failure.

    Middleware translates this to HTTP 503. ``classification``, ``status_code``,
    and ``reference_id`` are the only fields trusted at logging/HTTP boundaries;
    the exception text is provider-owned and must never be emitted there.
    """

    def __init__(
        self,
        message: str = "Auth provider unavailable",
        *,
        classification: str = "provider_unavailable",
        status_code: int | None = None,
        reference_id: str | None = None,
    ) -> None:
        self.classification = _safe_provider_classification(classification)
        self.status_code = (
            status_code
            if isinstance(status_code, int) and 100 <= status_code <= 599
            else None
        )
        self.reference_id = (
            reference_id
            if isinstance(reference_id, str) and _REFERENCE_RE.fullmatch(reference_id)
            else f"AUTH-{secrets.token_hex(4).upper()}"
        )
        self.provider = ""
        super().__init__(message)


def upstream_provider_error(
    *, service: str, operation: str, status_code: int
) -> ProviderError:
    """Build a bounded error without reading an untrusted response body."""
    safe_service = service if _SAFE_DIAGNOSTIC_RE.fullmatch(service) else "oauth"
    safe_operation = (
        operation if _SAFE_DIAGNOSTIC_RE.fullmatch(operation) else "request"
    )
    safe_status = status_code if isinstance(status_code, int) else 0
    classification = (
        f"upstream_http_{safe_status // 100}xx"
        if 100 <= safe_status <= 599
        else "upstream_http_error"
    )
    error = ProviderError(
        f"{safe_service} {safe_operation} returned HTTP {safe_status}",
        classification=classification,
        status_code=safe_status,
    )
    error.args = (f"{error.args[0]} (reference {error.reference_id})",)
    return error


def log_provider_failure(
    logger: logging.Logger,
    *,
    provider: str,
    operation: str,
    error: BaseException,
    level: int = logging.WARNING,
) -> str:
    """Log only allowlisted provider diagnostics and return the reference."""
    safe_provider = (
        provider if isinstance(provider, str) and _SAFE_DIAGNOSTIC_RE.fullmatch(provider)
        else "unknown"
    )
    safe_operation = (
        operation
        if isinstance(operation, str) and _SAFE_DIAGNOSTIC_RE.fullmatch(operation)
        else "request"
    )
    classification = getattr(error, "classification", "provider_exception")
    classification = (
        classification
        if isinstance(classification, str)
        and classification in _SAFE_PROVIDER_CLASSIFICATIONS
        else "provider_exception"
    )
    reference_id = getattr(error, "reference_id", None)
    if not isinstance(reference_id, str) or not _REFERENCE_RE.fullmatch(reference_id):
        reference_id = f"AUTH-{secrets.token_hex(4).upper()}"
        try:
            setattr(error, "reference_id", reference_id)
        except Exception:
            pass
    status_code = getattr(error, "status_code", None)
    status_detail = (
        f" HTTP {status_code}"
        if isinstance(status_code, int) and 100 <= status_code <= 599
        else ""
    )
    logger.log(
        level,
        "dashboard-auth: provider %r failed during %s (%s%s; reference %s)",
        safe_provider,
        safe_operation,
        classification,
        status_detail,
        reference_id,
    )
    return reference_id


_ACCESS_DENIED_REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class AccessDeniedError(Exception):
    """A verified identity is not authorized to access the dashboard.

    This is terminal for the provider stack: unlike an unknown/expired token,
    a provider has authenticated the principal and made an authorization
    decision, so callers must not try fallback providers or refresh into a
    login loop. ``reason`` is a stable machine-safe policy category. Optional
    ``details`` are for trusted internal diagnostics and must never be returned
    to clients or logged without explicit field-level filtering.
    """

    def __init__(
        self, reason: str, *, details: Mapping[str, Any] | None = None
    ) -> None:
        if not isinstance(reason, str) or not _ACCESS_DENIED_REASON_RE.fullmatch(
            reason
        ):
            raise ValueError(f"unsupported access-denial reason: {reason!r}")
        self.reason = reason
        self.details = dict(details or {})
        self.provider = ""
        super().__init__(reason)


class InvalidCodeError(Exception):
    """The OAuth callback ``code`` / ``state`` failed validation.

    Middleware translates this to HTTP 400.
    """


class InvalidCredentialsError(Exception):
    """A username/password pair was rejected by a password provider.

    Raised by :meth:`DashboardAuthProvider.complete_password_login`. The
    ``/auth/password-login`` route translates this to HTTP 401 with a
    deliberately generic detail (never distinguishing "unknown user" from
    "wrong password") so the endpoint can't be used as a username oracle.
    """


class RefreshExpiredError(Exception):
    """This provider rejects the refresh token as dead or invalid.

    In a multi-provider deployment this does not prove token ownership, so
    middleware may try remaining providers. It clears cookies and forces
    re-login only after every reachable provider rejects the token.
    """


class DashboardAuthProvider(ABC):
    """Protocol every dashboard-auth provider plugin implements.

    Lifecycle:
      1. ``start_login`` — user clicks "Log in with X" on the login page.
         Provider returns a redirect URL and any PKCE/CSRF state to stash
         in short-lived cookies.
      2. Browser bounces through the OAuth IDP and lands at /auth/callback.
      3. ``complete_login`` — exchange the code + verifier for a Session.
      4. ``verify_session`` — called on every request to validate the
         access token in the cookie. Returns ``None`` if the token is
         expired or invalid (middleware then triggers refresh or logout).
      5. ``refresh_session`` — called when the access token is near expiry.
         Returns a new Session with rotated tokens. ``access_token`` carries
         the prior identity token when one is still available; providers may
         re-verify and retain it when a conforming refresh response omits a new
         identity token.
      6. ``revoke_session`` — called on /auth/logout. Best-effort.

    Failure semantics:
      * ``start_login`` may raise ``ProviderError`` if the IDP is
        unreachable.
      * ``complete_login`` raises ``InvalidCodeError`` on bad code/state;
        ``AccessDeniedError`` when the verified identity is forbidden;
        ``ProviderError`` if the IDP is unreachable.
      * ``verify_session`` returns ``None`` on expiry / unknown token;
        raises ``AccessDeniedError`` for a recognized but forbidden identity,
        and ``ProviderError`` if the IDP is unreachable. Middleware
        treats expiry and unreachable differently (expiry → refresh;
        unreachable → 503).
      * ``refresh_session`` raises ``RefreshExpiredError`` when the refresh
        token is invalid for its integrity-bound owner. Refresh credentials
        are never submitted to another provider: rejection forces re-login,
        while ``ProviderError`` returns 503 without clearing credentials.
        ``AccessDeniedError`` is terminal and must not trigger another refresh.
      * ``revoke_session`` is best-effort and must not raise.

    Subclasses MUST set ``name`` (lowercase identifier, stable forever)
    and ``display_name`` (user-facing label on the login page).

    Password (non-redirect) providers:
      A provider that authenticates with a username + password instead of
      an OAuth redirect sets ``supports_password = True`` and implements
      ``complete_password_login``. The login page then renders a
      credential form (POSTing to ``/auth/password-login``) instead of a
      "Log in with X" redirect button. Everything downstream of login —
      ``verify_session`` / ``refresh_session`` / ``revoke_session``, the
      session cookies, the WS-ticket mint — is identical to the OAuth
      path, because a password session is just a :class:`Session` with
      provider-minted opaque tokens. The OAuth methods (``start_login`` /
      ``complete_login``) remain abstract; a pure-password provider that
      will never be reached via the redirect flow may implement them as
      stubs that raise ``NotImplementedError``.
    """

    name: str = ""
    display_name: str = ""

    # When True, this provider authenticates via username + password
    # (``complete_password_login``) rather than (or in addition to) the
    # OAuth redirect flow. The login page renders a credential form for
    # such providers; the ``/auth/password-login`` route dispatches to
    # ``complete_password_login``. OAuth-only providers leave this False
    # and are completely unaffected.
    supports_password: bool = False

    # When True, this provider can verify a non-interactive bearer token
    # (``verify_token``) presented on a single request by a service-to-service
    # caller — no login, no cookie, no refresh. This is the generic
    # API-token capability flag, mirroring ``supports_password``: a route
    # opts into token auth (see ``token_auth`` middleware seam) and the
    # gate consults every ``supports_token`` provider in turn until one
    # recognises the token. OAuth/password providers leave this False and
    # are completely unaffected. The drain bearer-secret plugin is the
    # first consumer, but the capability is deliberately generic so any
    # future machine-credential provider drops in without core changes.
    supports_token: bool = False

    # When True, this provider does the interactive cookie-session flow (login,
    # verify, refresh). The login page, /auth/login, and the gate's
    # verify/refresh loops consult only supports_session providers, so a
    # token-only credential (e.g. drain) is never offered a login. Mirrors
    # supports_token.
    supports_session: bool = True

    @abstractmethod
    def start_login(self, *, redirect_uri: str) -> LoginStart: ...

    @abstractmethod
    def complete_login(
        self,
        *,
        code: str,
        state: str,
        code_verifier: str,
        redirect_uri: str,
        nonce: str = "",
    ) -> Session: ...

    @abstractmethod
    def verify_session(self, *, access_token: str) -> Optional[Session]: ...

    @abstractmethod
    def refresh_session(
        self, *, refresh_token: str, access_token: str = ""
    ) -> Session: ...

    @abstractmethod
    def revoke_session(self, *, refresh_token: str) -> bool | None:
        """Best-effort revoke; ``False`` explicitly reports remote failure."""
        ...

    def complete_password_login(
        self, *, username: str, password: str
    ) -> "Session":
        """Verify a username/password pair and mint a :class:`Session`.

        Only called when ``supports_password`` is True (the
        ``/auth/password-login`` route guards on the flag). The default
        raises ``NotImplementedError`` so an OAuth-only provider that
        forgets to set the flag fails loudly rather than silently
        accepting credentials.

        The returned ``Session`` carries provider-minted opaque
        ``access_token`` / ``refresh_token`` exactly like the OAuth path,
        so all downstream session handling (cookies, verify, refresh,
        ws-tickets, logout) is identical.

        Failure semantics:
          * ``InvalidCredentialsError`` — username/password rejected. The
            route surfaces a generic 401 (no user-vs-password
            distinction). Implementations SHOULD spend constant time on
            unknown users (dummy hash verify) to avoid a timing oracle.
          * ``ProviderError`` — the backing credential store is
            unreachable (LDAP/DB down); the route surfaces 503.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support password login "
            "(set supports_password = True and override "
            "complete_password_login)"
        )

    def verify_token(self, *, token: str) -> "Optional[TokenPrincipal]":
        """Verify a non-interactive bearer token; return its principal.

        The token analog of ``verify_session``. Only consulted when
        ``supports_token`` is True. Called by the ``token_auth`` middleware
        seam for every request to a token-authable route, in registration
        order, until one provider returns a non-None principal.

        Contract (mirrors ``verify_session`` stacking semantics):
          * Return a :class:`TokenPrincipal` if this provider recognises and
            accepts the token.
          * Return ``None`` for a token this provider does NOT recognise —
            never raise, so the seam can fall through to the next provider.
            A malformed/expired/wrong token is "not recognised" → ``None``.
          * Raise ``ProviderError`` ONLY for a genuine backing-store outage
            (the provider can neither confirm nor deny). The seam treats this
            like ``verify_session``: remember it, keep trying other providers,
            and surface 503 only if NO provider accepts the token AND at least
            one was unreachable.

        Implementations MUST use a constant-time comparison
        (``hmac.compare_digest``) when matching a shared secret so the
        endpoint isn't a timing oracle.

        The default raises ``NotImplementedError`` so a provider that sets
        ``supports_token`` but forgets to implement this fails loudly rather
        than silently accepting every caller.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support token auth "
            "(set supports_token = True and override verify_token)"
        )


def assert_protocol_compliance(cls: type) -> None:
    """Raise ``TypeError`` if ``cls`` doesn't fully implement the provider protocol.

    Call this in every provider plugin's unit tests::

        def test_protocol_compliance():
            assert_protocol_compliance(MyProvider)

    Returns ``None`` on success so callers can assert it explicitly.
    """
    required_methods = (
        "start_login",
        "complete_login",
        "verify_session",
        "refresh_session",
        "revoke_session",
    )
    required_attrs = ("name", "display_name")

    for attr in required_attrs:
        val = getattr(cls, attr, "")
        if not val:
            raise TypeError(
                f"{cls.__name__} missing or empty attribute: {attr!r}"
            )
    for method in required_methods:
        if not callable(getattr(cls, method, None)):
            raise TypeError(f"{cls.__name__} missing method: {method}")
    # Also catch the ABC-not-overridden case.
    if getattr(cls, "__abstractmethods__", None):
        raise TypeError(
            f"{cls.__name__} has unimplemented abstract methods: "
            f"{sorted(cls.__abstractmethods__)}"
        )
