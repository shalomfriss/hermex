"""Real HTTP/WS dashboard server for Playwright acceptance tests."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

os.environ.setdefault("HERMES_NO_BANNER", "1")
os.environ.setdefault("HERMES_DASHBOARD_EMBEDDED_CHAT", "1")

from hermes_cli.dashboard_auth import clear_providers, register_provider
from hermes_cli.dashboard_auth import base as auth_base
from hermes_cli.dashboard_auth.base import (
    DashboardAuthProvider,
    InvalidCredentialsError,
    LoginStart,
    ProviderError,
    RefreshExpiredError,
    Session,
)
from starlette.types import ASGIApp, Receive, Scope, Send

AccessDeniedError = getattr(auth_base, "AccessDeniedError", ProviderError)

_SECRET = b"dashboard-playwright-fixture"


def _token(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    signature = hmac.new(_SECRET, raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw + signature).decode()


def _payload(token: str) -> dict[str, object] | None:
    try:
        blob = base64.urlsafe_b64decode(token)
        raw, signature = blob[:-32], blob[-32:]
        if not hmac.compare_digest(signature, hmac.new(_SECRET, raw, hashlib.sha256).digest()):
            return None
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


class AcceptanceProvider(DashboardAuthProvider):
    name = "acceptance"
    display_name = "Enterprise Test SSO"
    supports_password = True

    def __init__(self) -> None:
        self.mode = "ok"
        self.logout_count = 0

    def start_login(self, *, redirect_uri: str) -> LoginStart:
        raise NotImplementedError

    def complete_login(self, **_kwargs: object) -> Session:
        raise NotImplementedError

    def complete_password_login(self, *, username: str, password: str) -> Session:
        if self.mode == "outage":
            raise ProviderError("acceptance provider unavailable")
        if self.mode == "denied":
            raise AccessDeniedError("group_required")
        if not hmac.compare_digest(username, "operator@example.test") or not hmac.compare_digest(
            password, "correct horse battery staple"
        ):
            raise InvalidCredentialsError("invalid credentials")
        return self._session()

    def verify_session(self, *, access_token: str) -> Session | None:
        if self.mode == "outage":
            raise ProviderError("acceptance provider unavailable")
        if self.mode == "denied":
            raise AccessDeniedError("group_required")
        if self.mode == "expired":
            return None
        payload = _payload(access_token)
        if payload is None or int(str(payload.get("exp", 0))) <= int(time.time()):
            return None
        return self._session(access_token=access_token, refresh_token="")

    def refresh_session(self, *, refresh_token: str, access_token: str = "") -> Session:
        if self.mode == "outage":
            raise ProviderError("acceptance provider unavailable")
        if self.mode == "denied":
            raise AccessDeniedError("group_required")
        if self.mode == "expired" or _payload(refresh_token) is None:
            raise RefreshExpiredError("acceptance refresh expired")
        return self._session()

    def revoke_session(self, *, refresh_token: str) -> None:
        self.logout_count += 1

    def _session(self, *, access_token: str = "", refresh_token: str = "") -> Session:
        now = int(time.time())
        return Session(
            user_id="enterprise-operator-1",
            email="operator@example.test",
            display_name="Enterprise Operator",
            org_id="enterprise-org",
            provider=self.name,
            expires_at=now + 3600,
            access_token=access_token or _token({"sub": "enterprise-operator-1", "exp": now + 3600}),
            refresh_token=refresh_token or _token({"sub": "enterprise-operator-1", "exp": now + 86400}),
        )


class AcceptanceProxy:
    """Expose control endpoints and a realistic /hermes reverse-proxy prefix."""

    def __init__(self, app: ASGIApp, provider: AcceptanceProvider) -> None:
        self.app = app
        self.provider = provider

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = str(scope.get("path", ""))
        if path.startswith("/__e2e/") and scope["type"] == "http":
            await self._control(scope, receive, send)
            return

        forwarded: Scope = dict(scope)
        headers = list(forwarded.get("headers", []))
        if path == "/hermes" or path.startswith("/hermes/"):
            stripped = path[len("/hermes") :] or "/"
            forwarded["path"] = stripped
            forwarded["raw_path"] = stripped.encode()
            headers.append((b"x-forwarded-prefix", b"/hermes"))
        forwarded["headers"] = headers
        await self.app(forwarded, receive, send)

    async def _control(self, scope: Scope, _receive: Receive, send: Send) -> None:
        path = str(scope["path"])
        status = 200
        body: dict[str, Any]
        if path == "/__e2e/health":
            body = {"ok": True}
        elif path == "/__e2e/state":
            body = {"mode": self.provider.mode, "logout_count": self.provider.logout_count}
        elif path == "/__e2e/mode":
            query = parse_qs(scope.get("query_string", b"").decode())
            mode = query.get("value", [""])[0]
            if mode not in {"ok", "denied", "outage", "expired"}:
                status, body = 400, {"error": "invalid mode"}
            else:
                self.provider.mode = mode
                from hermes_cli.dashboard_auth.routes import _reset_password_rate_limit

                _reset_password_rate_limit()
                body = {"mode": mode}
        else:
            status, body = 404, {"error": "not found"}
        payload = json.dumps(body).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": payload})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9129)
    args = parser.parse_args()

    hermes_home = Path(os.environ["HERMES_HOME"])
    hermes_home.mkdir(parents=True, exist_ok=True)

    from hermes_cli import web_server

    provider = AcceptanceProvider()
    clear_providers()
    register_provider(provider)
    web_server.app.state.auth_required = True
    web_server.app.state.bound_host = "127.0.0.1"
    web_server.app.state.bound_port = args.port

    import uvicorn

    uvicorn.run(
        AcceptanceProxy(web_server.app, provider),
        host="127.0.0.1",
        port=args.port,
        server_header=False,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
