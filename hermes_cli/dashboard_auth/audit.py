"""Audit log for dashboard-auth events.

Profile-aware location: ``$HERMES_HOME/logs/dashboard-auth.log``.
Format: one JSON object per line. Token-like fields are stripped before
serialisation to avoid leaking refresh tokens or JWTs to disk.

This module deliberately keeps a minimal dependency surface — no imports
from ``hermes_constants`` or other hermes_cli modules — so it can be
imported safely from middleware code that loads early in the startup
sequence.
"""
from __future__ import annotations

import datetime as _dt
import enum
import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)
_write_lock = threading.Lock()

# Bound attacker-triggerable public-auth failures on disk. Rotation is kept in
# this leaf module rather than logging.handlers so creation mode and every
# rename stay under the same lock on all supported platforms.
MAX_LOG_BYTES = 10 * 1024 * 1024
BACKUP_COUNT = 5
MAX_RECORD_BYTES = 64 * 1024
_WRITE_WARNING_INTERVAL_SECONDS = 60.0
_last_write_warning_at: float | None = None

# Field names that must never appear in the log raw. Any kwarg matching
# these is silently dropped.
_REDACTED_FIELDS: frozenset = frozenset({
    "access_token", "refresh_token", "code", "code_verifier",
    "state", "ticket", "cookie", "Authorization", "authorization",
    "nonce", "raw_claims", "claims", "client_secret",
})

_REDACTED_FIELDS_LOWER = frozenset(name.lower() for name in _REDACTED_FIELDS) | {
    "id_token", "client_secret", "password", "nonce", "raw_claims",
}
_REDACTED_FIELDS_COMPACT = frozenset(
    re.sub(r"[^a-z0-9]", "", name) for name in _REDACTED_FIELDS_LOWER
)


def _is_secret_field(name: object) -> bool:
    if not isinstance(name, str):
        return False
    lowered = name.lower()
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    return (
        lowered in _REDACTED_FIELDS_LOWER
        or compact in _REDACTED_FIELDS_COMPACT
        or compact.endswith(("token", "secret", "password", "cookie"))
    )


def _redact(value: Any) -> Any:
    """Drop secret-bearing keys recursively while preserving audit context."""
    if isinstance(value, dict):
        return {
            key: _redact(item)
            for key, item in value.items()
            if not _is_secret_field(key)
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


def _rotate_locked(path: Path, incoming_bytes: int) -> None:
    try:
        # Repair legacy permissive files before either retaining or appending.
        path.chmod(0o600)
        current_size = path.stat().st_size
    except FileNotFoundError:
        return
    if current_size + incoming_bytes <= MAX_LOG_BYTES:
        return
    oldest = path.with_name(f"{path.name}.{BACKUP_COUNT}")
    oldest.unlink(missing_ok=True)
    for index in range(BACKUP_COUNT - 1, 0, -1):
        source = path.with_name(f"{path.name}.{index}")
        if source.exists():
            source.chmod(0o600)
            source.replace(path.with_name(f"{path.name}.{index + 1}"))
    if BACKUP_COUNT > 0:
        path.replace(path.with_name(f"{path.name}.1"))
    else:
        path.unlink(missing_ok=True)


def _append_owner_only(path: Path, payload: bytes) -> None:
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            # Native Windows does not expose meaningful POSIX owner bits.
            pass
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short audit-log write")
            view = view[written:]
    finally:
        os.close(fd)


def _warn_write_failure(exc: Exception) -> None:
    global _last_write_warning_at
    now = time.monotonic()
    if (
        _last_write_warning_at is not None
        and now - _last_write_warning_at < _WRITE_WARNING_INTERVAL_SECONDS
    ):
        return
    _last_write_warning_at = now
    _log.warning("dashboard-auth audit log write failed: %s", exc)


class AuditEvent(enum.Enum):
    """Event types written to dashboard-auth.log.

    Values are the literal ``event`` field on the JSON line.
    """

    LOGIN_START = "login_start"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    ACCESS_DENIED = "access_denied"
    LOGOUT = "logout"
    REFRESH_SUCCESS = "refresh_success"
    REFRESH_FAILURE = "refresh_failure"
    REVOKE = "revoke"
    SESSION_VERIFY_FAILURE = "session_verify_failure"
    WS_TICKET_MINTED = "ws_ticket_minted"
    WS_TICKET_REJECTED = "ws_ticket_rejected"
    TOKEN_AUTH_SUCCESS = "token_auth_success"
    TOKEN_AUTH_FAILURE = "token_auth_failure"
    # RFC 8252 native-app (system-browser + loopback + PKCE) flow.
    NATIVE_AUTHORIZE_START = "native_authorize_start"
    NATIVE_CODE_ISSUED = "native_code_issued"
    NATIVE_TOKEN_SUCCESS = "native_token_success"
    NATIVE_TOKEN_FAILURE = "native_token_failure"


def _resolve_log_path() -> Path:
    """``$HERMES_HOME/logs/dashboard-auth.log``.

    Uses ``hermes_constants.get_hermes_home()`` (a leaf module — no import
    cycle) so profile overrides and the native-Windows ``%LOCALAPPDATA%``
    fallback are honored.
    """
    from hermes_constants import get_hermes_home

    return get_hermes_home() / "logs" / "dashboard-auth.log"


def audit_log(event: AuditEvent, **fields: Any) -> None:
    """Append one event to the audit log.

    Token-like fields are dropped. Missing log directory is created.
    Write failures are logged at WARNING but never raise — auth must not
    fail because the audit logger broke.
    """
    safe_fields = _redact(fields)
    entry = {
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "event": event.value,
        **safe_fields,
    }
    line = json.dumps(entry, separators=(",", ":")) + "\n"
    payload = line.encode("utf-8")
    record_limit = min(MAX_RECORD_BYTES, MAX_LOG_BYTES)
    if len(payload) > record_limit:
        payload = (
            json.dumps(
                {"ts": entry["ts"], "event": event.value, "truncated": True},
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    path = _resolve_log_path()
    try:
        with _write_lock:
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            _rotate_locked(path, len(payload))
            _append_owner_only(path, payload)
    except Exception as e:
        _warn_write_failure(e)
