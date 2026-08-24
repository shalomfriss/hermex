"""Integrity-protected ownership binding for provider-scoped refresh tokens.

A refresh token is a bearer credential scoped to the provider that minted it.
The gateway therefore carries a compact proof alongside browser/native token
state.  The proof authenticates both the provider name and a SHA-256 digest of
the exact refresh token; callers cannot edit a provider hint or pair a proof
with another token to redirect the credential across trust boundaries.

The signing key is process-local.  A gateway restart intentionally invalidates
old proofs and requires reauthentication rather than guessing a provider or
probing every registered provider with the token.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

_VERSION = "v1"
_SIGNING_KEY = secrets.token_bytes(32)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def mint_refresh_binding(*, provider: str, refresh_token: str) -> str:
    """Return an opaque proof binding ``refresh_token`` to ``provider``."""
    if not provider or not refresh_token:
        return ""
    encoded_provider = _b64url(provider.encode("utf-8"))
    token_digest = _b64url(hashlib.sha256(refresh_token.encode("utf-8")).digest())
    payload = f"{_VERSION}.{encoded_provider}.{token_digest}"
    signature = _b64url(
        hmac.new(_SIGNING_KEY, payload.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{payload}.{signature}"


def resolve_refresh_owner(*, binding: str | None, refresh_token: str) -> str | None:
    """Return the authenticated owner, or ``None`` for any invalid proof."""
    if not binding or not refresh_token:
        return None
    try:
        version, encoded_provider, token_digest, supplied_signature = binding.split(".")
        if version != _VERSION:
            return None
        payload = f"{version}.{encoded_provider}.{token_digest}"
        expected_signature = hmac.new(
            _SIGNING_KEY, payload.encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(_unb64url(supplied_signature), expected_signature):
            return None
        expected_token_digest = hashlib.sha256(refresh_token.encode("utf-8")).digest()
        if not hmac.compare_digest(_unb64url(token_digest), expected_token_digest):
            return None
        provider = _unb64url(encoded_provider).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None
    return provider or None
