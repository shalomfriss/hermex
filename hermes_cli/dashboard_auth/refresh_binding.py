"""Durable ownership proofs for provider-scoped refresh tokens.

The proof authenticates the provider and a SHA-256 digest of the exact refresh
token. Signing keys live in an owner-only, profile-scoped keyring so routine
dashboard restarts do not invalidate browser or native sessions. The keyring
contains one active and at most one retired key: rotation mints with the new
key, accepts the previous generation during a bounded retirement window, and
retires older proofs on the next rotation.

Missing state is initialized atomically. Corrupt, insecure, or mismatched state
is never replaced implicitly and makes mint/resolve/rotate fail closed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
from typing import Any

from hermes_constants import get_hermes_home
from utils import atomic_json_write

_VERSION = "v2"
_KEYRING_VERSION = 1
_KEY_BYTES = 32
_MAX_KEYS = 2
_MAX_KEYRING_BYTES = 4096


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _state_dir() -> Path:
    return Path(get_hermes_home()) / "secrets"


def _keyring_path() -> Path:
    return _state_dir() / "dashboard_refresh_binding_keys.json"


def _lock_path() -> Path:
    return _state_dir() / "dashboard_refresh_binding_keys.lock"


class _StateLock:
    """Cross-process lock for keyring initialization and rotation."""

    def __init__(self, path: Path, *, exclusive: bool = True, create: bool = True):
        self.path = path
        self.exclusive = exclusive
        self.create = create
        self._handle = None
        self._overlapped = None

    def __enter__(self):
        if os.name == "nt":
            from hermes_cli.windows_secure_files import (
                acquire_secure_lock,
                ensure_secure_directory,
            )

            if self.create:
                ensure_secure_directory(
                    self.path.parent, label="refresh-binding secret directory"
                )
            self._handle, self._overlapped = acquire_secure_lock(
                self.path,
                label="refresh-binding lock",
                exclusive=self.exclusive,
                create=self.create,
            )
            return self

        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.path.parent, 0o700)
        if self.path.is_symlink():
            raise OSError("refresh-binding lock path must not be a symlink")
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.path, flags, 0o600)
        self._handle = os.fdopen(fd, "a+b")
        if os.name == "posix":
            os.chmod(self.path, 0o600)
            import fcntl

            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._handle is None:
            return
        if os.name == "nt":
            from hermes_cli.windows_secure_files import release_secure_lock

            release_secure_lock(self._handle, self._overlapped)
            self._handle = None
            self._overlapped = None
            return
        try:
            import fcntl

            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._handle = None


def _new_key() -> dict[str, str]:
    return {
        "id": secrets.token_hex(8),
        "secret": _b64url(secrets.token_bytes(_KEY_BYTES)),
    }


def _new_keyring() -> dict[str, Any]:
    key = _new_key()
    return {
        "version": _KEYRING_VERSION,
        "active_key_id": key["id"],
        "keys": [key],
    }


def _parse_keyring(raw: Any) -> tuple[str, list[tuple[str, bytes]]] | None:
    """Return validated key material without repairing malformed state."""
    if not isinstance(raw, dict) or raw.get("version") != _KEYRING_VERSION:
        return None
    active = raw.get("active_key_id")
    keys = raw.get("keys")
    if not isinstance(active, str) or not isinstance(keys, list):
        return None
    if not 1 <= len(keys) <= _MAX_KEYS:
        return None

    parsed: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    try:
        for entry in keys:
            if not isinstance(entry, dict):
                return None
            key_id = entry.get("id")
            encoded_secret = entry.get("secret")
            if (
                not isinstance(key_id, str)
                or len(key_id) != 16
                or any(char not in "0123456789abcdef" for char in key_id)
                or key_id in seen
                or not isinstance(encoded_secret, str)
            ):
                return None
            secret = _unb64url(encoded_secret)
            if len(secret) != _KEY_BYTES:
                return None
            parsed.append((key_id, secret))
            seen.add(key_id)
    except (ValueError, TypeError):
        return None
    if parsed[0][0] != active:
        return None
    return active, parsed


def _read_keyring(
    path: Path, *, acquire_lock: bool = True
) -> tuple[str, list[tuple[str, bytes]]] | None:
    try:
        if os.name == "nt":
            from hermes_cli.windows_secure_files import read_secure_bytes

            if acquire_lock:
                with _StateLock(_lock_path(), exclusive=False, create=False):
                    return _read_keyring(path, acquire_lock=False)
            raw = json.loads(
                read_secure_bytes(
                    path,
                    maximum=_MAX_KEYRING_BYTES,
                    label="refresh-binding keyring",
                )
            )
            return _parse_keyring(raw)
        if path.is_symlink():
            return None
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        if os.name == "posix" and os.fstat(fd).st_mode & 0o077:
            os.close(fd)
            return None
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError, TypeError):
        return None
    return _parse_keyring(raw)


def _write_keyring(path: Path, keyring: dict[str, Any]) -> None:
    if os.name == "nt":
        from hermes_cli.windows_secure_files import atomic_write_secure_bytes

        payload = json.dumps(
            keyring,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")
        if len(payload) > _MAX_KEYRING_BYTES:
            raise OSError("refresh-binding keyring is too large")
        atomic_write_secure_bytes(path, payload, label="refresh-binding keyring")
        return
    atomic_json_write(path, keyring, mode=0o600, sort_keys=True)
    if os.name == "posix":
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_fd = os.open(path.parent, flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def _load_or_create_keyring() -> tuple[str, list[tuple[str, bytes]]] | None:
    path = _keyring_path()
    try:
        # Existing state is atomically replaced by writers, so readers do not
        # need the write lock. This also permits deployment secret volumes to
        # be mounted read-only during normal dashboard operation.
        if path.is_symlink():
            return None
        if path.exists():
            return _read_keyring(path)
        with _StateLock(_lock_path()):
            # Another process may have initialized the profile while this one
            # waited for the lock.
            if path.is_symlink():
                return None
            if path.exists():
                return _read_keyring(path, acquire_lock=False)
            keyring = _new_keyring()
            _write_keyring(path, keyring)
            return _parse_keyring(keyring)
    except (OSError, RuntimeError):
        return None


def rotate_refresh_binding_key() -> bool:
    """Activate a new key while retaining exactly one prior generation.

    A missing keyring is initialized with one key. Existing corrupt/insecure
    state is left byte-for-byte untouched and returns ``False``.
    """
    path = _keyring_path()
    try:
        with _StateLock(_lock_path()):
            if path.is_symlink():
                return False
            if not path.exists():
                _write_keyring(path, _new_keyring())
                return True
            parsed = _read_keyring(path, acquire_lock=False)
            if parsed is None:
                return False
            _active, keys = parsed
            new_key = _new_key()
            retained = [
                {"id": keys[0][0], "secret": _b64url(keys[0][1])},
            ]
            _write_keyring(
                path,
                {
                    "version": _KEYRING_VERSION,
                    "active_key_id": new_key["id"],
                    "keys": [new_key, *retained],
                },
            )
            return True
    except (OSError, RuntimeError):
        return False


def mint_refresh_binding(*, provider: str, refresh_token: str) -> str:
    """Return an opaque proof binding ``refresh_token`` to ``provider``."""
    if not provider or not refresh_token:
        return ""
    keyring = _load_or_create_keyring()
    if keyring is None:
        return ""
    active_key_id, keys = keyring
    signing_key = keys[0][1]
    encoded_provider = _b64url(provider.encode("utf-8"))
    token_digest = _b64url(hashlib.sha256(refresh_token.encode("utf-8")).digest())
    payload = f"{_VERSION}.{active_key_id}.{encoded_provider}.{token_digest}"
    signature = _b64url(
        hmac.new(signing_key, payload.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{payload}.{signature}"


def resolve_refresh_owner(*, binding: str | None, refresh_token: str) -> str | None:
    """Return the authenticated owner, or ``None`` for any invalid proof."""
    if not binding or not refresh_token:
        return None
    keyring = _load_or_create_keyring()
    if keyring is None:
        return None
    try:
        version, key_id, encoded_provider, token_digest, supplied_signature = (
            binding.split(".")
        )
        if version != _VERSION:
            return None
        verification_key = next(
            (secret for candidate, secret in keyring[1] if candidate == key_id),
            None,
        )
        if verification_key is None:
            return None
        payload = f"{version}.{key_id}.{encoded_provider}.{token_digest}"
        expected_signature = hmac.new(
            verification_key, payload.encode("ascii"), hashlib.sha256
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
