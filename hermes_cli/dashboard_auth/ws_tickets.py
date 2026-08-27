"""WS-upgrade auth credentials for gated mode.

Browsers cannot set ``Authorization`` on a WebSocket upgrade. In loopback
mode the legacy ``?token=<_SESSION_TOKEN>`` query param works because the
token is injected into the SPA bundle. In gated mode there is no injected
token — so this module provides two credential shapes:

1. **Single-use browser tickets** (``mint_ticket`` / ``consume_ticket``).
   The SPA gets a fresh ticket via the authenticated REST endpoint
   ``POST /api/auth/ws-ticket`` and passes it as ``?ticket=`` on the WS
   upgrade. Single-use, TTL = 30 seconds — a leaked ticket is uninteresting.

2. **A process-lifetime internal credential** (``internal_ws_credential`` /
   ``consume_internal_credential``). This authenticates *server-spawned*
   WS clients — specifically the embedded-TUI PTY child, which attaches to
   ``/api/ws`` (JSON-RPC gateway) and ``/api/pub`` (event sidecar) over
   loopback. A single-use 30s ticket is the wrong shape for that link: the
   child reads its attach URL once at startup and **reuses it on every
   reconnect**, and on a slow cold boot the child may not dial within 30s.
   The internal credential is minted once per process, never expires, is
   multi-use, and — critically — is **never injected into any HTML/SPA**:
   it only ever leaves the process via the spawned child's environment, so
   browser-side XSS cannot read it. A leaked internal credential grants no
   more than a single-use ticket already does (the same two internal WS
   endpoints), and the same Origin / host guards still apply downstream.

In-memory; the dashboard is a single process so no distributed coordination
is needed. The module exposes a small functional API rather than a class so
tests can patch the process-monotonic ``_clock`` cleanly.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import deque
import hashlib
import ipaddress
from typing import Any, Deque, Dict, Optional, Tuple

#: Time-to-live for newly-minted tickets in seconds. 30 s is long enough
#: that the SPA can call ``getWsTicket()`` and immediately open the WS,
#: short enough that a leaked ticket is uninteresting.
TTL_SECONDS = 30

#: Hard ceiling for live browser tickets. Expired entries are removed before
#: this limit is evaluated; live tickets are never evicted because doing so
#: would make an already-issued credential fail nondeterministically.
MAX_ACTIVE_TICKETS = 2048

#: Successful issuance is tracked for one ticket lifetime, including tickets
#: that have already been consumed. This bounds request-rate abuse instead of
#: only bounding concurrent live credentials. The principal budget permits
#: eight complete five-surface reconnects in 30 seconds.
ISSUANCE_WINDOW_SECONDS = TTL_SECONDS
MAX_ISSUES_PER_PRINCIPAL = 40
MAX_ISSUES_PER_IP = 200
MAX_ISSUES_PER_WINDOW = 4096

# Process-local expiry and rate windows must not depend on adjustable wall
# time. Tests replace this callable with a deterministic clock.
_clock = time.monotonic

_lock = threading.Lock()
_tickets: Dict[str, Tuple[int, Dict[str, Any]]] = {}  # ticket -> (expires_at, info)
_issuance_events: Deque[Tuple[int, str, str]] = deque()
_principal_issue_times: Dict[str, Deque[int]] = {}
_ip_issue_times: Dict[str, Deque[int]] = {}

#: The process-lifetime internal credential (see module docstring). Lazily
#: minted on first ``internal_ws_credential()`` call and stable for the life
#: of the process. Guarded by ``_lock``.
_internal_credential: Optional[str] = None

#: Identity recorded for connections that authenticate via the internal
#: credential, so audit logs distinguish them from browser-initiated tickets.
INTERNAL_USER_ID = "server-internal"
INTERNAL_PROVIDER = "server-internal"


class TicketInvalid(Exception):
    """Ticket missing, expired, or already consumed."""


class TicketCapacityExceeded(Exception):
    """The bounded live-ticket store cannot accept another credential."""


class TicketRateLimited(Exception):
    """The principal or address exhausted its short issuance budget."""

    def __init__(self, retry_after: int):
        super().__init__("websocket ticket issuance rate limited")
        self.retry_after = max(1, retry_after)


def _principal_key(*, user_id: str, provider: str) -> str:
    """Return a non-reversible canonical bucket key for an auth principal."""
    canonical = f"{provider.strip().casefold()}\0{user_id.strip()}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _ip_key(client_ip: str) -> str:
    """Canonicalize equivalent IP spellings into one issuance bucket."""
    raw = client_ip.strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return raw.casefold() or "<unknown>"
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def mint_ticket(*, user_id: str, provider: str, client_ip: str = "") -> str:
    """Generate a one-shot ticket bound to this user identity.

    The returned token is base64url, 43 bytes of entropy (32-byte random
    seed). Stash returns the ``info`` dict to the caller on consume so the
    WS handler can carry the identity forward into its session log.
    """
    principal_key = _principal_key(user_id=user_id, provider=provider)
    ip_key = _ip_key(client_ip)
    with _lock:
        # Read the clock after acquiring the lock so event timestamps remain
        # monotonic in insertion order even when callers arrive concurrently.
        now = int(_clock())
        _gc_expired_locked(now)
        _gc_issuance_locked(now)
        if len(_tickets) >= MAX_ACTIVE_TICKETS:
            raise TicketCapacityExceeded("websocket ticket store at capacity")
        global_limited = len(_issuance_events) >= MAX_ISSUES_PER_WINDOW
        principal_events = _principal_issue_times.get(principal_key, ())
        ip_events = _ip_issue_times.get(ip_key, ())
        principal_limited = len(principal_events) >= MAX_ISSUES_PER_PRINCIPAL
        ip_limited = len(ip_events) >= MAX_ISSUES_PER_IP
        if global_limited or principal_limited or ip_limited:
            deadlines = []
            if global_limited and _issuance_events:
                deadlines.append(_issuance_events[0][0] + ISSUANCE_WINDOW_SECONDS)
            if principal_limited:
                deadlines.append(principal_events[0] + ISSUANCE_WINDOW_SECONDS)
            if ip_limited:
                deadlines.append(ip_events[0] + ISSUANCE_WINDOW_SECONDS)
            raise TicketRateLimited(max(deadlines) - now)
        ticket = secrets.token_urlsafe(32)
        _tickets[ticket] = (
            now + TTL_SECONDS,
            {
                "user_id": user_id,
                "provider": provider,
                "minted_at": int(time.time()),
            },
        )
        _issuance_events.append((now, principal_key, ip_key))
        _principal_issue_times.setdefault(principal_key, deque()).append(now)
        _ip_issue_times.setdefault(ip_key, deque()).append(now)
    return ticket


def consume_ticket(ticket: str) -> Dict[str, Any]:
    """Validate and consume. Raises :class:`TicketInvalid` on missing/expired/used.

    Single-use semantics: a successful consume immediately removes the
    ticket from the store, so a second call with the same value raises
    ``TicketInvalid("unknown ticket")`` without reflecting credential material.
    """
    with _lock:
        now = int(_clock())
        entry = _tickets.pop(ticket, None)
        if entry is None:
            raise TicketInvalid("unknown ticket")
        expires_at, info = entry
        if expires_at <= now:
            raise TicketInvalid("expired")
        return info


def _gc_expired_locked(now: int | None = None) -> None:
    """Drop the ordered expired prefix. Caller must hold ``_lock``.

    Tickets are inserted under the same lock with a fixed TTL and monotonic
    timestamp, so dict insertion order is also expiry order. Consumed entries
    may create holes but cannot disturb that ordering. This keeps the normal
    issuance path O(1) and makes cleanup amortized O(number expired).
    """
    now = int(_clock()) if now is None else now
    while _tickets:
        ticket, (expires_at, _) = next(iter(_tickets.items()))
        if expires_at > now:
            break
        _tickets.pop(ticket, None)


def _gc_issuance_locked(now: int) -> None:
    """Evict expired issuance events oldest-first. Caller holds ``_lock``."""
    while (
        _issuance_events
        and _issuance_events[0][0] + ISSUANCE_WINDOW_SECONDS <= now
    ):
        _, principal_key, ip_key = _issuance_events.popleft()
        for events_by_key, key in (
            (_principal_issue_times, principal_key),
            (_ip_issue_times, ip_key),
        ):
            events = events_by_key[key]
            events.popleft()
            if not events:
                events_by_key.pop(key, None)


def internal_ws_credential() -> str:
    """Return the process-lifetime internal WS credential, minting it once.

    Used by the server to authenticate WS clients it spawns itself (the
    embedded-TUI PTY child). The value is stable for the life of the process,
    multi-use, and never expires — so a server-spawned child can reconnect
    its ``/api/ws`` / ``/api/pub`` sockets indefinitely without re-minting.

    The credential is never injected into the SPA HTML or returned over any
    REST endpoint; it is only ever passed to a child process via its
    environment. See the module docstring for the threat-model rationale.
    """
    global _internal_credential
    with _lock:
        if _internal_credential is None:
            _internal_credential = secrets.token_urlsafe(32)
        return _internal_credential


def consume_internal_credential(value: str) -> Dict[str, Any]:
    """Validate an internal credential. Raises :class:`TicketInvalid` on mismatch.

    Unlike :func:`consume_ticket` this is **not** single-use — the value is
    not removed on success, so a server-spawned child can present it on every
    (re)connect. Returns the fixed server-internal identity ``info`` dict
    (``{user_id, provider}``), mirroring the ``info`` shape ``consume_ticket``
    returns, so a caller that wants to record the connecting identity can; the
    current ``_ws_auth_ok`` caller validates for the boolean outcome only and
    discards the dict.

    A constant-time compare against the (lazily-minted) credential avoids
    leaking length / prefix information on mismatch. If no internal
    credential has been minted yet, any value is rejected.
    """
    with _lock:
        expected = _internal_credential
    if not value or expected is None:
        raise TicketInvalid("no internal credential")
    if not secrets.compare_digest(value.encode(), expected.encode()):
        raise TicketInvalid("internal credential mismatch")
    return {
        "user_id": INTERNAL_USER_ID,
        "provider": INTERNAL_PROVIDER,
    }


def _reset_for_tests() -> None:
    """Test-only: drop all tickets and the internal credential."""
    global _internal_credential
    with _lock:
        _tickets.clear()
        _issuance_events.clear()
        _principal_issue_times.clear()
        _ip_issue_times.clear()
        _internal_credential = None
