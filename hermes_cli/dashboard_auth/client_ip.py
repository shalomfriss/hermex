"""Canonical client-IP resolution across dashboard authentication paths.

Forwarded addresses are security-sensitive: they affect throttling, native-flow
capacity, and audit attribution.  This module therefore accepts an append-style
``X-Forwarded-For`` chain only when the connection peer belongs to an explicit
trusted-proxy network and resolves the chain from right to left.
"""
from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable
from typing import TypeAlias

from fastapi import Request

_log = logging.getLogger(__name__)

_MAX_FORWARDED_FOR_BYTES = 4096
_MAX_FORWARDED_HOPS = 32
_IP_NETWORK: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network


def _canonical_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse and canonicalize an IP literal, folding IPv4-mapped IPv6."""
    raw = (value or "").strip()
    if not raw or "%" in raw:
        return None
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def parse_trusted_proxy_networks(values: Iterable[str] | None) -> tuple[_IP_NETWORK, ...]:
    """Return valid trusted proxy IP/CIDR networks; invalid entries are ignored."""
    if isinstance(values, (str, bytes)):
        _log.warning("Ignoring dashboard.trusted_proxies: expected a list of IP/CIDR values")
        return ()
    networks: list[_IP_NETWORK] = []
    for value in values or ():
        raw = str(value).strip()
        if not raw:
            continue
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            _log.warning("Ignoring invalid dashboard.trusted_proxies entry %r", raw)
            continue
        networks.append(network)
    return tuple(networks)


def _is_trusted(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: Iterable[_IP_NETWORK],
) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def trusted_peer(request: Request) -> bool:
    """Whether the immediate ASGI peer is in the configured proxy boundary."""
    peer = _canonical_ip(request.client.host if request.client else "")
    if peer is None:
        return False
    try:
        networks = tuple(
            getattr(request.app.state, "dashboard_trusted_proxy_networks", ())
            or ()
        )
    except (AttributeError, TypeError):
        return False
    return _is_trusted(peer, networks)


def client_ip(request: Request) -> str:
    """Resolve the request's canonical, unspoofable client IP.

    The immediate ASGI peer is authoritative by default.  An X-Forwarded-For
    chain is considered only when that peer is explicitly trusted.  Every hop
    must be a valid IP literal and the bounded chain is walked right-to-left,
    skipping trusted append proxies until the first untrusted address.  Any
    malformed or oversized chain falls back to the peer address.
    """
    peer = _canonical_ip(request.client.host if request.client else "")
    if peer is None:
        return ""
    peer_text = str(peer)

    try:
        networks = tuple(request.app.state.dashboard_trusted_proxy_networks or ())
    except (AttributeError, TypeError):
        networks = ()
    if not trusted_peer(request):
        return peer_text

    forwarded = request.headers.get("x-forwarded-for", "")
    if not forwarded:
        return peer_text
    if len(forwarded.encode("utf-8", errors="replace")) > _MAX_FORWARDED_FOR_BYTES:
        return peer_text

    parts = forwarded.split(",")
    if not parts or len(parts) > _MAX_FORWARDED_HOPS:
        return peer_text
    chain = [_canonical_ip(part) for part in parts]
    if any(address is None for address in chain):
        return peer_text

    parsed = [address for address in chain if address is not None]
    for address in reversed(parsed):
        if not _is_trusted(address, networks):
            return str(address)
    return str(parsed[0])
