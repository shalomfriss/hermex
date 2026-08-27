"""Tests for the WS-upgrade ticket store (Phase 5 task 5.1).

The store is process-local and threading-safe. Tests run with xdist so
each worker has its own module instance — no cross-worker bleed — but we
call ``_reset_for_tests`` between tests to keep things deterministic.
"""

from __future__ import annotations

import subprocess
import sys
import threading

import pytest

from hermes_cli.dashboard_auth import ws_tickets
from hermes_cli.dashboard_auth.ws_tickets import (
    TTL_SECONDS,
    TicketInvalid,
    _reset_for_tests,
    consume_ticket,
    mint_ticket,
)


@pytest.fixture(autouse=True)
def _reset():
    _reset_for_tests()
    yield
    _reset_for_tests()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestMintAndConsume:
    def test_round_trip(self):
        ticket = mint_ticket(user_id="u1", provider="nous")
        info = consume_ticket(ticket)
        assert info["user_id"] == "u1"
        assert info["provider"] == "nous"
        assert "minted_at" in info

    def test_ticket_has_minimum_length(self):
        # ``secrets.token_urlsafe(32)`` produces ~43 chars; enforce a floor
        # so a future refactor can't accidentally shrink the entropy.
        ticket = mint_ticket(user_id="u1", provider="nous")
        assert len(ticket) >= 32


# ---------------------------------------------------------------------------
# Single-use
# ---------------------------------------------------------------------------


class TestSingleUse:
    def test_second_consume_raises(self):
        ticket = mint_ticket(user_id="u1", provider="stub")
        consume_ticket(ticket)
        with pytest.raises(TicketInvalid, match="unknown"):
            consume_ticket(ticket)

    def test_unknown_ticket_rejected(self):
        with pytest.raises(TicketInvalid, match="unknown"):
            consume_ticket("nope-never-minted")


# ---------------------------------------------------------------------------
# TTL
# ---------------------------------------------------------------------------


class TestTTL:
    def test_constant_is_30_seconds(self):
        # Pinned so a refactor that doubled the lifetime would surface here.
        assert TTL_SECONDS == 30

    def test_expired_ticket_rejected(self, monkeypatch):
        # Mock the store's monotonic clock so mint and consume see different
        # instants without relying on wall-clock adjustments.
        clock = {"now": 1_000_000}

        def fake_time():
            return clock["now"]

        monkeypatch.setattr(ws_tickets, "_clock", fake_time)

        ticket = mint_ticket(user_id="u1", provider="stub")
        clock["now"] += TTL_SECONDS + 1
        with pytest.raises(TicketInvalid, match="expired"):
            consume_ticket(ticket)

    def test_ticket_expires_at_ttl_boundary(self, monkeypatch):
        clock = {"now": 1_000_000}
        monkeypatch.setattr(ws_tickets, "_clock", lambda: clock["now"])

        ticket = mint_ticket(user_id="u1", provider="stub")
        clock["now"] += TTL_SECONDS

        with pytest.raises(TicketInvalid, match="expired"):
            consume_ticket(ticket)

    def test_consume_checks_expiry_after_acquiring_store_lock(self, monkeypatch):
        clock = {"now": 0}
        monkeypatch.setattr(ws_tickets, "_clock", lambda: clock["now"])
        ticket = mint_ticket(user_id="u1", provider="stub")
        clock["now"] = TTL_SECONDS - 1

        class _AdvanceClockOnEnter:
            def __init__(self):
                self._lock = threading.Lock()

            def __enter__(self):
                self._lock.acquire()
                clock["now"] = TTL_SECONDS

            def __exit__(self, *_args):
                self._lock.release()

        monkeypatch.setattr(ws_tickets, "_lock", _AdvanceClockOnEnter())

        with pytest.raises(TicketInvalid, match="expired"):
            consume_ticket(ticket)


class TestCapacity:
    def test_global_saturation_rejects_without_evicting_live_tickets(
        self, monkeypatch
    ):
        monkeypatch.setattr(ws_tickets, "MAX_ACTIVE_TICKETS", 2)
        first = mint_ticket(user_id="u1", provider="stub", client_ip="192.0.2.1")
        second = mint_ticket(user_id="u2", provider="stub", client_ip="192.0.2.2")

        with pytest.raises(ws_tickets.TicketCapacityExceeded):
            mint_ticket(user_id="u3", provider="stub", client_ip="192.0.2.3")

        assert consume_ticket(first)["user_id"] == "u1"
        assert consume_ticket(second)["user_id"] == "u2"

    def test_expiry_recovers_global_capacity(self, monkeypatch):
        clock = {"now": 1_000}
        monkeypatch.setattr(ws_tickets, "_clock", lambda: clock["now"])
        monkeypatch.setattr(ws_tickets, "MAX_ACTIVE_TICKETS", 1)
        first = mint_ticket(user_id="u1", provider="stub")

        clock["now"] += TTL_SECONDS
        second = mint_ticket(user_id="u2", provider="stub")

        with pytest.raises(TicketInvalid, match="unknown"):
            consume_ticket(first)
        assert consume_ticket(second)["user_id"] == "u2"


class TestIssuanceThrottles:
    def test_principal_burst_is_bounded_even_after_each_ticket_is_consumed(
        self, monkeypatch
    ):
        monkeypatch.setattr(ws_tickets, "MAX_ISSUES_PER_PRINCIPAL", 2)
        for _ in range(2):
            ticket = mint_ticket(
                user_id="same-user", provider="stub", client_ip="192.0.2.10"
            )
            consume_ticket(ticket)

        with pytest.raises(ws_tickets.TicketRateLimited):
            mint_ticket(
                user_id="same-user", provider="stub", client_ip="192.0.2.10"
            )

    def test_retry_after_tracks_the_bucket_that_was_limited(
        self, monkeypatch
    ):
        clock = {"now": 1_000}
        monkeypatch.setattr(ws_tickets, "_clock", lambda: clock["now"])
        monkeypatch.setattr(ws_tickets, "MAX_ISSUES_PER_PRINCIPAL", 1)
        mint_ticket(user_id="other", provider="stub", client_ip="192.0.2.1")
        clock["now"] += 10
        mint_ticket(user_id="target", provider="stub", client_ip="192.0.2.2")
        clock["now"] += 1

        with pytest.raises(ws_tickets.TicketRateLimited) as exc_info:
            mint_ticket(user_id="target", provider="stub", client_ip="192.0.2.2")

        assert exc_info.value.retry_after == ws_tickets.ISSUANCE_WINDOW_SECONDS - 1

    def test_canonical_provider_and_user_identity_share_one_bucket(
        self, monkeypatch
    ):
        monkeypatch.setattr(ws_tickets, "MAX_ISSUES_PER_PRINCIPAL", 2)
        for provider, user_id in ((" Stub ", " user-1 "), ("stub", "user-1")):
            ticket = mint_ticket(
                user_id=user_id, provider=provider, client_ip="192.0.2.10"
            )
            consume_ticket(ticket)

        with pytest.raises(ws_tickets.TicketRateLimited):
            mint_ticket(user_id="user-1", provider="STUB", client_ip="192.0.2.11")

        other_provider = mint_ticket(
            user_id="user-1", provider="other", client_ip="192.0.2.11"
        )
        assert consume_ticket(other_provider)["provider"] == "other"

    def test_equivalent_ip_spellings_share_one_bucket(self, monkeypatch):
        monkeypatch.setattr(ws_tickets, "MAX_ISSUES_PER_IP", 2)
        for user_id, address in (("u1", "192.0.2.10"), ("u2", "::ffff:192.0.2.10")):
            ticket = mint_ticket(
                user_id=user_id, provider="stub", client_ip=address
            )
            consume_ticket(ticket)

        with pytest.raises(ws_tickets.TicketRateLimited):
            mint_ticket(user_id="u3", provider="stub", client_ip="192.0.2.10")

    def test_global_issuance_saturation_recovers_at_window_boundary(
        self, monkeypatch
    ):
        clock = {"now": 1_000}
        monkeypatch.setattr(ws_tickets, "_clock", lambda: clock["now"])
        monkeypatch.setattr(ws_tickets, "MAX_ISSUES_PER_WINDOW", 2)
        for index in range(2):
            ticket = mint_ticket(
                user_id=f"u{index}",
                provider="stub",
                client_ip=f"192.0.2.{index + 1}",
            )
            consume_ticket(ticket)

        with pytest.raises(ws_tickets.TicketRateLimited):
            mint_ticket(user_id="u3", provider="stub", client_ip="192.0.2.3")

        clock["now"] += ws_tickets.ISSUANCE_WINDOW_SECONDS
        recovered = mint_ticket(
            user_id="u3", provider="stub", client_ip="192.0.2.3"
        )
        assert consume_ticket(recovered)["user_id"] == "u3"


# ---------------------------------------------------------------------------
# Truncated value in error message (secret hygiene)
# ---------------------------------------------------------------------------


class TestErrorMessages:
    def test_unknown_ticket_error_does_not_reflect_ticket_material(self):
        long_value = "a" * 100
        with pytest.raises(TicketInvalid) as exc_info:
            consume_ticket(long_value)
        message = str(exc_info.value)
        assert long_value not in message
        assert long_value[:8] not in message


# ---------------------------------------------------------------------------
# Thread safety: mint + consume from many threads doesn't deadlock or
# return duplicates.
# ---------------------------------------------------------------------------


class TestConcurrency:
    def test_mint_and_consume_concurrent(self):
        results: list[dict] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def worker(i: int):
            try:
                t = mint_ticket(user_id=f"u{i}", provider="stub")
                info = consume_ticket(t)
                with lock:
                    results.append(info)
            except Exception as exc:  # noqa: BLE001 — collect for assert
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
            assert not t.is_alive(), "thread deadlocked"

        assert errors == []
        assert len(results) == 20
        # Every consume returns a distinct user_id (no cross-thread bleed).
        assert {r["user_id"] for r in results} == {f"u{i}" for i in range(20)}

    def test_concurrent_redemption_has_exactly_one_winner(self):
        ticket = mint_ticket(user_id="winner", provider="stub")
        barrier = threading.Barrier(20)
        successes: list[dict] = []
        failures: list[Exception] = []
        result_lock = threading.Lock()

        def redeem():
            barrier.wait(timeout=5.0)
            try:
                result = consume_ticket(ticket)
                with result_lock:
                    successes.append(result)
            except TicketInvalid as exc:
                with result_lock:
                    failures.append(exc)

        threads = [threading.Thread(target=redeem) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5.0)
            assert not thread.is_alive(), "thread deadlocked"

        assert [result["user_id"] for result in successes] == ["winner"]
        assert len(failures) == 19


# ---------------------------------------------------------------------------
# Process-lifetime internal credential (server-spawned PTY child auth).
# Direct unit coverage for internal_ws_credential / consume_internal_credential
# — _ws_auth_ok exercises these indirectly, but the mint-once, unminted, and
# empty-value branches are only reachable via direct calls.
# ---------------------------------------------------------------------------


class TestInternalCredential:



    def test_reset_clears_and_remints(self):
        first = ws_tickets.internal_ws_credential()
        _reset_for_tests()
        # The old value no longer validates after reset.
        with pytest.raises(TicketInvalid):
            ws_tickets.consume_internal_credential(first)
        # A fresh mint produces a different value.
        second = ws_tickets.internal_ws_credential()
        assert second != first
        assert ws_tickets.consume_internal_credential(second)["user_id"] == (
            ws_tickets.INTERNAL_USER_ID
        )

    def test_independent_of_ticket_store(self):
        """The internal credential is not a ticket — minting tickets doesn't
        touch it, and consuming the credential doesn't consume tickets."""
        cred = ws_tickets.internal_ws_credential()
        ticket = mint_ticket(user_id="u1", provider="nous")
        # Consuming the internal credential leaves the ticket intact.
        ws_tickets.consume_internal_credential(cred)
        assert consume_ticket(ticket)["user_id"] == "u1"


class TestProcessRestart:
    def test_restart_invalidates_tickets_and_starts_with_empty_budgets(self):
        mint = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from hermes_cli.dashboard_auth.ws_tickets import mint_ticket; "
                    "print(mint_ticket(user_id='u1', provider='stub'))"
                ),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        ticket = mint.stdout.strip()

        restarted = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "from hermes_cli.dashboard_auth.ws_tickets import "
                    "TicketInvalid, consume_ticket, mint_ticket; "
                    "\ntry: consume_ticket(sys.argv[1])\n"
                    "except TicketInvalid: print('old-invalid')\n"
                    "else: raise SystemExit('old ticket survived restart')\n"
                    "replacement=mint_ticket(user_id='u1', provider='stub'); "
                    "print(consume_ticket(replacement)['user_id'])"
                ),
                ticket,
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        assert restarted.stdout.splitlines() == ["old-invalid", "u1"]
