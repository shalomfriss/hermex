"""Audit log for dashboard-auth events.

Profile-aware location: ``$HERMES_HOME/logs/dashboard-auth.log``.
Format: one JSON object per line. Token-like kwargs are dropped before
serialisation so we never leak refresh tokens or JWTs to disk.
"""
from __future__ import annotations

import errno
import json
import os
import stat
import pytest

from hermes_cli.dashboard_auth import audit
from hermes_cli.dashboard_auth.audit import audit_log, AuditEvent


@pytest.fixture
def profile_home(tmp_path, monkeypatch):
    """Redirect $HERMES_HOME and ~ to a tmp dir for the duration of the test."""
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    # Some code paths fall back to Path.home() — patch that too.
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    return home


def test_audit_writes_jsonlines(profile_home):
    audit_log(AuditEvent.LOGIN_START, provider="nous", ip="1.2.3.4")
    audit_log(
        AuditEvent.LOGIN_SUCCESS,
        provider="nous", user_id="u1",
        email="a@b.com", ip="1.2.3.4",
    )

    path = profile_home / "logs" / "dashboard-auth.log"
    assert path.exists(), f"audit log not created at {path}"
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 2

    second = json.loads(lines[1])
    assert second["event"] == "login_success"
    assert second["provider"] == "nous"
    assert second["user_id"] == "u1"
    assert second["email"] == "a@b.com"
    assert "ts" in second  # ISO-8601 timestamp


def test_audit_redacts_token_like_fields(profile_home):
    audit_log(
        AuditEvent.ACCESS_DENIED,
        provider="nous", access_token="should-not-appear",
        refresh_token="also-not", code="not-this", state="nope",
        nonce="not-a-nonce", raw_claims="not-claims",
        client_secret="not-a-secret", reason="group_required",
    )
    raw = (profile_home / "logs" / "dashboard-auth.log").read_text()
    for forbidden in (
        "should-not-appear", "also-not", "not-this", "nope",
        "not-a-nonce", "not-claims", "not-a-secret",
    ):
        assert forbidden not in raw, f"token-like value leaked into audit log: {forbidden}"
    entry = json.loads(raw)
    assert entry["event"] == "access_denied"
    assert entry["reason"] == "group_required"


def test_audit_log_is_owner_only_even_with_permissive_umask(profile_home):
    previous = os.umask(0)
    try:
        audit_log(AuditEvent.LOGIN_FAILURE, reason="denied")
    finally:
        os.umask(previous)

    path = profile_home / "logs" / "dashboard-auth.log"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_audit_rotates_before_exceeding_bound_and_caps_retention(
    profile_home, monkeypatch
):
    monkeypatch.setattr(audit, "MAX_LOG_BYTES", 220)
    monkeypatch.setattr(audit, "BACKUP_COUNT", 2)

    for index in range(20):
        audit_log(AuditEvent.LOGIN_FAILURE, reason="x" * 40, attempt=index)

    log_dir = profile_home / "logs"
    files = sorted(log_dir.glob("dashboard-auth.log*"))
    assert [path.name for path in files] == [
        "dashboard-auth.log",
        "dashboard-auth.log.1",
        "dashboard-auth.log.2",
    ]
    assert all(path.stat().st_size <= audit.MAX_LOG_BYTES for path in files)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in files)


def test_audit_caps_a_single_attacker_controlled_record(profile_home, monkeypatch):
    monkeypatch.setattr(audit, "MAX_LOG_BYTES", 220)
    audit_log(AuditEvent.LOGIN_FAILURE, reason="attacker" * 10_000)

    path = profile_home / "logs" / "dashboard-auth.log"
    assert path.stat().st_size <= audit.MAX_LOG_BYTES
    assert json.loads(path.read_text())["truncated"] is True


def test_audit_disk_pressure_never_breaks_auth_and_throttles_warning(
    profile_home, monkeypatch, caplog
):
    def disk_full(*_args, **_kwargs):
        raise OSError(errno.ENOSPC, "disk full")

    monkeypatch.setattr(audit.os, "write", disk_full)
    monkeypatch.setattr(audit, "_last_write_warning_at", 0.0)
    caplog.set_level("WARNING")

    audit_log(AuditEvent.LOGIN_FAILURE, reason="first")
    audit_log(AuditEvent.LOGIN_FAILURE, reason="second")

    warnings = [r for r in caplog.records if "audit log write failed" in r.message]
    assert len(warnings) == 1


def test_audit_recursively_redacts_case_insensitive_secret_fields(profile_home):
    audit_log(
        AuditEvent.LOGIN_FAILURE,
        ID_TOKEN="header.payload.signature",
        details={
            "client_secret": "client-secret-value",
            "nested": {
                "Password": "password-value",
                "accessToken": "camel-token-value",
                "refresh-token": "hyphen-token-value",
                "clientSecret": "camel-secret-value",
                "reason": "denied",
            },
        },
    )

    raw = (profile_home / "logs" / "dashboard-auth.log").read_text()
    for forbidden in (
        "header.payload.signature",
        "client-secret-value",
        "password-value",
        "camel-token-value",
        "hyphen-token-value",
        "camel-secret-value",
    ):
        assert forbidden not in raw
    assert json.loads(raw)["details"]["nested"]["reason"] == "denied"


