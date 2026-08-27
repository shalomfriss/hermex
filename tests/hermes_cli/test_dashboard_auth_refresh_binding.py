"""Behavior tests for provider-scoped refresh-token ownership proofs."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys

from hermes_cli.dashboard_auth.refresh_binding import (
    mint_refresh_binding,
    resolve_refresh_owner,
    rotate_refresh_binding_key,
)


def test_binding_authenticates_provider_and_exact_refresh_token():
    binding = mint_refresh_binding(provider="owner", refresh_token="rt-one")

    assert resolve_refresh_owner(binding=binding, refresh_token="rt-one") == "owner"
    assert resolve_refresh_owner(binding=binding, refresh_token="rt-two") is None


def test_binding_rejects_mutable_provider_and_tampered_proof():
    binding = mint_refresh_binding(provider="owner", refresh_token="rt-one")
    parts = binding.split(".")
    parts[2] += "A"
    tampered = ".".join(parts)

    assert resolve_refresh_owner(binding="owner", refresh_token="rt-one") is None
    assert resolve_refresh_owner(binding=tampered, refresh_token="rt-one") is None


def test_empty_or_malformed_binding_fails_closed():
    assert mint_refresh_binding(provider="", refresh_token="rt") == ""
    assert mint_refresh_binding(provider="owner", refresh_token="") == ""
    assert resolve_refresh_owner(binding=None, refresh_token="rt") is None
    assert resolve_refresh_owner(binding="not-a-proof", refresh_token="rt") is None


def test_key_rotation_keeps_one_retired_generation_then_retires_it():
    first = mint_refresh_binding(provider="owner", refresh_token="rt-one")

    assert rotate_refresh_binding_key() is True
    second = mint_refresh_binding(provider="owner", refresh_token="rt-two")
    assert resolve_refresh_owner(binding=first, refresh_token="rt-one") == "owner"
    assert resolve_refresh_owner(binding=second, refresh_token="rt-two") == "owner"

    assert rotate_refresh_binding_key() is True
    third = mint_refresh_binding(provider="owner", refresh_token="rt-three")
    assert resolve_refresh_owner(binding=first, refresh_token="rt-one") is None
    assert resolve_refresh_owner(binding=second, refresh_token="rt-two") == "owner"
    assert resolve_refresh_owner(binding=third, refresh_token="rt-three") == "owner"


def test_corrupt_key_state_fails_closed_without_overwrite(tmp_path, monkeypatch):
    home = tmp_path / "profile"
    monkeypatch.setenv("HERMES_HOME", str(home))
    key_path = home / "secrets" / "dashboard_refresh_binding_keys.json"
    key_path.parent.mkdir(parents=True)
    corrupt = b'{"version":1,"active_key_id":"missing"}'
    key_path.write_bytes(corrupt)
    if os.name == "posix":
        key_path.chmod(0o600)

    assert mint_refresh_binding(provider="owner", refresh_token="rt") == ""
    assert (
        resolve_refresh_owner(binding="v2.unknown.payload", refresh_token="rt") is None
    )
    assert rotate_refresh_binding_key() is False
    assert key_path.read_bytes() == corrupt


def test_insecure_key_state_fails_closed_without_repair(tmp_path, monkeypatch):
    if os.name != "posix":
        return
    home = tmp_path / "profile"
    monkeypatch.setenv("HERMES_HOME", str(home))
    binding = mint_refresh_binding(provider="owner", refresh_token="rt")
    key_path = home / "secrets" / "dashboard_refresh_binding_keys.json"
    original = key_path.read_bytes()
    key_path.chmod(0o644)

    assert mint_refresh_binding(provider="owner", refresh_token="rt-two") == ""
    assert resolve_refresh_owner(binding=binding, refresh_token="rt") is None
    assert rotate_refresh_binding_key() is False
    assert key_path.read_bytes() == original
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o644


def test_symlinked_key_state_fails_closed_without_touching_target(
    tmp_path, monkeypatch
):
    source_home = tmp_path / "source-profile"
    monkeypatch.setenv("HERMES_HOME", str(source_home))
    binding = mint_refresh_binding(provider="owner", refresh_token="rt")
    source_key = source_home / "secrets" / "dashboard_refresh_binding_keys.json"
    original = source_key.read_bytes()

    linked_home = tmp_path / "linked-profile"
    linked_key = linked_home / "secrets" / "dashboard_refresh_binding_keys.json"
    linked_key.parent.mkdir(parents=True)
    linked_key.symlink_to(source_key)
    monkeypatch.setenv("HERMES_HOME", str(linked_home))

    assert mint_refresh_binding(provider="owner", refresh_token="rt-two") == ""
    assert resolve_refresh_owner(binding=binding, refresh_token="rt") is None
    assert rotate_refresh_binding_key() is False
    assert linked_key.is_symlink()
    assert source_key.read_bytes() == original


def test_browser_and_desktop_refresh_survive_real_gateway_restart(tmp_path):
    """A second interpreter can refresh/revoke pre-restart browser/Desktop state."""
    home = tmp_path / "profile"
    env = {**os.environ, "HERMES_HOME": str(home)}
    mint_script = """
import json, time
from hermes_cli.dashboard_auth.refresh_binding import mint_refresh_binding
from tests.hermes_cli.conftest_dashboard_auth import _sign
now = int(time.time())
refresh = _sign({'sub':'stub-user-1','kind':'refresh','exp':now + 86400})
access = _sign({'sub':'stub-user-1','email':'stub@example.test','name':'Stub User','org_id':'stub-org-1','exp':now + 3600})
expired = _sign({'sub':'stub-user-1','email':'stub@example.test','name':'Stub User','org_id':'stub-org-1','exp':now - 1})
print(json.dumps({'refresh': refresh, 'access': access, 'expired': expired,
                  'binding': mint_refresh_binding(provider='stub', refresh_token=refresh)}))
"""
    minted = subprocess.run(
        [sys.executable, "-c", mint_script],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    tokens = json.loads(minted.stdout)

    restart_script = """
import json, sys
from fastapi.testclient import TestClient
from hermes_cli import web_server
from hermes_cli.dashboard_auth import clear_providers, register_provider
from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider
tokens = json.loads(sys.stdin.read())
clear_providers(); register_provider(StubAuthProvider())
web_server.app.state.bound_host = 'fly-app.fly.dev'
web_server.app.state.bound_port = 443
web_server.app.state.auth_required = True
client = TestClient(web_server.app, base_url='https://fly-app.fly.dev', follow_redirects=False)
client.cookies.set('__Host-hermes_session_at', tokens['expired'], path='/')
client.cookies.set('__Host-hermes_session_rt', tokens['refresh'], path='/')
client.cookies.set('__Host-hermes_session_provider', tokens['binding'], path='/')
browser = client.get('/api/auth/me')
native = client.post('/auth/native/refresh', json={
    'access_token': tokens['access'], 'refresh_token': tokens['refresh'],
    'refresh_binding': tokens['binding'], 'provider': 'attacker'})
rotated = native.json()
revoke = client.post('/api/auth/native/revoke',
    headers={'Authorization': 'Bearer ' + rotated.get('access_token', '')},
    json={'refresh_token': rotated.get('refresh_token', ''),
          'refresh_binding': rotated.get('refresh_binding', ''),
          'provider': 'attacker', 'user_id': 'stub-user-1'})
print(json.dumps({'browser': browser.status_code, 'native': native.status_code,
                  'revoke': revoke.status_code, 'revoked': revoke.json().get('revoked')}))
"""
    restarted = subprocess.run(
        [sys.executable, "-c", restart_script],
        input=json.dumps(tokens),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )

    assert json.loads(restarted.stdout) == {
        "browser": 200,
        "native": 200,
        "revoke": 200,
        "revoked": True,
    }
    key_path = home / "secrets" / "dashboard_refresh_binding_keys.json"
    if os.name == "posix":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert len(json.loads(key_path.read_text())["keys"]) == 1
