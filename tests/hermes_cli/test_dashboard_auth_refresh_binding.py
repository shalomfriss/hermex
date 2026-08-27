"""Behavior tests for provider-scoped refresh-token ownership proofs."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import threading

import pytest

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


def test_keyring_publication_fsyncs_secret_directory(tmp_path, monkeypatch):
    """Creation and rotation durably publish their directory entries."""
    if os.name != "posix":
        pytest.skip("directory fsync is a POSIX durability contract")
    home = tmp_path / "profile"
    monkeypatch.setenv("HERMES_HOME", str(home))
    directory_fsyncs = []
    real_fsync = os.fsync

    def record_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", record_fsync)

    assert mint_refresh_binding(provider="owner", refresh_token="rt-one")
    assert rotate_refresh_binding_key() is True

    assert len(directory_fsyncs) == 2


def test_existing_keyring_resolves_from_read_only_secret_volume(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("mode-based read-only volume fixture is POSIX-only")
    home = tmp_path / "profile"
    monkeypatch.setenv("HERMES_HOME", str(home))
    binding = mint_refresh_binding(provider="owner", refresh_token="rt")
    secret_dir = home / "secrets"
    key_path = secret_dir / "dashboard_refresh_binding_keys.json"
    lock_path = secret_dir / "dashboard_refresh_binding_keys.lock"
    lock_path.unlink()
    key_path.chmod(0o400)
    secret_dir.chmod(0o500)

    try:
        assert resolve_refresh_owner(binding=binding, refresh_token="rt") == "owner"
        assert not lock_path.exists()
    finally:
        secret_dir.chmod(0o700)
        key_path.chmod(0o600)


def _windows_acl_principals(path):
    import win32security

    info = (
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION
    )
    descriptor = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, info
    )
    owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
    dacl = descriptor.GetSecurityDescriptorDacl()
    principals = {
        win32security.ConvertSidToStringSid(dacl.GetAce(index)[-1])
        for index in range(dacl.GetAceCount())
        if dacl.GetAce(index)[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE
        and dacl.GetAce(index)[1]
    }
    protected = bool(
        descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED
    )
    return owner, principals, protected


@pytest.mark.windows_only
def test_windows_keyring_and_lock_have_protected_owner_system_dacl(
    tmp_path, monkeypatch
):
    import win32api
    import win32con
    import win32security

    home = tmp_path / "shared-profile"
    monkeypatch.setenv("HERMES_HOME", str(home))
    assert mint_refresh_binding(provider="owner", refresh_token="rt")

    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
    )
    current = win32security.ConvertSidToStringSid(
        win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    )
    system = "S-1-5-18"
    for path in (
        home / "secrets" / "dashboard_refresh_binding_keys.json",
        home / "secrets" / "dashboard_refresh_binding_keys.lock",
    ):
        owner, principals, protected = _windows_acl_principals(path)
        assert owner == current
        assert principals == {current, system}
        assert protected is True


@pytest.mark.windows_only
@pytest.mark.parametrize("target", ["keyring", "lock"])
def test_windows_permissive_keyring_or_lock_acl_fails_closed(
    tmp_path, monkeypatch, target
):
    import ntsecuritycon
    import win32security

    home = tmp_path / f"shared-profile-{target}"
    monkeypatch.setenv("HERMES_HOME", str(home))
    binding = mint_refresh_binding(provider="owner", refresh_token="rt")
    key_path = home / "secrets" / "dashboard_refresh_binding_keys.json"
    lock_path = home / "secrets" / "dashboard_refresh_binding_keys.lock"
    everyone = win32security.ConvertStringSidToSid("S-1-1-0")
    path = key_path if target == "keyring" else lock_path

    descriptor = win32security.GetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
    )
    dacl = descriptor.GetSecurityDescriptorDacl()
    dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION, ntsecuritycon.FILE_GENERIC_READ, everyone
    )
    win32security.SetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )
    if target == "keyring":
        assert resolve_refresh_owner(binding=binding, refresh_token="rt") is None
    else:
        assert rotate_refresh_binding_key() is False


@pytest.mark.windows_only
def test_windows_incomplete_keyring_acl_fails_closed(tmp_path, monkeypatch):
    import ntsecuritycon
    import win32api
    import win32con
    import win32security

    home = tmp_path / "shared-profile-incomplete"
    monkeypatch.setenv("HERMES_HOME", str(home))
    binding = mint_refresh_binding(provider="owner", refresh_token="rt")
    key_path = home / "secrets" / "dashboard_refresh_binding_keys.json"
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
    )
    current = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    incomplete = win32security.ACL()
    incomplete.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        ntsecuritycon.FILE_GENERIC_READ | win32con.READ_CONTROL,
        current,
    )
    win32security.SetNamedSecurityInfo(
        str(key_path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        incomplete,
        None,
    )

    assert resolve_refresh_owner(binding=binding, refresh_token="rt") is None


@pytest.mark.windows_only
def test_windows_concurrent_rotations_acquire_and_release_secure_lock(
    tmp_path, monkeypatch
):
    home = tmp_path / "profile-locking"
    monkeypatch.setenv("HERMES_HOME", str(home))
    assert mint_refresh_binding(provider="owner", refresh_token="initial")
    barrier = threading.Barrier(3)
    results = []

    def rotate():
        barrier.wait()
        results.append(rotate_refresh_binding_key())

    writers = [threading.Thread(target=rotate) for _ in range(2)]
    for writer in writers:
        writer.start()
    barrier.wait()
    for writer in writers:
        writer.join()

    assert results == [True, True]
    binding = mint_refresh_binding(provider="owner", refresh_token="after")
    assert resolve_refresh_owner(binding=binding, refresh_token="after") == "owner"


@pytest.mark.windows_only
def test_windows_concurrent_rotation_never_exposes_partial_keyring(
    tmp_path, monkeypatch
):
    home = tmp_path / "profile"
    monkeypatch.setenv("HERMES_HOME", str(home))
    failures = []

    for generation in range(25):
        token = f"rt-{generation}"
        binding = mint_refresh_binding(provider="owner", refresh_token=token)
        barrier = threading.Barrier(9)

        def read_while_rotating():
            barrier.wait()
            for _ in range(100):
                if (
                    resolve_refresh_owner(binding=binding, refresh_token=token)
                    != "owner"
                ):
                    failures.append(generation)

        readers = [threading.Thread(target=read_while_rotating) for _ in range(8)]
        for reader in readers:
            reader.start()
        barrier.wait()
        assert rotate_refresh_binding_key() is True
        for reader in readers:
            reader.join()

    assert failures == []
