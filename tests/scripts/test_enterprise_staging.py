from __future__ import annotations

import json
import os
import plistlib
import tarfile
import urllib.error
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.enterprise_staging import (
    _probe,
    _maintenance_lock,
    _service_command,
    _validate_install_prerequisites,
    DeploymentConfig,
    activate_release,
    build_caddyfile,
    check,
    create_backup,
    read_secret_env,
    render_launchd_plists,
    restore_backup,
    start,
)


def config(tmp_path: Path) -> DeploymentConfig:
    state_root = tmp_path / "enterprise-staging"
    state_root.mkdir(mode=0o700, exist_ok=True)
    return DeploymentConfig(
        state_root=state_root,
        public_url="https://hermes-test.example.test",
        dashboard_python=Path("/opt/hermes/venv/bin/python"),
        keycloak_command=state_root / "keycloak" / "bin" / "kc.sh",
        caddy_command=Path("/opt/caddy"),
        ngrok_command=Path("/opt/ngrok"),
        dashboard_port=19138,
        proxy_port=19137,
        keycloak_port=18081,
        health_interval_seconds=60,
    )


def test_secret_env_requires_private_regular_file_and_allowlisted_names(tmp_path: Path):
    path = tmp_path / "keycloak.env"
    path.write_text("KC_BOOTSTRAP_ADMIN_PASSWORD=random-value\nKC_HTTP_ENABLED=true\n")
    path.chmod(0o600)

    assert read_secret_env(
        path, {"KC_BOOTSTRAP_ADMIN_PASSWORD", "KC_HTTP_ENABLED"}
    ) == {
        "KC_BOOTSTRAP_ADMIN_PASSWORD": "random-value",
        "KC_HTTP_ENABLED": "true",
    }

    path.chmod(0o644)
    with pytest.raises(PermissionError, match="0600"):
        read_secret_env(path, {"KC_BOOTSTRAP_ADMIN_PASSWORD", "KC_HTTP_ENABLED"})

    path.chmod(0o600)
    link = tmp_path / "linked.env"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="symlink"):
        read_secret_env(link, {"KC_BOOTSTRAP_ADMIN_PASSWORD", "KC_HTTP_ENABLED"})

    path.write_text("UNEXPECTED=value\n")
    with pytest.raises(ValueError, match="not allowed"):
        read_secret_env(path, {"KC_BOOTSTRAP_ADMIN_PASSWORD"})


def test_launchd_jobs_restart_services_without_embedding_secrets(tmp_path: Path):
    cfg = config(tmp_path)
    config_path = cfg.state_root / "deployment.json"
    config_path.write_text("{}")
    runner = cfg.state_root / "bin" / "enterprise-staging"

    rendered = render_launchd_plists(cfg, runner, config_path)

    assert set(rendered) == {"dashboard", "keycloak", "caddy", "ngrok", "monitor"}
    for service in ("dashboard", "keycloak", "caddy", "ngrok"):
        payload = plistlib.loads(rendered[service])
        assert payload["RunAtLoad"] is True
        assert payload["KeepAlive"] is True
        assert payload["ProcessType"] == "Interactive"
        assert payload["ThrottleInterval"] >= 10
        assert payload["ProgramArguments"] == [
            str(runner),
            "run-service",
            service,
            "--config",
            str(config_path),
        ]
        assert "EnvironmentVariables" not in payload
        assert "PASSWORD" not in rendered[service].decode()

    monitor = plistlib.loads(rendered["monitor"])
    assert monitor["StartInterval"] == 60
    assert monitor["RunAtLoad"] is True
    assert "KeepAlive" not in monitor


def test_caddy_routes_idp_and_dashboard_with_external_forwarding(tmp_path: Path):
    text = build_caddyfile(config(tmp_path))

    assert ":19137" in text
    assert "bind 127.0.0.1" in text
    assert "path /realms/* /resources/*" in text
    assert "reverse_proxy @keycloak 127.0.0.1:18081" in text
    assert "reverse_proxy 127.0.0.1:19138" in text
    assert "X-Forwarded-Proto https" in text
    assert "X-Forwarded-Host hermes-test.example.test" in text
    assert "header_down -Server" in text
    assert "auto_https off" in text


def test_keycloak_is_bound_to_loopback(tmp_path: Path):
    cfg = config(tmp_path)
    cfg.keycloak_secret_file.parent.mkdir(parents=True)
    cfg.keycloak_secret_file.write_text("KC_BOOTSTRAP_ADMIN_PASSWORD=random\n")
    cfg.keycloak_secret_file.chmod(0o600)

    command, _cwd, _env = _service_command(cfg, "keycloak")

    assert "--http-host=127.0.0.1" in command


def test_config_rejects_unsafe_public_url_and_port_collisions(tmp_path: Path):
    cfg = config(tmp_path)
    cfg.public_url = "http://public.example.test"
    with pytest.raises(ValueError, match="HTTPS"):
        cfg.validate()

    cfg = config(tmp_path)
    cfg.proxy_port = cfg.dashboard_port
    with pytest.raises(ValueError, match="distinct"):
        cfg.validate()


def test_release_activation_preserves_previous_target_for_rollback(tmp_path: Path):
    cfg = config(tmp_path)
    first = cfg.state_root / "releases" / "first"
    second = cfg.state_root / "releases" / "second"
    first.mkdir(parents=True)
    second.mkdir(parents=True)

    assert activate_release(cfg, first) is None
    assert cfg.active_release.resolve() == first.resolve()
    assert activate_release(cfg, second) == first.resolve()
    assert cfg.active_release.resolve() == second.resolve()
    assert cfg.previous_release.resolve() == first.resolve()


def test_backup_restore_roundtrip_is_private_and_excludes_logs(tmp_path: Path):
    cfg = config(tmp_path)
    home = cfg.hermes_home
    keycloak_data = cfg.keycloak_data
    home.mkdir(parents=True)
    keycloak_data.mkdir(parents=True)
    (home / "state.db").write_text("state-before")
    (home / "config.yaml").write_text("dashboard: {}\n")
    (home / "logs").mkdir()
    (home / "logs" / "dashboard-auth.log").write_text("do-not-back-up-logs")
    (keycloak_data / "realm.db").write_text("realm-before")

    backup = create_backup(cfg, cfg.state_root / "backups" / "snapshot.tar.gz")
    assert backup.stat().st_mode & 0o777 == 0o600

    (home / "state.db").write_text("state-after")
    (keycloak_data / "realm.db").write_text("realm-after")
    restore_backup(cfg, backup)

    assert (home / "state.db").read_text() == "state-before"
    assert (keycloak_data / "realm.db").read_text() == "realm-before"
    assert not (home / "logs" / "dashboard-auth.log").exists()


def test_backup_rejects_symlinks_in_secret_bearing_state(tmp_path: Path):
    cfg = config(tmp_path)
    cfg.hermes_home.mkdir(parents=True)
    cfg.keycloak_data.mkdir(parents=True)
    outside = tmp_path / "outside-secret"
    outside.write_text("must-not-enter-backup")
    (cfg.hermes_home / "linked-secret").symlink_to(outside)

    with pytest.raises(ValueError, match="symlink"):
        create_backup(cfg, cfg.state_root / "backups" / "snapshot.tar.gz")


def test_backup_refuses_while_a_managed_service_holds_the_runtime_lock(tmp_path: Path):
    cfg = config(tmp_path)
    cfg.hermes_home.mkdir(parents=True)
    cfg.keycloak_data.mkdir(parents=True)

    with _maintenance_lock(cfg, exclusive=False):
        with pytest.raises(RuntimeError, match="managed service is active"):
            create_backup(cfg, cfg.state_root / "backups" / "snapshot.tar.gz")


def test_restore_rejects_wrong_deployment_and_preserves_live_state(tmp_path: Path):
    cfg = config(tmp_path)
    cfg.hermes_home.mkdir(parents=True)
    cfg.keycloak_data.mkdir(parents=True)
    (cfg.hermes_home / "state.db").write_text("live-hermes")
    (cfg.keycloak_data / "realm.db").write_text("live-keycloak")
    backup = cfg.state_root / "backups" / "wrong-host.tar.gz"
    backup.parent.mkdir()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"format": 1, "public_host": "different.example.test"})
    )
    payload_home = tmp_path / "hermes-home"
    payload_keycloak = tmp_path / "keycloak-data"
    payload_home.mkdir()
    payload_keycloak.mkdir()
    with tarfile.open(backup, "w:gz") as archive:
        archive.add(manifest, arcname="manifest.json")
        archive.add(payload_home, arcname="hermes-home")
        archive.add(payload_keycloak, arcname="keycloak-data")

    with pytest.raises(ValueError, match="different deployment"):
        restore_backup(cfg, backup)

    assert (cfg.hermes_home / "state.db").read_text() == "live-hermes"
    assert (cfg.keycloak_data / "realm.db").read_text() == "live-keycloak"


def test_config_roundtrip_contains_no_secret_values(tmp_path: Path):
    cfg = config(tmp_path)
    payload = cfg.to_json()
    recovered = DeploymentConfig.from_json(payload)

    assert recovered == cfg
    serialized = json.dumps(json.loads(payload), sort_keys=True)
    assert "password" not in serialized.lower()
    assert "token" not in serialized.lower()
    assert str(cfg.keycloak_secret_file) not in serialized


def test_health_check_probes_a_real_built_frontend_asset(tmp_path: Path, monkeypatch):
    cfg = config(tmp_path)
    release = cfg.state_root / "releases" / "accepted"
    dist = release / "hermes_cli" / "web_dist"
    dist.mkdir(parents=True)
    (dist / "index.html").write_text(
        '<script type="module" src="/assets/index-accepted.js"></script>'
    )
    activate_release(cfg, release)
    urls: list[str] = []

    def fake_probe(url: str, expected=(200,)):
        urls.append(url)
        return {"ok": True, "status": next(iter(expected)), "bytes": 1}

    monkeypatch.setattr("scripts.enterprise_staging._probe", fake_probe)

    payload = check(cfg)

    assert payload["ok"] is True
    assert "https://hermes-test.example.test/assets/index-accepted.js" in urls
    checks = payload["checks"]
    assert isinstance(checks, dict)
    assert checks["public_frontend_asset"]["ok"] is True


def test_start_reloads_plists_before_kickstart(tmp_path: Path, monkeypatch):
    cfg = config(tmp_path)
    launch_dir = tmp_path / "LaunchAgents"
    launch_dir.mkdir()
    for service in ("keycloak", "dashboard", "caddy", "ngrok", "monitor"):
        (launch_dir / f"ai.hermes.enterprise-staging.{service}.plist").write_text(
            "plist"
        )
    calls: list[tuple[str, ...]] = []

    def fake_launchctl(*args, check_result=True):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "scripts.enterprise_staging._launch_agent_dir", lambda: launch_dir
    )
    monkeypatch.setattr("scripts.enterprise_staging._launchctl", fake_launchctl)

    start(cfg)

    for service in ("keycloak", "dashboard", "caddy", "ngrok", "monitor"):
        label = f"gui/{os.getuid()}/ai.hermes.enterprise-staging.{service}"
        bootout = calls.index(("bootout", label))
        bootstrap = calls.index((
            "bootstrap",
            f"gui/{os.getuid()}",
            str(launch_dir / f"ai.hermes.enterprise-staging.{service}.plist"),
        ))
        kickstart = calls.index(("kickstart", "-k", label))
        assert bootout < bootstrap < kickstart


def test_install_prerequisites_require_active_release_and_state(tmp_path: Path):
    cfg = config(tmp_path)

    with pytest.raises(RuntimeError, match="active release"):
        _validate_install_prerequisites(cfg)


def test_service_environment_does_not_inherit_unrelated_secrets(
    tmp_path: Path, monkeypatch
):
    cfg = config(tmp_path)
    monkeypatch.setenv("UNRELATED_API_SECRET", "must-not-reach-child")
    monkeypatch.setattr("scripts.enterprise_staging._wait_url", lambda *a, **k: None)

    _command, _cwd, env = _service_command(cfg, "caddy")

    assert "UNRELATED_API_SECRET" not in env
    assert env.get("HOME") == os.environ.get("HOME")


def test_probe_does_not_follow_redirects(monkeypatch):
    headers = Message()
    headers["Location"] = "https://unrelated.example.test/healthy"

    class RedirectingOpener:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(
                request.full_url,
                302,
                "Found",
                headers,
                None,
            )

    monkeypatch.setattr(
        "scripts.enterprise_staging._NO_REDIRECT_OPENER", RedirectingOpener()
    )

    assert _probe("https://hermes-test.example.test/api/health") == {
        "ok": False,
        "status": 302,
        "bytes": 0,
    }
