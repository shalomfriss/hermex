#!/usr/bin/env python3
"""Supervise the disposable enterprise dashboard evaluation stack on macOS.

The script deliberately keeps credentials out of argv, launchd plists, the
non-secret deployment JSON, and normal status output. Runtime credentials live
in mode-0600 files below ``state_root/secrets`` and are read only by the service
wrapper that needs them.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import fcntl
import io
import json
import logging
import logging.handlers
import os
import plistlib
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable

_LABEL_PREFIX = "ai.hermes.enterprise-staging"
_SERVICES = ("keycloak", "dashboard", "caddy", "ngrok")
_KEYCLOAK_ENV_NAMES = {
    "KC_BOOTSTRAP_ADMIN_USERNAME",
    "KC_BOOTSTRAP_ADMIN_PASSWORD",
    "KC_HOSTNAME",
    "KC_HTTP_ENABLED",
    "KC_PROXY_HEADERS",
}
_NGROK_ENV_NAMES = {"NGROK_AUTHTOKEN"}
_SAFE_AMBIENT_ENV_NAMES = {
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TMPDIR",
}


@dataclasses.dataclass
class DeploymentConfig:
    state_root: Path
    public_url: str
    dashboard_python: Path
    keycloak_command: Path
    caddy_command: Path
    ngrok_command: Path
    dashboard_port: int = 9138
    proxy_port: int = 9137
    keycloak_port: int = 8081
    health_interval_seconds: int = 60

    @property
    def active_release(self) -> Path:
        return self.state_root / "current"

    @property
    def previous_release(self) -> Path:
        return self.state_root / "previous"

    @property
    def hermes_home(self) -> Path:
        return self.state_root / "hermes-home"

    @property
    def keycloak_home(self) -> Path:
        return self.keycloak_command.parent.parent

    @property
    def keycloak_data(self) -> Path:
        return self.keycloak_home / "data"

    @property
    def keycloak_secret_file(self) -> Path:
        return self.state_root / "secrets" / "keycloak.env"

    @property
    def ngrok_secret_file(self) -> Path:
        return self.state_root / "secrets" / "ngrok.env"

    @property
    def logs_dir(self) -> Path:
        return self.state_root / "logs"

    @property
    def caddyfile(self) -> Path:
        return self.state_root / "Caddyfile"

    def validate(self) -> None:
        parsed = urllib.parse.urlsplit(self.public_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("public_url must be an absolute HTTPS URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError(
                "public_url must not contain credentials, query, or fragment"
            )
        ports = {self.dashboard_port, self.proxy_port, self.keycloak_port}
        if len(ports) != 3:
            raise ValueError("dashboard, proxy, and Keycloak ports must be distinct")
        if any(port < 1024 or port > 65535 for port in ports):
            raise ValueError("service ports must be unprivileged TCP ports")
        if self.health_interval_seconds < 15:
            raise ValueError("health interval must be at least 15 seconds")
        for value in (
            self.state_root,
            self.dashboard_python,
            self.keycloak_command,
            self.caddy_command,
            self.ngrok_command,
        ):
            if not value.is_absolute():
                raise ValueError(f"deployment paths must be absolute: {value}")

    def to_json(self) -> str:
        self.validate()
        payload = {
            "state_root": str(self.state_root),
            "public_url": self.public_url.rstrip("/"),
            "dashboard_python": str(self.dashboard_python),
            "keycloak_command": str(self.keycloak_command),
            "caddy_command": str(self.caddy_command),
            "ngrok_command": str(self.ngrok_command),
            "dashboard_port": self.dashboard_port,
            "proxy_port": self.proxy_port,
            "keycloak_port": self.keycloak_port,
            "health_interval_seconds": self.health_interval_seconds,
        }
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str) -> "DeploymentConfig":
        raw = json.loads(text)
        cfg = cls(
            state_root=Path(raw["state_root"]),
            public_url=str(raw["public_url"]).rstrip("/"),
            dashboard_python=Path(raw["dashboard_python"]),
            keycloak_command=Path(raw["keycloak_command"]),
            caddy_command=Path(raw["caddy_command"]),
            ngrok_command=Path(raw["ngrok_command"]),
            dashboard_port=int(raw.get("dashboard_port", 9138)),
            proxy_port=int(raw.get("proxy_port", 9137)),
            keycloak_port=int(raw.get("keycloak_port", 8081)),
            health_interval_seconds=int(raw.get("health_interval_seconds", 60)),
        )
        cfg.validate()
        return cfg


def load_config(path: Path) -> DeploymentConfig:
    return DeploymentConfig.from_json(path.read_text(encoding="utf-8"))


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def read_secret_env(path: Path, allowed_names: set[str]) -> dict[str, str]:
    if path.is_symlink():
        raise ValueError(f"secret file must not be a symlink: {path}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"secret path must be a regular file: {path}")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise PermissionError(f"secret file must have mode 0600: {path}")
    result: dict[str, str] = {}
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"malformed secret file line {number}")
        name, value = line.split("=", 1)
        if name not in allowed_names:
            raise ValueError(f"secret name is not allowed for this service: {name}")
        if not value or "\x00" in value:
            raise ValueError(f"secret value is empty or invalid on line {number}")
        result[name] = value
    return result


def build_caddyfile(cfg: DeploymentConfig) -> str:
    cfg.validate()
    host = urllib.parse.urlsplit(cfg.public_url).hostname
    return f"""{{
    admin off
    auto_https off
}}

:{cfg.proxy_port} {{
    bind 127.0.0.1

    log {{
        output discard
    }}

    @keycloak path /realms/* /resources/*
    reverse_proxy @keycloak 127.0.0.1:{cfg.keycloak_port} {{
        header_up Host {host}
        header_up X-Forwarded-Host {host}
        header_up X-Forwarded-Proto https
        header_up X-Forwarded-Port 443
        header_down -Server
    }}

    reverse_proxy 127.0.0.1:{cfg.dashboard_port} {{
        header_up Host {host}
        header_up X-Forwarded-Host {host}
        header_up X-Forwarded-Proto https
        header_up X-Forwarded-Port 443
        header_down -Server
        flush_interval -1
    }}
}}
"""


def _plist(label: str, arguments: list[str], *, interval: int | None = None) -> bytes:
    payload: dict[str, object] = {
        "Label": label,
        "ProgramArguments": arguments,
        "RunAtLoad": True,
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
        "LimitLoadToSessionType": "Aqua",
    }
    if interval is None:
        payload.update({
            "KeepAlive": True,
            "ProcessType": "Interactive",
            "ThrottleInterval": 10,
            "SoftResourceLimits": {"NumberOfFiles": 65536},
        })
    else:
        payload["StartInterval"] = interval
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True)


def render_launchd_plists(
    cfg: DeploymentConfig, runner: Path, config_path: Path
) -> dict[str, bytes]:
    cfg.validate()
    rendered = {
        service: _plist(
            f"{_LABEL_PREFIX}.{service}",
            [str(runner), "run-service", service, "--config", str(config_path)],
        )
        for service in _SERVICES
    }
    rendered["monitor"] = _plist(
        f"{_LABEL_PREFIX}.monitor",
        [str(runner), "check", "--config", str(config_path), "--write-status"],
        interval=cfg.health_interval_seconds,
    )
    return rendered


def _replace_symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = link.with_name(f".{link.name}.{os.getpid()}.tmp")
    try:
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(target)
        os.replace(temporary, link)
    finally:
        temporary.unlink(missing_ok=True)


def activate_release(cfg: DeploymentConfig, release: Path) -> Path | None:
    cfg.validate()
    resolved = release.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("release must be a directory")
    releases_root = (cfg.state_root / "releases").resolve()
    if resolved != releases_root and releases_root not in resolved.parents:
        raise ValueError("release must be below state_root/releases")
    prior = cfg.active_release.resolve() if cfg.active_release.exists() else None
    if prior and prior != resolved:
        _replace_symlink(cfg.previous_release, prior)
    _replace_symlink(cfg.active_release, resolved)
    return prior


def _backup_filter(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return not relative.parts or relative.parts[0] not in {
        "logs",
        "cache",
        "skills",
        "audio_cache",
    }


def _private_tarinfo(info: tarfile.TarInfo) -> tarfile.TarInfo:
    if info.issym() or info.islnk():
        raise ValueError(f"backup source must not contain symlinks: {info.name}")
    if info.isdev():
        raise ValueError(f"backup source must not contain devices: {info.name}")
    info.mode = 0o700 if info.isdir() else 0o600
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _assert_services_stopped(cfg: DeploymentConfig) -> None:
    listening: list[int] = []
    for port in (cfg.dashboard_port, cfg.proxy_port, cfg.keycloak_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                listening.append(port)
    if listening:
        joined = ", ".join(str(port) for port in listening)
        raise RuntimeError(
            f"backup/restore requires a stopped stack; ports still listening: {joined}"
        )


@contextlib.contextmanager
def _maintenance_lock(cfg: DeploymentConfig, *, exclusive: bool):
    cfg.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = cfg.state_root / "maintenance.lock"
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.chmod(path, 0o600)
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    try:
        try:
            fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            message = (
                "managed service is active; stop the stack before backup/restore"
                if exclusive
                else "staging maintenance is active; service start deferred"
            )
            raise RuntimeError(message) from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _create_backup_locked(cfg: DeploymentConfig, destination: Path) -> Path:
    cfg.validate()
    _assert_services_stopped(cfg)
    for required in (cfg.hermes_home, cfg.keycloak_data):
        if not required.is_dir():
            raise RuntimeError(
                f"cannot create complete backup; missing state: {required}"
            )
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(
        prefix=".backup.", suffix=".tar.gz", dir=destination.parent
    )
    os.close(fd)
    try:
        with tarfile.open(temporary, "w:gz") as archive:
            manifest = json.dumps(
                {
                    "format": 1,
                    "created_at": int(time.time()),
                    "public_host": urllib.parse.urlsplit(cfg.public_url).hostname,
                },
                sort_keys=True,
            ).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest)
            info.mode = 0o600
            archive.addfile(_private_tarinfo(info), io.BytesIO(manifest))
            archive.add(
                cfg.hermes_home,
                arcname="hermes-home",
                recursive=False,
                filter=_private_tarinfo,
            )
            for path in sorted(cfg.hermes_home.rglob("*")):
                if _backup_filter(path, cfg.hermes_home):
                    archive.add(
                        path,
                        arcname=Path("hermes-home") / path.relative_to(cfg.hermes_home),
                        recursive=False,
                        filter=_private_tarinfo,
                    )
            archive.add(
                cfg.keycloak_data,
                arcname="keycloak-data",
                recursive=True,
                filter=_private_tarinfo,
            )
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return destination


def create_backup(cfg: DeploymentConfig, destination: Path) -> Path:
    with _maintenance_lock(cfg, exclusive=True):
        return _create_backup_locked(cfg, destination)


def _validate_archive(archive: tarfile.TarFile, cfg: DeploymentConfig) -> None:
    members = archive.getmembers()
    names = [member.name.rstrip("/") for member in members]
    if len(names) != len(set(names)):
        raise ValueError("backup contains duplicate members")
    by_name = {member.name.rstrip("/"): member for member in members}
    manifest_member = by_name.get("manifest.json")
    if not manifest_member or not manifest_member.isfile():
        raise ValueError("backup is missing a regular manifest.json")
    manifest_handle = archive.extractfile(manifest_member)
    if manifest_handle is None:
        raise ValueError("backup manifest cannot be read")
    try:
        manifest = json.loads(manifest_handle.read(4096))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("backup manifest is invalid") from exc
    expected_host = urllib.parse.urlsplit(cfg.public_url).hostname
    if manifest.get("format") != 1:
        raise ValueError("backup format is unsupported")
    if manifest.get("public_host") != expected_host:
        raise ValueError("backup belongs to a different deployment")
    for root in ("hermes-home", "keycloak-data"):
        member = by_name.get(root)
        if not member or not member.isdir():
            raise ValueError(f"backup is missing required directory {root}")
    for member in members:
        path = Path(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"unsafe backup member: {member.name}")
        if member.issym() or member.islnk() or member.isdev():
            raise ValueError(f"unsupported backup member: {member.name}")
        if stat.S_IMODE(member.mode) & 0o077:
            raise ValueError(f"backup member has unsafe permissions: {member.name}")
        if path.parts and path.parts[0] not in {
            "manifest.json",
            "hermes-home",
            "keycloak-data",
        }:
            raise ValueError(f"unexpected backup member: {member.name}")


def _make_private(root: Path) -> None:
    for path in [root, *root.rglob("*")]:
        if path.is_symlink():
            raise ValueError(f"restored state contains a symlink: {path}")
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


def _restore_backup_locked(cfg: DeploymentConfig, source: Path) -> None:
    cfg.validate()
    _assert_services_stopped(cfg)
    staging = Path(tempfile.mkdtemp(prefix=".restore.", dir=cfg.state_root))
    originals = cfg.state_root / f".restore-original.{os.getpid()}"
    destinations: tuple[tuple[Path, Path, Path], ...] = ()
    installed: list[Path] = []
    try:
        with tarfile.open(source, "r:gz") as archive:
            _validate_archive(archive, cfg)
            archive.extractall(staging, filter="data")
        restored_home = staging / "hermes-home"
        restored_keycloak = staging / "keycloak-data"
        _make_private(restored_home)
        _make_private(restored_keycloak)
        _assert_services_stopped(cfg)
        originals.mkdir(mode=0o700)
        destinations = (
            (restored_home, cfg.hermes_home, originals / "hermes-home"),
            (restored_keycloak, cfg.keycloak_data, originals / "keycloak-data"),
        )
        for _restored, destination, original in destinations:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                os.replace(destination, original)
        try:
            for restored, destination, _original in destinations:
                os.replace(restored, destination)
                installed.append(destination)
        except Exception:
            for destination in reversed(installed):
                if destination.is_dir():
                    shutil.rmtree(destination)
                else:
                    destination.unlink(missing_ok=True)
            for _restored, destination, original in destinations:
                if original.exists():
                    os.replace(original, destination)
            raise
        shutil.rmtree(originals)
    finally:
        if originals.exists():
            for _restored, destination, original in destinations:
                if original.exists() and not destination.exists():
                    os.replace(original, destination)
        shutil.rmtree(staging, ignore_errors=True)
        shutil.rmtree(originals, ignore_errors=True)


def restore_backup(cfg: DeploymentConfig, source: Path) -> None:
    with _maintenance_lock(cfg, exclusive=True):
        _restore_backup_locked(cfg, source)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect())


def _wait_url(
    url: str, *, expected: Iterable[int] = (200,), timeout: float = 90.0
) -> None:
    deadline = time.monotonic() + timeout
    last_error = "not attempted"
    while time.monotonic() < deadline:
        try:
            with _NO_REDIRECT_OPENER.open(url, timeout=5) as response:
                if response.status in expected:
                    return
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
        except Exception as exc:  # noqa: BLE001 - bounded readiness retry
            last_error = exc.__class__.__name__
        time.sleep(1)
    raise RuntimeError(f"readiness timed out for {url} ({last_error})")


def _service_command(
    cfg: DeploymentConfig, service: str
) -> tuple[list[str], Path, dict[str, str]]:
    env = {
        name: value
        for name, value in os.environ.items()
        if name in _SAFE_AMBIENT_ENV_NAMES
    }
    if service == "keycloak":
        env.update(read_secret_env(cfg.keycloak_secret_file, _KEYCLOAK_ENV_NAMES))
        env.setdefault(
            "JAVA_HOME", "/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home"
        )
        return (
            [
                str(cfg.keycloak_command),
                "start-dev",
                "--http-host=127.0.0.1",
                f"--http-port={cfg.keycloak_port}",
                "--import-realm",
            ],
            cfg.keycloak_home,
            env,
        )
    if service == "dashboard":
        _wait_url(f"http://127.0.0.1:{cfg.keycloak_port}/realms/hermes-staging")
        env["HERMES_HOME"] = str(cfg.hermes_home)
        env["HERMES_WEB_DIST"] = str(cfg.active_release / "hermes_cli" / "web_dist")
        return (
            [
                str(cfg.dashboard_python),
                str(cfg.active_release / "hermes"),
                "dashboard",
                "--host",
                "127.0.0.1",
                "--port",
                str(cfg.dashboard_port),
                "--skip-build",
                "--no-open",
            ],
            cfg.active_release,
            env,
        )
    if service == "caddy":
        _wait_url(f"http://127.0.0.1:{cfg.dashboard_port}/api/health")
        return (
            [
                str(cfg.caddy_command),
                "run",
                "--config",
                str(cfg.caddyfile),
                "--adapter",
                "caddyfile",
            ],
            cfg.state_root,
            env,
        )
    if service == "ngrok":
        _wait_url(f"http://127.0.0.1:{cfg.proxy_port}/api/health")
        if cfg.ngrok_secret_file.exists():
            env.update(read_secret_env(cfg.ngrok_secret_file, _NGROK_ENV_NAMES))
        return (
            [
                str(cfg.ngrok_command),
                "http",
                str(cfg.proxy_port),
                "--url",
                cfg.public_url,
            ],
            cfg.state_root,
            env,
        )
    raise ValueError(f"unknown service: {service}")


def _service_logger(cfg: DeploymentConfig, service: str) -> logging.Logger:
    cfg.logs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    logger = logging.getLogger(f"enterprise-staging.{service}.{os.getpid()}")
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(
        cfg.logs_dir / f"{service}.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    os.chmod(cfg.logs_dir / f"{service}.log", 0o600)
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(handler)
    return logger


def _run_service_locked(cfg: DeploymentConfig, service: str) -> int:
    cfg.validate()
    command, cwd, env = _service_command(cfg, service)
    secret_values = [
        value
        for name, value in env.items()
        if name in (_KEYCLOAK_ENV_NAMES | _NGROK_ENV_NAMES)
    ]
    logger = _service_logger(cfg, service)
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=False,
    )

    def stop(_signum: int, _frame: object) -> None:
        if process.poll() is None:
            process.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    assert process.stdout is not None
    try:
        for raw_line in process.stdout:
            line = raw_line.rstrip("\r\n")
            for value in secret_values:
                if value:
                    line = line.replace(value, "[REDACTED]")
            logger.info("%s", line)
        return process.wait()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        process.stdout.close()


def run_service(cfg: DeploymentConfig, service: str) -> int:
    with _maintenance_lock(cfg, exclusive=False):
        return _run_service_locked(cfg, service)


def _probe(url: str, expected: Iterable[int] = (200,)) -> dict[str, object]:
    request = urllib.request.Request(
        url, headers={"User-Agent": "Hermes-Staging-Monitor/1"}
    )
    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=10) as response:
            status = response.status
            body = response.read(1024)
            return {"ok": status in expected, "status": status, "bytes": len(body)}
    except urllib.error.HTTPError as exc:
        return {"ok": exc.code in expected, "status": exc.code, "bytes": 0}
    except Exception as exc:  # noqa: BLE001 - health report must classify, not crash
        return {"ok": False, "error": exc.__class__.__name__}


def check(cfg: DeploymentConfig, *, write_status: bool = False) -> dict[str, object]:
    cfg.validate()
    base = cfg.public_url.rstrip("/")
    checks = {
        "dashboard_local": _probe(f"http://127.0.0.1:{cfg.dashboard_port}/api/health"),
        "idp_local": _probe(
            f"http://127.0.0.1:{cfg.keycloak_port}/realms/hermes-staging"
        ),
        "proxy_local": _probe(f"http://127.0.0.1:{cfg.proxy_port}/api/health"),
        "public_health": _probe(f"{base}/api/health"),
        "public_login": _probe(f"{base}/login"),
        "public_idp": _probe(
            f"{base}/realms/hermes-staging/.well-known/openid-configuration"
        ),
        "public_auth_gate": _probe(f"{base}/api/auth/me", expected=(401,)),
    }
    index_path = cfg.active_release / "hermes_cli" / "web_dist" / "index.html"
    asset_match = None
    if index_path.is_file():
        asset_match = re.search(
            r"""(?:src|href)=["'](/assets/[^"']+)["']""",
            index_path.read_text(encoding="utf-8"),
        )
    checks["public_frontend_asset"] = (
        _probe(f"{base}{asset_match.group(1)}")
        if asset_match
        else {"ok": False, "error": "built_asset_missing"}
    )
    payload: dict[str, object] = {
        "ok": all(bool(item.get("ok")) for item in checks.values()),
        "checked_at": int(time.time()),
        "checks": checks,
    }
    if write_status:
        _atomic_write(
            cfg.state_root / "health.json",
            (json.dumps(payload, sort_keys=True) + "\n").encode(),
            0o600,
        )
    return payload


def _launch_agent_dir() -> Path:
    return Path.home() / "Library" / "LaunchAgents"


def _validate_install_prerequisites(cfg: DeploymentConfig) -> None:
    if not cfg.active_release.is_symlink() or not cfg.active_release.is_dir():
        raise RuntimeError("active release symlink is missing; run activate first")
    required_files = (
        cfg.active_release / "hermes",
        cfg.active_release / "hermes_cli" / "web_dist" / "index.html",
        cfg.hermes_home / "config.yaml",
    )
    for path in required_files:
        if not path.is_file():
            raise RuntimeError(f"required deployment file is missing: {path}")
    if not cfg.keycloak_data.is_dir():
        raise RuntimeError(f"required Keycloak state is missing: {cfg.keycloak_data}")
    for executable in (
        cfg.dashboard_python,
        cfg.keycloak_command,
        cfg.caddy_command,
        cfg.ngrok_command,
    ):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise RuntimeError(
                f"required executable is missing or not executable: {executable}"
            )
    read_secret_env(cfg.keycloak_secret_file, _KEYCLOAK_ENV_NAMES)
    if cfg.ngrok_secret_file.exists():
        read_secret_env(cfg.ngrok_secret_file, _NGROK_ENV_NAMES)


def install(cfg: DeploymentConfig, config_path: Path, *, load: bool = True) -> None:
    cfg.validate()
    _validate_install_prerequisites(cfg)
    for directory in (
        cfg.state_root,
        cfg.state_root / "bin",
        cfg.state_root / "secrets",
        cfg.logs_dir,
        cfg.state_root / "backups",
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
    runner = cfg.state_root / "bin" / "enterprise-staging"
    _atomic_write(runner, Path(__file__).read_bytes(), 0o700)
    _atomic_write(cfg.caddyfile, build_caddyfile(cfg).encode(), 0o600)
    _atomic_write(config_path, cfg.to_json().encode(), 0o600)
    launch_dir = _launch_agent_dir()
    launch_dir.mkdir(parents=True, exist_ok=True)
    for service, body in render_launchd_plists(cfg, runner, config_path).items():
        _atomic_write(launch_dir / f"{_LABEL_PREFIX}.{service}.plist", body, 0o600)
    if load:
        start(cfg)


def _launchctl(
    *arguments: str, check_result: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/launchctl", *arguments],
        check=check_result,
        text=True,
        capture_output=True,
    )


def stop(_cfg: DeploymentConfig) -> None:
    domain = f"gui/{os.getuid()}"
    for service in ("monitor", "ngrok", "caddy", "dashboard", "keycloak"):
        _launchctl("bootout", f"{domain}/{_LABEL_PREFIX}.{service}", check_result=False)


def start(_cfg: DeploymentConfig) -> None:
    domain = f"gui/{os.getuid()}"
    launch_dir = _launch_agent_dir()
    for service in (*_SERVICES, "monitor"):
        plist = launch_dir / f"{_LABEL_PREFIX}.{service}.plist"
        label = f"{domain}/{_LABEL_PREFIX}.{service}"
        _launchctl("bootout", label, check_result=False)
        deadline = time.monotonic() + 10
        while True:
            result = _launchctl("bootstrap", domain, str(plist), check_result=False)
            if result.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f"could not load {service}: {result.stderr.strip()}")
            time.sleep(0.25)
        _launchctl("kickstart", "-k", label)


def rollback(cfg: DeploymentConfig) -> None:
    if not cfg.previous_release.exists():
        raise RuntimeError("no previous release is recorded")
    current = cfg.active_release.resolve()
    previous = cfg.previous_release.resolve(strict=True)
    _replace_symlink(cfg.active_release, previous)
    _replace_symlink(cfg.previous_release, current)
    stop(cfg)
    start(cfg)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    for action in (
        "activate",
        "install",
        "start",
        "stop",
        "restart",
        "status",
        "check",
        "backup",
        "restore",
        "rollback",
        "run-service",
    ):
        command = subparsers.add_parser(action)
        command.add_argument("--config", type=Path, required=True)
        if action == "activate":
            command.add_argument("--release", type=Path, required=True)
        elif action == "install":
            command.add_argument("--no-load", action="store_true")
        elif action == "check":
            command.add_argument("--write-status", action="store_true")
        elif action == "backup":
            command.add_argument("--output", type=Path, required=True)
        elif action == "restore":
            command.add_argument("--input", type=Path, required=True)
        elif action == "run-service":
            command.add_argument("service", choices=_SERVICES)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    cfg = load_config(args.config)
    if args.action == "activate":
        prior = activate_release(cfg, args.release)
        print(f"activated {args.release.resolve()}")
        if prior:
            print(f"previous {prior}")
    elif args.action == "install":
        install(cfg, args.config, load=not args.no_load)
    elif args.action == "start":
        start(cfg)
    elif args.action == "stop":
        stop(cfg)
    elif args.action == "restart":
        stop(cfg)
        start(cfg)
    elif args.action == "status":
        status_path = cfg.state_root / "health.json"
        print(
            status_path.read_text(encoding="utf-8")
            if status_path.exists()
            else json.dumps(check(cfg), indent=2)
        )
    elif args.action == "check":
        payload = check(cfg, write_status=args.write_status)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if payload["ok"] else 1
    elif args.action == "backup":
        create_backup(cfg, args.output)
        print(args.output)
    elif args.action == "restore":
        restore_backup(cfg, args.input)
    elif args.action == "rollback":
        rollback(cfg)
    elif args.action == "run-service":
        return run_service(cfg, args.service)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
