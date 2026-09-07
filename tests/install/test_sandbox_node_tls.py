"""Regression coverage for Node TLS through the dev-sandbox MITM proxy."""

import importlib.util
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
PROXY_PATH = REPO_ROOT / "scripts" / "sandbox" / "proxy.py"
STAGE2_PATH = REPO_ROOT / "scripts" / "sandbox" / "stage2-run.sh"
INSTALL_E2E_PATH = REPO_ROOT / "tests" / "install" / "install-update-e2e.sh"


def _mint_ca(openssl: str, cert: Path, key: Path, common_name: str) -> None:
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            f"/CN={common_name}",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )


def _mint_leaf(
    openssl: str, ca_cert: Path, ca_key: Path, cert: Path, key: Path, host: str
) -> None:
    csr = cert.with_suffix(".csr")
    subprocess.run(
        [
            openssl,
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            f"/CN={host}",
            "-addext",
            f"subjectAltName=DNS:{host}",
            "-keyout",
            str(key),
            "-out",
            str(csr),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            openssl,
            "x509",
            "-req",
            "-days",
            "1",
            "-in",
            str(csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-copy_extensions",
            "copy",
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )


def _load_proxy(fixture_root: Path, certs: Path, real_ca: Path):
    spec = importlib.util.spec_from_file_location(
        f"sandbox_proxy_tls_test_{time.monotonic_ns()}", PROXY_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    original_argv = sys.argv
    try:
        sys.argv = [str(PROXY_PATH), str(fixture_root), str(certs), str(real_ca)]
        spec.loader.exec_module(module)
    finally:
        sys.argv = original_argv
    return module


def _start_proxy(proxy) -> int:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    threading.Thread(target=proxy.serve, args=(server,), daemon=True).start()
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return port
        except OSError:
            time.sleep(0.01)
    raise AssertionError("sandbox proxy did not start")


def _npm_ping(npm: str, port: int, ca: Path, tmp_path: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    for inherited in (
        "NODE_OPTIONS",
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "NODE_USE_SYSTEM_CA",
        "SSL_CERT_FILE",
        "npm_config_ca",
        "npm_config_cafile",
        "NPM_CONFIG_CA",
        "NPM_CONFIG_CAFILE",
    ):
        env.pop(inherited, None)
    env["NODE_EXTRA_CA_CERTS"] = str(ca)
    env["npm_config_strict_ssl"] = "true"
    env["NPM_CONFIG_STRICT_SSL"] = "true"
    env["npm_config_userconfig"] = str(tmp_path / "empty-user-npmrc")
    env["npm_config_globalconfig"] = str(tmp_path / "empty-global-npmrc")
    env["HTTP_PROXY"] = f"http://127.0.0.1:{port}"
    env["HTTPS_PROXY"] = f"http://127.0.0.1:{port}"
    env["NO_PROXY"] = ""
    env["npm_config_cache"] = str(tmp_path / "npm-cache")
    env["npm_config_fetch_retries"] = "0"
    return subprocess.run(
        [npm, "ping", "--silent", "--registry=https://fixture.invalid"],
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
    )


def _client_proxy_fixture(tmp_path: Path):
    npm = shutil.which("npm")
    openssl = shutil.which("openssl")
    assert npm, "npm is required for the sandbox Node TLS regression"
    assert openssl, "openssl is required for the sandbox Node TLS regression"

    certs = tmp_path / "certs"
    fixture_root = tmp_path / "http"
    certs.mkdir()
    fixture = fixture_root / "fixture.invalid" / "-" / "ping"
    fixture.parent.mkdir(parents=True)
    fixture.write_text('{"ok":true}', encoding="utf-8")

    _mint_ca(openssl, certs / "ca.pem", certs / "ca.key", "Sandbox MITM CA")
    _mint_ca(openssl, certs / "real-ca.pem", certs / "real-ca.key", "Real upstream CA")
    _mint_ca(openssl, certs / "wrong-ca.pem", certs / "wrong-ca.key", "Wrong Client CA")

    stage2 = STAGE2_PATH.read_text(encoding="utf-8")
    match = re.search(r"--setenv NODE_EXTRA_CA_CERTS /work/certs/([^ ]+) ", stage2)
    assert match, "stage2-run.sh must set NODE_EXTRA_CA_CERTS to a sandbox CA file"
    configured_ca = certs / match.group(1)

    proxy = _load_proxy(fixture_root, certs, certs / "real-ca.pem")
    return npm, _start_proxy(proxy), configured_ca, certs / "wrong-ca.pem"


def test_stage2_node_trust_completes_https_through_sandbox_proxy(tmp_path: Path) -> None:
    npm, port, configured_ca, _ = _client_proxy_fixture(tmp_path)
    result = _npm_ping(npm, port, configured_ca, tmp_path)

    assert result.returncode == 0, (
        "npm rejected the proxy-minted HTTPS certificate with stage2's configured "
        f"extra CA ({configured_ca.name}):\n{result.stderr}"
    )


def test_wrong_client_ca_fails_closed(tmp_path: Path) -> None:
    npm, port, _, wrong_ca = _client_proxy_fixture(tmp_path)
    result = _npm_ping(npm, port, wrong_ca, tmp_path)

    assert result.returncode != 0, "npm unexpectedly trusted a proxy leaf from another CA"


class _Collector:
    def __init__(self) -> None:
        self.data = bytearray()

    def sendall(self, chunk: bytes) -> None:
        self.data.extend(chunk)


def _start_tls_upstream(tmp_path: Path, delay: float):
    openssl = shutil.which("openssl")
    assert openssl, "openssl is required for the sandbox proxy TLS regression"
    ca_cert = tmp_path / "upstream-ca.pem"
    ca_key = tmp_path / "upstream-ca.key"
    leaf_cert = tmp_path / "localhost.pem"
    leaf_key = tmp_path / "localhost.key"
    _mint_ca(openssl, ca_cert, ca_key, "Local upstream CA")
    _mint_leaf(openssl, ca_cert, ca_key, leaf_cert, leaf_key, "localhost")

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    errors = []

    def serve_once() -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(leaf_cert, leaf_key)
        try:
            raw, _ = server.accept()
            with raw, context.wrap_socket(raw, server_side=True) as tls:
                tls.recv(65536)
                time.sleep(delay)
                tls.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError) as error:
            errors.append(error)
        finally:
            server.close()

    thread = threading.Thread(target=serve_once, daemon=True)
    thread.start()
    return port, ca_cert, thread, errors


def test_connect_timeout_does_not_limit_slow_tls_transfer(tmp_path: Path) -> None:
    port, upstream_ca, thread, errors = _start_tls_upstream(tmp_path, delay=0.25)
    proxy = _load_proxy(tmp_path / "http", tmp_path, upstream_ca)
    proxy.UPSTREAM_TIMEOUT_SECONDS = 0.1
    destination = _Collector()

    proxy.forward_https(
        destination,
        "localhost",
        port,
        b"GET /private?token=hidden HTTP/1.1\r\nAuthorization: hidden\r\n\r\n",
    )
    thread.join(timeout=2)

    assert destination.data.endswith(b"\r\n\r\nok")
    assert not errors


def test_wrong_upstream_ca_fails_closed_with_safe_stage_diagnostic(
    tmp_path: Path,
) -> None:
    port, _, thread, _ = _start_tls_upstream(tmp_path, delay=0)
    openssl = shutil.which("openssl")
    assert openssl
    wrong_ca = tmp_path / "wrong-upstream-ca.pem"
    wrong_key = tmp_path / "wrong-upstream-ca.key"
    _mint_ca(openssl, wrong_ca, wrong_key, "Wrong upstream CA")
    proxy = _load_proxy(tmp_path / "http", tmp_path, wrong_ca)

    with pytest.raises(proxy.ProxyStageError) as caught:
        proxy.forward_https(
            _Collector(),
            "localhost",
            port,
            b"GET /secret?token=hidden HTTP/1.1\r\nCookie: hidden\r\n\r\n",
        )
    thread.join(timeout=2)

    diagnostic = str(caught.value)
    assert "stage=upstream_handshake" in diagnostic
    assert "host=localhost" in diagnostic
    assert "error=SSLCertVerificationError" in diagnostic
    assert "elapsed_ms=" in diagnostic
    assert "/secret" not in diagnostic
    assert "token=" not in diagnostic
    assert "Cookie" not in diagnostic
    assert str(wrong_ca) not in diagnostic


def test_stage_diagnostic_never_includes_exception_details(tmp_path: Path) -> None:
    openssl = shutil.which("openssl")
    assert openssl
    real_ca = tmp_path / "real-ca.pem"
    real_key = tmp_path / "real-ca.key"
    _mint_ca(openssl, real_ca, real_key, "Real CA")
    proxy = _load_proxy(tmp_path / "http", tmp_path, real_ca)

    error = proxy.ProxyStageError(
        "relay",
        "registry.npmjs.org",
        443,
        ValueError("/secret?token=hidden Authorization: hidden Cookie: hidden"),
        12.4,
    )
    diagnostic = str(error)

    assert diagnostic == (
        "stage=relay host=registry.npmjs.org port=443 "
        "error=ValueError elapsed_ms=12"
    )

    hostile = proxy.ProxyStageError(
        "client_handshake",
        "user:password@example.com/path?token=hidden",
        443,
        ValueError("hidden"),
        1,
    )
    assert "host=unknown" in str(hostile)
    assert "user" not in str(hostile)
    assert "password" not in str(hostile)

    colon_hostile = proxy.ProxyStageError(
        "client_handshake", "user:password", 443, ValueError("hidden"), 1
    )
    assert "host=unknown" in str(colon_hostile)
    assert "password" not in str(colon_hostile)


def test_upstream_tls_handshake_keeps_connect_timeout(tmp_path: Path) -> None:
    openssl = shutil.which("openssl")
    assert openssl
    upstream_ca = tmp_path / "upstream-ca.pem"
    upstream_key = tmp_path / "upstream-ca.key"
    _mint_ca(openssl, upstream_ca, upstream_key, "Upstream CA")
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def stall_after_accept() -> None:
        raw, _ = server.accept()
        with raw:
            time.sleep(1)
        server.close()

    threading.Thread(target=stall_after_accept, daemon=True).start()
    proxy = _load_proxy(tmp_path / "http", tmp_path, upstream_ca)
    proxy.UPSTREAM_TIMEOUT_SECONDS = 0.1
    errors = []

    def forward() -> None:
        try:
            proxy.forward_https(
                _Collector(), "localhost", port, b"GET / HTTP/1.1\r\n\r\n"
            )
        except Exception as error:
            errors.append(error)

    worker = threading.Thread(target=forward, daemon=True)
    worker.start()
    worker.join(timeout=0.5)

    assert not worker.is_alive(), "upstream TLS handshake ignored the connect timeout"
    assert len(errors) == 1
    assert isinstance(errors[0], proxy.ProxyStageError)
    assert errors[0].stage == "upstream_handshake"
    assert errors[0].error_name == "TimeoutError"


def test_e2e_archives_fail_closed_node_resolution_manifests() -> None:
    stage2 = STAGE2_PATH.read_text(encoding="utf-8")
    e2e = INSTALL_E2E_PATH.read_text(encoding="utf-8")

    assert "--setenv NODE_EXTRA_CA_CERTS /work/certs/ca.pem" in stage2
    assert "--setenv npm_config_strict_ssl true" in stage2
    assert "ssl.create_default_context(cafile=str(REAL_CA))" in PROXY_PATH.read_text(
        encoding="utf-8"
    )
    assert "capture_node_resolution_manifest pre-install baseline" in e2e
    assert "capture_node_resolution_manifest post-install managed" in e2e
    assert "capture_node_resolution_manifest pre-reinstall managed" in e2e
    assert "capture_node_resolution_manifest post-update managed" in e2e
    assert "capture_node_resolution_manifest post-reinstall managed" in e2e
    assert 'local npm_logs="$SANDBOX_ROOT/home/.npm/_logs"' in e2e
    assert "npm install --loglevel verbose" in e2e
    assert 'args+=(--installer "$diagnostic_installer")' in e2e
    assert "node_path=" in e2e
    assert "npm_path=" in e2e
    assert "process_exec_path=" in e2e
    assert "strict_ssl=" in e2e
    assert "cafile=" in e2e
    assert "nodedir=" in e2e
    assert "sandbox_ca_sha256=" in e2e
    assert "upstream_ca_sha256=" in e2e
    assert "NODE_TLS_REJECT_UNAUTHORIZED" not in stage2
    assert "strict-ssl=false" not in stage2
