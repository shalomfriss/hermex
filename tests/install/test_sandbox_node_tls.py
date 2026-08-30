"""Regression coverage for Node TLS through the dev-sandbox MITM proxy."""

import importlib.util
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import threading
import time


REPO_ROOT = Path(__file__).resolve().parents[2]
PROXY_PATH = REPO_ROOT / "scripts" / "sandbox" / "proxy.py"
STAGE2_PATH = REPO_ROOT / "scripts" / "sandbox" / "stage2-run.sh"

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


def _load_proxy(fixture_root: Path, certs: Path, real_ca: Path):
    spec = importlib.util.spec_from_file_location("sandbox_proxy_tls_test", PROXY_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    original_argv = sys.argv
    try:
        sys.argv = [str(PROXY_PATH), str(fixture_root), str(certs), str(real_ca)]
        spec.loader.exec_module(module)
    finally:
        sys.argv = original_argv
    return module


def test_stage2_node_trust_completes_https_through_sandbox_proxy(tmp_path: Path) -> None:
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

    stage2 = STAGE2_PATH.read_text(encoding="utf-8")
    match = re.search(r"--setenv NODE_EXTRA_CA_CERTS /work/certs/([^ ]+) ", stage2)
    assert match, "stage2-run.sh must set NODE_EXTRA_CA_CERTS to a sandbox CA file"
    configured_ca = certs / match.group(1)

    proxy = _load_proxy(fixture_root, certs, certs / "real-ca.pem")
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    threading.Thread(target=proxy.serve, args=(server,), daemon=True).start()
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except OSError:
            time.sleep(0.01)
    else:
        raise AssertionError("sandbox proxy did not start")

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
    env["NODE_EXTRA_CA_CERTS"] = str(configured_ca)
    env["npm_config_strict_ssl"] = "true"
    env["NPM_CONFIG_STRICT_SSL"] = "true"
    env["npm_config_userconfig"] = str(tmp_path / "empty-user-npmrc")
    env["npm_config_globalconfig"] = str(tmp_path / "empty-global-npmrc")
    env["HTTP_PROXY"] = f"http://127.0.0.1:{port}"
    env["HTTPS_PROXY"] = f"http://127.0.0.1:{port}"
    env["NO_PROXY"] = ""
    env["npm_config_cache"] = str(tmp_path / "npm-cache")
    env["npm_config_fetch_retries"] = "0"
    result = subprocess.run(
        [npm, "ping", "--silent", "--registry=https://fixture.invalid"],
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 0, (
        "npm rejected the proxy-minted HTTPS certificate with stage2's configured "
        f"extra CA ({configured_ca.name}):\n{result.stderr}"
    )
