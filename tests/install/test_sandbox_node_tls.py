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

NODE_HTTPS_PROBE = r"""
const net = require('net');
const tls = require('tls');
const port = Number(process.argv[1]);
const raw = net.connect(port, '127.0.0.1');
let head = Buffer.alloc(0);

raw.on('connect', () => {
  raw.write('CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n');
});
raw.on('error', error => {
  console.error(error.code || error.message);
  process.exitCode = 1;
});
raw.on('data', function readConnect(chunk) {
  head = Buffer.concat([head, chunk]);
  const boundary = head.indexOf('\r\n\r\n');
  if (boundary === -1) return;
  raw.removeListener('data', readConnect);
  const remainder = head.subarray(boundary + 4);
  if (remainder.length) raw.unshift(remainder);

  const secure = tls.connect({
    socket: raw,
    servername: 'fixture.invalid',
    rejectUnauthorized: true,
  });
  let response = '';
  secure.on('secureConnect', () => {
    secure.write('GET /ping HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n');
  });
  secure.on('data', chunk => { response += chunk; });
  secure.on('end', () => {
    if (!response.includes('sandbox tls ok')) {
      console.error(response);
      process.exitCode = 1;
    }
  });
  secure.on('error', error => {
    console.error(error.code || error.message);
    process.exitCode = 1;
  });
});
"""


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
    node = shutil.which("node")
    openssl = shutil.which("openssl")
    assert node, "node is required for the sandbox Node TLS regression"
    assert openssl, "openssl is required for the sandbox Node TLS regression"

    certs = tmp_path / "certs"
    fixture_root = tmp_path / "http"
    certs.mkdir()
    fixture = fixture_root / "fixture.invalid" / "ping"
    fixture.parent.mkdir(parents=True)
    fixture.write_text("sandbox tls ok", encoding="utf-8")

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
    env["NODE_EXTRA_CA_CERTS"] = str(configured_ca)
    result = subprocess.run(
        [node, "-e", NODE_HTTPS_PROBE, str(port)],
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 0, (
        "Node rejected the proxy-minted HTTPS certificate with stage2's configured "
        f"extra CA ({configured_ca.name}):\n{result.stderr}"
    )
