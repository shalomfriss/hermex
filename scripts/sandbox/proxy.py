"""MITM proxy backing the dev sandbox's fake Internet.

Listens on 127.0.0.1:8080 and is pointed at by http_proxy/https_proxy inside
the sandbox. For each request it either serves a fixture from the filesystem or
forwards to the real host:

* ``<root>/<host>/<path>`` exists -> serve it. This is how the sandbox answers
  the canonical install URL with the installer under test, so the payload can
  run the true ``curl -fsSL https://…/install.sh | bash`` one-liner.
* otherwise -> forward upstream, verifying against the real CA bundle. The
  sandbox is isolated from the *host*, not from the internet: a real install
  still has to reach PyPI and npm.

HTTPS is intercepted by minting a per-host certificate from the sandbox's own
throwaway CA, which payload clients trust via CURL_CA_BUNDLE, SSL_CERT_FILE, or
NODE_EXTRA_CA_CERTS. This client-side CA is distinct from the real CA bundle
that the proxy uses to verify an HTTPS server when forwarding upstream.

Usage: proxy.py <fixture-root> <certs-dir> <real-ca-bundle>
"""

import ipaddress
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import unquote, urlsplit

ROOT, CERTS, REAL_CA = map(pathlib.Path, sys.argv[1:])

LISTEN_ADDRESS = ('127.0.0.1', 8080)
MAX_REQUEST_BYTES = 65536
UPSTREAM_TIMEOUT_SECONDS = 30
CERT_VALIDITY_DAYS = 2
HTTP_TOKEN_BYTES = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)


def _safe_host(host):
    """Return a log-safe hostname without copying request data into logs."""
    value = str(host)
    if not value or len(value) > 253:
        return 'unknown'
    if ':' in value:
        candidate = value[1:-1] if value.startswith('[') and value.endswith(']') else value
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return 'unknown'
        return candidate
    if any(
        not char.isascii() or not (char.isalnum() or char in '.:_-')
        for char in value
    ):
        return 'unknown'
    return value


class ProxyStageError(RuntimeError):
    """Secret-safe failure at one proxy transport boundary."""

    def __init__(self, stage, host, port, error, elapsed_ms):
        self.stage = stage
        self.host = _safe_host(host)
        self.port = int(port)
        self.error_name = type(error).__name__
        self.elapsed_ms = round(elapsed_ms)
        super().__init__(str(self))

    def __str__(self):
        return (
            f'stage={self.stage} host={self.host} port={self.port} '
            f'error={self.error_name} elapsed_ms={self.elapsed_ms}'
        )


def _stage_error(stage, host, port, started, error):
    return ProxyStageError(
        stage, host, port, error, (time.monotonic() - started) * 1000
    )


def read_request(conn):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < MAX_REQUEST_BYTES:
        part = conn.recv(4096)
        if not part:
            return b""
        data += part
    return data


def run_openssl(args):
    """Run openssl, raising with its stderr when it fails.

    Discarding stderr here costs real debugging time: the caller sees only a
    dropped connection (``curl: (35) Recv failure``) and the log holds nothing
    but the argv, so an unwritable directory, a missing CA key, and an option
    the host's openssl rejects all look identical.
    """
    done = subprocess.run(
        ['openssl', *args], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    if done.returncode != 0:
        detail = done.stderr.decode('utf-8', 'replace').strip()
        raise RuntimeError(
            f'openssl {args[0]} failed (exit {done.returncode}): {detail}'
        )


_CERT_LOCK = threading.Lock()


def cert_for(host):
    """Return a (cert, key) pair for host, minting it from the sandbox CA.

    Minting is serialized and published atomically. The proxy is threaded, so
    two concurrent requests for the same host would otherwise both run openssl
    into the same paths, and a reader could pick up a finished certificate
    beside a key from the other writer -- which TLS rejects as
    ``[X509: KEY_VALUES_MISMATCH] key values mismatch``.
    """
    safe = ''.join(char if char.isalnum() or char in '.-' else '_' for char in host)
    cert, key = CERTS / f'{safe}.pem', CERTS / f'{safe}.key'
    if cert.exists() and key.exists():
        return cert, key
    with _CERT_LOCK:
        # Re-check: another thread may have finished while we waited.
        if cert.exists() and key.exists():
            return cert, key
        # Build under unique temp names, then rename into place. os.replace is
        # atomic, so a reader sees either the old pair or the new one, never a
        # half-written mix. The key lands first: the certificate's existence is
        # what everything else keys off.
        stamp = f'{os.getpid()}.{threading.get_ident()}'
        tmp_key = CERTS / f'{safe}.key.{stamp}'
        tmp_cert = CERTS / f'{safe}.pem.{stamp}'
        csr = CERTS / f'{safe}.csr.{stamp}'
        run_openssl([
            'req', '-newkey', 'rsa:2048', '-nodes',
            '-subj', f'/CN={host}',
            '-addext', f'subjectAltName=DNS:{host}',
            '-keyout', str(tmp_key), '-out', str(csr),
        ])
        run_openssl([
            'x509', '-req', '-days', str(CERT_VALIDITY_DAYS), '-in', str(csr),
            '-CA', str(CERTS / 'ca.pem'), '-CAkey', str(CERTS / 'ca.key'),
            '-CAcreateserial', '-copy_extensions', 'copy', '-out', str(tmp_cert),
        ])
        csr.unlink(missing_ok=True)
        os.replace(tmp_key, key)
        os.replace(tmp_cert, cert)
    return cert, key


def file_for(host, target):
    """Resolve a request to a fixture file, or None to forward upstream."""
    path = urlsplit(target).path or '/'
    parts = pathlib.PurePosixPath(unquote(path)).parts
    if '..' in parts:
        return None
    candidate = ROOT / host / pathlib.PurePosixPath(*[p for p in parts if p != '/'])
    if candidate.is_dir():
        candidate /= 'index.html'
    return candidate if candidate.is_file() else None


def respond_fixture(conn, found):
    body = found.read_bytes()
    headers = (
        f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode()
    )
    conn.sendall(b'HTTP/1.1 200 OK\r\n' + headers + body)


def close_request(request, target=None):
    """Rewrite a proxied request for a direct upstream connection."""
    headers, separator, body = request.partition(b'\r\n\r\n')
    lines = headers.split(b'\r\n')
    if target is not None:
        method, _, version = lines[0].split(b' ', 2)
        lines[0] = b' '.join((method, target.encode(), version))
    lines = [
        line for line in lines
        if not line.lower().startswith((b'connection:', b'keep-alive:', b'proxy-connection:'))
    ]
    lines.append(b'Connection: close')
    return b'\r\n'.join(lines) + separator + body


def relay(source, destination):
    while True:
        chunk = source.recv(MAX_REQUEST_BYTES)
        if not chunk:
            return
        destination.sendall(chunk)


def relay_response(source, destination, method, allow_keepalive=True):
    """Relay one HTTP response and return whether the client TLS may be reused."""
    data = b''
    while b'\r\n\r\n' not in data and len(data) < MAX_REQUEST_BYTES:
        chunk = source.recv(4096)
        if not chunk:
            break
        data += chunk
    headers, separator, body = data.partition(b'\r\n\r\n')
    if not separator:
        destination.sendall(data)
        relay(source, destination)
        return False

    lines = headers.split(b'\r\n')
    status_parts = lines[0].split(b' ', 2)
    if (
        len(status_parts) < 2
        or status_parts[0] not in (b'HTTP/1.0', b'HTTP/1.1')
        or len(status_parts[1]) != 3
        or not status_parts[1].isdigit()
    ):
        raise ConnectionError('malformed upstream HTTP status line')
    status = int(status_parts[1])
    # Forward an informational response and its eventual final response as one
    # close-delimited exchange. Reusing the client connection here would require
    # parsing another header block from the already-buffered bytes.
    if 100 <= status < 200:
        destination.sendall(data)
        relay(source, destination)
        return False

    content_lengths = []
    transfer_encodings = []
    forwarded = [lines[0]]
    for line in lines[1:]:
        if b':' not in line:
            raise ConnectionError('malformed upstream HTTP header')
        name, value = line.split(b':', 1)
        if not name or any(byte not in HTTP_TOKEN_BYTES for byte in name):
            raise ConnectionError('malformed upstream HTTP header name')
        lower_name = name.lower()
        if lower_name in (b'connection', b'keep-alive', b'proxy-connection'):
            continue
        if lower_name == b'content-length':
            values = [part.strip() for part in value.split(b',')]
            if not values or any(not part.isdigit() for part in values):
                raise ConnectionError('invalid upstream Content-Length')
            content_lengths.extend(int(part) for part in values)
        if lower_name == b'transfer-encoding':
            transfer_encodings.extend(
                part.strip().lower() for part in value.split(b',') if part.strip()
            )
        forwarded.append(line)

    if content_lengths and len(set(content_lengths)) != 1:
        raise ConnectionError('conflicting upstream Content-Length fields')
    if content_lengths and transfer_encodings:
        raise ConnectionError('ambiguous upstream response framing')
    content_length = content_lengths[0] if content_lengths else None
    no_body = method.upper() == 'HEAD' or status in (204, 304)
    if no_body and body:
        raise ConnectionError('unexpected body on bodyless upstream response')
    if content_length is not None and len(body) > content_length:
        raise ConnectionError('upstream response exceeded Content-Length')

    # Content-Length and bodyless responses can be consumed exactly. Chunked
    # framing remains safe but is deliberately not reused until its trailers and
    # terminating zero chunk are parsed and validated.
    framed_for_reuse = no_body or content_length is not None
    keepalive = allow_keepalive and framed_for_reuse
    forwarded.append(b'Connection: keep-alive' if keepalive else b'Connection: close')
    destination.sendall(b'\r\n'.join(forwarded) + separator)

    if no_body:
        return keepalive
    if content_length is not None:
        remaining = content_length
        if body:
            destination.sendall(body)
            remaining -= len(body)
        while remaining:
            chunk = source.recv(min(MAX_REQUEST_BYTES, remaining))
            if not chunk:
                raise ConnectionError('upstream response ended before Content-Length')
            if len(chunk) > remaining:
                raise ConnectionError('upstream response exceeded Content-Length')
            destination.sendall(chunk)
            remaining -= len(chunk)
        return keepalive

    if body:
        destination.sendall(body)
    relay(source, destination)
    return False


def forward_https(conn, host, port, request):
    # This is the upstream trust boundary. Payload clients never receive these
    # certificates; they receive the sandbox-CA leaf minted in handle_connect.
    context = ssl.create_default_context(cafile=str(REAL_CA))
    started = time.monotonic()
    try:
        raw = socket.create_connection(
            (host, port), timeout=UPSTREAM_TIMEOUT_SECONDS
        )
    except Exception as error:
        raise _stage_error('upstream_connect', host, port, started, error) from error
    with raw:
        # create_connection's timeout bounds upstream setup through the TLS
        # handshake. Clear it only after the handshake succeeds; leaving it on
        # the wrapped socket turns it into a transfer idle timeout and aborts
        # valid slow registry responses. The installer keeps its separate
        # NODE_DEPS_TIMEOUT=600 wall-clock cap.
        started = time.monotonic()
        try:
            upstream = context.wrap_socket(raw, server_hostname=host)
        except Exception as error:
            raise _stage_error(
                'upstream_handshake', host, port, started, error
            ) from error
        upstream.settimeout(None)
        with upstream:
            started = time.monotonic()
            try:
                upstream.sendall(close_request(request))
                method = request.split(b' ', 1)[0].decode('ascii', 'replace')
                client_closes = any(
                    line.lower().strip() == b'connection: close'
                    for line in request.split(b'\r\n')[1:]
                )
                return relay_response(
                    upstream, conn, method, allow_keepalive=not client_closes
                )
            except Exception as error:
                raise _stage_error('relay', host, port, started, error) from error


def forward_http(conn, host, port, request, target):
    parsed = urlsplit(target)
    path = parsed.path or '/'
    if parsed.query:
        path += f'?{parsed.query}'
    started = time.monotonic()
    try:
        upstream = socket.create_connection(
            (host, port), timeout=UPSTREAM_TIMEOUT_SECONDS
        )
    except Exception as error:
        raise _stage_error('upstream_connect', host, port, started, error) from error
    with upstream:
        upstream.settimeout(None)
        started = time.monotonic()
        try:
            upstream.sendall(close_request(request, path))
            relay(upstream, conn)
        except Exception as error:
            raise _stage_error('relay', host, port, started, error) from error


def handle_connect(conn, target):
    """Intercept a CONNECT tunnel, terminating TLS with a minted cert."""
    host, _, port_text = target.rpartition(':')
    port = int(port_text or '443')
    started = time.monotonic()
    try:
        conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        cert, key = cert_for(host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        tls = context.wrap_socket(conn, server_side=True)
    except Exception as error:
        raise _stage_error('client_handshake', host, port, started, error) from error
    try:
        keepalive = True
        while keepalive:
            nested = read_request(tls)
            if not nested:
                return
            line = nested.split(b'\r\n', 1)[0].decode('iso-8859-1')
            nested_target = line.split(' ', 2)[1]
            found = file_for(host, nested_target)
            if found is not None:
                respond_fixture(tls, found)
                keepalive = False
            else:
                keepalive = forward_https(tls, host, port, nested)
    finally:
        # A bare SSLSocket.close() drops TCP without TLS close-notify. Undici can
        # receive that EOF while its response parser is paused on backpressure
        # and abort an otherwise complete tarball. Complete the TLS shutdown,
        # bounded by the same setup timeout so an uncooperative client cannot
        # retain a proxy thread indefinitely.
        tls.settimeout(UPSTREAM_TIMEOUT_SECONDS)
        try:
            raw = tls.unwrap()
        except (OSError, ssl.SSLError):
            tls.close()
        else:
            raw.close()


def host_from_headers(request):
    for header in request.split(b'\r\n')[1:]:
        if header.lower().startswith(b'host:'):
            value = header.split(b':', 1)[1].strip().decode()
            return value.split(':', 1)[0]
    return None


def handle_request(conn):
    with conn:
        request = read_request(conn)
        if not request:
            return
        line = request.split(b'\r\n', 1)[0].decode('iso-8859-1')
        method, target, _ = line.split(' ', 2)
        if method.upper() == 'CONNECT':
            handle_connect(conn, target)
            return
        parsed = urlsplit(target)
        host = parsed.hostname or host_from_headers(request) or 'unknown'
        found = file_for(host, target)
        if found is not None:
            respond_fixture(conn, found)
        else:
            forward_http(conn, host, parsed.port or 80, request, target)


def handle(conn):
    try:
        handle_request(conn)
    except ProxyStageError as error:
        print(f'proxy request failed: {error}', file=sys.stderr, flush=True)
    except Exception as error:
        # Request bytes and arbitrary exception messages are intentionally never
        # logged: they can contain paths, query parameters, auth, or cookies.
        safe = ProxyStageError('client_handshake', 'unknown', 0, error, 0)
        print(f'proxy request failed: {safe}', file=sys.stderr, flush=True)


def serve(server):
    """Accept connections on an already-bound socket."""
    server.listen()
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(LISTEN_ADDRESS)
        serve(server)


if __name__ == '__main__':
    main()
