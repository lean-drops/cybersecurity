# Defense/Tls.py
"""
TLS demo (Python stdlib only):

Demo A: Connect to a public HTTPS host and print TLS details.
- Uses system trust store by default.
- If verification fails, it tries to use certifi (if installed).

Demo B: Local TLS echo server + two clients:
- Insecure client: no certificate verification (MITM-vulnerable).
- Verified client: validates certificate + hostname.
- Uses openssl to generate a short-lived self-signed cert with SAN for localhost/127.0.0.1.

No CLI args needed.
"""

from __future__ import annotations

import hashlib
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from typing import Optional, Tuple
import certifi
import ssl


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _try_https_once(host: str, port: int, ctx: ssl.SSLContext) -> None:
    with socket.create_connection((host, port), timeout=6) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            print("Connected to %s:%d" % (host, port))
            print("TLS version:", ssock.version())
            print("Cipher:", ssock.cipher())

            der = ssock.getpeercert(binary_form=True)
            print("Server cert SHA-256:", _sha256_hex(der))

            cert = ssock.getpeercert()
            print("Server cert subject:", cert.get("subject", []))
            print("Server cert notAfter:", cert.get("notAfter", ""))

            req = (
                "GET / HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: tls-demo/1.0\r\n"
                "Connection: close\r\n"
                "\r\n"
            ) % host
            ssock.sendall(req.encode("ascii", "strict"))
            data = ssock.recv(200)
            print("First bytes of HTTP response:", data[:80])


def demo_https_introspection(host: str = "example.com", port: int = 443) -> None:
    print("=== Demo A: Inspect TLS handshake to a public HTTPS site ===")

    # First attempt: normal default verification (system/venv trust store)
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        _try_https_once(host, port, ctx)
        print()
        return
    except ssl.SSLCertVerificationError as e:
        print("HTTPS verification failed:", repr(e))
        print("Reason: your Python environment likely lacks a CA bundle.")
        # Second attempt: try certifi if present
        try:
            import certifi  # type: ignore

            ctx2 = ssl.create_default_context(cafile=certifi.where())
            ctx2.minimum_version = ssl.TLSVersion.TLSv1_2
            print("Retrying with certifi CA bundle...")
            _try_https_once(host, port, ctx2)
            print()
            return
        except Exception as e2:
            print("Retry with certifi failed (certifi missing or still failing):", repr(e2))
            print(
                "Fix options (macOS):\n"
                "- If you use the python.org installer: run 'Install Certificates.command' (it ships with Python).\n"
                "- Or install 'certifi' into this venv and re-run.\n"
                "- In PyCharm, ensure your interpreter points to the venv where the CA bundle is installed."
            )
            print()
            return
    except Exception as e:
        print("HTTPS introspection failed (network blocked/offline?):", repr(e))
        print()


def _openssl_available() -> bool:
    try:
        r = subprocess.run(
            ["openssl", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
        return r.returncode == 0
    except Exception:
        return False


def _generate_self_signed_cert_with_openssl(tmpdir: str) -> Tuple[str, str]:
    """
    Creates server.crt + server.key in tmpdir using openssl with SAN for localhost and 127.0.0.1.
    Returns (cert_path, key_path).
    """
    if not _openssl_available():
        raise RuntimeError("openssl not found on PATH; cannot generate demo certificate")

    cert_path = os.path.join(tmpdir, "server.crt")
    key_path = os.path.join(tmpdir, "server.key")
    cfg_path = os.path.join(tmpdir, "openssl.cnf")

    cfg = (
        "[ req ]\n"
        "default_bits = 2048\n"
        "prompt = no\n"
        "default_md = sha256\n"
        "x509_extensions = v3_req\n"
        "distinguished_name = dn\n"
        "\n"
        "[ dn ]\n"
        "CN = localhost\n"
        "\n"
        "[ v3_req ]\n"
        "subjectAltName = @alt_names\n"
        "keyUsage = digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        "\n"
        "[ alt_names ]\n"
        "DNS.1 = localhost\n"
        "IP.1 = 127.0.0.1\n"
    )

    with open(cfg_path, "w", encoding="ascii") as f:
        f.write(cfg)

    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-keyout",
        key_path,
        "-out",
        cert_path,
        "-config",
        cfg_path,
    ]
    r = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        check=False,
    )
    if r.returncode != 0:
        raise RuntimeError("openssl failed: %s" % (r.stderr.strip() or r.stdout.strip()))

    return cert_path, key_path


def _run_tls_echo_server(
    bind_host: str,
    port_holder: dict,
    ready_evt: threading.Event,
    stop_evt: threading.Event,
) -> None:
    try:
        with tempfile.TemporaryDirectory() as td:
            cert_path, key_path = _generate_self_signed_cert_with_openssl(td)

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

            with open(cert_path, "r", encoding="ascii") as f:
                port_holder["cert_pem"] = f.read()

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as lsock:
                lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                lsock.bind((bind_host, 0))
                lsock.listen(5)
                lsock.settimeout(0.5)

                port_holder["port"] = lsock.getsockname()[1]
                ready_evt.set()

                while not stop_evt.is_set():
                    try:
                        conn, _addr = lsock.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break

                    try:
                        with ctx.wrap_socket(conn, server_side=True) as tls_conn:
                            tls_conn.settimeout(2)
                            msg = tls_conn.recv(4096)
                            tls_conn.sendall(b"ECHO:" + msg)
                    except Exception:
                        try:
                            conn.close()
                        except Exception:
                            pass
    except Exception as e:
        port_holder["error"] = repr(e)
        ready_evt.set()


def _connect_tls(
    host: str,
    port: int,
    ctx: ssl.SSLContext,
    server_hostname: str,
    payload: bytes,
) -> Tuple[bytes, str, Tuple[str, str, int]]:
    with socket.create_connection((host, port), timeout=4) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
            ssock.sendall(payload)
            resp = ssock.recv(4096)
            tls_ver = ssock.version() or ""
            cipher = ssock.cipher() or ("", "", 0)
            return resp, tls_ver, cipher


def demo_local_tls_echo() -> None:
    print("=== Demo B: Local TLS echo server + clients (verify vs no-verify) ===")

    bind_host = "127.0.0.1"
    port_holder: dict = {}
    ready_evt = threading.Event()
    stop_evt = threading.Event()

    t = threading.Thread(
        target=_run_tls_echo_server,
        args=(bind_host, port_holder, ready_evt, stop_evt),
        daemon=True,
    )
    t.start()
    ready_evt.wait(timeout=6)

    if "error" in port_holder:
        print("Server failed to start:", port_holder["error"])
        print("Hint: openssl must be available, and Python must be able to use the generated cert/key.")
        print()
        return

    port = int(port_holder.get("port", 0))
    cert_pem = port_holder.get("cert_pem", "")
    if port == 0 or not cert_pem:
        print("Server did not start correctly.")
        print()
        return

    print("Server listening on %s:%d (self-signed cert generated via openssl)" % (bind_host, port))
    payload = b"hello over tls"

    # INSECURE client: no verification (this is what NOT to do in real code)
    try:
        insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        insecure.minimum_version = ssl.TLSVersion.TLSv1_2
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE

        resp, ver, cip = _connect_tls(bind_host, port, insecure, "localhost", payload)
        print("INSECURE client received:", resp)
        print("INSECURE TLS version:", ver, "cipher:", cip)
    except Exception as e:
        print("INSECURE client failed:", repr(e))

    # VERIFIED client: validates cert chain + hostname
    try:
        verified = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        verified.minimum_version = ssl.TLSVersion.TLSv1_2
        verified.check_hostname = True
        verified.verify_mode = ssl.CERT_REQUIRED
        verified.load_verify_locations(cadata=cert_pem)

        resp, ver, cip = _connect_tls(bind_host, port, verified, "localhost", payload)
        print("VERIFIED client received:", resp)
        print("VERIFIED TLS version:", ver, "cipher:", cip)
    except Exception as e:
        print("VERIFIED client failed:", repr(e))

    # Hostname mismatch demo (should fail)
    try:
        verified2 = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        verified2.minimum_version = ssl.TLSVersion.TLSv1_2
        verified2.check_hostname = True
        verified2.verify_mode = ssl.CERT_REQUIRED
        verified2.load_verify_locations(cadata=cert_pem)

        _resp, _ver, _cip = _connect_tls(bind_host, port, verified2, "not-localhost", payload)
        print("UNEXPECTED: hostname mismatch did not fail")
    except Exception as e:
        print("Expected hostname-check failure:", repr(e))

    stop_evt.set()
    time.sleep(0.2)
    print()


def main() -> None:
    demo_https_introspection()
    demo_local_tls_echo()
    print("Done.")


if __name__ == "__main__":
    main()