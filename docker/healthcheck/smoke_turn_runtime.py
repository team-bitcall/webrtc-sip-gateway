#!/usr/bin/env python3
"""Test the changed credential helper and Kamailio route in isolated containers.

Tests packaged image contents unless --source-overlay is explicitly requested.
Requires Docker and openssl. Publishes no ports and uses --network none.
Only temporary containers created by this invocation are removed.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid


WSS_STRESS_SCRIPT = r'''
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
import socket
import ssl

context = ssl.create_default_context(cafile="/etc/ssl/cert.pem")

def handshake(_):
    key = base64.b64encode(os.urandom(16)).decode()
    expected_accept = base64.b64encode(hashlib.sha1(
        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
    with socket.create_connection(("127.0.0.1", 443), timeout=2) as raw:
        with context.wrap_socket(raw, server_hostname="relay.example.test") as sock:
            sock.sendall(("GET / HTTP/1.1\r\nHost: relay.example.test\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Protocol: sip\r\n"
                "Origin: https://phone.example.test\r\n\r\n").encode())
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = sock.recv(4096)
                assert chunk, "EOF during WebSocket upgrade"
                response += chunk
                assert len(response) <= 16384, "Oversized upgrade response"
            header, pending = response.split(b"\r\n\r\n", 1)
            lines = header.decode().split("\r\n")
            assert lines[0].startswith("HTTP/1.1 101 "), lines[0]
            headers = dict((k.lower(), v.strip()) for k, v in
                           (line.split(":", 1) for line in lines[1:]))
            assert headers.get("sec-websocket-accept") == expected_accept
            assert headers.get("sec-websocket-protocol") == "sip"
            # Client control frames must be masked; 1000 is normal closure.
            mask, payload = os.urandom(4), b"\x03\xe8"
            sock.sendall(b"\x88\x82" + mask + bytes(
                value ^ mask[index % 4] for index, value in enumerate(payload)))
            while len(pending) < 2:
                chunk = sock.recv(128)
                assert chunk, "EOF before WebSocket close reply"
                pending += chunk
            assert pending[0] == 0x88 and pending[1] <= 125, "Expected unmasked close reply"
            while len(pending) < 2 + pending[1]:
                chunk = sock.recv(128)
                assert chunk, "Truncated WebSocket close reply"
                pending += chunk

with ThreadPoolExecutor(max_workers=4) as pool:
    list(pool.map(handshake, range(24), timeout=15))
print("24 verified TLS/WSS upgrades and normal closes (concurrency 4)")
'''


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True, help="Already available gateway image")
    parser.add_argument("--source-overlay", action="store_true",
                        help="Mount checkout config/helper over a baseline image for source-only testing")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    source_mounts = []
    if args.source_overlay:
        source_mounts = [
            "-v", f"{root / 'kamailio/kamailio.cfg'}:/etc/kamailio/kamailio.cfg:ro",
            "-v", f"{root / 'healthcheck/healthcheck_server.py'}:/opt/bitcall/healthcheck_server.py:ro",
        ]
    with tempfile.TemporaryDirectory(prefix="bitcall-turn-smoke-") as tmp:
        cert, key = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
        # The packaged RTPengine config expects a default network interface;
        # this test deliberately has only loopback. Use the run script's
        # explicit interface/port flags instead of package defaults.
        rtp_config = Path(tmp) / "rtpengine.conf"
        rtp_config.write_text("[rtpengine]\n")
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1",
            "-nodes", "-subj", "/CN=relay.example.test",
            "-addext", "subjectAltName=DNS:relay.example.test",
            "-keyout", str(key), "-out", str(cert),
            stderr=subprocess.DEVNULL)
        for mode, ttl, helper_expected, expected in [
                ("coturn", "3600", 200, 200), ("none", "3600", 404, 404), ("coturn", "0", 503, 502)]:
            name = "bitcall-turn-contract-" + uuid.uuid4().hex[:12]
            created = False
            try:
                run("docker", "run", "-d", "--name", name, "--network", "none",
                    "--add-host", "relay.example.test:127.0.0.1",
                    "--read-only", "--tmpfs", "/run:rw,exec,size=128m", "--tmpfs", "/tmp:rw,size=64m",
                    "--cpus", "1", "--memory", "512m", "--pids-limit", "256",
                    "--security-opt", "no-new-privileges:true",
                    "-e", "DOMAIN=relay.example.test", "-e", "PRIVATE_IP=127.0.0.1",
                    "-e", "PUBLIC_IP=127.0.0.1", "-e", "ALLOWED_SIP_DOMAINS=",
                    "-e", "TURN_SECRET=smoke-only-not-a-real-secret", "-e", "TURN_API_TOKEN=smoke-only-token",
                    "-e", "WEBPHONE_ORIGIN=https://phone.example.test",
                    "-e", "TURN_MODE=" + mode, "-e", "TURN_TTL=" + ttl,
                    "-v", f"{cert}:/etc/ssl/cert.pem:ro", "-v", f"{key}:/etc/ssl/key.pem:ro",
                    "-v", f"{rtp_config}:/etc/rtpengine/rtpengine.conf:ro",
                    *source_mounts,
                    args.image)
                created = True

                def request(path="/turn-credentials", method="GET", auth=True, origin=None):
                    # -k applies only to this disposable self-signed certificate.
                    cmd = ["docker", "exec", name, "curl", "-sk", "--connect-timeout", "1",
                           "--max-time", "3", "-D", "-", "-X", method]
                    if auth:
                        cmd += ["-H", "Authorization: Bearer smoke-only-token"]
                    if origin:
                        cmd += ["-H", "Origin: " + origin]
                    output = run(*cmd, "https://127.0.0.1" + path, stderr=subprocess.DEVNULL)
                    headers, body = output.replace("\r\n", "\n").split("\n\n", 1)
                    return int(headers.splitlines()[0].split()[1]), headers.lower(), body

                deadline = time.monotonic() + 30
                while True:
                    try:
                        helper_status = int(run("docker", "exec", name, "curl", "-s",
                            "--connect-timeout", "1", "--max-time", "2", "-o", "/dev/null", "-w", "%{http_code}",
                            "http://127.0.0.1:8880/turn-credentials", stderr=subprocess.DEVNULL))
                        if helper_status == helper_expected:
                            break
                    except subprocess.CalledProcessError:
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Credential helper did not reach its expected state")
                    time.sleep(0.5)
                deadline = time.monotonic() + 30
                while True:
                    try:
                        status, headers, body = request()
                        break
                    except subprocess.CalledProcessError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Isolated gateway did not start")
                        time.sleep(0.5)
                assert status == expected, (mode, ttl, status, expected)
                assert request(auth=False)[0] == 401
                assert request(method="POST")[0] == 405
                assert request(path="/turn-credentials-extra")[0] == 404
                assert request(origin="https://untrusted.example.test")[0] == 403
                if expected == 200:
                    data = json.loads(body)
                    assert data["expiresAt"] == int(data["username"].split(":")[0])
                    assert data["username"].endswith(":webrtc"), data["username"]
                    assert "cache-control: private, no-store" in headers
                    assert len(data["uris"]) == 3
                    assert 3500 <= data["expiresAt"] - time.time() <= 3600
                    scope = "t_" + "a" * 64
                    scoped_status, scoped_headers, scoped_body = request(
                        path="/turn-credentials?scope=" + scope)
                    assert scoped_status == 200
                    scoped = json.loads(scoped_body)
                    assert scoped["username"].endswith(":" + scope), scoped["username"]
                    assert scoped["username"].split(":", 1)[0] == str(scoped["expiresAt"])
                    assert scoped["username"] != data["username"]
                    assert "cache-control: private, no-store" in scoped_headers
                    assert request(path="/turn-credentials?scope=not-a-member")[0] == 400
                    assert request(path="/turn-credentials?scope=" + scope + "&scope=" + scope)[0] == 400
                    assert request(path="/turn-credentials?scope=" + scope, auth=False)[0] == 401
                    pids_before = sorted(run("docker", "exec", name, "pgrep", "-x", "kamailio").split())
                    print(run("docker", "exec", name, "python3", "-c", WSS_STRESS_SCRIPT,
                              timeout=18).strip(), flush=True)
                    assert request()[0] == 200, "Credential route failed after TLS/WSS stress"
                    pids_after = sorted(run("docker", "exec", name, "pgrep", "-x", "kamailio").split())
                    assert pids_before and pids_before == pids_after, "Kamailio processes restarted during TLS/WSS stress"
                    run("docker", "stop", "--time", "10", name, timeout=15)
                    state = json.loads(run("docker", "inspect", "--format", "{{json .State}}", name))
                    assert state["ExitCode"] == 0 and not state["OOMKilled"], state
                    logs = run("docker", "logs", name, stderr=subprocess.STDOUT)
                    assert not re.search(r"segfault|segmentation fault|core dumped|double free|"
                                         r"corrupted (?:size|double-linked)|malloc\(\):|free\(\):|"
                                         r"\bSIG(?:SEGV|ABRT)\b|\bsignal\s*[:=]?\s*(?:6|11)\b",
                                         logs, re.IGNORECASE), "Crash signature in gateway logs"
                    print("PASS stable Kamailio processes, post-stress credentials, and graceful shutdown", flush=True)
                print(f"PASS mode={mode} ttl={ttl}: legacy and scoped credentials; auth/method/path/origin guards", flush=True)
            except Exception:
                if created:
                    print(run("docker", "logs", "--tail", "80", name, stderr=subprocess.STDOUT), flush=True)
                raise
            finally:
                if created:
                    run("docker", "rm", "-f", name, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
