#!/usr/bin/env python3
"""Test the changed credential helper and Kamailio route in isolated containers.

Requires Docker and openssl. Publishes no ports and uses --network none.
Only temporary containers created by this invocation are removed.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True, help="Already available gateway image")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="bitcall-turn-smoke-") as tmp:
        cert, key = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
        # The packaged RTPengine config expects a default network interface;
        # this test deliberately has only loopback. Use the run script's
        # explicit interface/port flags instead of package defaults.
        rtp_config = Path(tmp) / "rtpengine.conf"
        rtp_config.write_text("[rtpengine]\n")
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1",
            "-nodes", "-subj", "/CN=relay.example.test", "-keyout", str(key), "-out", str(cert),
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
                    "-v", f"{root / 'kamailio/kamailio.cfg'}:/etc/kamailio/kamailio.cfg:ro",
                    "-v", f"{root / 'healthcheck/healthcheck_server.py'}:/opt/bitcall/healthcheck_server.py:ro",
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
                    assert "cache-control: private, no-store" in headers
                    assert len(data["uris"]) == 3
                    assert 3500 <= data["expiresAt"] - time.time() <= 3600
                print(f"PASS mode={mode} ttl={ttl}: status={status}; auth/method/path/origin guards", flush=True)
            except Exception:
                if created:
                    print(run("docker", "logs", "--tail", "80", name, stderr=subprocess.STDOUT), flush=True)
                raise
            finally:
                if created:
                    run("docker", "rm", "-f", name, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
