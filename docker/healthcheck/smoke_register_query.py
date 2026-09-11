#!/usr/bin/env python3
"""Exercise Contact-less REGISTER routing in a disposable gateway container.

The fixture uses only loopback and generated identities. It proves that:
* a normal REGISTER with compact `m` still creates a local WS binding and is
  rewritten to the gateway Contact upstream;
* a Contact-less REGISTER reaches the upstream fixture without Contact;
* an upstream 403 for that query does not remove the existing local binding.
"""

import argparse
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


IN_CONTAINER_TEST = r'''
import base64
import hashlib
import os
import socket
import ssl
import struct
import threading
import uuid

DOMAIN = "query.example.test"
UPSTREAM_PORT = 15060

def read_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        assert chunk, "unexpected EOF"
        data += chunk
    return data

def send_frame(sock, payload, opcode=1):
    payload = payload if isinstance(payload, bytes) else payload.encode()
    header = bytes([0x80 | opcode])
    if len(payload) < 126:
        header += bytes([0x80 | len(payload)])
    else:
        header += bytes([0x80 | 126]) + struct.pack("!H", len(payload))
    mask = os.urandom(4)
    sock.sendall(header + mask + bytes(
        value ^ mask[index % 4] for index, value in enumerate(payload)))

def read_frame(sock):
    first, second = read_exact(sock, 2)
    length = second & 127
    if length == 126:
        length = struct.unpack("!H", read_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(sock, 8))[0]
    mask = read_exact(sock, 4) if second & 128 else None
    payload = read_exact(sock, length)
    if mask:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return first & 15, payload

def read_text(sock):
    while True:
        opcode, payload = read_frame(sock)
        if opcode == 9:
            send_frame(sock, payload, 10)
            continue
        assert opcode == 1, f"unexpected WebSocket opcode {opcode}"
        return payload.decode("utf-8", "replace")

def parse(message):
    lines = message.split("\r\n")
    headers = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers.setdefault(name.lower(), []).append(value.strip())
    return lines[0], headers

def response_for(request, status, reason, include_contact=False):
    _, headers = parse(request)
    lines = [f"SIP/2.0 {status} {reason}"]
    lines += [f"Via: {value}" for value in headers["via"]]
    lines += [
        f"From: {headers['from'][0]}",
        f"To: {headers['to'][0]};tag=fixture",
        f"Call-ID: {headers['call-id'][0]}",
        f"CSeq: {headers['cseq'][0]}",
    ]
    if include_contact:
        lines.append(f"Contact: {headers['contact'][0]}")
    return "\r\n".join(lines + ["Content-Length: 0", "", ""]).encode()

failures = []
def upstream():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", UPSTREAM_PORT))
            sock.settimeout(8)
            normal, peer = sock.recvfrom(65535)
            normal = normal.decode("utf-8", "replace")
            line, headers = parse(normal)
            assert line == f"REGISTER sip:{DOMAIN} SIP/2.0", line
            assert "contact" in headers and "m" not in headers, headers.keys()
            assert headers["contact"] == [f"<sip:alice@{DOMAIN}:5060;transport=udp>"], headers["contact"]
            sock.sendto(response_for(normal, 200, "OK", include_contact=True), peer)

            query, peer = sock.recvfrom(65535)
            query = query.decode("utf-8", "replace")
            line, headers = parse(query)
            assert line == f"REGISTER sip:{DOMAIN} SIP/2.0", line
            assert "contact" not in headers and "m" not in headers, headers.keys()
            assert "expires" not in headers, headers.keys()
            sock.sendto(response_for(query, 403, "Forbidden"), peer)

            invite_id = uuid.uuid4().hex
            invite = "\r\n".join([
                f"INVITE sip:alice@{DOMAIN} SIP/2.0",
                f"Via: SIP/2.0/UDP 127.0.0.1:{UPSTREAM_PORT};branch=z9hG4bK{invite_id};rport",
                "Max-Forwards: 16",
                f"From: <sip:caller@provider.invalid>;tag={invite_id}",
                f"To: <sip:alice@{DOMAIN}>",
                f"Call-ID: {invite_id}@provider.invalid",
                "CSeq: 1 INVITE",
                f"Contact: <sip:caller@127.0.0.1:{UPSTREAM_PORT}>",
                "Content-Length: 0", "", "",
            ]).encode()
            sock.sendto(invite, ("127.0.0.1", 5060))

            while True:
                next_normal, peer = sock.recvfrom(65535)
                # The gateway transaction sends 100 Trying for the fixture's
                # INVITE back to this same socket before the client re-registers.
                if next_normal.startswith(b"REGISTER "):
                    break
                assert next_normal.startswith(b"SIP/2.0 "), next_normal[:80]
            next_normal = next_normal.decode("utf-8", "replace")
            line, headers = parse(next_normal)
            assert line == f"REGISTER sip:{DOMAIN} SIP/2.0", line
            assert headers.get("contact") == [f"<sip:alice@{DOMAIN}:5060;transport=udp>"], headers.get("contact")
            sock.sendto(response_for(next_normal, 200, "OK", include_contact=True), peer)
    except BaseException as exc:
        failures.append(exc)

thread = threading.Thread(target=upstream, daemon=True)
thread.start()

context = ssl.create_default_context(cafile="/etc/ssl/cert.pem")
with socket.create_connection(("127.0.0.1", 443), timeout=8) as raw:
    with context.wrap_socket(raw, server_hostname=DOMAIN) as sock:
        key = base64.b64encode(os.urandom(16)).decode()
        upgrade = "\r\n".join([
            "GET / HTTP/1.1", f"Host: {DOMAIN}", "Connection: Upgrade",
            "Upgrade: websocket", "Sec-WebSocket-Version: 13",
            f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Protocol: sip",
            f"Origin: https://{DOMAIN}", "", "",
        ])
        sock.sendall(upgrade.encode())
        answer = b""
        while b"\r\n\r\n" not in answer:
            answer += read_exact(sock, 1)
        assert b" 101 " in answer.split(b"\r\n", 1)[0], answer[:100]

        call_id = f"{uuid.uuid4().hex}@client.invalid"
        tag = uuid.uuid4().hex
        normal = "\r\n".join([
            f"REGISTER sip:{DOMAIN} SIP/2.0",
            f"Via: SIP/2.0/WSS client.invalid;branch=z9hG4bK{uuid.uuid4().hex};rport",
            "Max-Forwards: 16", f"From: <sip:alice@{DOMAIN}>;tag={tag}",
            f"To: <sip:alice@{DOMAIN}>", f"Call-ID: {call_id}",
            "CSeq: 1 REGISTER",
            "m: <sip:alice@client.invalid;transport=ws>;expires=600",
            "Content-Length: 0", "", "",
        ])
        send_frame(sock, normal)
        status, headers = parse(read_text(sock))
        assert status.startswith("SIP/2.0 200 "), status
        assert headers.get("contact") == ["<sip:alice@client.invalid;transport=ws>;expires=600"], headers.get("contact")

        query = "\r\n".join([
            f"REGISTER sip:{DOMAIN} SIP/2.0",
            f"Via: SIP/2.0/WSS client.invalid;branch=z9hG4bK{uuid.uuid4().hex};rport",
            "Max-Forwards: 16", f"From: <sip:alice@{DOMAIN}>;tag={tag}",
            f"To: <sip:alice@{DOMAIN}>", f"Call-ID: {call_id}",
            "CSeq: 2 REGISTER", "Content-Length: 0", "", "",
        ])
        send_frame(sock, query)
        status, _ = parse(read_text(sock))
        assert status.startswith("SIP/2.0 403 "), status

        request, _ = parse(read_text(sock))
        assert request.startswith(f"INVITE sip:alice@") and "SIP/2.0" in request, request

        next_normal = "\r\n".join([
            f"REGISTER sip:{DOMAIN} SIP/2.0",
            f"Via: SIP/2.0/WSS client.invalid;branch=z9hG4bK{uuid.uuid4().hex};rport",
            "Max-Forwards: 16", f"From: <sip:alice@{DOMAIN}>;tag={tag}",
            f"To: <sip:alice@{DOMAIN}>", f"Call-ID: {call_id}",
            "CSeq: 3 REGISTER",
            "Contact: <sip:alice@client.invalid;transport=ws>;expires=600",
            "Content-Length: 0", "", "",
        ])
        send_frame(sock, next_normal)
        status, headers = parse(read_text(sock))
        assert status.startswith("SIP/2.0 200 "), status
        assert headers.get("contact") == ["<sip:alice@client.invalid;transport=ws>;expires=600"], headers.get("contact")

thread.join(timeout=2)
assert not thread.is_alive(), "upstream fixture did not finish"
if failures:
    raise failures[0]
print("PASS compact normal REGISTER rewrite/restore and local binding")
print("PASS Contact-less query forwarded without Contact or Expires")
print("PASS query 403 preserved local binding for subsequent upstream INVITE")
print("PASS next normal REGISTER retained existing upstream Contact rewrite/restore")
'''


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs)


def main():
    default_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Already available gateway image")
    parser.add_argument("--gateway-root", type=Path, default=default_root)
    parser.add_argument("--source-overlay", action="store_true",
                        help="Mount checkout Kamailio config over an older image")
    args = parser.parse_args()
    config = args.gateway_root.resolve() / "docker/kamailio/kamailio.cfg"
    if args.source_overlay and not config.is_file():
        parser.error(f"gateway config not found: {config}")
    source_mount = (["-v", f"{config}:/etc/kamailio/kamailio.cfg:ro"]
                    if args.source_overlay else [])

    name = "bitcall-register-query-" + uuid.uuid4().hex[:12]
    created = False
    with tempfile.TemporaryDirectory(prefix="bitcall-register-query-") as tmp:
        tmp = Path(tmp)
        cert, key = tmp / "cert.pem", tmp / "key.pem"
        rtp_config = tmp / "rtpengine.conf"
        rtp_config.write_text("[rtpengine]\n")
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1",
            "-nodes", "-subj", "/CN=query.example.test",
            "-addext", "subjectAltName=DNS:query.example.test",
            "-keyout", str(key), "-out", str(cert), stderr=subprocess.DEVNULL)
        try:
            run("docker", "run", "-d", "--name", name, "--network", "none",
                "--read-only", "--tmpfs", "/run:rw,exec,size=128m",
                "--tmpfs", "/tmp:rw,size=64m", "--cpus", "1", "--memory", "512m",
                "--pids-limit", "256", "--security-opt", "no-new-privileges:true",
                "-e", "DOMAIN=query.example.test", "-e", "PRIVATE_IP=127.0.0.1",
                "-e", "PUBLIC_IP=127.0.0.1", "-e", "ROUTING_MODE=single-provider",
                "-e", "SIP_PROVIDER_URI=sip:127.0.0.1:15060;transport=udp",
                "-e", "ALLOWED_SIP_DOMAINS=query.example.test",
                "-e", "WEBPHONE_ORIGIN=https://query.example.test",
                "-v", f"{cert}:/etc/ssl/cert.pem:ro", "-v", f"{key}:/etc/ssl/key.pem:ro",
                "-v", f"{rtp_config}:/etc/rtpengine/rtpengine.conf:ro",
                *source_mount, args.image)
            created = True
            deadline = time.monotonic() + 35
            while True:
                try:
                    run("docker", "exec", name, "sh", "-ec",
                        "pgrep -x kamailio >/dev/null && ss -ltn | grep -q ':443 '",
                        stderr=subprocess.DEVNULL)
                    break
                except subprocess.CalledProcessError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("disposable gateway did not become ready")
                    time.sleep(0.5)
            print(run("docker", "exec", "-i", name, "python3", "-",
                      input=IN_CONTAINER_TEST, timeout=20).strip())
        except Exception:
            if created:
                print(run("docker", "logs", "--tail", "100", name,
                          stderr=subprocess.STDOUT))
            raise
        finally:
            if created:
                run("docker", "rm", "-f", name, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
