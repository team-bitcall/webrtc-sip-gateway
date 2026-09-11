#!/usr/bin/env python3
"""Disposable, network-less SEAT routing smoke test.

This is intentionally an image-level fixture: it mounts the checkout's routing
overlay, renderer, compiler and a private generated snapshot into one isolated
gateway.  The in-container peer is both a WSS phone and a UDP carrier.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid


IN_CONTAINER_TEST = r'''
import base64, hashlib, os, re, socket, ssl, struct, threading, time, uuid

SEAT_DOMAIN = "seats.example.test"
GATEWAY_DOMAIN = "query.example.test"
UPSTREAM = 15060
LOCAL_PASSWORD = "local-pass"
failures = []
seen = [0]

def exact(s, n):
    out = b""
    while len(out) < n:
        bit = s.recv(n - len(out)); assert bit, "unexpected EOF"; out += bit
    return out
def send_frame(s, payload, opcode=1):
    payload = payload.encode() if isinstance(payload, str) else payload
    head = bytes([0x80 | opcode]); n = len(payload)
    head += bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack("!H", n)
    mask = os.urandom(4); s.sendall(head + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(payload)))
def text(s):
    while True:
        a, b = exact(s, 2); n = b & 127
        if n == 126: n = struct.unpack("!H", exact(s, 2))[0]
        elif n == 127: n = struct.unpack("!Q", exact(s, 8))[0]
        mask = exact(s, 4) if b & 128 else None; p = exact(s, n)
        if mask: p = bytes(v ^ mask[i % 4] for i, v in enumerate(p))
        if (a & 15) == 9: send_frame(s, p, 10); continue
        assert (a & 15) == 1, a; return p.decode("utf-8", "replace")
def parse(message):
    lines = message.split("\r\n"); h = {}
    for line in lines[1:]:
        if not line: break
        if ":" in line:
            key, value = line.split(":", 1); h.setdefault(key.lower(), []).append(value.strip())
    return lines[0], h
def reply(request, code, reason, challenge=None):
    _, h = parse(request); out = ["SIP/2.0 %d %s" % (code, reason)]
    out += ["Via: " + x for x in h["via"]]
    out += ["From: " + h["from"][0], "To: " + h["to"][0] + ("" if ";tag=" in h["to"][0] else ";tag=carrier"), "Call-ID: " + h["call-id"][0], "CSeq: " + h["cseq"][0]]
    if challenge: out.append(challenge)
    return ("\r\n".join(out + ["Content-Length: 0", "", ""])).encode()
def digest(method, uri, user, realm, password, nonce, qop=None, nc=None, cnonce=None):
    ha1 = hashlib.md5((user + ":" + realm + ":" + password).encode()).hexdigest()
    return digest_ha1(method, uri, ha1, nonce, qop, nc, cnonce)
def digest_ha1(method, uri, ha1, nonce, qop=None, nc=None, cnonce=None):
    ha2 = hashlib.md5((method + ":" + uri).encode()).hexdigest()
    source = ":".join((ha1, nonce, nc, cnonce, qop, ha2)) if qop else ":".join((ha1, nonce, ha2))
    return hashlib.md5(source.encode()).hexdigest()
def params(challenge):
    return {match.group(1).lower(): match.group(2) or match.group(3)
            for match in re.finditer(r'([A-Za-z]+)=(?:"([^"]*)"|([^, ]+))', challenge)}
def auth_header(method, uri, user, password, challenge, name="Authorization"):
    p = params(challenge); realm, value = p["realm"], p["nonce"]
    qop = "auth" if "auth" in p.get("qop", "") else None
    cnonce, nc = uuid.uuid4().hex, "00000001"
    response = digest(method, uri, user, realm, password, value, qop, nc, cnonce)
    fields = ['username="%s"' % user, 'realm="%s"' % realm, 'nonce="%s"' % value, 'uri="%s"' % uri, 'response="%s"' % response]
    if qop: fields += ["qop=auth", "nc=" + nc, 'cnonce="%s"' % cnonce]
    return name + ": Digest " + ", ".join(fields)
def request(method, uri, user, cseq, call_id, extra=()):
    to_uri = "sip:%s@%s" % (user, SEAT_DOMAIN) if method == "REGISTER" else uri
    contact = ("Contact: <sip:%s@browser.invalid;transport=ws>;expires=600" % user,) if method == "REGISTER" else ()
    return "\r\n".join(["%s %s SIP/2.0" % (method, uri), "Via: SIP/2.0/WSS phone.invalid;branch=z9hG4bK" + uuid.uuid4().hex + ";rport", "Max-Forwards: 16", "From: <sip:%s@%s>;tag=phone" % (user, SEAT_DOMAIN), "To: <%s>" % to_uri, "Call-ID: " + call_id, "CSeq: %d %s" % (cseq, method), *contact, *extra, "Content-Length: 0", "", ""])
def valid_digest(header, method, uri, ha1):
    p = params(header); qop = p.get("qop")
    assert p.get("username") == "upstream-a" and p.get("realm") == "carrier.example.test", p
    assert p.get("response") == digest_ha1(method, uri, ha1, p["nonce"], qop, p.get("nc"), p.get("cnonce")), p
def dialog_request(method, uri, user, cseq, call_id, to, routes):
    return "\r\n".join(["%s %s SIP/2.0" % (method, uri), "Via: SIP/2.0/WSS phone.invalid;branch=z9hG4bK" + uuid.uuid4().hex + ";rport", "Max-Forwards: 16", "From: <sip:%s@%s>;tag=phone" % (user, SEAT_DOMAIN), "To: " + to, "Call-ID: " + call_id, "CSeq: %d %s" % (cseq, method), *("Route: " + route for route in routes), "Content-Length: 0", "", ""])

def carrier():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", UPSTREAM)); s.settimeout(12)
            for index in range(2):
                invite, peer = s.recvfrom(65535); invite = invite.decode(); line, h = parse(invite)
                assert line.startswith("INVITE ") and "upstream-a" in h["from"][0], line
                assert not any(key.startswith("p-k-cseq") for key in h), h
                assert "x-bitcall-tenant" not in h and "p-asserted-identity" not in h, h
                assert "authorization" not in h and "proxy-authorization" not in h, h
                initial_cseq = int(h["cseq"][0].split()[0])
                seen[0] += 1
                challenge_name, status_code, status_reason, auth_name, qop = (("Proxy-Authenticate", 407, "Proxy Authentication Required", "proxy-authorization", "auth") if index == 0 else ("WWW-Authenticate", 401, "Unauthorized", "authorization", None))
                qop_field = ', qop="auth"' if qop else ""
                s.sendto(reply(invite, status_code, status_reason, '%s: Digest realm="carrier.example.test", nonce="upstream-%d"%s' % (challenge_name, seen[0], qop_field)), peer)
                # tm ACKs the 407 before retransmitting the authenticated INVITE.
                while True:
                    authenticated, peer = s.recvfrom(65535); authenticated = authenticated.decode(); status, h = parse(authenticated)
                    if status.startswith("INVITE ") and auth_name in h: break
                    assert status.startswith("ACK ") or status.startswith("SIP/2.0 100 "), status
                assert int(h["cseq"][0].split()[0]) == initial_cseq + 1, h
                header = h[auth_name][0]
                assert ("qop=auth" in header) == bool(qop), header
                valid_digest(header, "INVITE", status.split()[1], "6ee53e85140577a263e338faa5535881")
                record_routes = "".join("Record-Route: " + value + "\r\n" for value in h.get("record-route", []))
                answer = reply(authenticated, 200, "OK").decode().replace("Content-Length: 0", "Contact: <sip:provider@127.0.0.1:15060>\r\n" + record_routes + "Content-Length: 0").encode()
                s.sendto(answer, peer)
                while True:
                    message, peer = s.recvfrom(65535); message = message.decode(); status, h = parse(message)
                    if status.startswith("ACK "):
                        assert h["cseq"][0].split()[0] == parse(authenticated)[1]["cseq"][0].split()[0], h
                        break
                    assert status.startswith("SIP/2.0 100 "), status
                bye, peer = s.recvfrom(65535); bye = bye.decode(); status, bye_headers = parse(bye)
                assert status.startswith("BYE "), status
                assert int(bye_headers["cseq"][0].split()[0]) == initial_cseq + 2, "BYE CSeq translation failed"
                s.sendto(reply(bye, 200, "OK"), peer)
    except BaseException as exc: failures.append(exc)

t = threading.Thread(target=carrier, daemon=True); t.start()
context = ssl.create_default_context(cafile="/etc/ssl/cert.pem")
with socket.create_connection(("127.0.0.1", 443), timeout=10) as raw:
  with context.wrap_socket(raw, server_hostname=GATEWAY_DOMAIN) as ws:
    key = base64.b64encode(os.urandom(16)).decode()
    ws.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Protocol: sip\r\nOrigin: https://%s\r\n\r\n" % (GATEWAY_DOMAIN, key, GATEWAY_DOMAIN)).encode())
    headers = b""
    while b"\r\n\r\n" not in headers: headers += exact(ws, 1)
    assert b" 101 " in headers.split(b"\r\n", 1)[0], headers[:100]
    def challenged(method, uri, user, password, cseq, call, from_user=None, extra=()):
        send_frame(ws, request(method, uri, from_user or user, cseq, call, extra))
        status, h = parse(text(ws)); expected, challenge = ("401", "www-authenticate") if method == "REGISTER" else ("407", "proxy-authenticate")
        assert status.startswith("SIP/2.0 " + expected + " "), status
        name = "Authorization" if method == "REGISTER" else "Proxy-Authorization"
        send_frame(ws, request(method, uri, from_user or user, cseq + 1, call, extra + (auth_header(method, uri, user, password, h[challenge][0], name),)))
        while True:
            result = parse(text(ws))
            if int(result[0].split()[1]) >= 200:
                return result
    # Bad credentials, unknown users, revoked users, and header/user mismatch stay local.
    call = uuid.uuid4().hex + "@phone.invalid"
    status, _ = challenged("REGISTER", "sip:" + SEAT_DOMAIN, "alice", "wrong", 1, call); assert status.startswith("SIP/2.0 401 "), status
    send_frame(ws, request("REGISTER", "sip:" + SEAT_DOMAIN, "nobody", 3, call)); status, _ = parse(text(ws)); assert status.startswith("SIP/2.0 403 "), status
    send_frame(ws, request("REGISTER", "sip:" + SEAT_DOMAIN, "revoked", 4, call)); status, _ = parse(text(ws)); assert status.startswith("SIP/2.0 403 "), status
    for bad_domain in ("SEATS.EXAMPLE.TEST", "seats.example.test."):
        send_frame(ws, request("REGISTER", "sip:" + SEAT_DOMAIN, "nobody", 4, call).replace(SEAT_DOMAIN, bad_domain)); status, _ = parse(text(ws)); assert status.startswith("SIP/2.0 403 "), status
    status, _ = challenged("REGISTER", "sip:" + SEAT_DOMAIN, "alice", LOCAL_PASSWORD, 5, call, from_user="bob"); assert status.startswith("SIP/2.0 401 "), status
    time.sleep(.2); assert seen[0] == 0, seen
    # Owner and agent each complete a local REGISTER, then an INVITE through one profile.
    for user, password, cseq in (("alice", LOCAL_PASSWORD, 10), ("bob", "other-pass", 20)):
        call = uuid.uuid4().hex + "@phone.invalid"
        status, reg_headers = challenged("REGISTER", "sip:" + SEAT_DOMAIN, user, password, cseq, call); assert status.startswith("SIP/2.0 200 "), status
        assert len(reg_headers.get("contact", [])) == 1 and reg_headers["contact"][0].startswith("<sip:%s@browser.invalid;transport=ws>;expires=600" % user), "local Contact was not retained"
        uri = "sip:18005550100@" + SEAT_DOMAIN
        status, reply_headers = challenged("INVITE", uri, user, password, cseq + 2, call, extra=("Contact: <sip:phone@browser.invalid;transport=ws>", "P-K-CSeq-Auth: 9999", "P-K-CSeq-Refresh: 9999", "X-Bitcall-Tenant: forged", "P-Asserted-Identity: <sip:forged@example.test>")); assert status.startswith("SIP/2.0 200 "), status
        assert reply_headers["cseq"] == ["%d INVITE" % (cseq + 3)], reply_headers
        assert "contact" in reply_headers and "record-route" in reply_headers, reply_headers
        target = reply_headers["contact"][0].split("<", 1)[1].split(">", 1)[0]
        to = reply_headers["to"][0]
        routes = list(reversed(reply_headers["record-route"]))
        send_frame(ws, dialog_request("ACK", target, user, cseq + 3, call, to, routes))
        send_frame(ws, dialog_request("BYE", target, user, cseq + 4, call, to, routes))
        status, _ = parse(text(ws)); assert status.startswith("SIP/2.0 200 "), status
t.join(3); assert not t.is_alive(), "carrier did not complete"
if failures: raise failures[0]
print("PASS local denial isolation")
print("PASS owner password-profile upstream digest")
print("PASS agent HA1-profile upstream digest")
print("PASS CSeq and identity-header isolation")
'''


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs)


def diagnostic_logs(name):
    output = run("docker", "logs", "--tail", "100", name, stderr=subprocess.STDOUT)
    keep = (line for line in output.splitlines()
            if "ERROR" in line or "CRITICAL" in line or "kamailio-cfg: invalid" in line)
    return "\n".join(keep)


def snapshot():
    ha1 = __import__("hashlib").md5(b"alice:seats.example.test:local-pass").hexdigest()
    return {"schemaVersion": 1, "revision": 1, "issuedAt": int(time.time()), "validUntil": int(time.time()) + 240,
            "domain": "seats.example.test",
            "profiles": [{"id": "profile-a", "tenantId": "tenant-a", "enabled": True, "username": "upstream-a", "realm": "carrier.example.test", "requestDomain": "carrier.example.test", "outboundProxy": "sip:127.0.0.1:15060;transport=udp", "credential": {"kind": "password", "value": "carrier-pass"}, "fromUser": "upstream-a"}, {"id": "profile-b", "tenantId": "tenant-a", "enabled": True, "username": "upstream-a", "realm": "carrier.example.test", "requestDomain": "carrier.example.test", "outboundProxy": "sip:127.0.0.1:15060;transport=udp", "credential": {"kind": "ha1", "value": "6ee53e85140577a263e338faa5535881"}, "fromUser": "upstream-a"}],
            "seats": [{"id": "alice-seat", "tenantId": "tenant-a", "username": "alice", "profileId": "profile-a", "enabled": True, "ha1": ha1}, {"id": "bob-seat", "tenantId": "tenant-a", "username": "bob", "profileId": "profile-b", "enabled": True, "ha1": __import__("hashlib").md5(b"bob:seats.example.test:other-pass").hexdigest()}, {"id": "revoked-seat", "tenantId": "tenant-a", "username": "revoked", "profileId": "profile-a", "enabled": False, "ha1": ha1}]}


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--gateway-root", type=Path, default=root)
    parser.add_argument("--source-overlay", action="store_true")
    args = parser.parse_args()
    root = args.gateway_root.resolve()
    files = {"config": root / "docker/kamailio/kamailio.cfg", "seat config": root / "docker/kamailio/seat-routing.cfg", "renderer": root / "docker/rootfs/etc/cont-init.d/07-render-kamailio-cfg", "compiler": root / "docker/seat/compile_snapshot.py"}
    if args.source_overlay and any(not path.is_file() for path in files.values()):
        parser.error("source overlay is incomplete")
    name = "bitcall-seat-routing-" + uuid.uuid4().hex[:12]
    created = False
    with tempfile.TemporaryDirectory(prefix="bitcall-seat-routing-") as temp:
        temp = Path(temp); cert, key, state = temp / "cert.pem", temp / "key.pem", temp / "seats.json"
        state.write_text(json.dumps(snapshot()), encoding="utf-8"); state.chmod(0o600)
        (temp / "rtpengine.conf").write_text("[rtpengine]\n")
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1", "-nodes", "-subj", "/CN=query.example.test", "-addext", "subjectAltName=DNS:query.example.test", "-keyout", str(key), "-out", str(cert), stderr=subprocess.DEVNULL)
        renderer_copy = temp / "07-render-kamailio-cfg"
        if args.source_overlay:
            shutil.copyfile(files["renderer"], renderer_copy)
            renderer_copy.chmod(0o755)
        mounts = []
        if args.source_overlay:
            mounts = ["-v", f"{files['config']}:/etc/kamailio/kamailio.cfg:ro", "-v", f"{files['seat config']}:/etc/kamailio/seat-routing.cfg:ro", "-v", f"{renderer_copy}:/etc/cont-init.d/07-render-kamailio-cfg:ro", "-v", f"{files['compiler']}:/opt/bitcall/compile_seat_snapshot.py:ro"]
        try:
            run("docker", "run", "-d", "--name", name, "--network", "none", "--read-only", "--tmpfs", "/run:rw,exec,size=128m", "--tmpfs", "/tmp:rw,size=64m", "--cpus", "1", "--memory", "512m", "--pids-limit", "256", "--security-opt", "no-new-privileges:true", "-e", "DOMAIN=query.example.test", "-e", "PRIVATE_IP=127.0.0.1", "-e", "PUBLIC_IP=127.0.0.1", "-e", "WEBPHONE_ORIGIN=https://query.example.test", "-e", "SEAT_DOMAIN=seats.example.test", "-e", "SEAT_MODE=local", "-e", "SEAT_SNAPSHOT_FILE=/etc/bitcall/seats.json", "-v", f"{state}:/etc/bitcall/seats.json:ro", "-v", f"{cert}:/etc/ssl/cert.pem:ro", "-v", f"{key}:/etc/ssl/key.pem:ro", "-v", f"{temp / 'rtpengine.conf'}:/etc/rtpengine/rtpengine.conf:ro", *mounts, args.image)
            created = True; deadline = time.monotonic() + 35
            while True:
                try:
                    run("docker", "exec", name, "sh", "-ec", "pgrep -x kamailio >/dev/null && ss -ltn | grep -q ':443 '", stderr=subprocess.DEVNULL); break
                except subprocess.CalledProcessError:
                    if time.monotonic() >= deadline: raise RuntimeError("gateway did not become ready")
                    time.sleep(.5)
            print(run("docker", "exec", "-i", name, "python3", "-", input=IN_CONTAINER_TEST, timeout=25).strip())
        except Exception:
            if created:
                diagnostics = diagnostic_logs(name)
                if diagnostics:
                    print(diagnostics)
            raise
        finally:
            if created: run("docker", "rm", "-f", name, stderr=subprocess.DEVNULL)


if __name__ == "__main__": main()
