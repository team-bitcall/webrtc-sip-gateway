#!/usr/bin/env python3
"""Bounded real-wire dialog and failure cases for local SEAT routing.

Run this separately from ``smoke_seat_routing.py``. It starts its own
network-less container and exercises authentication retries, both dialog
directions, connection pinning, retransmission, cancellation, and lease expiry.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

from smoke_seat_routing import diagnostic_logs, run, snapshot


IN_CONTAINER_TEST = r'''
import base64, hashlib, os, re, socket, ssl, struct, threading, time, uuid

SEAT_DOMAIN = "seats.example.test"
GATEWAY_DOMAIN = "query.example.test"
UPSTREAM_PORT = 15060
LOCAL_PASSWORD = "local-pass"
failures = []
failure_case_done = [threading.Event(), threading.Event()]
retransmit_sent = threading.Event()
expiry_ready = threading.Event()
timeout_case_done = threading.Event()
LEASE_UNTIL = int(os.environ["FIXTURE_VALID_UNTIL"])

def exact(sock, size):
    data = b""
    while len(data) < size:
        try:
            chunk = sock.recv(size - len(data))
        except socket.timeout:
            if failures: raise failures[0]
            raise
        assert chunk, "unexpected EOF"; data += chunk
    return data
def frame_send(sock, value, opcode=1):
    value = value.encode() if isinstance(value, str) else value
    size = len(value); head = bytes([0x80 | opcode])
    head += bytes([0x80 | size]) if size < 126 else bytes([0x80 | 126]) + struct.pack("!H", size)
    mask = os.urandom(4); sock.sendall(head + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(value)))
def frame_text(sock):
    while True:
        first, second = exact(sock, 2); size = second & 127
        if size == 126: size = struct.unpack("!H", exact(sock, 2))[0]
        mask = exact(sock, 4) if second & 128 else None; value = exact(sock, size)
        if mask: value = bytes(v ^ mask[i % 4] for i, v in enumerate(value))
        if (first & 15) == 9: frame_send(sock, value, 10); continue
        assert (first & 15) == 1; return value.decode("utf-8", "replace")
def parse(message):
    lines, headers = message.split("\r\n"), {}
    for line in lines[1:]:
        if not line: break
        if ":" in line:
            key, value = line.split(":", 1); headers.setdefault(key.lower(), []).append(value.strip())
    return lines[0], headers
def params(value):
    return {m.group(1).lower(): m.group(2) or m.group(3) for m in re.finditer(r'([A-Za-z]+)=(?:"([^"]*)"|([^, ]+))', value)}
def response(request, code, reason, challenge):
    _, h = parse(request)
    lines = ["SIP/2.0 %d %s" % (code, reason)]
    lines += ["Via: " + value for value in h["via"]]
    to = h["to"][0] + ("" if ";tag=" in h["to"][0] else ";tag=edge")
    lines += ["From: " + h["from"][0], "To: " + to, "Call-ID: " + h["call-id"][0], "CSeq: " + h["cseq"][0]]
    if challenge: lines.append(challenge)
    lines += ["Content-Length: 0", "", ""]
    return "\r\n".join(lines).encode()
def browser_response(request, code, reason):
    _, h = parse(request)
    lines = ["SIP/2.0 %d %s" % (code, reason)]
    lines += ["Via: " + value for value in h["via"]]
    lines += ["From: " + h["from"][0], "To: " + h["to"][0], "Call-ID: " + h["call-id"][0], "CSeq: " + h["cseq"][0], "Content-Length: 0", "", ""]
    return "\r\n".join(lines)
def local_auth(method, uri, challenge):
    p = params(challenge); cnonce, nc = uuid.uuid4().hex, "00000001"
    ha1 = hashlib.md5(("alice:" + p["realm"] + ":" + LOCAL_PASSWORD).encode()).hexdigest()
    ha2 = hashlib.md5((method + ":" + uri).encode()).hexdigest()
    value = hashlib.md5((ha1 + ":" + p["nonce"] + ":" + nc + ":" + cnonce + ":auth:" + ha2).encode()).hexdigest()
    return 'Proxy-Authorization: Digest username="alice", realm="%s", nonce="%s", uri="%s", response="%s", qop=auth, nc=%s, cnonce="%s"' % (p["realm"], p["nonce"], uri, value, nc, cnonce)
def request(uri, call, cseq, auth=None, branch=None, method="INVITE"):
    branch = branch or "z9hG4bK" + uuid.uuid4().hex
    lines = ["%s %s SIP/2.0" % (method, uri), "Via: SIP/2.0/WSS edge.invalid;branch=" + branch + ";rport", "Max-Forwards: 16", "From: <sip:alice@%s>;tag=edge" % SEAT_DOMAIN, "To: <%s>" % uri, "Call-ID: " + call, "CSeq: %d %s" % (cseq, method)]
    if method == "INVITE":
        lines.append("Contact: <sip:alice@browser.invalid;transport=ws>")
    if auth: lines.append(auth)
    return "\r\n".join(lines + ["Content-Length: 0", "", ""])
def dialog_request(method, uri, call, cseq, to, routes, branch=None):
    branch = branch or "z9hG4bK" + uuid.uuid4().hex
    lines = ["%s %s SIP/2.0" % (method, uri), "Via: SIP/2.0/WSS edge.invalid;branch=" + branch + ";rport", "Max-Forwards: 16", "From: <sip:alice@%s>;tag=edge" % SEAT_DOMAIN, "To: " + to, "Call-ID: " + call, "CSeq: %d %s" % (cseq, method)]
    lines += ["Route: " + value for value in routes]
    if method == "INVITE": lines.append("Contact: <sip:alice@browser.invalid;transport=ws>")
    return "\r\n".join(lines + ["Content-Length: 0", "", ""])
def carrier_dialog_request(method, uri, call, cseq, from_value, to_value, routes, branch=None):
    branch = branch or "z9hG4bK" + uuid.uuid4().hex
    lines = ["%s %s SIP/2.0" % (method, uri), "Via: SIP/2.0/UDP 127.0.0.1:%d;branch=%s;rport" % (UPSTREAM_PORT, branch),
             "Max-Forwards: 16", "From: " + from_value, "To: " + to_value,
             "Call-ID: " + call, "CSeq: %d %s" % (cseq, method)]
    lines += ["Route: " + value for value in routes]
    if method == "INVITE": lines.append("Contact: <sip:provider@127.0.0.1:%d>" % UPSTREAM_PORT)
    return "\r\n".join(lines + ["Content-Length: 0", "", ""]).encode(), branch
def open_ws():
    context = ssl.create_default_context(cafile="/etc/ssl/cert.pem")
    raw = socket.create_connection(("127.0.0.1", 443), timeout=8)
    ws = context.wrap_socket(raw, server_hostname=GATEWAY_DOMAIN)
    key = base64.b64encode(os.urandom(16)).decode()
    ws.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Protocol: sip\r\nOrigin: https://%s\r\n\r\n" % (GATEWAY_DOMAIN, key, GATEWAY_DOMAIN)).encode())
    head = b""
    while b"\r\n\r\n" not in head: head += exact(ws, 1)
    assert b" 101 " in head.split(b"\r\n", 1)[0]
    return ws
def no_more_invites(sock):
    sock.settimeout(.8)
    try:
        while True:
            extra, _ = sock.recvfrom(65535)
            line, _ = parse(extra.decode("utf-8", "replace"))
            assert line.startswith("ACK ") or line.startswith("SIP/2.0 100 "), line
    except socket.timeout:
        pass
    finally:
        sock.settimeout(6)

def carrier():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", UPSTREAM_PORT)); sock.settimeout(6)
            for case_index, case in enumerate(("bad-realm", "repeat")):
                first, peer = sock.recvfrom(65535); first = first.decode(); line, _ = parse(first)
                assert line.startswith("INVITE "), line
                challenge = ('Proxy-Authenticate: Digest realm="wrong.example.test", nonce="bad", qop="auth"' if case == "bad-realm" else 'Proxy-Authenticate: Digest realm="carrier.example.test", nonce="first", qop="auth"')
                sock.sendto(response(first, 407, "Proxy Authentication Required", challenge), peer)
                if case == "bad-realm":
                    no_more_invites(sock)
                    failure_case_done[case_index].set()
                    continue
                while True:
                    retry, peer = sock.recvfrom(65535); retry = retry.decode(); line, h = parse(retry)
                    if line.startswith("INVITE ") and "proxy-authorization" in h: break
                    assert line.startswith("ACK ") or line.startswith("SIP/2.0 100 "), line
                sock.sendto(response(retry, 407, "Proxy Authentication Required", 'Proxy-Authenticate: Digest realm="carrier.example.test", nonce="second", qop="auth"'), peer)
                no_more_invites(sock)
                failure_case_done[case_index].set()
            # Test-only accelerated TM timers turn carrier silence into a real,
            # bounded transaction timeout without changing production policy.
            timed_out, _ = sock.recvfrom(65535); timed_out = timed_out.decode(); line, timeout_request_h = parse(timed_out)
            assert line.startswith("INVITE "), line
            sock.settimeout(.25)
            pending_dialog_invite = None
            while not timeout_case_done.is_set():
                try:
                    retransmission, retransmission_peer = sock.recvfrom(65535); retransmission = retransmission.decode(); repeat_line, repeat_h = parse(retransmission)
                    if repeat_h.get("call-id") != timeout_request_h["call-id"]:
                        # The browser sets timeout_case_done before sending the
                        # next case. recvfrom may already be blocked and consume
                        # that datagram before this loop rechecks the event.
                        assert timeout_case_done.is_set() and repeat_line.startswith("INVITE "), repeat_line
                        pending_dialog_invite = (retransmission, retransmission_peer)
                        break
                    assert repeat_line.startswith("INVITE "), repeat_line
                except socket.timeout:
                    pass
            sock.settimeout(6)
            # Keep one established dialog through browser/provider re-INVITEs,
            # a second-WSS spoof, a separate retransmission, and lease expiry.
            while True:
                if pending_dialog_invite:
                    invite, peer = pending_dialog_invite; pending_dialog_invite = None
                else:
                    invite, peer = sock.recvfrom(65535); invite = invite.decode()
                line, h = parse(invite)
                if line.startswith("INVITE ") and h["call-id"] != timeout_request_h["call-id"]: break
            dialog_call = h["call-id"][0]
            record_routes = "".join("Record-Route: " + value + "\r\n" for value in h.get("record-route", []))
            answer = response(invite, 200, "OK", "").decode().replace("Content-Length: 0", "Contact: <sip:provider@127.0.0.1:15060>\r\n" + record_routes + "Content-Length: 0").encode()
            sock.sendto(answer, peer)
            while True:
                ack, _ = sock.recvfrom(65535); line, _ = parse(ack.decode())
                if line.startswith("ACK "):
                    break
                assert line.startswith("SIP/2.0 100 "), line
            # Browser re-INVITE failure: the browser sees its original CSeq.
            reinvite, peer = sock.recvfrom(65535); reinvite = reinvite.decode(); line, reinvite_h = parse(reinvite)
            assert line.startswith("INVITE "), line
            sock.sendto(response(reinvite, 488, "Not Acceptable Here", ""), peer)
            while True:
                nack, _ = sock.recvfrom(65535); line, _ = parse(nack.decode())
                if line.startswith("ACK "):
                    break
                assert line.startswith("SIP/2.0 100 "), line
            # Browser re-INVITE success through one upstream digest retry.
            reinvite, peer = sock.recvfrom(65535); reinvite = reinvite.decode(); line, first_reinvite_h = parse(reinvite)
            assert line.startswith("INVITE ") and "proxy-authorization" not in first_reinvite_h, line
            sock.sendto(response(reinvite, 407, "Proxy Authentication Required", 'Proxy-Authenticate: Digest realm="carrier.example.test", nonce="dialog", qop="auth"'), peer)
            while True:
                retry, peer = sock.recvfrom(65535); retry = retry.decode(); line, retry_h = parse(retry)
                if line.startswith("INVITE ") and "proxy-authorization" in retry_h: break
                assert line.startswith("ACK ") or line.startswith("SIP/2.0 100 "), line
            answer = response(retry, 200, "OK", "").decode().replace("Content-Length: 0", "Contact: <sip:provider@127.0.0.1:15060>\r\n" + record_routes + "Content-Length: 0").encode()
            sock.sendto(answer, peer)
            while True:
                ack, _ = sock.recvfrom(65535); line, _ = parse(ack.decode())
                if line.startswith("ACK "): break
                assert line.startswith("SIP/2.0 100 "), line

            provider_from = h["to"][0] + ("" if ";tag=" in h["to"][0] else ";tag=edge")
            provider_to = h["from"][0]
            browser_target = h["contact"][0].split("<", 1)[1].split(">", 1)[0]
            provider_routes = h.get("record-route", [])
            # Provider re-INVITE failure and its transaction ACK.
            provider_reinvite, provider_branch = carrier_dialog_request("INVITE", browser_target,
                dialog_call, 70, provider_from, provider_to, provider_routes)
            sock.sendto(provider_reinvite, peer)
            while True:
                provider_reply, _ = sock.recvfrom(65535); line, _ = parse(provider_reply.decode())
                if not line.startswith("SIP/2.0 100 "): break
            assert line.startswith("SIP/2.0 488 "), line
            provider_ack, _ = carrier_dialog_request("ACK", browser_target, dialog_call, 70,
                provider_from, provider_to, provider_routes, provider_branch)
            sock.sendto(provider_ack, peer)
            # Provider re-INVITE success and a distinct 2xx ACK.
            provider_reinvite, _ = carrier_dialog_request("INVITE", browser_target,
                dialog_call, 71, provider_from, provider_to, provider_routes)
            sock.sendto(provider_reinvite, peer)
            while True:
                provider_reply, _ = sock.recvfrom(65535); line, _ = parse(provider_reply.decode())
                if not line.startswith("SIP/2.0 100 "): break
            assert line.startswith("SIP/2.0 200 "), line
            provider_ack, _ = carrier_dialog_request("ACK", browser_target, dialog_call, 71,
                provider_from, provider_to, provider_routes)
            sock.sendto(provider_ack, peer)

            # The separate authenticated INVITE is retransmitted byte-for-byte;
            # the carrier must receive only one transaction request.
            retransmit, retransmit_peer = sock.recvfrom(65535); retransmit = retransmit.decode(); line, _ = parse(retransmit)
            assert line.startswith("INVITE "), line
            assert retransmit_sent.wait(2), "browser retransmission was not sent"
            # Stay below SIP T1 so this observes only the browser duplicate,
            # not Kamailio's own timer-driven upstream retransmission.
            sock.settimeout(.25)
            try:
                duplicate, _ = sock.recvfrom(65535)
                duplicate_line, _ = parse(duplicate.decode())
                assert not duplicate_line.startswith("INVITE "), "retransmission reached carrier twice"
            except socket.timeout:
                pass
            finally:
                sock.settimeout(6)
            sock.sendto(response(retransmit, 486, "Busy Here", ""), retransmit_peer)

            # CANCEL is matched to the UAC-authenticated upstream retry, not
            # the browser's earlier local-auth transaction.
            while True:
                invite, peer = sock.recvfrom(65535); invite = invite.decode(); line, h = parse(invite)
                if line.startswith("INVITE "): break
                assert line.startswith("ACK ") or line.startswith("SIP/2.0 100 "), line
            sock.sendto(response(invite, 407, "Proxy Authentication Required", 'Proxy-Authenticate: Digest realm="carrier.example.test", nonce="cancel", qop="auth"'), peer)
            while True:
                retry, peer = sock.recvfrom(65535); retry = retry.decode(); line, retry_h = parse(retry)
                if line.startswith("INVITE ") and "proxy-authorization" in retry_h:
                    break
                assert line.startswith("ACK ") or line.startswith("SIP/2.0 100 "), line
            sock.sendto(response(retry, 180, "Ringing", ""), peer)
            cancel, peer = sock.recvfrom(65535); cancel = cancel.decode(); line, cancel_h = parse(cancel)
            assert line.startswith("CANCEL "), line
            assert params(cancel_h["via"][0])["branch"] == params(retry_h["via"][0])["branch"], "CANCEL branch mismatch"
            assert cancel_h["cseq"][0].split()[0] == retry_h["cseq"][0].split()[0], (cancel_h, retry_h)
            sock.sendto(response(cancel, 200, "OK", ""), peer)
            sock.sendto(response(retry, 487, "Request Terminated", ""), peer)
            while True:
                ack, _ = sock.recvfrom(65535); line, _ = parse(ack.decode())
                if line.startswith("ACK "):
                    break
                assert line.startswith("SIP/2.0 100 "), line
            # Expiry blocks new authorization, but the established provider can
            # still tear down its dialog from the pinned UDP peer.
            assert expiry_ready.wait(45), "browser did not reach lease expiry"
            bye, _ = carrier_dialog_request("BYE", browser_target, dialog_call, 72,
                provider_from, provider_to, provider_routes)
            sock.sendto(bye, peer)
            while True:
                bye_reply, _ = sock.recvfrom(65535); line, _ = parse(bye_reply.decode())
                if not line.startswith("SIP/2.0 100 "): break
            assert line.startswith("SIP/2.0 200 "), line
    except BaseException as exc: failures.append(exc)

thread = threading.Thread(target=carrier, daemon=True); thread.start()
with open_ws() as ws:
    for case_index, number in enumerate((1, 10)):
        uri, call = "sip:18005550100@" + SEAT_DOMAIN, uuid.uuid4().hex + "@edge.invalid"
        frame_send(ws, request(uri, call, number))
        status, h = parse(frame_text(ws)); assert status.startswith("SIP/2.0 407 "), status
        branch = "z9hG4bK" + uuid.uuid4().hex
        frame_send(ws, request(uri, call, number + 1, local_auth("INVITE", uri, h["proxy-authenticate"][0]), branch))
        while True:
            status, failure_headers = parse(frame_text(ws))
            if not status.startswith("SIP/2.0 100 "): break
        assert status.startswith("SIP/2.0 502 "), status
        frame_send(ws, dialog_request("ACK", uri, call, number + 1, failure_headers["to"][0], [], branch))
        assert failure_case_done[case_index].wait(3), "carrier retry check did not finish"
    timeout_uri, timeout_call = "sip:18005550100@" + SEAT_DOMAIN, uuid.uuid4().hex + "@edge.invalid"
    frame_send(ws, request(timeout_uri, timeout_call, 15))
    status, timeout_h = parse(frame_text(ws)); assert status.startswith("SIP/2.0 407 "), status
    timeout_branch = "z9hG4bK" + uuid.uuid4().hex
    frame_send(ws, request(timeout_uri, timeout_call, 16,
        local_auth("INVITE", timeout_uri, timeout_h["proxy-authenticate"][0]), timeout_branch))
    while True:
        status, timeout_h = parse(frame_text(ws))
        if status.startswith("SIP/2.0 408 "): break
    frame_send(ws, dialog_request("ACK", timeout_uri, timeout_call, 16, timeout_h["to"][0], [], timeout_branch))
    timeout_case_done.set()
    uri, call = "sip:18005550100@" + SEAT_DOMAIN, uuid.uuid4().hex + "@edge.invalid"
    frame_send(ws, request(uri, call, 20))
    status, h = parse(frame_text(ws)); assert status.startswith("SIP/2.0 407 "), status
    frame_send(ws, request(uri, call, 21, local_auth("INVITE", uri, h["proxy-authenticate"][0])))
    while True:
        status, h = parse(frame_text(ws))
        if status.startswith("SIP/2.0 200 "):
            break
    target = h["contact"][0].split("<", 1)[1].split(">", 1)[0]
    routes = list(reversed(h["record-route"]))
    frame_send(ws, dialog_request("ACK", target, call, 21, h["to"][0], routes))
    reinvite_branch = "z9hG4bK" + uuid.uuid4().hex
    frame_send(ws, dialog_request("INVITE", target, call, 22, h["to"][0], routes, reinvite_branch))
    while True:
        status, failure_h = parse(frame_text(ws))
        if status.startswith("SIP/2.0 488 "):
            break
    assert failure_h["cseq"][0] == "22 INVITE", failure_h["cseq"]
    frame_send(ws, dialog_request("ACK", target, call, 22, h["to"][0], routes, reinvite_branch))

    reinvite_branch = "z9hG4bK" + uuid.uuid4().hex
    frame_send(ws, dialog_request("INVITE", target, call, 23, h["to"][0], routes, reinvite_branch))
    while True:
        status, success_h = parse(frame_text(ws))
        if status.startswith("SIP/2.0 200 "): break
    assert success_h["cseq"][0] == "23 INVITE", success_h["cseq"]
    frame_send(ws, dialog_request("ACK", target, call, 23, h["to"][0], routes))

    # Provider re-INVITE failure and success both stay on the established WSS.
    provider_reinvite = frame_text(ws); line, provider_h = parse(provider_reinvite)
    assert line.startswith("INVITE ") and provider_h["cseq"][0] == "70 INVITE", (line, provider_h)
    frame_send(ws, browser_response(provider_reinvite, 488, "Not Acceptable Here"))
    provider_ack = frame_text(ws); line, provider_ack_h = parse(provider_ack)
    assert line.startswith("ACK ") and provider_ack_h["cseq"][0] == "70 ACK", (line, provider_ack_h)
    provider_reinvite = frame_text(ws); line, provider_h = parse(provider_reinvite)
    assert line.startswith("INVITE ") and provider_h["cseq"][0] == "71 INVITE", (line, provider_h)
    accepted = browser_response(provider_reinvite, 200, "OK").replace("Content-Length: 0",
        "Contact: <sip:alice@browser.invalid;transport=ws>\r\nContent-Length: 0")
    frame_send(ws, accepted)
    provider_ack = frame_text(ws); line, provider_ack_h = parse(provider_ack)
    assert line.startswith("ACK ") and provider_ack_h["cseq"][0] == "71 ACK", (line, provider_ack_h)

    # A different WebSocket connection cannot take over the known dialog.
    with open_ws() as spoof:
        frame_send(spoof, dialog_request("BYE", target, call, 24, h["to"][0], routes))
        spoof_status, _ = parse(frame_text(spoof)); assert spoof_status.startswith("SIP/2.0 403 "), spoof_status

    # Retransmit one authenticated initial request with the exact branch/body.
    retransmit_uri, retransmit_call = "sip:18005550100@" + SEAT_DOMAIN, uuid.uuid4().hex + "@edge.invalid"
    frame_send(ws, request(retransmit_uri, retransmit_call, 30))
    status, challenge_h = parse(frame_text(ws)); assert status.startswith("SIP/2.0 407 "), status
    retransmit_branch = "z9hG4bK" + uuid.uuid4().hex
    authenticated = request(retransmit_uri, retransmit_call, 31,
        local_auth("INVITE", retransmit_uri, challenge_h["proxy-authenticate"][0]), retransmit_branch)
    frame_send(ws, authenticated); frame_send(ws, authenticated); retransmit_sent.set()
    while True:
        status, retransmit_h = parse(frame_text(ws))
        if status.startswith("SIP/2.0 486 "): break
    frame_send(ws, dialog_request("ACK", retransmit_uri, retransmit_call, 31,
        retransmit_h["to"][0], [], retransmit_branch))

    # Preserve the existing authenticated-CANCEL regression before expiry.
    uri, call = "sip:18005550100@" + SEAT_DOMAIN, uuid.uuid4().hex + "@edge.invalid"
    frame_send(ws, request(uri, call, 30))
    status, h = parse(frame_text(ws)); assert status.startswith("SIP/2.0 407 "), status
    browser_branch = "z9hG4bK" + uuid.uuid4().hex
    frame_send(ws, request(uri, call, 31, local_auth("INVITE", uri, h["proxy-authenticate"][0]), browser_branch))
    while True:
        status, cancel_reply = parse(frame_text(ws))
        if status.startswith("SIP/2.0 180 "):
            break
    frame_send(ws, request(uri, call, 31, branch=browser_branch, method="CANCEL"))
    received = set()
    while received != {"200", "487"}:
        status, cancel_reply = parse(frame_text(ws))
        code = status.split()[1]
        if code in {"200", "487"}:
            received.add(code)
        if code == "487":
            frame_send(ws, dialog_request("ACK", uri, call, 31, cancel_reply["to"][0], [], browser_branch))

    wait = max(0, LEASE_UNTIL - int(time.time()) + 1)
    assert wait <= 35, wait
    time.sleep(wait); expiry_ready.set()
    remote_bye = frame_text(ws); line, remote_bye_h = parse(remote_bye)
    assert line.startswith("BYE ") and remote_bye_h["cseq"][0] == "72 BYE", (line, remote_bye_h)
    frame_send(ws, browser_response(remote_bye, 200, "OK"))
thread.join(5); assert not thread.is_alive(), "carrier did not complete"
if failures: raise failures[0]
print("PASS upstream bad realm produces one attempt and 502")
print("PASS repeated upstream challenge produces one retry and 502")
print("PASS silent upstream reaches a bounded transaction timeout")
print("PASS browser re-INVITE failure and authenticated success preserve browser CSeq")
print("PASS provider re-INVITE failure and success preserve provider CSeq")
print("PASS second WSS connection cannot take over a dialog")
print("PASS authenticated INVITE retransmission reaches the carrier once")
print("PASS provider BYE succeeds after the seat lease expires")
print("PASS CANCEL maps browser transaction to authenticated upstream retry")
'''


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--gateway-root", type=Path, default=root)
    parser.add_argument("--source-overlay", action="store_true")
    args = parser.parse_args()
    root = args.gateway_root.resolve()
    files = {
        "config": root / "docker/kamailio/kamailio.cfg",
        "seat": root / "docker/kamailio/seat-routing.cfg",
        "renderer": root / "docker/rootfs/etc/cont-init.d/07-render-kamailio-cfg",
        "compiler": root / "docker/seat/compile_snapshot.py",
    }
    if args.source_overlay and any(not item.is_file() for item in files.values()):
        parser.error("source overlay is incomplete")
    name = "bitcall-seat-dialog-" + uuid.uuid4().hex[:12]
    created = False
    with tempfile.TemporaryDirectory(prefix="bitcall-seat-dialog-") as temp_dir:
        temp = Path(temp_dir)
        state, cert, key = temp / "seats.json", temp / "cert.pem", temp / "key.pem"
        fixture = snapshot()
        fixture["issuedAt"] = int(time.time())
        fixture["validUntil"] = fixture["issuedAt"] + 30
        state.write_text(json.dumps(fixture), encoding="utf-8")
        state.chmod(0o600)
        (temp / "rtpengine.conf").write_text("[rtpengine]\n")
        packaged_config = files["config"].read_text(encoding="utf-8") if args.source_overlay else run(
            "docker", "run", "--rm", "--network", "none", "--entrypoint", "cat", args.image,
            "/etc/kamailio/kamailio.cfg")
        marker = 'loadmodule "tm.so"'
        if packaged_config.count(marker) != 1:
            raise RuntimeError("packaged tm module marker unavailable")
        test_config = temp / "kamailio.cfg"
        test_config.write_text(packaged_config.replace(marker, marker + '\nmodparam("tm", "fr_timer", 1500)\nmodparam("tm", "fr_inv_timer", 3000)'), encoding="utf-8")
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1", "-nodes", "-subj", "/CN=query.example.test", "-addext", "subjectAltName=DNS:query.example.test", "-keyout", str(key), "-out", str(cert), stderr=subprocess.DEVNULL)
        mounts = []
        if args.source_overlay:
            renderer = temp / "07-render-kamailio-cfg"
            shutil.copyfile(files["renderer"], renderer)
            renderer.chmod(0o755)
            mounts = ["-v", f"{files['seat']}:/opt/bitcall/seat-routing.cfg:ro", "-v", f"{renderer}:/etc/cont-init.d/07-render-kamailio-cfg:ro", "-v", f"{files['compiler']}:/opt/bitcall/compile_seat_snapshot.py:ro"]
        mounts = ["-v", f"{test_config}:/etc/kamailio/kamailio.cfg:ro", *mounts]
        try:
            run("docker", "run", "-d", "--name", name, "--network", "none", "--read-only", "--tmpfs", "/run:rw,exec,size=128m", "--tmpfs", "/tmp:rw,size=64m", "--cpus", "1", "--memory", "512m", "--pids-limit", "256", "--security-opt", "no-new-privileges:true", "--entrypoint", "/bin/sh", "-e", "DOMAIN=query.example.test", "-e", "PRIVATE_IP=127.0.0.1", "-e", "PUBLIC_IP=127.0.0.1", "-e", "WEBPHONE_ORIGIN=https://query.example.test", "-e", "SEAT_DOMAIN=seats.example.test", "-e", "SEAT_MODE=local", "-e", f"FIXTURE_VALID_UNTIL={fixture['validUntil']}", "-e", "SEAT_SNAPSHOT_FILE=/tmp/seat-snapshot.json", "-v", f"{state}:/fixture-seats.json:ro", "-v", f"{cert}:/etc/ssl/cert.pem:ro", "-v", f"{key}:/etc/ssl/key.pem:ro", "-v", f"{temp / 'rtpengine.conf'}:/etc/rtpengine/rtpengine.conf:ro", *mounts, args.image, "-ec", "umask 077; cp /fixture-seats.json /tmp/seat-snapshot.json; exec /init")
            created = True
            deadline = time.monotonic() + 35
            while True:
                try:
                    run("docker", "exec", name, "sh", "-ec", "pgrep -x kamailio >/dev/null && ss -ltn | grep -q ':443 '", stderr=subprocess.DEVNULL)
                    break
                except subprocess.CalledProcessError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("gateway did not become ready")
                    time.sleep(.5)
            print(run("docker", "exec", "-i", name, "python3", "-", input=IN_CONTAINER_TEST, timeout=55).strip())
        except Exception:
            if created:
                output = diagnostic_logs(name)
                if output:
                    print(output)
            raise
        finally:
            if created:
                run("docker", "rm", "-f", name, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
