#!/usr/bin/env python3
"""Real-wire custom-From and identity-header caller-ID format smoke test."""

import sys


IN_CONTAINER_SCENARIO = r'''
base_exact = exact

def exact(sock, count):
    try:
        return base_exact(sock, count)
    except (TimeoutError, socket.timeout):
        if failures: raise failures[0]
        raise

def identity(headers, from_user, cli, headers_mode):
    assert len(headers.get("from", [])) == 1 and ("sip:%s@carrier.example.test" % from_user) in headers["from"][0], headers
    for name in ("p-asserted-identity", "remote-party-id"):
        assert len(headers.get(name, [])) == 1 and ("sip:%s@carrier.example.test" % cli) in headers[name][0], headers
    if headers_mode:
        assert len(headers.get("p-preferred-identity", [])) == 1
        assert ("sip:%s@carrier.example.test" % cli) in headers["p-preferred-identity"][0], headers
    else:
        assert "p-preferred-identity" not in headers, headers
    assert headers.get("privacy") == ["none"], headers
    asserted = sum((headers.get(name, []) for name in
                    ("p-asserted-identity", "p-preferred-identity", "remote-party-id")), [])
    assert "forged@example.test" not in "\n".join(asserted), headers

def invite_for(sock, call):
    while True:
        packet, peer = sock.recvfrom(65535); message = packet.decode(); line, headers = parse(message)
        if line.startswith("INVITE "):
            assert headers.get("call-id") == [call], (line, headers.get("call-id"), call)
            return message, peer, headers
        assert (line.startswith("ACK ") or line.startswith("SIP/2.0 100 ")) and headers.get("call-id") == [call], line

def upstream_auth(sock, invite, peer, code, nonce):
    challenge_name, auth_name, qop = (("Proxy-Authenticate", "proxy-authorization", True)
                                      if code == 407 else ("WWW-Authenticate", "authorization", False))
    challenge = '%s: Digest realm="carrier.example.test", nonce="%s"%s' % (
        challenge_name, nonce, ', qop="auth"' if qop else "")
    sock.sendto(reply(invite, code, "Proxy Authentication Required" if code == 407 else "Unauthorized", challenge), peer)
    return auth_name

def answer_call(sock, invite, peer, call, account_from, cli, headers_mode):
    invite_headers = parse(invite)[1]
    record_routes = "".join("Record-Route: " + value + "\r\n" for value in invite_headers.get("record-route", []))
    answer = reply(invite, 200, "OK").decode().replace(
        "Content-Length: 0", "Contact: <sip:provider@127.0.0.1:15060>\r\n" + record_routes + "Content-Length: 0")
    sock.sendto(answer.encode(), peer)
    packet, _ = sock.recvfrom(65535); line, ack_headers = parse(packet.decode())
    assert line.startswith("ACK ") and ack_headers.get("call-id") == [call], line
    assert ("sip:%s@carrier.example.test" % (account_from if headers_mode else cli)) in ack_headers["from"][0], ack_headers
    assert ack_headers["cseq"][0].split()[0] == invite_headers["cseq"][0].split()[0]
    reinvite, peer, reinvite_headers = invite_for(sock, call)
    identity(reinvite_headers, account_from if headers_mode else cli, cli, headers_mode)
    assert int(reinvite_headers["cseq"][0].split()[0]) > int(invite_headers["cseq"][0].split()[0])
    sock.sendto(reply(reinvite, 200, "OK"), peer)
    packet, _ = sock.recvfrom(65535); assert packet.decode().startswith("ACK "), packet[:60]
    packet, peer = sock.recvfrom(65535); bye = packet.decode(); line, bye_headers = parse(bye)
    assert line.startswith("BYE ") and bye_headers.get("call-id") == [call], line
    assert ("sip:%s@carrier.example.test" % (account_from if headers_mode else cli)) in bye_headers["from"][0], bye_headers
    sock.sendto(reply(bye, 200, "OK"), peer)

calls = {name: uuid.uuid4().hex + "@phone.invalid" for name in ("custom", "headers", "rejected")}
expected_effective_caller_ids = {
    calls["custom"]: "+12025550100", calls["headers"]: "+12025550199",
    calls["rejected"]: "+12025550100",
}
expected_event_seat_ids = {
    calls["custom"]: original_projection["seats"][0]["id"],
    calls["headers"]: original_projection["seats"][1]["id"],
    calls["rejected"]: original_projection["seats"][0]["id"],
}

def carrier():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", UPSTREAM)); sock.settimeout(10)
            for name, account_from, cli, headers_mode, code in (
                ("custom", "account-from-a", "+12025550100", False, 407),
                ("headers", "account-from-b", "+12025550199", True, 401),
            ):
                initial, peer, initial_headers = invite_for(sock, calls[name])
                identity(initial_headers, account_from if headers_mode else cli, cli, headers_mode)
                assert "authorization" not in initial_headers and "proxy-authorization" not in initial_headers
                auth_name = upstream_auth(sock, initial, peer, code, name + "-nonce")
                authenticated, peer, authenticated_headers = invite_for(sock, calls[name])
                identity(authenticated_headers, account_from if headers_mode else cli, cli, headers_mode)
                assert int(authenticated_headers["cseq"][0].split()[0]) > int(initial_headers["cseq"][0].split()[0])
                valid_digest(authenticated_headers[auth_name][0], "INVITE", parse(authenticated)[0].split()[1],
                             "6ee53e85140577a263e338faa5535881")
                answer_call(sock, authenticated, peer, calls[name], account_from, cli, headers_mode)

            rejected, peer, rejected_headers = invite_for(sock, calls["rejected"])
            identity(rejected_headers, "+12025550100", "+12025550100", False)
            sock.sendto(reply(rejected, 433, "Anonymity Disallowed"), peer)
            packet, _ = sock.recvfrom(65535); assert packet.decode().startswith("ACK "), packet[:60]
            sock.settimeout(.5)
            try:
                packet, _ = sock.recvfrom(65535)
            except socket.timeout:
                pass
            else:
                line, headers = parse(packet.decode())
                assert not (line.startswith("INVITE ") and headers.get("call-id") == [calls["rejected"]]), (line, headers)
    except BaseException as error:
        failures.append(error)

thread = threading.Thread(target=carrier, daemon=True); thread.start()
context = ssl.create_default_context(cafile="/etc/ssl/cert.pem")
with socket.create_connection(("127.0.0.1", 443), timeout=10) as raw:
  with context.wrap_socket(raw, server_hostname=GATEWAY_DOMAIN) as ws:
    key = base64.b64encode(os.urandom(16)).decode()
    ws.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Protocol: sip\r\nOrigin: https://%s\r\n\r\n" % (GATEWAY_DOMAIN, key, GATEWAY_DOMAIN)).encode())
    response = b""
    while b"\r\n\r\n" not in response: response += exact(ws, 1)
    assert b" 101 " in response.split(b"\r\n", 1)[0], response[:100]

    def challenged(uri, user, password, cseq, call, cli):
        extra = ("Contact: <sip:phone@browser.invalid;transport=ws>", "X-Bitcall-Caller-ID: " + cli,
                 "P-Asserted-Identity: <sip:forged@example.test>",
                 "P-Preferred-Identity: <sip:forged@example.test>",
                 "Remote-Party-ID: <sip:forged@example.test>")
        send_frame(ws, request("INVITE", uri, user, cseq, call, extra))
        status, headers = parse(text(ws)); assert status.startswith("SIP/2.0 407 "), status
        send_frame(ws, request("INVITE", uri, user, cseq + 1, call, extra + (
            auth_header("INVITE", uri, user, password, headers["proxy-authenticate"][0], "Proxy-Authorization"),)))
        while True:
            result = parse(text(ws))
            if int(result[0].split()[1]) >= 200: return result

    def next_final():
        while True:
            result = parse(text(ws))
            if int(result[0].split()[1]) >= 200: return result

    uri = "sip:18005550100@" + SEAT_DOMAIN
    for name, user, password, cseq, cli in (
        ("custom", "alice", LOCAL_PASSWORD, 10, "+12025550100"),
        ("headers", "bob", "other-pass", 30, "+12025550199"),
    ):
        status, headers = challenged(uri, user, password, cseq, calls[name], cli)
        assert status.startswith("SIP/2.0 200 "), status
        assert ("sip:%s@%s" % (user, SEAT_DOMAIN)) in headers["from"][0], headers
        target = headers["contact"][0].split("<", 1)[1].split(">", 1)[0]
        to = headers["to"][0]; routes = list(reversed(headers["record-route"]))
        send_frame(ws, dialog_request("ACK", target, user, cseq + 1, calls[name], to, routes))
        send_frame(ws, dialog_request("INVITE", target, user, cseq + 2, calls[name], to, routes))
        update, update_headers = next_final(); assert update.startswith("SIP/2.0 200 "), update
        assert ("sip:%s@%s" % (user, SEAT_DOMAIN)) in update_headers["from"][0], update_headers
        send_frame(ws, dialog_request("ACK", target, user, cseq + 2, calls[name], to, routes))
        send_frame(ws, dialog_request("BYE", target, user, cseq + 3, calls[name], to, routes))
        ended, _ = next_final(); assert ended.startswith("SIP/2.0 200 "), ended
        expect_cdr(calls[name], [("admitted", None, None, None), ("answered", 200, None, None),
                                 ("ended", None, "normal", "agent")])

    status, _ = challenged(uri, "alice", LOCAL_PASSWORD, 50, calls["rejected"], "+12025550100")
    assert status.startswith("SIP/2.0 433 "), status
    expect_cdr(calls["rejected"], [("admitted", None, None, None),
                                    ("failed", 433, "upstream_failure", "upstream")])
    time.sleep(.6)

thread.join(3)
assert not thread.is_alive(), "caller-ID format carrier did not finish"
if failures: raise failures[0]
print("PASS direct custom and identity-header caller-ID formats with bounded authentication and dialogs")
'''


def main():
    from smoke_seat_routing import main as seat_main
    if "--scenario" not in sys.argv:
        sys.argv.extend(("--managed", "--call-events", "--scenario", "caller-id-formats"))
    seat_main()


if __name__ == "__main__":
    main()
