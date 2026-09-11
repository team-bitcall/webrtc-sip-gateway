"""Managed-mode additions to the existing packaged WSS/digest call fixture.

These fragments execute around the unchanged two-seat call scenario, in its
isolated network-less container. All credentials here are synthetic fixtures.
"""

BEFORE_CALLS = r'''
import copy, hashlib, http.client, json, time

control_token = "a" * 43
with open("/tmp/seat-snapshot.json", encoding="utf-8") as source:
    original_projection = json.load(source)

def control(method, data=None, token=control_token, origin=None):
    connection = http.client.HTTPConnection("127.0.0.1", 8881, timeout=5)
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    if origin is not None: headers["Origin"] = origin
    try:
        path = "/v1/tenants/" + original_projection["seats"][0]["tenantId"] + "/" + ("status" if method == "GET" else "snapshot")
        connection.request(method, path, None if data is None else json.dumps(data), headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()

deadline = time.monotonic() + 10
while True:
    try:
        code, applied = control("POST", original_projection)
        if code == 200: break
        assert code == 503, (code, applied)
    except (OSError, http.client.HTTPException):
        pass
    assert time.monotonic() < deadline, "control helper did not become ready"
    time.sleep(.2)
expected_hash = hashlib.sha256(json.dumps(original_projection, ensure_ascii=False, sort_keys=True,
                                         separators=(",", ":")).encode()).hexdigest()
assert applied["status"] == "applied" and applied["contentSha256"] == expected_hash
assert control("POST", original_projection)[1] == applied, "duplicate delivery changed acknowledgement"
assert control("GET", token="invalid")[0] == 401
assert control("GET", origin="https://query.example.test")[0] == 403
print("PASS private control authentication, canonical digest and idempotent apply")
'''

CALL_EVENT_FAILURES = r'''
# Real final replies exercise the same failure route as provider rejections.
failure_codes = [(486, "Busy Here", "busy"), (603, "Decline", "rejected"), (480, "Unavailable", "no_answer")]
def failing_carrier():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer_socket:
            peer_socket.bind(("127.0.0.1", UPSTREAM)); peer_socket.settimeout(8)
            for code, reason, _ in failure_codes:
                while True:
                    packet, peer = peer_socket.recvfrom(65535)
                    packet = packet.decode()
                    if packet.startswith("INVITE "): break
                    assert packet.startswith("ACK "), packet.split("\r\n")[0]
                peer_socket.sendto(reply(packet, 180, "Ringing"), peer)
                peer_socket.sendto(reply(packet, code, reason), peer)
    except BaseException as error:
        failures.append(error)

failure_thread = threading.Thread(target=failing_carrier, daemon=True)
failure_thread.start()
with socket.create_connection(("127.0.0.1", 443), timeout=8) as raw:
  with context.wrap_socket(raw, server_hostname=GATEWAY_DOMAIN) as ws:
    key = base64.b64encode(os.urandom(16)).decode()
    send = "GET / HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Protocol: sip\r\nOrigin: https://%s\r\n\r\n"
    ws.sendall((send % (GATEWAY_DOMAIN, key, GATEWAY_DOMAIN)).encode())
    headers = b""
    while b"\r\n\r\n" not in headers: headers += exact(ws, 1)
    assert b" 101 " in headers.split(b"\r\n", 1)[0]
    for index, (code, _, reason) in enumerate(failure_codes):
        call = uuid.uuid4().hex + "@phone.invalid"
        status, _ = challenged("INVITE", "sip:18005550100@" + SEAT_DOMAIN, "alice", LOCAL_PASSWORD, 200 + index * 10, call,
                              extra=("Contact: <sip:phone@browser.invalid;transport=ws>",))
        assert status.startswith("SIP/2.0 %d " % code), status
        expect_cdr(call, [("admitted", None, None, None), ("progress", 180, None, None),
                          ("failed", code, reason, "upstream")])
failure_thread.join(3)
assert not failure_thread.is_alive(), "failure carrier did not finish"
if failures: raise failures[0]
print("PASS gateway ringing, busy, rejected and no-answer journal hooks")
'''

AFTER_CALLS = r'''
# Reopen a fresh WSS client after the two ordinary owner/agent calls have ended.
projection = copy.deepcopy(original_projection)
projection["revision"] += 1
projection["seats"][0]["enabled"] = False
assert control("POST", projection)[0] == 200
assert control("POST", original_projection)[0] == 409, "stale delivery restored revoked state"
assert control("POST", projection)[0] == 200
with socket.create_connection(("127.0.0.1", 443), timeout=8) as raw:
  with context.wrap_socket(raw, server_hostname=GATEWAY_DOMAIN) as ws:
    key = base64.b64encode(os.urandom(16)).decode()
    ws.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Protocol: sip\r\nOrigin: https://%s\r\n\r\n" % (GATEWAY_DOMAIN, key, GATEWAY_DOMAIN)).encode())
    headers = b""
    while b"\r\n\r\n" not in headers: headers += exact(ws, 1)
    assert b" 101 " in headers.split(b"\r\n", 1)[0]
    call = uuid.uuid4().hex + "@phone.invalid"
    send_frame(ws, request("REGISTER", "sip:" + SEAT_DOMAIN, "alice", 100, call))
    status, _ = parse(text(ws)); assert status.startswith("SIP/2.0 403 "), status
    status, _ = challenged("REGISTER", "sip:" + SEAT_DOMAIN, "bob", "other-pass", 110, call)
    assert status.startswith("SIP/2.0 200 "), status
    projection["revision"] += 1
    projection["seats"][1]["ha1"] = hashlib.md5(b"bob:seats.example.test:rotated-pass").hexdigest()
    assert control("POST", projection)[0] == 200
    status, _ = challenged("REGISTER", "sip:" + SEAT_DOMAIN, "bob", "other-pass", 120, call)
    assert status.startswith("SIP/2.0 401 "), status
    status, _ = challenged("REGISTER", "sip:" + SEAT_DOMAIN, "bob", "rotated-pass", 130, call)
    assert status.startswith("SIP/2.0 200 "), status
    projection.update(revision=projection["revision"] + 1, issuedAt=int(time.time()), validUntil=int(time.time()) + 3)
    assert control("POST", projection)[0] == 200
    time.sleep(4)
    send_frame(ws, request("REGISTER", "sip:" + SEAT_DOMAIN, "bob", 140, call))
    status, _ = parse(text(ws)); assert status.startswith("SIP/2.0 503 "), status
assert control("GET")[1]["status"] == "expired"
assert control("POST", projection)[0] == 409
print("PASS revocation, unaffected second seat, credential rotation and fail-closed expiry over WSS")
'''

CALL_EVENTS = r'''
# The journal is exported through the existing bearer-only control listener.
projected_tenant = original_projection["seats"][0]["tenantId"]
connection = http.client.HTTPConnection("127.0.0.1", 8881, timeout=5)
try:
    connection.request("GET", "/v1/tenants/" + projected_tenant + "/call-events?after=0&limit=100",
                       headers={"Authorization": "Bearer " + control_token})
    response = connection.getresponse(); assert response.status == 200, response.status
    exported = json.loads(response.read())
finally:
    connection.close()
assert exported["schemaVersion"] == 1 and exported["tenantId"] == projected_tenant
assert len(exported["events"]) >= 6, exported
assert {"admitted", "answered", "ended"}.issubset({event["type"] for event in exported["events"]}), exported
sequences = [event["sequence"] for event in exported["events"]]
assert sequences == sorted(sequences) and len(sequences) == len(set(sequences)), sequences
for event in exported["events"]:
    assert set(event) == {"schemaVersion", "eventId", "sequence", "callId", "tenantId", "seatId", "snapshotRevision", "type", "occurredAtMs", "startedAtMs", "sipCallId", "fromTag", "legId", "destination", "requestedCallerId", "effectiveCallerId", "sipCode", "reason", "endedBy"}
    assert "password" not in json.dumps(event).lower()
calls = {}
for event in exported["events"]:
    calls.setdefault(event["sipCallId"], []).append(event)
assert set(calls) == set(expected_cdr_calls), (set(calls), set(expected_cdr_calls))
assert not (set(calls) & rejected_cdr_calls), (set(calls), rejected_cdr_calls)
for sip_call_id, expected in expected_cdr_calls.items():
    events = calls[sip_call_id]
    actual = [(event["type"], event["sipCode"], event["reason"], event["endedBy"])
              for event in events]
    assert actual[0] == expected[0], (sip_call_id, actual, expected)
    if any(item[0] == "progress" for item in expected):
        # Separate SIP workers may append progress after the final failure.
        # Still require exactly the expected events, codes and terminal reason.
        assert sorted(actual[1:]) == sorted(expected[1:]), (sip_call_id, actual, expected)
    else:
        assert actual == expected, (sip_call_id, actual, expected)
    assert len({event["callId"] for event in events}) == 1, events
    assert all(event["startedAtMs"] <= event["occurredAtMs"] for event in events), events
    if events[-1]["type"] == "ended":
        assert events[-1]["legId"] == events[1]["legId"], events
        assert all(left["occurredAtMs"] <= right["occurredAtMs"]
                   for left, right in zip(events, events[1:])), events
with open("/tmp/call-events.json", "w", encoding="utf-8") as output:
    json.dump(exported, output)
last = exported["nextSequence"]
connection = http.client.HTTPConnection("127.0.0.1", 8881, timeout=5)
try:
    connection.request("POST", "/v1/tenants/" + projected_tenant + "/call-events/ack", json.dumps({"throughSequence": last}),
                       {"Authorization": "Bearer " + control_token, "Content-Type": "application/json"})
    response = connection.getresponse(); assert response.status == 200, response.status
    assert json.loads(response.read())["acknowledgedSequence"] == last
finally:
    connection.close()
print("PASS managed durable call-event export and acknowledgement")
'''
