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
        path = "/v1/tenants/tenant-a/" + ("status" if method == "GET" else "snapshot")
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
