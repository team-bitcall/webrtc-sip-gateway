import http.client
import http.server
import json
import tempfile
import threading
import unittest

from provisioning import ControlError, ControlHandler, KamailioRpc, TenantProjectionStore
from test_compile_snapshot import NOW, snapshot
from test_provisioning import MemoryRpc


TENANT = "t_" + "a" * 64
SEAT_ALICE = "s_" + "b" * 64
SEAT_BOB = "s_" + "c" * 64


class PresenceRpc(MemoryRpc):
    def __init__(self):
        super().__init__()
        self.result = {"registrations": [], "dialogs": []}
        self.error = None
        self.calls = []

    def presence(self, tenant, domain, usernames):
        self.calls.append((tenant, domain, dict(usernames)))
        if self.error:
            raise self.error
        return self.result


def tenant_snapshot():
    data = snapshot()
    for item in data["profiles"] + data["seats"]:
        item["tenantId"] = TENANT
    data["seats"][0]["id"] = SEAT_ALICE
    return data


class PresenceParserTests(unittest.TestCase):
    def test_whitelists_live_wss_connections_and_tenant_dialogs(self):
        usernames = {"alice+1": SEAT_ALICE, "bob": SEAT_BOB}
        contacts = {"Domains": [{"Domain": {"Domain": "seat_location", "AoRs": [
            {"Info": {"AoR": "alice+1", "Contacts": [
                {"Contact": {"Address": "sip:a@browser.invalid;transport=ws", "Expires": 300, "Tcpconn-Id": 4}},
                {"Contact": {"Address": "sip:a@browser.invalid;transport=ws", "Expires": 300, "Tcpconn-Id": 4}},
                {"Contact": {"Address": "sip:a@browser.invalid;transport=ws", "Expires": "expired", "Tcpconn-Id": 5}},
                {"Contact": {"Address": "sip:a@browser.invalid;transport=ws", "Expires": 0, "Tcpconn-Id": 4}},
            ]}},
            {"Info": {"AoR": "stranger", "Contacts": [
                {"Contact": {"Address": "sip:x@browser.invalid;transport=ws", "Expires": 300, "Tcpconn-Id": 4}},
            ]}},
        ]}}]}
        registrations = KamailioRpc._seat_contacts(contacts, "seats.example.test", usernames, {4})
        self.assertEqual(registrations, [{"seatId": SEAT_ALICE, "connections": 1}, {"seatId": SEAT_BOB, "connections": 0}])
        dialogs = KamailioRpc._seat_dialogs([
            {"state": 1, "variables": [{"seat_tenant": TENANT}, {"seat_id": SEAT_ALICE},
                                             {"seat_cdr_id": "b" * 32}, {"seat_auth_password": "never-return"}]},
            {"state": 3, "variables": [{"seat_tenant": TENANT}, {"seat_id": SEAT_ALICE},
                                             {"seat_cdr_id": "b" * 32}]},
            {"state": 4, "variables": [{"seat_tenant": "t_" + "b" * 64}, {"seat_id": SEAT_BOB},
                                             {"seat_cdr_id": "c" * 32}]},
            {"state": 5},
        ], TENANT)
        self.assertEqual(dialogs, [{"callId": "b" * 32, "seatId": SEAT_ALICE, "state": "confirmed"}])
        self.assertNotIn("never-return", json.dumps(dialogs))

    def test_dialog_conflicts_and_connection_overflow_are_unavailable(self):
        with self.assertRaises(ControlError):
            KamailioRpc._seat_dialogs([
                {"state": 1, "variables": [{"seat_tenant": TENANT}, {"seat_id": SEAT_ALICE}, {"seat_cdr_id": "d" * 32}]},
                {"state": 4, "variables": [{"seat_tenant": TENANT}, {"seat_id": SEAT_BOB}, {"seat_cdr_id": "d" * 32}]},
            ], TENANT)

    def test_invalid_or_incomplete_private_inventory_never_means_empty(self):
        with self.assertRaises(ControlError) as error:
            KamailioRpc._tcp_connection_ids({"connections": []})
        self.assertEqual(error.exception.code, "GATEWAY_STATE_UNAVAILABLE")
        with self.assertRaises(ControlError):
            KamailioRpc._seat_contacts({"Domains": [{"Domain": {"Domain": "seat_location", "AoRs": [{}]}}]},
                                        "seats.example.test", {"alice": "alice"}, set())
        with self.assertRaises(ControlError):
            KamailioRpc._seat_dialogs([{"state": 6, "variables": []}], TENANT)


class PresenceHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.rpc = PresenceRpc()
        self.now = NOW
        self.store = TenantProjectionStore(self.temp.name, "seats.example.test", self.rpc,
                                           clock=lambda: self.now)
        self.store.apply(TENANT, tenant_snapshot())
        self.server = http.server.HTTPServer(("127.0.0.1", 0), ControlHandler)
        self.server.token, self.server.store = "a" * 43, self.store
        self.server.control_boot_id = "123e4567-e89b-12d3-a456-426614174000"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(2)
        self.server.server_close()
        self.store.close()
        self.temp.cleanup()

    def request(self, headers=None, path="presence"):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        try:
            connection.request("GET", "/v1/tenants/" + TENANT + "/" + path, headers=headers or {})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_private_presence_contract_scopes_and_never_exposes_secrets(self):
        self.rpc.result = {"registrations": [{"seatId": SEAT_ALICE, "connections": 1}],
                           "dialogs": [{"callId": "d" * 32, "seatId": SEAT_ALICE, "state": "early"}]}
        auth = {"Authorization": "Bearer " + self.server.token}
        self.assertEqual(self.request()[0], 401)
        self.assertEqual(self.request({**auth, "Origin": "https://phone.invalid"})[0], 403)
        code, body = self.request(auth)
        self.assertEqual(code, 200)
        self.assertEqual(set(body), {"schemaVersion", "tenantId", "observedAtMs", "controlBootId",
                                     "policyRevision", "projectionStatus", "registrations", "dialogs"})
        self.assertEqual(body["projectionStatus"], "applied")
        self.assertEqual(self.rpc.calls[-1][0], TENANT)
        self.assertNotIn("password", json.dumps(body).lower())

    def test_expired_still_observes_and_rpc_failure_returns_no_empty_snapshot(self):
        auth = {"Authorization": "Bearer " + self.server.token}
        self.now += 121
        code, body = self.request(auth)
        self.assertEqual((code, body["projectionStatus"], body["registrations"], body["dialogs"]),
                         (200, "expired", [], []))
        self.rpc.error = ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
        code, body = self.request(auth)
        self.assertEqual((code, body), (503, {"error": {"code": "GATEWAY_STATE_UNAVAILABLE"}}))

    def test_malformed_observation_rows_are_unavailable(self):
        self.rpc.result = {"registrations": [{"seatId": SEAT_ALICE, "connections": 1, "raw": "forbidden"}],
                           "dialogs": []}
        code, body = self.request({"Authorization": "Bearer " + self.server.token})
        self.assertEqual((code, body), (503, {"error": {"code": "GATEWAY_STATE_UNAVAILABLE"}}))


if __name__ == "__main__":
    unittest.main()
