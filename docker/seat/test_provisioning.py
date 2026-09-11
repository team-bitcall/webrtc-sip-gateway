import copy
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from compile_snapshot import snapshot_entries, validate_snapshot
from provisioning import (
    ControlError,
    ControlHandler,
    KamailioRpc,
    TenantProjectionStore,
    canonical_json,
    durable_state_directory,
)
from test_compile_snapshot import NOW, snapshot


class MemoryRpc:
    def __init__(self):
        self.values = {}
        self.fail_after = None
        self.writes = 0
        self.switched = []

    def get(self, table, key):
        return self.values.get((table, key))

    def set(self, table, key, value):
        if self.writes == self.fail_after:
            raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
        self.writes += 1
        self.values[(table, key)] = value
        if table == "seat_meta" and key.endswith("::active"):
            self.switched.append((key, value, copy.deepcopy(self.values)))


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.rpc = MemoryRpc()
        self.now = NOW
        self.store = self.open_store()

    def open_store(self):
        return TenantProjectionStore(self.temp.name, "seats.example.test", self.rpc, clock=lambda: self.now)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def apply(self, data=None):
        return self.store.apply("tenant-a", data or snapshot())

    def test_ack_only_after_complete_generation_and_one_pointer_switch(self):
        result = self.apply()
        self.assertEqual(result, {"status": "applied", "tenantId": "tenant-a", "revision": 7,
                                 "validUntil": NOW + 120,
                                 "contentSha256": hashlib.sha256(canonical_json(snapshot()).encode()).hexdigest()})
        self.assertEqual(len(self.rpc.switched), 1)
        at_switch = self.rpc.switched[0][2]
        for table, key, value in snapshot_entries(validate_snapshot(snapshot(), NOW), "tenant-a"):
            self.assertEqual(at_switch[(table, key)], value)
        self.assertNotIn("credential", json.dumps(result))
        self.assertEqual(os.stat(Path(self.temp.name) / "state.sqlite3").st_mode & 0o777, 0o600)

    def test_duplicate_identical_revision_is_idempotent_and_conflicts_stay_revoked(self):
        self.apply()
        writes = self.rpc.writes
        self.apply()
        self.assertEqual(writes, self.rpc.writes)
        revoked = snapshot()
        revoked["revision"] = 8
        revoked["seats"][0]["enabled"] = False
        self.apply(revoked)
        for stale in (snapshot(), {**revoked, "seats": snapshot()["seats"]}):
            with self.assertRaises(ControlError) as error:
                self.apply(stale)
            self.assertEqual(error.exception.code, "REVISION_CONFLICT")
        self.assertEqual(self.rpc.get("seat_meta", "tenant-a::active"), "8")
        self.assertEqual(self.rpc.get("seat_users", "tenant-a::8::alice+1::enabled"), 0)

    def test_partial_staging_is_not_ready_and_high_water_survives_restart(self):
        self.apply()
        revised = snapshot()
        revised["revision"] = 9
        revised["seats"][0]["enabled"] = False
        self.rpc.fail_after = self.rpc.writes + 3
        with self.assertRaises(ControlError):
            self.apply(revised)
        self.assertEqual(self.rpc.get("seat_meta", "tenant-a::active"), "7")
        self.assertEqual(self.store.status("tenant-a")["status"], "pending")
        self.store.close()
        self.store = self.open_store()
        with self.assertRaises(ControlError) as error:
            self.apply()
        self.assertEqual(error.exception.code, "REVISION_CONFLICT")
        self.rpc.fail_after = None
        self.store.reconcile()
        self.assertEqual(self.store.status("tenant-a")["status"], "applied")
        self.assertEqual(self.rpc.get("seat_meta", "tenant-a::active"), "9")

    def test_lost_ack_and_gateway_restart_reconcile_same_revision(self):
        self.apply()
        # Simulate a crash after the memory switch but before durable applied mark.
        self.store.db.execute("UPDATE tenants SET applied=0")
        self.store.db.commit()
        self.store.close()
        self.store = self.open_store()
        self.store.reconcile()
        self.assertEqual(self.store.status("tenant-a")["revision"], 7)
        self.rpc.values.clear()
        self.store.reconcile()
        self.assertEqual(self.store.status("tenant-a")["status"], "applied")
        self.assertEqual(self.rpc.get("seat_meta", "tenant-a::active"), "7")

    def test_expiry_never_refreshes_itself_and_new_lease_requires_new_revision(self):
        self.apply()
        self.now = NOW + 121
        self.assertEqual(self.store.status("tenant-a")["status"], "expired")
        self.rpc.values.clear()
        self.store.reconcile()
        self.assertEqual(self.rpc.values, {})
        with self.assertRaises(ControlError) as error:
            self.apply()
        self.assertEqual(error.exception.code, "SNAPSHOT_EXPIRED")
        renewed = snapshot()
        renewed.update(issuedAt=self.now, validUntil=self.now + 120)
        with self.assertRaises(ControlError) as error:
            self.apply(renewed)
        self.assertEqual(error.exception.code, "REVISION_CONFLICT")
        renewed["revision"] += 1
        self.apply(renewed)
        self.assertEqual(self.store.status("tenant-a")["status"], "applied")

    def test_tenant_updates_are_independent_and_usernames_cannot_move(self):
        self.apply()
        other = snapshot()
        for item in other["profiles"] + other["seats"]:
            item["tenantId"] = "tenant-b"
        with self.assertRaises(ControlError) as error:
            self.store.apply("tenant-b", other)
        self.assertEqual(error.exception.code, "SEAT_IDENTITY_CONFLICT")
        other["seats"][0]["username"] = "bob"
        self.store.apply("tenant-b", other)
        revoked = snapshot()
        revoked.update(revision=8, seats=[], profiles=[])
        self.apply(revoked)
        self.assertEqual(self.store.status("tenant-b")["revision"], 7)
        self.assertEqual(self.rpc.get("seat_meta", "tenant-b::active"), "7")
        with self.assertRaises(ControlError) as error:
            self.store.apply("tenant-b", snapshot())
        self.assertEqual(error.exception.code, "INVALID_SNAPSHOT")

    def test_second_writer_and_unprotected_state_are_rejected(self):
        with self.assertRaises(ControlError) as error:
            self.open_store()
        self.assertEqual(error.exception.code, "CONTROL_WRITER_ALREADY_RUNNING")
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o755)
            with self.assertRaises(ControlError):
                TenantProjectionStore(directory, "seats.example.test", self.rpc)

    def test_managed_state_requires_explicit_durable_mount(self):
        for path, mounts in ((None, ""), ("relative", ""), (self.temp.name, ""),
                             (self.temp.name, f"30 1 0:1 / {self.temp.name} rw - tmpfs tmpfs rw")):
            with self.assertRaises(ControlError):
                durable_state_directory(path, mounts)
        mounts = f"30 1 8:1 /volumes/seat {self.temp.name} rw - ext4 /dev/sda1 rw"
        self.assertEqual(str(durable_state_directory(self.temp.name, mounts)), self.temp.name)


class DialogInventoryTests(unittest.TestCase):
    class Rpc(KamailioRpc):
        def __init__(self, result):
            self.result = result
            self.inventory = None

        def call(self, method, *params, inventory=False):
            if method != "dlg.list_ctx" or params:
                raise AssertionError("unexpected dialog inventory RPC")
            self.inventory = inventory
            return self.result

    class ReplySocket:
        def __init__(self, flags):
            self.flags = flags

        def recvmsg(self, size):
            self.size = size
            return b'{"result":[]}', [], self.flags, None

        def recv(self, size):
            self.size = size
            return b'{"result":[]}'

    def test_dialog_context_array_extracts_only_valid_cdr_ids(self):
        call_id = "a" * 32
        rpc = self.Rpc([
            {"variables": [{"unrelated": "ignored"}, {"seat_cdr_id": call_id}]},
            {"variables": []},
        ])
        self.assertEqual(rpc.active_cdr_ids(), {call_id})
        self.assertTrue(rpc.inventory)

    def test_empty_inventory_is_authoritative_and_bad_shapes_are_unavailable(self):
        self.assertEqual(self.Rpc([]).active_cdr_ids(), set())
        for result in (
            {},
            [{"variables": {}}],
            [{"variables": ["bad"]}],
            [{"variables": [{"seat_cdr_id": "not-a-call-id"}]}],
        ):
            with self.assertRaises(ControlError) as error:
                self.Rpc(result).active_cdr_ids()
            self.assertEqual(error.exception.code, "GATEWAY_STATE_UNAVAILABLE")

    def test_truncated_inventory_is_rejected_before_json_decode(self):
        client = self.ReplySocket(socket.MSG_TRUNC)
        with self.assertRaises(OSError):
            KamailioRpc._receive_reply(client, inventory=True)
        self.assertEqual(client.size, 1024 * 1024)

    def test_ordinary_rpc_replies_keep_small_bounded_receive(self):
        client = self.ReplySocket(0)
        self.assertEqual(KamailioRpc._receive_reply(client, inventory=False), b'{"result":[]}')
        self.assertEqual(client.size, 16384)


class HttpContractTests(unittest.TestCase):
    def test_server_auth_scope_payload_and_status(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TenantProjectionStore(directory, "seats.example.test", MemoryRpc(), clock=lambda: NOW)
            server = http.server.HTTPServer(("127.0.0.1", 0), ControlHandler)
            server.token, server.store = "a" * 43, store
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def request(method, action, body=None, headers=None):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                try:
                    connection.request(method, "/v1/tenants/tenant-a/" + action, body=body, headers=headers or {})
                    response = connection.getresponse()
                    return response.status, json.loads(response.read())
                finally:
                    connection.close()

            auth = {"Authorization": "Bearer " + server.token, "Content-Type": "application/json"}
            try:
                self.assertEqual(request("GET", "status")[0], 401)
                self.assertEqual(request("GET", "status", headers={**auth, "Origin": "https://webphone.test"})[0], 403)
                self.assertEqual(request("GET", "status", headers=auth)[0], 404)
                self.assertEqual(request("POST", "snapshot", '{"revision":1,"revision":2}', auth)[0], 400)
                self.assertEqual(request("POST", "snapshot", json.dumps(snapshot()), auth)[0], 200)
                status, body = request("GET", "status", headers=auth)
                self.assertEqual((status, body["status"]), (200, "applied"))
                self.assertNotIn("super-secret", json.dumps(body))
                self.assertEqual(request("PUT", "snapshot", "{}", auth)[0], 405)
                self.assertEqual(request("POST", "snapshot", "{}", {**auth, "Content-Type": "text/plain"})[0], 415)
            finally:
                server.shutdown()
                thread.join(2)
                server.server_close()
                store.close()


if __name__ == "__main__":
    unittest.main()
