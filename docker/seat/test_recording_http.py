"""Authenticate control requests before forwarding to the private worker."""

import http.client
import http.server
import hashlib
import json
import errno
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
import threading
import unittest

from provisioning import ControlHandler
from recording_runtime import dispatch
from recording_transport import RecordingTransportServer


class RecordingHttpTests(unittest.TestCase):
    def _open(self, transport):
        try:
            transport.open()
        except PermissionError as error:
            if error.errno in {errno.EPERM, errno.EACCES}:
                self.skipTest("the desktop sandbox disallows AF_UNIX bind")
            raise

    def test_authenticated_http_unix_artifact_chunk_and_rejections(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="capture-") as temporary:
            directory = Path(temporary).resolve()
            output = directory / "output"
            output.mkdir(mode=0o700)
            os.chmod(output, 0o700)
            tenant, other = "t_" + "a" * 64, "t_" + "c" * 64
            call, manifest_id = "a" * 32, "b" * 32
            payload = bytes(range(250)) * 40
            audio = (b"RIFF" + struct.pack("<I", 36 + len(payload)) + b"WAVEfmt "
                     + struct.pack("<IHHIIHH", 16, 1, 2, 8000, 32000, 4, 16)
                     + b"data" + struct.pack("<I", len(payload)) + payload)
            binding = {"tenantId": "opaque", "gatewayId": "https://gateway.test", "callId": call,
                       "publicCallId": "c" * 32, "membershipId": "member"}
            manifest = {"schemaVersion": 1, **binding, "manifestId": manifest_id, "finalized": True,
                        "relativeFile": manifest_id + ".wav", "sha256": hashlib.sha256(audio).hexdigest(),
                        "sizeBytes": len(audio), "contentType": "audio/wav"}
            (output / (manifest_id + ".wav")).write_bytes(audio)
            (output / (manifest_id + ".json")).write_bytes(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            )
            for suffix in ("wav", "json"):
                os.chmod(output / (manifest_id + "." + suffix), 0o600)

            class Controller:
                def __init__(self):
                    self.output, self.lock = output, threading.RLock()
                    self.db = sqlite3.connect(":memory:", check_same_thread=False)
                    self.db.row_factory = sqlite3.Row
                    self.db.execute("CREATE TABLE captures(call_id TEXT,manifest_id TEXT,tenant_id TEXT,binding TEXT,state TEXT)")
                    self.db.execute("INSERT INTO captures VALUES(?,?,?,?,?)", (call, manifest_id, tenant, json.dumps(binding), "ready"))

            controller = Controller()
            raw_manifest = (output / (manifest_id + ".json")).read_bytes()
            command = {"action": "chunk", "callId": call, "manifestId": manifest_id,
                       "manifestSha256": hashlib.sha256(raw_manifest).hexdigest(), "offset": 0, "length": 9000}
            transport = RecordingTransportServer(
                directory, lambda scoped, request: dispatch(controller, scoped, request, "https://gateway.test", now_ms=1000)
            )
            self._open(transport)
            stop = threading.Event()

            def serve_unix():
                while not stop.is_set():
                    transport.serve_once()

            worker = threading.Thread(target=serve_unix, daemon=True)
            worker.start()
            server = http.server.HTTPServer(("127.0.0.1", 0), ControlHandler)
            server.token, server.recording_directory = "a" * 43, directory
            http_thread = threading.Thread(target=server.serve_forever, daemon=True)
            http_thread.start()

            def send(path_tenant=tenant, issued=1000):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                try:
                    body = {"issuedAtMs": issued, "command": command}
                    connection.request("POST", "/v1/tenants/" + path_tenant + "/recordings", json.dumps(body),
                                       {"Authorization": "Bearer " + server.token, "Content-Type": "application/json"})
                    response = connection.getresponse()
                    return response.status, json.loads(response.read())
                finally:
                    connection.close()

            try:
                status, result = send()
                self.assertEqual(status, 200)
                self.assertGreater(len(result["dataBase64"]), 8192)
                self.assertEqual(status, 200)
                self.assertEqual(send(issued=-30001), (409, {"error": {"code": "RECORDING_REQUEST_EXPIRED"}}))
                self.assertEqual(send(path_tenant=other), (404, {"error": {"code": "RECORDING_NOT_FOUND"}}))
            finally:
                server.shutdown()
                server.server_close()
                http_thread.join(2)
                stop.set()
                worker.join(3)
                transport.close()
                controller.db.close()

    def test_auth_disabled_mode_and_real_unix_forwarding(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="capture-") as temporary:
            directory = Path(temporary).resolve()
            commands = []

            def dispatch(tenant, request):
                commands.append((tenant, request))
                return {"state": "capturing"}

            transport = RecordingTransportServer(directory, dispatch)
            self._open(transport)
            stop = threading.Event()

            def serve_unix():
                while not stop.is_set():
                    transport.serve_once()

            worker = threading.Thread(target=serve_unix, daemon=True)
            worker.start()
            server = http.server.HTTPServer(("127.0.0.1", 0), ControlHandler)
            server.token, server.recording_directory = "a" * 43, directory
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            tenant = "t_" + "a" * 64
            request = {
                "issuedAtMs": 1000,
                "command": {
                    "action": "status",
                    "callId": "a" * 32,
                    "manifestId": "b" * 32,
                },
            }
            headers = {
                "Authorization": "Bearer " + server.token,
                "Content-Type": "application/json",
            }

            def send(extra=None, payload=None):
                connection = http.client.HTTPConnection(
                    "127.0.0.1", server.server_port, timeout=3
                )
                try:
                    connection.request(
                        "POST",
                        "/v1/tenants/" + tenant + "/recordings",
                        json.dumps(request) if payload is None else payload,
                        {**headers, **(extra or {})},
                    )
                    response = connection.getresponse()
                    return response.status, json.loads(response.read())
                finally:
                    connection.close()

            try:
                self.assertEqual(send({"Authorization": "Bearer wrong"})[0], 401)
                self.assertEqual(send({"Origin": "https://browser.example"})[0], 403)
                self.assertEqual(send(payload="{" + "x" * 7200)[0], 400)
                self.assertEqual(commands, [])
                self.assertEqual(send(), (200, {"state": "capturing"}))
                self.assertEqual(commands, [(tenant, request)])
                server.recording_directory = None
                self.assertEqual(send()[0], 404)
                self.assertEqual(len(commands), 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)
                stop.set()
                worker.join(3)
                transport.close()
                self.assertFalse(worker.is_alive())
