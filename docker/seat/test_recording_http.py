"""Authenticate control requests before forwarding to the private worker."""

import http.client
import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest

from provisioning import ControlHandler
from recording_transport import RecordingTransportServer


class RecordingHttpTests(unittest.TestCase):
    def test_auth_disabled_mode_and_real_unix_forwarding(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="capture-") as temporary:
            directory = Path(temporary).resolve()
            commands = []

            def dispatch(tenant, request):
                commands.append((tenant, request))
                return {"state": "capturing"}

            transport = RecordingTransportServer(directory, dispatch)
            transport.open()
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
