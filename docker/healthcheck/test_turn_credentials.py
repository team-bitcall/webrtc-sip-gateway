"""Exercise the real HTTP handler without a gateway or live TURN credentials."""
import base64
import hashlib
import hmac
import http.client
import http.server
import json
import os
import threading
import unittest
from unittest.mock import patch

import healthcheck_server as helper


class TurnCredentialsTest(unittest.TestCase):
    def request(self, *, secret="unit-test-only", mode="coturn", ttl=3600,
                path="/turn-credentials"):
        with patch.multiple(helper, DOMAIN="relay.example.test", TURN_SECRET=secret,
                            TURN_TTL=ttl, TURN_UDP_PORT=3478, TURNS_TCP_PORT=5349), \
                patch.dict(os.environ, {"TURN_MODE": mode}), \
                patch.object(helper.time, "time", return_value=1700000000):
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), helper.TurnCredentialsHandler)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            connection = http.client.HTTPConnection(*server.server_address, timeout=2)
            try:
                connection.request("GET", path)
                response = connection.getresponse()
                return response.status, dict(response.getheaders()), response.read()
            finally:
                connection.close()
                server.shutdown()
                server.server_close()
                worker.join()

    def test_credentials_match_coturn_hmac_and_expiry(self):
        status, headers, body = self.request()
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["expiresAt"], 1700003600)
        self.assertEqual(payload["username"], "1700003600:webrtc")
        expected = base64.b64encode(hmac.new(
            b"unit-test-only", b"1700003600:webrtc", hashlib.sha1).digest()).decode()
        self.assertEqual(payload["credential"], expected)
        self.assertEqual(payload["uris"], [
            "turn:relay.example.test:3478",
            "turn:relay.example.test:3478?transport=tcp",
            "turns:relay.example.test:5349",
        ])
        self.assertEqual(headers["Cache-Control"], "private, no-store")
        self.assertNotIn(b"unit-test-only", body)

    def test_disabled_or_missing_secret_does_not_issue_credentials(self):
        for kwargs in ({"secret": ""}, {"mode": "none"}, {"path": "/other"}):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(self.request(**kwargs)[0], 404)

    def test_invalid_ttl_does_not_issue_credentials(self):
        for ttl in (0, -1):
            with self.subTest(ttl=ttl):
                self.assertEqual(self.request(ttl=ttl)[0], 503)

    def test_legacy_secret_only_configuration_still_works(self):
        self.assertEqual(self.request(mode="")[0], 200)
        self.assertEqual(self.request(ttl=172800)[0], 200)


if __name__ == "__main__":
    unittest.main()
