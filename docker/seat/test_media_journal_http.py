import errno
import http.client
import http.server
import json
import tempfile
import threading
import unittest

from call_journal import CallJournal
from media_journal import MediaJournal
from provisioning import JournalHandler


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.journal = CallJournal(self.temp.name, clock=lambda: 1000)
        _, self.call = self.journal.admit({"tenantId": "t_" + "1" * 64, "seatId": "s_" + "2" * 64, "snapshotRevision": 1, "sipCallId": "call", "fromTag": "from", "legId": "", "destination": "+12025550100", "requestedCallerId": None, "effectiveCallerId": "user"})
        try:
            self.server = http.server.HTTPServer(("127.0.0.1", 0), JournalHandler)
        except PermissionError as error:
            self.journal.close(); self.temp.cleanup()
            if error.errno in {errno.EPERM, errno.EACCES}: self.skipTest("sandbox blocks loopback")
            raise
        self.server.journal, self.server.token, self.server.media_journal = self.journal, "a" * 43, MediaJournal(self.journal)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        if hasattr(self, "server"):
            self.server.shutdown(); self.server.server_close(); self.thread.join(2)
        if hasattr(self, "journal"): self.journal.close()
        if hasattr(self, "temp"): self.temp.cleanup()

    def post(self, path, body, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            data = json.dumps(body)
            values = {"Authorization": "Bearer " + self.server.token, "Content-Type": "application/json", **(headers or {})}
            connection.request("POST", path, data, values)
            reply = connection.getresponse()
            return reply.status, json.loads(reply.read())
        finally:
            connection.close()

    def test_private_media_routes_auth_origin_disable_and_schema(self):
        begin = {"callId": self.call, "revision": 1, "method": "INVITE", "fromTag": "from", "toTag": "to", "sipCode": 200, "sdpSha256": "a" * 64}
        self.assertEqual(self.post("/v1/call-events/media/begin", begin), (200, {"revision": 1, "status": "pending"}))
        self.assertEqual(self.post("/v1/call-events/media/complete", {"callId": self.call, "revision": 1, "success": True}), (200, {"revision": 1, "status": "applied"}))
        self.assertEqual(self.post("/v1/call-events/media/close", {"callId": self.call, "count": 1, "unsafe": False}), (200, {"count": 1, "unsafe": False}))
        self.assertEqual(self.post("/v1/call-events/media/begin", begin | {"rawSdp": "secret"})[0], 400)
        self.assertEqual(self.post("/v1/call-events/media/begin", begin, {"Authorization": "Bearer bad"})[0], 401)
        self.assertEqual(self.post("/v1/call-events/media/begin", begin, {"Origin": "https://browser.test"})[0], 403)
        self.server.media_journal = None
        self.assertEqual(self.post("/v1/call-events/media/begin", begin)[0], 404)


if __name__ == "__main__":
    unittest.main()
