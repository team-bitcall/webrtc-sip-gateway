import os
import tempfile
import unittest

from call_journal import CallJournal
from media_control import MediaController, MediaError


TENANT = "t_" + "a" * 64
SEAT = "s_" + "b" * 64
ACTOR = "c" * 32
LISTENER = "d" * 32


def context(suffix=""):
    return {"tenantId": TENANT, "seatId": SEAT, "snapshotRevision": 1,
            "sipCallId": "call" + suffix + "@example.test", "fromTag": "browser-tag",
            "legId": "", "destination": "+12025550100", "requestedCallerId": None,
            "effectiveCallerId": "+12025550101"}


class Rpc:
    def __init__(self):
        self.active = set()

    def active_cdr_ids(self):
        return set(self.active)


class Ng:
    def __init__(self, fail_start=False, fail_unsubscribe=False, unknown_unsubscribe=False):
        self.fail_start, self.fail_unsubscribe = fail_start, fail_unsubscribe
        self.unknown_unsubscribe, self.requests = unknown_unsubscribe, []

    def request(self, value):
        self.requests.append(value)
        if value["command"] == "query":
            return {"result": "ok", "tags": {"browser-tag": {}, "upstream-tag": {}}}
        if value["command"] == "subscribe request":
            return {"result": "error"} if self.fail_start else {"result": "ok", "sdp": "v=0\r\nm=audio 9 RTP/AVP 0\r\na=sendonly\r\nm=audio 9 RTP/AVP 0\r\na=sendonly\r\n"}
        if value["command"] == "unsubscribe":
            if self.fail_unsubscribe:
                return {"result": "error", "error-reason": "temporary failure"}
            if self.unknown_unsubscribe:
                return {"result": "error", "error-reason": "Unknown call-id"}
        return {"result": "ok"}


class MediaControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        os.chmod(self.temp.name, 0o700)
        self.now = [1_000]
        self.journal = CallJournal(self.temp.name, clock=lambda: self.now[0])
        self.rpc, self.ng = Rpc(), Ng()
        self.controller = MediaController(self.temp.name, self.journal, self.rpc,
                                          clock=lambda: self.now[0], ng=self.ng,
                                          projection=lambda _tenant: {"status": "applied", "validUntil": 999999})
        _, self.call_id = self.journal.admit(context())
        self.journal.append({"callId": self.call_id, "type": "answered", "legId": "upstream-tag",
                             "sipCode": 200, "reason": None, "endedBy": None})
        self.rpc.active.add(self.call_id)

    def tearDown(self):
        self.controller.close()
        self.journal.close()
        self.temp.cleanup()

    def request(self, action, **extra):
        value = {"action": action, "callId": self.call_id, "listenerId": LISTENER,
                 "actorId": ACTOR, **extra}
        return self.controller.handle(TENANT, value)

    def start(self):
        return self.request("start", leaseSeconds=15)

    def test_tenant_and_stale_call_are_unavailable(self):
        with self.assertRaises(MediaError) as error:
            self.controller.handle("t_" + "e" * 64, {"action": "start", "callId": self.call_id,
                                   "listenerId": LISTENER, "actorId": ACTOR, "leaseSeconds": 15})
        self.assertEqual(error.exception.code, "MEDIA_UNAVAILABLE")
        self.rpc.active.clear()
        with self.assertRaises(MediaError) as error:
            self.start()
        self.assertEqual(error.exception.code, "MEDIA_UNAVAILABLE")

    def test_foreign_actor_cannot_read_a_listener_session(self):
        self.start()
        with self.assertRaises(MediaError) as error:
            self.controller.handle(TENANT, {"action": "status", "callId": self.call_id,
                                             "listenerId": LISTENER, "actorId": "e" * 32})
        self.assertEqual(error.exception.code, "MEDIA_FORBIDDEN")

    def test_answer_replay_does_not_repeat_ng_command(self):
        offered = self.start()
        answer = {"fence": offered["fence"], "sdp": "v=0\r\nm=audio 9 RTP/AVP 0\r\na=recvonly\r\nm=audio 9 RTP/AVP 0\r\na=recvonly\r\n"}
        self.assertEqual(self.request("answer", **answer)["state"], "listening")
        self.assertEqual(self.request("answer", **answer)["state"], "listening")
        self.assertEqual(sum(item["command"] == "subscribe answer" for item in self.ng.requests), 1)

    def test_expiry_unsubscribes_and_ends_the_session(self):
        self.start()
        self.now[0] += 15_001
        self.controller.sweep()
        status = self.request("status")
        self.assertEqual(status["state"], "ended")
        self.assertEqual(sum(item["command"] == "unsubscribe" for item in self.ng.requests), 1)

    def test_per_call_limit_and_failed_start_rollback(self):
        self.start()
        with self.assertRaises(MediaError) as error:
            self.controller.handle(TENANT, {"action": "start", "callId": self.call_id,
                                             "listenerId": "e" * 32, "actorId": "f" * 32,
                                             "leaseSeconds": 15})
        self.assertEqual(error.exception.code, "MEDIA_LIMIT")
        self.controller.close()
        failing = MediaController(self.temp.name, self.journal, self.rpc, clock=lambda: self.now[0], ng=Ng(True),
                                  projection=lambda _tenant: {"status": "applied", "validUntil": 999999})
        failing.maximum = 2
        with self.assertRaises(MediaError):
            failing.handle(TENANT, {"action": "start", "callId": self.call_id,
                                    "listenerId": "e" * 32, "actorId": "f" * 32, "leaseSeconds": 15})
        self.assertEqual(failing._row(TENANT, "e" * 32)["state"], "ended")
        failing.close()
        self.controller = MediaController(self.temp.name, self.journal, self.rpc, clock=lambda: self.now[0], ng=self.ng,
                                          projection=lambda _tenant: {"status": "applied", "validUntil": 999999})

    def test_stop_serializes_later_renew_and_unknown_call_cleanup_settles(self):
        offered = self.start()
        self.ng.unknown_unsubscribe = True
        stopped = self.request("stop", fence=offered["fence"])
        self.assertEqual(stopped["state"], "ended")
        with self.assertRaises(MediaError):
            self.request("renew", fence=offered["fence"], leaseSeconds=15)

    def test_expiry_stops_even_when_rpc_inventory_is_unavailable(self):
        self.start()
        self.now[0] += 15_001
        self.rpc.active_cdr_ids = lambda: (_ for _ in ()).throw(OSError("offline"))
        self.controller.sweep()
        self.assertEqual(self.request("status")["state"], "ended")

    def test_closed_rows_prune_only_after_source_call_leaves_live_inventory(self):
        offered = self.start()
        self.request("stop", fence=offered["fence"])
        self.now[0] += 300_001
        self.controller.sweep()
        retained = self.controller._row(TENANT, LISTENER)
        self.assertIsNotNone(retained)
        self.assertEqual(retained["fence"], offered["fence"])
        self.rpc.active.clear()
        self.controller.sweep()
        self.assertIsNone(self.controller._row(TENANT, LISTENER))

    def test_unknown_stop_and_status_do_not_touch_ng(self):
        unknown = "e" * 32
        before = list(self.ng.requests)
        for action, extra in (("status", {}), ("stop", {"fence": 1})):
            with self.assertRaises(MediaError) as error:
                self.controller.handle(TENANT, {"action": action, "callId": self.call_id,
                                                 "listenerId": unknown, "actorId": ACTOR, **extra})
            self.assertEqual((error.exception.status, error.exception.code), (404, "MEDIA_NOT_FOUND"))
        self.assertEqual(self.ng.requests, before)


if __name__ == "__main__":
    unittest.main()
