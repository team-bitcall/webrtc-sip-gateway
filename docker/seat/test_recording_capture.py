import json, os, sqlite3, sys, tempfile, threading, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
from recording_capture import CaptureController, CaptureError

TEN = "t_" + "1" * 64
CALL = "a" * 32
MAN = "b" * 32


class Journal:
    def __init__(self):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(
            "CREATE TABLE calls(call_id TEXT PRIMARY KEY,terminal INTEGER);CREATE TABLE events(sequence INTEGER PRIMARY KEY,payload TEXT,occurred_at INTEGER,call_id TEXT);"
        )

    def end(self, call=CALL, at=2000, uncertain=False):
        self.db.execute("INSERT OR REPLACE INTO calls VALUES(?,1)", (call,))
        self.db.execute(
            "INSERT INTO events(payload,occurred_at,call_id) VALUES(?,?,?)",
            (json.dumps({"type": "ended"}), at, call),
        )
        if uncertain:
            self.db.execute(
                "INSERT INTO events(payload,occurred_at,call_id) VALUES(?,?,?)",
                (json.dumps({"type": "uncertain"}), at, call),
            )


class Rpc:
    def __init__(self):
        self.active = {CALL}

    def active_cdr_ids(self):
        return self.active


class Resolver:
    def resolve_call(self, t, c):
        return "sip-" + c, ["from", "to"]


class NG:
    def __init__(self, pcaps):
        self.calls = []
        self.pcaps = pcaps
        self.stop_ok = True
        self.stop_unknown = False
        self.unknown = False
        self.bad_dtls = False

    def request(self, x):
        self.calls.append(x)
        cmd = x["command"]
        if cmd == "stop recording":
            if self.stop_unknown:
                return {"result": "error", "error-reason": "Unknown call-id"}
            if not self.stop_ok:
                raise OSError("offline")
            return {"result": "ok"}
        if cmd == "start recording":
            return {"result": "ok"}
        if self.unknown:
            return {"result": "error", "error-reason": "Unknown call-id"}
        flags = ["RTP"] if self.bad_dtls else ["RTP", "DTLS fingerprint verified"]
        media_flags = ["DTLS-SRTP"] if self.bad_dtls else []
        tags = {}
        for n, tag in enumerate(["from", "to"]):
            codec = "PCMU/8000" if n == 0 else "PCMA/8000"
            tags[tag] = {
                "medias": [
                    {
                        "type": "audio",
                        "codec": codec,
                        "flags": media_flags,
                        "streams": [
                            {
                                "flags": flags,
                                "endpoint": {
                                    "address": "10.0.0." + str(n + 1),
                                    "port": 1000 + n,
                                },
                                "local port": 2000 + n,
                                "SSRC": n + 1,
                            }
                        ],
                    }
                ]
            }
        return {"result": "ok", "tags": tags}


class Producer:
    def __init__(self, health_error=False):
        self.controller = None
        self.health_error = health_error
        self.stop_pending_seen = []
        self.stops = 0

    def start(self, _row, _tags):
        pass

    def health(self, _row):
        if self.health_error:
            raise OSError("producer unavailable")

    def finish(self, _row):
        pass

    def stop(self, row):
        self.stops += 1
        if self.controller is not None:
            pending = self.controller.db.execute(
                "SELECT stop_pending FROM captures WHERE manifest_id=?",
                (row["manifest_id"],),
            ).fetchone()[0]
            self.stop_pending_seen.append(pending)

    def close(self):
        pass


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.r = Path(self.tmp.name)
        for p in (
            self.r / "state",
            self.r / "spool",
            self.r / "spool/pcaps",
            self.r / "spool/metadata",
            self.r / "out",
        ):
            p.mkdir()
            os.chmod(p, 0o700)
        self.j = Journal()
        self.rpc = Rpc()
        self.ng = NG(self.r / "spool/pcaps")
        self.c = self.make()
        self.bind = {
            "tenantId": "customer-opaque",
            "gatewayId": "https://gateway.example.test",
            "callId": CALL,
            "publicCallId": "c" * 32,
            "membershipId": "member-1",
        }

    def make(self, **kw):
        size = (
            os.statvfs(self.r / "spool").f_blocks
            * os.statvfs(self.r / "spool").f_frsize
        )
        kw.setdefault("maxConcurrent", 1)
        return CaptureController(
            self.r / "state",
            self.j,
            self.rpc,
            ng=self.ng,
            spool=self.r / "spool",
            output=self.r / "out",
            call_resolver=Resolver(),
            maxSpoolBytes=size,
            **kw
        )

    def tearDown(self):
        if getattr(self, "c", None):
            self.c.close()
        self.tmp.cleanup()

    def start(self, call=CALL, man=MAN, binding=None):
        b = dict(self.bind if binding is None else binding)
        b["callId"] = call
        return self.c.handle(
            TEN, {"action": "start", "callId": call, "manifestId": man, "binding": b}
        )

    def test_replay_wrong_tenant_and_slots(self):
        self.assertEqual(self.start()["state"], "capturing")
        self.assertEqual(self.start()["state"], "capturing")
        with self.assertRaises(CaptureError):
            self.c.handle(
                "t_" + "2" * 64,
                {
                    "action": "start",
                    "callId": CALL,
                    "manifestId": MAN,
                    "binding": self.bind,
                },
            )
        c2 = "d" * 32
        m2 = "e" * 32
        with self.assertRaisesRegex(CaptureError, "RECORDING_LIMIT"):
            self.start(c2, m2)

    def test_second_owner_blocked_then_released(self):
        with self.assertRaisesRegex(CaptureError, "RECORDING_ALREADY_RUNNING"):
            self.make()
        self.c.close()
        self.c = self.make()

    def test_restart_stop_retry_blocks_new_start(self):
        self.start()
        self.c.close()
        self.ng.stop_ok = False
        self.c = self.make()
        self.c.recover()
        row = self.c.db.execute("SELECT * FROM captures").fetchone()
        self.assertEqual((row["state"], row["stop_pending"]), ("failed", 1))
        with self.assertRaisesRegex(CaptureError, "RECORDING_CLEANUP_PENDING"):
            self.start("d" * 32, "e" * 32)
        self.ng.stop_ok = True
        self.c.tick()
        self.assertEqual(
            self.c.db.execute("SELECT stop_pending FROM captures").fetchone()[0], 0
        )

    def test_first_status_after_restart_recovers_unknown_ng_call(self):
        self.start()
        self.c.close()
        self.ng.stop_unknown = True
        self.c = self.make()

        result = self.c.handle(
            TEN, {"action": "status", "callId": CALL, "manifestId": MAN}
        )

        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["errorCode"], "RECORDING_RESTART_UNSAFE")
        row = self.c.db.execute(
            "SELECT stop_pending FROM captures WHERE manifest_id=?", (MAN,)
        ).fetchone()
        self.assertEqual(row["stop_pending"], 0)
        self.assertIn(
            {"command": "stop recording", "call-id": "sip-" + CALL}, self.ng.calls
        )

    def test_bad_dtls_and_binding_validation(self):
        self.ng.bad_dtls = True
        with self.assertRaisesRegex(CaptureError, "RECORDING_MEDIA_UNAVAILABLE"):
            self.start()
        self.ng.bad_dtls = False
        b = dict(self.bind)
        b["gatewayId"] = "http://example.test"
        with self.assertRaisesRegex(CaptureError, "INVALID_RECORDING_REQUEST"):
            self.start(binding=b)

    def test_malformed_public_call_id_returns_400(self):
        for malformed in (None, 7, "not-hex"):
            with self.subTest(publicCallId=malformed):
                binding = dict(self.bind)
                binding["publicCallId"] = malformed
                with self.assertRaises(CaptureError) as caught:
                    self.start(binding=binding)
                self.assertEqual(caught.exception.code, "INVALID_RECORDING_REQUEST")
                self.assertEqual(caught.exception.status, 400)

    def test_finish_ng_outage_retries_and_bad_metadata_has_no_artifact(self):
        self.start()
        pcap = self.r / "spool/pcaps" / (MAN + ".pcap")
        pcap.write_bytes(b"bad")
        os.chmod(pcap, 0o600)
        self.j.end(at=2000)
        self.rpc.active = set()
        self.ng.request = lambda x: (_ for _ in ()).throw(OSError())
        cmd = {"action": "finish", "callId": CALL, "manifestId": MAN}
        with self.assertRaisesRegex(CaptureError, "RECORDING_CALL_NOT_COMPLETE"):
            self.c.handle(TEN, cmd)
        self.assertEqual(self.c.status(TEN, cmd)["state"], "capturing")
        self.ng.unknown = True
        self.ng.request = NG.request.__get__(self.ng, NG)
        result = self.c.handle(TEN, cmd)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["errorCode"], "RECORDING_METADATA_MISSING")
        self.assertEqual(list((self.r / "out").iterdir()), [])

    def test_closed_rtpengine_metadata_is_privatized_after_validation(self):
        self.start()
        row = self.c.db.execute("SELECT * FROM captures").fetchone()
        pcap = self.r / "spool/pcaps" / (MAN + ".pcap")
        metadata = self.r / "spool/metadata/random-prefix.txt"
        metadata.write_text(
            str(pcap) + "\n" + "bitcall-recording:" + MAN + "\n",
            encoding="utf-8",
        )
        os.chmod(metadata, 0o664)  # RTPengine's upstream creation mode.
        self.c._metadata_file(row, pcap)
        self.assertEqual(metadata.stat().st_mode & 0o777, 0o600)

    def test_ended_call_still_in_ng_is_stopped_when_duration_expires(self):
        self.start()
        self.j.end(at=2000)
        self.c.clock = lambda: 10**18
        self.c.tick()
        row = self.c.db.execute(
            "SELECT state,error,stop_pending FROM captures"
        ).fetchone()
        self.assertEqual(
            (row["state"], row["error"], row["stop_pending"]),
            ("failed", "RECORDING_LIMIT_REACHED", 0),
        )
        self.assertIn(
            {"command": "stop recording", "call-id": "sip-" + CALL}, self.ng.calls
        )

    def _closed_files(self):
        pcap = self.c.pcaps / (MAN + ".pcap")
        metadata = self.c.metadata / "closed.txt"
        pcap.write_bytes(b"fixture")
        metadata.write_text(str(pcap) + "\nbitcall-recording:" + MAN + "\n")
        os.chmod(pcap, 0o600)
        os.chmod(metadata, 0o600)

    def test_media_guard_stable_checkpoint_allows_ready(self):
        checkpoint = {"revision": 1, "digest": "d" * 64}
        self.c.close()
        self.c = self.make(media_guard=lambda *_args, **kwargs: {**checkpoint, "closed": bool(kwargs.get("require_closed"))})
        self.c.clock = lambda: 1_000_000
        self.start()
        self._closed_files()
        self.j.end()
        self.rpc.active, self.ng.unknown = set(), True
        with mock.patch("recording_capture.finalize_capture", return_value={}):
            self.assertEqual(self.c.handle(TEN, {"action": "finish", "callId": CALL, "manifestId": MAN})["state"], "ready")

    def test_media_guard_change_during_start_fails_and_stops(self):
        calls = []
        def guard(*_args, **_kwargs):
            calls.append(1)
            return {"revision": len(calls), "digest": ("a" if len(calls) == 1 else "b") * 64, "closed": False}
        self.c.close()
        self.c = self.make(media_guard=guard)
        self.assertEqual(self.start()["state"], "failed")
        self.assertIn({"command": "stop recording", "call-id": "sip-" + CALL}, self.ng.calls)

    def test_media_guard_already_closed_rejects_start(self):
        self.c.close()
        self.c = self.make(media_guard=lambda *_args, **_kwargs: {"revision": 1, "digest": "d" * 64, "closed": True})
        with self.assertRaisesRegex(CaptureError, "RECORDING_MEDIA_UNCERTAIN"):
            self.start()

    def test_media_guard_missing_or_unsafe_close_never_writes_wav(self):
        for closed in (False,):
            with self.subTest(closed=closed):
                checkpoint = {"revision": 1, "digest": "d" * 64, "closed": closed}
                self.c.close()
                self.c = self.make(media_guard=lambda *_args, **kwargs: {**checkpoint, "closed": closed if kwargs.get("require_closed") else False})
                self.c.clock = lambda: 1_000_000
                self.start()
                self._closed_files()
                self.j.end()
                self.rpc.active, self.ng.unknown = set(), True
                result = self.c.handle(TEN, {"action": "finish", "callId": CALL, "manifestId": MAN})
                self.assertEqual(result["state"], "failed")
                self.assertEqual(list((self.r / "out").iterdir()), [])

    def test_native_health_failure_persists_cleanup_intent_before_stop(self):
        producer = Producer(health_error=True)
        self.c.close()
        self.c = self.make(producer=producer)
        producer.controller = self.c
        self.c.clock = lambda: 1_000_000
        self.start()
        self.j.end()
        self.rpc.active, self.ng.unknown = set(), True

        result = self.c.handle(
            TEN, {"action": "finish", "callId": CALL, "manifestId": MAN}
        )

        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["errorCode"], "RECORDING_FINALIZE_FAILED")
        self.assertEqual(producer.stop_pending_seen, [1])
        self.assertEqual(
            self.c.db.execute("SELECT stop_pending FROM captures").fetchone()[0], 0
        )
        self.assertNotIn("stop recording", [x["command"] for x in self.ng.calls])

    def test_native_missing_producer_retries_without_legacy_ng_stop(self):
        self.start()
        row = self.c.db.execute("SELECT epoch FROM captures").fetchone()
        epoch = json.loads(row["epoch"])
        epoch["captureMode"] = "subscription-v1"
        with self.c.db:
            self.c.db.execute(
                "UPDATE captures SET epoch=? WHERE manifest_id=?",
                (json.dumps(epoch), MAN),
            )
        self.j.end()
        self.rpc.active, self.ng.unknown = set(), True

        result = self.c.handle(
            TEN, {"action": "finish", "callId": CALL, "manifestId": MAN}
        )
        self.assertEqual(result["errorCode"], "RECORDING_MEDIA_UNAVAILABLE")
        self.assertEqual(
            self.c.db.execute("SELECT stop_pending FROM captures").fetchone()[0], 1
        )
        self.c.tick()
        pending = self.c.db.execute(
            "SELECT stop_pending FROM captures WHERE manifest_id=?", (MAN,)
        ).fetchone()[0]
        self.assertEqual(pending, 1)
        self.assertNotIn("stop recording", [x["command"] for x in self.ng.calls])

    def test_native_same_revision_requires_initial_digest(self):
        initial = {"revision": 3, "digest": "a" * 64}

        def guard(_call_id, require_closed=False):
            return {
                "revision": 3,
                "digest": ("b" if require_closed else "a") * 64,
                "closed": require_closed,
            }

        producer = Producer()
        self.c.close()
        self.c = self.make(media_guard=guard, producer=producer)
        producer.controller = self.c
        self.c.clock = lambda: 1_000_000
        self.start()
        stored = json.loads(
            self.c.db.execute("SELECT epoch FROM captures").fetchone()["epoch"]
        )
        self.assertEqual(stored["mediaCheckpoint"], initial)
        self._closed_files()
        self.j.end()
        self.rpc.active, self.ng.unknown = set(), True

        with mock.patch("recording_capture.finalize_capture") as finalize:
            result = self.c.handle(
                TEN, {"action": "finish", "callId": CALL, "manifestId": MAN}
            )

        self.assertEqual(result["errorCode"], "RECORDING_MEDIA_CHANGED")
        finalize.assert_not_called()


if __name__ == "__main__":
    unittest.main()
