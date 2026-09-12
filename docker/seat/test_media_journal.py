import tempfile
import threading
import unittest
from pathlib import Path

from call_journal import CallJournal, JournalError
from media_journal import MediaJournal, media_checkpoint


TENANT, SEAT = "t_" + "1" * 64, "s_" + "2" * 64


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.journal = CallJournal(self.temp.name, clock=lambda: 1000)
        _, self.call = self.journal.admit({"tenantId": TENANT, "seatId": SEAT, "snapshotRevision": 1, "sipCallId": "call", "fromTag": "from", "legId": "", "destination": "+12025550100", "requestedCallerId": None, "effectiveCallerId": "user"})
        self.media = MediaJournal(self.journal)

    def tearDown(self):
        self.journal.close()
        self.temp.cleanup()

    def begin(self, revision=1, digest="a" * 64):
        return {"callId": self.call, "revision": revision, "method": "INVITE", "fromTag": "from", "toTag": "to", "sipCode": 200, "sdpSha256": digest}

    def test_duplicate_gap_failure_and_closed_checkpoint(self):
        self.assertEqual(self.media.begin(self.begin())["status"], "pending")
        with self.assertRaisesRegex(JournalError, "MEDIA_EVIDENCE_CONFLICT"):
            self.media.begin(self.begin())
        with self.assertRaisesRegex(JournalError, "MEDIA_EVIDENCE_INCOMPLETE"):
            self.media.checkpoint(self.call)
        with self.assertRaisesRegex(JournalError, "MEDIA_EVIDENCE_CONFLICT"):
            self.media.complete({"callId": self.call, "revision": 1, "success": True})

    def test_failed_closure_and_reopen(self):
        with self.assertRaisesRegex(JournalError, "CALL_NOT_FOUND"):
            self.media.begin({**self.begin(), "callId": "f" * 32})
        self.media.begin(self.begin())
        self.media.complete({"callId": self.call, "revision": 1, "success": False})
        with self.assertRaisesRegex(JournalError, "MEDIA_EVIDENCE_INCOMPLETE"):
            self.media.checkpoint(self.call)
        self.media.media_closure({"callId": self.call, "count": 1, "unsafe": True})
        with self.assertRaisesRegex(JournalError, "MEDIA_EVIDENCE_INCOMPLETE"):
            self.media.checkpoint(self.call, True)
        self.journal.close()
        self.journal = CallJournal(self.temp.name, clock=lambda: 1000)
        self.media = MediaJournal(self.journal)
        with self.assertRaisesRegex(JournalError, "MEDIA_EVIDENCE_INCOMPLETE"):
            media_checkpoint(self.journal, self.call)

    def test_concurrent_identical_begin_and_immutable_close_before_complete(self):
        command, replies = self.begin(), []
        def begin():
            try: replies.append(self.media.begin(command))
            except JournalError as error: replies.append(error.code)
        threads = [threading.Thread(target=begin) for _ in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertIn({"revision": 1, "status": "pending"}, replies)
        self.assertIn("MEDIA_EVIDENCE_CONFLICT", replies)
        with self.assertRaisesRegex(JournalError, "MEDIA_EVIDENCE_CONFLICT"):
            self.media.complete({"callId": self.call, "revision": 1, "success": True})
        # A closure made before completion is immutable; a late begin poisons it.
        _, second = self.journal.admit({"tenantId": TENANT, "seatId": SEAT, "snapshotRevision": 1, "sipCallId": "second", "fromTag": "from2", "legId": "", "destination": "+12025550101", "requestedCallerId": None, "effectiveCallerId": "user"})
        command = {**self.begin(), "callId": second}
        self.media.begin(command)
        self.media.media_closure({"callId": second, "count": 1, "unsafe": False})
        self.media.complete({"callId": second, "revision": 1, "success": True})
        with self.assertRaisesRegex(JournalError, "MEDIA_EVIDENCE_CLOSED"):
            self.media.begin(command)
        with self.assertRaisesRegex(JournalError, "MEDIA_EVIDENCE_INCOMPLETE"):
            self.media.checkpoint(second)

    def test_conflicting_closure_stays_unsafe_after_replay_and_reopen(self):
        self.media.begin(self.begin())
        self.media.complete({"callId": self.call, "revision": 1, "success": True})
        closure = {"callId": self.call, "count": 1, "unsafe": False}
        self.media.media_closure(closure)
        with self.assertRaisesRegex(JournalError, "MEDIA_EVIDENCE_CONFLICT"):
            self.media.media_closure({**closure, "unsafe": True})
        self.journal.close()
        self.journal = CallJournal(self.temp.name, clock=lambda: 1000)
        self.media = MediaJournal(self.journal)
        with self.assertRaisesRegex(JournalError, "MEDIA_EVIDENCE_INCOMPLETE"):
            self.media.media_closure(closure)
        with self.assertRaisesRegex(JournalError, "MEDIA_EVIDENCE_INCOMPLETE"):
            self.media.checkpoint(self.call, True)

    def test_compaction_keeps_media_while_unacknowledged_lifecycle_remains(self):
        self.media.begin(self.begin())
        self.media.complete({"callId": self.call, "revision": 1, "success": True})
        self.journal.append({"callId": self.call, "type": "ended", "legId": "", "sipCode": 200, "reason": "normal", "endedBy": "agent"})
        self.journal.clock = lambda: 2000
        self.journal.compact(retention_ms=1)
        self.assertEqual(self.journal.db.execute("SELECT COUNT(*) FROM media_observations").fetchone()[0], 1)
        events = self.journal.events(TENANT)
        self.journal.acknowledge(TENANT, events["nextSequence"])
        self.journal.clock = lambda: 3000
        self.journal.compact(retention_ms=1)
        self.assertEqual(self.journal.db.execute("SELECT COUNT(*) FROM media_observations").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
