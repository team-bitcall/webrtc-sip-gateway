import os
from pathlib import Path
import tempfile
import unittest

from call_journal import CallJournal, JournalError


def context():
    return {"tenantId": "t_" + "a" * 64, "seatId": "s_" + "b" * 64, "snapshotRevision": 7,
      "sipCallId": "call@example.test", "fromTag": "tag",
      "legId": "", "destination": "+12025550100", "requestedCallerId": None, "effectiveCallerId": "+12025550101"}


class CallJournalTests(unittest.TestCase):
    def test_admission_is_durable_idempotent_and_tenant_scoped_ack(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            journal = CallJournal(directory, clock=lambda: 2000)
            _, call_id = journal.admit(context())
            _, same = journal.admit(context())
            self.assertEqual(call_id, same)
            answered = journal.append({"callId": call_id, "type": "answered",
              "legId": "to-tag", "sipCode": 200, "reason": None, "endedBy": None})
            self.assertEqual(answered["sequence"], 2)
            self.assertEqual(answered["occurredAtMs"], 2000)
            events = journal.events(context()["tenantId"])
            self.assertEqual([item["type"] for item in events["events"]], ["admitted", "answered"])
            self.assertEqual(journal.acknowledge(context()["tenantId"], 2)["acknowledgedSequence"], 2)
            self.assertEqual(journal.acknowledge(context()["tenantId"], 2)["acknowledgedSequence"], 2)
            self.assertEqual(journal.events(context()["tenantId"], after=2)["events"], [])
            journal.close()
            restarted = CallJournal(directory)
            self.assertEqual(restarted.events(context()["tenantId"], after=2)["events"], [])
            restarted.close()

    def test_semantic_reply_duplicate_does_not_allocate_another_sequence(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            journal = CallJournal(directory)
            _, call_id = journal.admit(context())
            payload = {"callId": call_id, "type": "progress",
              "legId": "branch-a", "sipCode": 180, "reason": None, "endedBy": None}
            self.assertEqual(journal.append(payload)["sequence"], 2)
            self.assertEqual(journal.append(payload)["sequence"], 2)
            with self.assertRaises(JournalError): journal.acknowledge(context()["tenantId"], 3)
            journal.close()

    def test_ack_retains_semantic_dedupe_and_capacity_reserves_terminal_events(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            journal = CallJournal(directory, max_pending=3, terminal_reserve=1)
            _, call_id = journal.admit(context())
            bye = {"callId": call_id, "type": "ended", "legId": "", "sipCode": 200,
                   "reason": "normal", "endedBy": "agent"}
            event = journal.append(bye)
            journal.events(context()["tenantId"])
            journal.acknowledge(context()["tenantId"], event["sequence"])
            self.assertEqual(journal.append(bye)["eventId"], event["eventId"])
            second = {**context(), "sipCallId": "second@example.test", "fromTag": "tag-two"}
            _, second_id = journal.admit(second)
            journal.append({"callId": second_id, "type": "progress", "legId": "", "sipCode": 180,
                            "reason": None, "endedBy": None})
            with self.assertRaises(JournalError) as error:
                journal.admit({**context(), "sipCallId": "third@example.test", "fromTag": "tag-three"})
            self.assertEqual(error.exception.code, "JOURNAL_CAPACITY")
            journal.close()

    def test_restart_uncertainty_requires_authoritative_empty_dialog_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            journal = CallJournal(directory)
            _, call_id = journal.admit(context())
            journal.close()
            restarted = CallJournal(directory)
            self.assertEqual([event["type"] for event in restarted.events(context()["tenantId"])["events"]], ["admitted"])
            restarted.reconcile_active(set(), grace_ms=0)
            self.assertEqual(restarted.events(context()["tenantId"])["events"][-1]["type"], "uncertain")
            restarted.close()

    def test_answer_evidence_reopens_failed_call_but_never_ended_call(self):
        clock = [1_000]
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            journal = CallJournal(directory, clock=lambda: clock[0])

            def append(call_id, event_type, sip_code, reason=None, ended_by=None):
                return journal.append({"callId": call_id, "type": event_type, "legId": "to-tag",
                                       "sipCode": sip_code, "reason": reason, "endedBy": ended_by})

            _, failed_then_answered = journal.admit(context())
            append(failed_then_answered, "failed", 487, "cancelled", "upstream")
            append(failed_then_answered, "answered", 200)
            self.assertEqual(journal.db.execute("SELECT terminal FROM calls WHERE call_id=?", (failed_then_answered,)).fetchone()["terminal"], 0)

            _, answered_then_failed = journal.admit({**context(), "sipCallId": "answer-first@example.test", "fromTag": "two"})
            append(answered_then_failed, "answered", 200)
            append(answered_then_failed, "failed", 487, "cancelled", "upstream")
            self.assertEqual(journal.db.execute("SELECT terminal FROM calls WHERE call_id=?", (answered_then_failed,)).fetchone()["terminal"], 0)

            _, ended_then_answered = journal.admit({**context(), "sipCallId": "ended@example.test", "fromTag": "three"})
            append(ended_then_answered, "ended", 200, "normal", "agent")
            append(ended_then_answered, "answered", 200)
            self.assertEqual(journal.db.execute("SELECT terminal FROM calls WHERE call_id=?", (ended_then_answered,)).fetchone()["terminal"], 1)

            journal.reconcile_active(set(), grace_ms=0)
            events = journal.events(context()["tenantId"])["events"]
            self.assertEqual([event["type"] for event in events if event["callId"] == failed_then_answered][-1], "uncertain")
            journal.close()

    def test_acknowledged_terminal_evidence_compacts_after_retention_but_active_context_remains(self):
        clock = [1_000]
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            journal = CallJournal(directory, clock=lambda: clock[0])
            _, call_id = journal.admit(context())
            ended = journal.append({"callId": call_id, "type": "ended", "legId": "", "sipCode": 200,
                                    "reason": "normal", "endedBy": "agent"})
            journal.events(context()["tenantId"])
            journal.acknowledge(context()["tenantId"], ended["sequence"])
            first_ack = journal.db.execute("SELECT acked_at FROM events WHERE sequence=?", (ended["sequence"],)).fetchone()["acked_at"]
            clock[0] += 3
            journal.acknowledge(context()["tenantId"], ended["sequence"])
            self.assertEqual(journal.db.execute("SELECT acked_at FROM events WHERE sequence=?", (ended["sequence"],)).fetchone()["acked_at"], first_ack)
            self.assertFalse(journal.health()["degraded"])
            clock[0] += 8
            journal.compact(retention_ms=7)
            self.assertEqual(journal.events(context()["tenantId"])["events"], [])
            _, active_id = journal.admit({**context(), "sipCallId": "active@example.test", "fromTag": "active"})
            clock[0] += 8
            journal.compact(retention_ms=7)
            self.assertEqual(journal.append({"callId": active_id, "type": "progress", "legId": "", "sipCode": 180,
                                             "reason": None, "endedBy": None})["callId"], active_id)
            journal.close()


if __name__ == "__main__": unittest.main()
