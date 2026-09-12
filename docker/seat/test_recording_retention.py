import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from call_journal import CallJournal
from recording_capture import CaptureError
from recording_retention import RecordingRetention
from recording_capture import CaptureController


TENANT, SEAT = "t_" + "1" * 64, "s_" + "2" * 64


class Rpc:
    def active_cdr_ids(self): return set()
class NG:
    def request(self, _value): return {"result": "error", "error-reason": "Unknown call-id"}
class Controller:
    def __init__(self, root, journal):
        self.lock, self.journal, self.rpc, self.ng = threading.RLock(), journal, Rpc(), NG()
        self.output, self.pcaps, self.metadata = root / "out", root / "pcaps", root / "metadata"
        for path in (self.output, self.pcaps, self.metadata): path.mkdir(mode=0o700, exist_ok=True); os.chmod(path, 0o700)
        self.db = sqlite3.connect(root / "retention.sqlite"); self.db.row_factory = sqlite3.Row
        self.db.executescript("CREATE TABLE IF NOT EXISTS captures(call_id TEXT,manifest_id TEXT,tenant_id TEXT,sip_call_id TEXT,pcap TEXT,metadata TEXT,state TEXT,started_us INTEGER,ended_us INTEGER,stop_pending INTEGER,publication TEXT); CREATE TABLE IF NOT EXISTS recording_cleanup(manifest_id TEXT,state TEXT);")
        self.db.commit(); os.chmod(root / "retention.sqlite", 0o600)
    def _metadata_file(self, row, pcap):
        path = self.metadata / row["metadata"]
        assert path.read_text().splitlines() == [str(pcap), "bitcall-recording:" + row["manifest_id"]]
        return path


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.journal = CallJournal(self.temp.name, clock=lambda: 1000)
        self.staging = mock.patch.dict(sys.modules, {"recording_staging": SimpleNamespace(recover_staging=lambda *_args: True)}); self.staging.start()
        self.context = {"tenantId": TENANT, "seatId": SEAT, "snapshotRevision": 1, "sipCallId": "sip", "fromTag": "from", "legId": "", "destination": "+12025550100", "requestedCallerId": None, "effectiveCallerId": "user"}
        _, self.call = self.journal.admit(self.context); self.controller = Controller(Path(self.temp.name), self.journal)
    def tearDown(self): self.controller.db.close(); self.journal.close(); self.staging.stop(); self.temp.cleanup()
    def terminal(self): self.journal.append({"callId": self.call, "type": "ended", "legId": "", "sipCode": 200, "reason": "normal", "endedBy": "agent"})
    def test_failed_disposes_only_verified_terminal_raw_files(self):
        self.terminal(); man = "a" * 32; pcap = self.controller.pcaps / (man + ".pcap"); meta = self.controller.metadata / "closed"
        pcap.write_bytes(b"raw"); meta.write_text(str(pcap) + "\nbitcall-recording:" + man + "\n")
        os.chmod(pcap, 0o600); os.chmod(meta, 0o600)
        self.controller.db.execute("INSERT INTO captures VALUES(?,?,?,?,?,?,?,?,?,?,NULL)", (self.call, man, TENANT, "sip", pcap.name, meta.name, "failed", 0, 0, 0)); self.controller.db.commit()
        self.assertEqual(RecordingRetention(self.controller, 1, 1, clock=lambda: 100).sweep(), {"processed": 1})
        self.assertFalse(pcap.exists()); self.assertFalse(meta.exists()); self.assertIsNone(self.controller.db.execute("SELECT 1 FROM captures").fetchone())
    def test_pruned_stored_call_cannot_replay_and_tombstone_can_bound(self):
        self.terminal(); events = self.journal.events(TENANT); self.journal.acknowledge(TENANT, events["nextSequence"]); self.journal.clock = lambda: 3000; self.journal.compact(1)
        man = "b" * 32
        self.controller.db.execute("INSERT INTO captures VALUES(?,?,?,?,?,?,?,?,?,?,NULL)", (self.call, man, TENANT, "sip", man + ".pcap", "closed", "stored", 0, 0, 0)); self.controller.db.execute("INSERT INTO recording_cleanup VALUES(?,?)", (man, "stored")); self.controller.db.commit()
        self.assertEqual(RecordingRetention(self.controller, 1, 1, clock=lambda: 100).sweep()["processed"], 1)
        _, new_call = self.journal.admit(self.context); self.assertNotEqual(new_call, self.call)

    def test_disabled_and_invalid_configuration_do_not_dispose(self):
        self.assertEqual(RecordingRetention(self.controller).sweep(), {"processed": 0})
        for values in ((0, 1), (1, None), ("1", 1)):
            with self.subTest(values=values):
                with self.assertRaises(ValueError): RecordingRetention(self.controller, *values)

    def test_partial_unlink_reopens_and_retries_from_file_backed_intent(self):
        self.terminal(); man = "c" * 32; pcap = self.controller.pcaps / (man + ".pcap"); meta = self.controller.metadata / "closed"
        pcap.write_bytes(b"raw"); meta.write_text(str(pcap) + "\nbitcall-recording:" + man + "\n")
        os.chmod(pcap, 0o600); os.chmod(meta, 0o600)
        self.controller.db.execute("INSERT INTO captures VALUES(?,?,?,?,?,?,?,?,?,?,NULL)", (self.call, man, TENANT, "sip", pcap.name, meta.name, "failed", 0, 0, 0)); self.controller.db.commit()
        original = __import__("recording_retention")._remove
        def crash(controller, row, entry):
            original(controller, row, entry)
            if entry["role"] == "pcap": raise CaptureError("RECORDING_RETENTION_PENDING")
        with mock.patch("recording_retention._remove", side_effect=crash):
            self.assertEqual(RecordingRetention(self.controller, 1, 1, clock=lambda: 100).sweep()["processed"], 0)
        self.controller.db.close(); self.controller = Controller(Path(self.temp.name), self.journal)
        self.assertEqual(RecordingRetention(self.controller, 1, 1, clock=lambda: 100).sweep()["processed"], 1)

    def test_replaced_pending_inode_is_not_deleted(self):
        self.terminal(); man = "d" * 32; pcap = self.controller.pcaps / (man + ".pcap"); meta = self.controller.metadata / "closed"
        pcap.write_bytes(b"raw"); meta.write_text(str(pcap) + "\nbitcall-recording:" + man + "\n")
        os.chmod(pcap, 0o600); os.chmod(meta, 0o600)
        self.controller.db.execute("INSERT INTO captures VALUES(?,?,?,?,?,?,?,?,?,?,NULL)", (self.call, man, TENANT, "sip", pcap.name, meta.name, "failed", 0, 0, 0)); self.controller.db.commit()
        with mock.patch.object(RecordingRetention, "_complete", side_effect=CaptureError("RECORDING_RETENTION_PENDING")):
            RecordingRetention(self.controller, 1, 1, clock=lambda: 100).sweep()
        meta.rename(Path(self.temp.name) / "held-meta"); meta.write_text(str(pcap) + "\nbitcall-recording:" + man + "\n"); os.chmod(meta, 0o600)
        self.assertEqual(RecordingRetention(self.controller, 1, 1, clock=lambda: 100).sweep()["processed"], 0)
        self.assertTrue(meta.exists())

    def test_cursor_reaches_eligible_after_five_ineligible_rows(self):
        self.terminal()
        for index in range(6):
            man = "e" * 31 + format(index, "x")
            pcap, meta = self.controller.pcaps / (man + ".pcap"), self.controller.metadata / ("m" + str(index))
            if index == 5:
                pcap.write_bytes(b"raw"); meta.write_text(str(pcap) + "\nbitcall-recording:" + man + "\n"); os.chmod(pcap, 0o600); os.chmod(meta, 0o600)
            self.controller.db.execute("INSERT INTO captures VALUES(?,?,?,?,?,?,?,?,?,?,NULL)", (self.call, man, TENANT, "sip", pcap.name, meta.name, "failed", 0, 0, 1 if index < 5 else 0))
        self.controller.db.commit(); retention = RecordingRetention(self.controller, 1, 1, clock=lambda: 100)
        self.assertEqual(retention.sweep()["processed"], 0); self.assertEqual(retention.sweep()["processed"], 1)

    def test_failed_native_start_without_artifacts_releases_capacity(self):
        self.terminal(); man = "7" * 32
        self.controller.db.execute("ALTER TABLE captures ADD COLUMN epoch TEXT")
        epoch = json.dumps({"captureMode": "subscription-v1"})
        self.controller.db.execute(
            "INSERT INTO captures(call_id,manifest_id,tenant_id,sip_call_id,pcap,metadata,state,started_us,ended_us,stop_pending,publication,epoch) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (self.call, man, TENANT, "sip", man + ".pcap", None,
             "failed", 0, 0, 0, None, epoch),
        )
        self.controller.db.commit()

        result = RecordingRetention(
            self.controller, 1, 1, clock=lambda: 100
        ).sweep()

        self.assertEqual(result, {"processed": 1})
        self.assertIsNone(
            self.controller.db.execute("SELECT 1 FROM captures").fetchone()
        )

    def test_failed_native_empty_retirement_refuses_stray_or_linked_files(self):
        self.terminal()
        self.controller.db.execute("ALTER TABLE captures ADD COLUMN epoch TEXT")
        cases = ("pcap-file", "pcap-link", "metadata-file", "metadata-link")
        for index, case in enumerate(cases):
            with self.subTest(case=case):
                man = "8" * 31 + format(index, "x")
                pcap = self.controller.pcaps / (man + ".pcap")
                metadata = self.controller.metadata / (man + ".meta")
                target = Path(self.temp.name) / ("foreign-" + str(index))
                target.write_bytes(b"foreign")
                if case == "pcap-file": pcap.write_bytes(b"stray")
                elif case == "pcap-link": pcap.symlink_to(target)
                elif case == "metadata-file": metadata.write_bytes(b"stray")
                else: metadata.symlink_to(target)
                self.controller.db.execute(
                    "INSERT INTO captures(call_id,manifest_id,tenant_id,sip_call_id,pcap,metadata,state,started_us,ended_us,stop_pending,publication,epoch) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (self.call, man, TENANT, "sip", man + ".pcap", None,
                     "failed", 0, 0, 0, None,
                     json.dumps({"captureMode": "subscription-v1"})),
                )
                self.controller.db.commit()
                retention = RecordingRetention(self.controller, 1, 1, clock=lambda: 100)
                with mock.patch.object(
                    self.controller, "_metadata_file",
                    side_effect=CaptureError("RECORDING_METADATA_MISSING"),
                ):
                    self.assertEqual(retention.sweep(), {"processed": 0})
                self.assertIsNotNone(
                    self.controller.db.execute(
                        "SELECT 1 FROM captures WHERE manifest_id=?", (man,)
                    ).fetchone()
                )
                self.controller.db.execute(
                    "DELETE FROM captures WHERE manifest_id=?", (man,)
                )
                self.controller.db.execute(
                    "DELETE FROM recording_retention WHERE manifest_id=?", (man,)
                )
                self.controller.db.commit()
                pcap.unlink(missing_ok=True); metadata.unlink(missing_ok=True)

    def test_pending_empty_intent_rechecks_source_call_is_gone(self):
        self.terminal(); man = "6" * 32
        self.controller.db.execute("ALTER TABLE captures ADD COLUMN epoch TEXT")
        self.controller.db.execute(
            "INSERT INTO captures(call_id,manifest_id,tenant_id,sip_call_id,pcap,metadata,state,started_us,ended_us,stop_pending,publication,epoch) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (self.call, man, TENANT, "sip", man + ".pcap", None,
             "failed", 0, 0, 0, None,
             json.dumps({"captureMode": "subscription-v1"})),
        )
        self.controller.db.commit()
        retention = RecordingRetention(self.controller, 1, 1, clock=lambda: 100)
        with mock.patch.object(
            RecordingRetention, "_complete",
            side_effect=CaptureError("RECORDING_RETENTION_PENDING"),
        ):
            self.assertEqual(retention.sweep(), {"processed": 0})
        self.assertIsNotNone(
            self.controller.db.execute(
                "SELECT 1 FROM recording_retention WHERE manifest_id=?", (man,)
            ).fetchone()
        )
        self.controller.ng = SimpleNamespace(
            request=lambda _value: {"result": "ok", "tags": {}}
        )

        self.assertEqual(retention.sweep(), {"processed": 0})
        self.assertIsNotNone(
            self.controller.db.execute(
                "SELECT 1 FROM captures WHERE manifest_id=?", (man,)
            ).fetchone()
        )

    def test_published_orphan_wav_requires_exact_receipt(self):
        self.terminal(); man = "f" * 32; pcap = self.controller.pcaps / (man + ".pcap"); meta = self.controller.metadata / "closed"; wav = self.controller.output / (man + ".wav")
        pcap.write_bytes(b"raw"); meta.write_text(str(pcap) + "\nbitcall-recording:" + man + "\n"); wav.write_bytes(b"orphan")
        for path in (pcap, meta, wav): os.chmod(path, 0o600)
        from recording_cleanup import _private_identity
        receipt = json.dumps({"wav": _private_identity(wav), "manifest": {"dev": 0, "ino": 0, "size": 0, "uid": 0, "mode": 0}})
        self.controller.db.execute("INSERT INTO captures VALUES(?,?,?,?,?,?,?,?,?,?,?)", (self.call, man, TENANT, "sip", pcap.name, meta.name, "failed", 0, 0, 0, receipt)); self.controller.db.commit()
        self.assertEqual(RecordingRetention(self.controller, 1, 1, clock=lambda: 100).sweep()["processed"], 1); self.assertFalse(wav.exists())

    def test_orphan_wav_wrong_receipt_inode_is_retained(self):
        self.terminal(); man = "9" * 32; pcap = self.controller.pcaps / (man + ".pcap"); meta = self.controller.metadata / "closed"; wav = self.controller.output / (man + ".wav")
        pcap.write_bytes(b"raw"); meta.write_text(str(pcap) + "\nbitcall-recording:" + man + "\n"); wav.write_bytes(b"old")
        for path in (pcap, meta, wav): os.chmod(path, 0o600)
        from recording_cleanup import _private_identity
        receipt = json.dumps({"wav": _private_identity(wav), "manifest": {"dev": 0, "ino": 0, "size": 0, "uid": 0, "mode": 0}})
        wav.rename(Path(self.temp.name) / "held-wav"); wav.write_bytes(b"new"); os.chmod(wav, 0o600)
        self.controller.db.execute("INSERT INTO captures VALUES(?,?,?,?,?,?,?,?,?,?,?)", (self.call, man, TENANT, "sip", pcap.name, meta.name, "failed", 0, 0, 0, receipt)); self.controller.db.commit()
        self.assertEqual(RecordingRetention(self.controller, 1, 1, clock=lambda: 100).sweep()["processed"], 0); self.assertTrue(wav.exists())

    def test_real_capture_controller_rejects_old_call_after_journal_prune(self):
        self.terminal(); events = self.journal.events(TENANT); self.journal.acknowledge(TENANT, events["nextSequence"]); self.journal.clock = lambda: 3000; self.journal.compact(1)
        root = Path(self.temp.name) / "real"; state, spool, output = root / "state", root / "spool", root / "out"
        for path in (state, spool, spool / "pcaps", spool / "metadata", output): path.mkdir(parents=True, mode=0o700); os.chmod(path, 0o700)
        class RealRpc:
            def active_cdr_ids(self): return set()
        class RealNG:
            def request(self, _value): return {"result": "error", "error-reason": "Unknown call-id"}
        size = os.statvfs(spool).f_blocks * os.statvfs(spool).f_frsize
        capture = CaptureController(state, self.journal, RealRpc(), projection=lambda _tenant: {"status": "applied", "validUntil": 9999999999}, ng=RealNG(), spool=spool, output=output, maxSpoolBytes=size)
        try:
            binding = {"tenantId": "customer", "gatewayId": "https://gateway.test", "callId": self.call, "publicCallId": "a" * 32, "membershipId": "member"}
            with self.assertRaisesRegex(CaptureError, "RECORDING_UNAVAILABLE"):
                capture.handle(TENANT, {"action": "start", "callId": self.call, "manifestId": "b" * 32, "binding": binding})
        finally: capture.close()


if __name__ == "__main__": unittest.main()
