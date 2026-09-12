import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import recording_cleanup
from recording_artifacts import RecordingArtifacts


TENANT = "t_" + "1" * 64
OTHER = "t_" + "2" * 64
CALL, MANIFEST = "a" * 32, "b" * 32


class Controller:
    def __init__(self, root):
        self.lock = threading.RLock()
        self.output, self.pcaps, self.metadata = root / "out", root / "pcaps", root / "metadata"
        for directory in (self.output, self.pcaps, self.metadata):
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
        self.db = sqlite3.connect(root / "cleanup.sqlite", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("CREATE TABLE IF NOT EXISTS captures(call_id TEXT,manifest_id TEXT,tenant_id TEXT,binding TEXT,pcap TEXT,metadata TEXT,state TEXT,error TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS recording_cleanup(manifest_id TEXT PRIMARY KEY,tenant_id TEXT,call_id TEXT,manifest_sha256 TEXT,wav_sha256 TEXT,size_bytes INTEGER,inventory TEXT,state TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS recording_cleanup_cursor(id INTEGER PRIMARY KEY,cursor INTEGER)")
        self.db.execute("INSERT OR IGNORE INTO recording_cleanup_cursor VALUES(1,0)")
        self.db.commit()
        os.chmod(root / "cleanup.sqlite", 0o600)

    def _metadata_file(self, row, pcap):
        path = self.metadata / row["metadata"]
        lines = path.read_text(encoding="utf8").splitlines()
        if not lines or lines[0] != str(pcap) or "bitcall-recording:" + row["manifest_id"] not in lines:
            raise RuntimeError("invalid metadata fixture")
        return path


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.controller = Controller(self.root)
        self.binding = {"tenantId": "opaque", "gatewayId": "https://gateway.test", "callId": CALL, "publicCallId": "c" * 32, "membershipId": "member"}
        payload = b"x" * 400
        self.audio = b"RIFF" + struct.pack("<I", 36 + len(payload)) + b"WAVEfmt " + struct.pack("<IHHIIHH", 16, 1, 2, 8000, 32000, 4, 16) + b"data" + struct.pack("<I", len(payload)) + payload
        self.manifest = {"schemaVersion": 1, **self.binding, "manifestId": MANIFEST, "finalized": True, "relativeFile": MANIFEST + ".wav", "sha256": hashlib.sha256(self.audio).hexdigest(), "sizeBytes": len(self.audio), "contentType": "audio/wav"}
        self.write_files()
        self.controller.db.execute("INSERT INTO captures VALUES(?,?,?,?,?,?,?,NULL)", (CALL, MANIFEST, TENANT, json.dumps(self.binding, sort_keys=True, separators=(",", ":")), MANIFEST + ".pcap", "closed.txt", "ready"))
        self.controller.db.commit()

    def tearDown(self):
        self.controller.db.close()
        self.temp.cleanup()

    def write_files(self):
        values = {
            self.controller.output / (MANIFEST + ".wav"): self.audio,
            self.controller.output / (MANIFEST + ".json"): json.dumps(self.manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n",
            self.controller.pcaps / (MANIFEST + ".pcap"): b"pcap",
            self.controller.metadata / "closed.txt": (str(self.controller.pcaps / (MANIFEST + ".pcap")) + "\nbitcall-recording:" + MANIFEST + "\n").encode(),
        }
        for path, value in values.items():
            path.write_bytes(value)
            os.chmod(path, 0o600)

    def command(self, **changes):
        raw = (self.controller.output / (MANIFEST + ".json")).read_bytes()
        value = {"action": "acknowledge", "callId": CALL, "manifestId": MANIFEST, "manifestSha256": hashlib.sha256(raw).hexdigest(), "sha256": self.manifest["sha256"], "sizeBytes": len(self.audio)}
        value.update(changes)
        return value

    def test_acknowledge_persists_then_deletes_and_tombstones(self):
        command = self.command()
        result = RecordingArtifacts(self.controller).handle(TENANT, command)
        self.assertEqual(result["state"], "stored")
        self.assertEqual(self.controller.db.execute("SELECT state FROM captures").fetchone()[0], "stored")
        self.assertEqual(self.controller.db.execute("SELECT state FROM recording_cleanup").fetchone()[0], "stored")
        self.assertFalse(any(any(directory.iterdir()) for directory in (self.controller.output, self.controller.pcaps, self.controller.metadata)))
        self.assertEqual(RecordingArtifacts(self.controller).handle(TENANT, command)["state"], "stored")
        self.assertEqual(RecordingArtifacts(self.controller).handle(TENANT, {"action": "list-ready", "after": 0, "limit": 25}), {"items": [], "nextCursor": None})

    def test_mismatch_and_foreign_tenant_do_not_acknowledge(self):
        with self.assertRaisesRegex(Exception, "RECORDING_ACK_MISMATCH"):
            RecordingArtifacts(self.controller).handle(TENANT, self.command(sha256="0" * 64))
        with self.assertRaisesRegex(Exception, "RECORDING_NOT_FOUND"):
            RecordingArtifacts(self.controller).handle(OTHER, self.command())
        self.assertIsNone(self.controller.db.execute("SELECT 1 FROM recording_cleanup").fetchone())
        self.assertTrue((self.controller.output / (MANIFEST + ".wav")).exists())

    def test_crashpoint_resume_and_replaced_file_fail_closed(self):
        with mock.patch("recording_cleanup._complete", side_effect=recording_cleanup.CaptureError("RECORDING_CLEANUP_PENDING")):
            self.assertEqual(RecordingArtifacts(self.controller).handle(TENANT, self.command())["state"], "cleanup_pending")
        self.assertEqual(self.controller.db.execute("SELECT state FROM recording_cleanup").fetchone()[0], "pending")
        wav = self.controller.output / (MANIFEST + ".wav")
        wav.rename(self.root / "held-original-wav")
        wav.write_bytes(self.audio)
        os.chmod(wav, 0o600)
        recording_cleanup.resume(self.controller)
        self.assertEqual(self.controller.db.execute("SELECT state FROM captures").fetchone()[0], "ready")
        self.assertTrue(wav.exists())
        # The exact same durable receipt is idempotent and remains retryable.
        self.assertEqual(RecordingArtifacts(self.controller).handle(TENANT, self.command())["state"], "cleanup_pending")

    def test_identical_receipt_resumes_after_partial_unlink_without_reading_files(self):
        command = self.command()
        original = recording_cleanup._remove

        def crash_after_wav(controller, row, entry):
            original(controller, row, entry)
            if entry["role"] == "wav":
                raise recording_cleanup.CaptureError("RECORDING_CLEANUP_PENDING")

        with mock.patch("recording_cleanup._remove", side_effect=crash_after_wav):
            self.assertEqual(RecordingArtifacts(self.controller).handle(TENANT, command)["state"], "cleanup_pending")
        self.assertFalse((self.controller.output / (MANIFEST + ".wav")).exists())
        self.controller.db.close()
        self.controller = Controller(self.root)
        self.assertEqual(RecordingArtifacts(self.controller).handle(TENANT, command)["state"], "stored")

    def test_fsync_failure_recovers_from_durable_inventory(self):
        command = self.command()
        with mock.patch("recording_cleanup.os.fsync", side_effect=OSError()):
            self.assertEqual(RecordingArtifacts(self.controller).handle(TENANT, command)["state"], "cleanup_pending")
        self.assertEqual(self.controller.db.execute("SELECT state FROM captures").fetchone()[0], "ready")
        recording_cleanup.resume(self.controller)
        self.assertEqual(self.controller.db.execute("SELECT state FROM captures").fetchone()[0], "stored")

    def test_resume_rotates_past_failing_pending_intents(self):
        for value in range(6):
            call, manifest = ("0" * 31 + format(value, "x")), ("d" * 31 + format(value, "x"))
            binding = dict(self.binding, callId=call)
            self.controller.db.execute("INSERT INTO captures VALUES(?,?,?,?,?,?,?,NULL)", (call, manifest, TENANT, json.dumps(binding), manifest + ".pcap", "closed.txt", "ready"))
            self.controller.db.execute("INSERT INTO recording_cleanup VALUES(?,?,?,?,?,?,?,?)", (manifest, TENANT, call, "a" * 64, "b" * 64, 44, "[]", "pending"))
        self.controller.db.commit()
        cursors = []
        for _ in range(6):
            recording_cleanup.resume(self.controller, 1)
            cursors.append(self.controller.db.execute("SELECT cursor FROM recording_cleanup_cursor WHERE id=1").fetchone()[0])
        self.assertEqual(len(set(cursors)), 6)


if __name__ == "__main__":
    unittest.main()
