import base64
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

sys.path.insert(0, str(Path(__file__).parent))
from recording_artifacts import RecordingArtifacts
from recording_capture import CaptureError


TENANT = "t_" + "1" * 64
OTHER_TENANT = "t_" + "2" * 64
CALL = "a" * 32
MANIFEST = "b" * 32


def wav(payload):
    return (
        b"RIFF" + struct.pack("<I", 36 + len(payload)) + b"WAVEfmt "
        + struct.pack("<IHHIIHH", 16, 1, 2, 8000, 32000, 4, 16)
        + b"data" + struct.pack("<I", len(payload)) + payload
    )


class Controller:
    def __init__(self, output):
        self.output = output
        self.lock = threading.RLock()
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute(
            "CREATE TABLE captures(call_id TEXT,manifest_id TEXT,tenant_id TEXT,binding TEXT,state TEXT)"
        )


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.output = Path(self.temp.name) / "output"
        self.output.mkdir(mode=0o700)
        os.chmod(self.output, 0o700)
        self.controller = Controller(self.output)
        self.api = RecordingArtifacts(self.controller)
        self.payload = bytes(range(256)) * 3
        self.audio = wav(self.payload)
        self.binding = {
            "tenantId": "tenant-private", "gatewayId": "https://gateway.test",
            "callId": CALL, "publicCallId": "c" * 32, "membershipId": "member-private",
        }
        self.manifest = {
            "schemaVersion": 1, **self.binding, "manifestId": MANIFEST,
            "finalized": True, "relativeFile": MANIFEST + ".wav",
            "sha256": hashlib.sha256(self.audio).hexdigest(), "sizeBytes": len(self.audio),
            "contentType": "audio/wav",
        }
        self.add_row()
        self.write_artifacts()

    def tearDown(self):
        self.controller.db.close()
        self.temp.cleanup()

    def add_row(self, tenant=TENANT, call=CALL, manifest=MANIFEST, state="ready"):
        binding = dict(self.binding)
        binding["callId"] = call
        self.controller.db.execute(
            "INSERT INTO captures VALUES(?,?,?,?,?)",
            (call, manifest, tenant, json.dumps(binding, separators=(",", ":")), state),
        )
        self.controller.db.commit()

    def write_artifacts(self):
        (self.output / (MANIFEST + ".wav")).write_bytes(self.audio)
        raw = json.dumps(self.manifest, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        (self.output / (MANIFEST + ".json")).write_bytes(raw)
        for suffix in ("wav", "json"):
            os.chmod(self.output / (MANIFEST + "." + suffix), 0o600)

    def manifest_command(self):
        return {"action": "manifest", "callId": CALL, "manifestId": MANIFEST}

    def test_manifest_and_chunks_reconstruct_the_real_wav(self):
        reply = self.api.handle(TENANT, self.manifest_command())
        self.assertEqual(reply["manifest"], self.manifest)
        self.assertEqual(base64.b64decode(reply["rawBase64"]), (self.output / (MANIFEST + ".json")).read_bytes())
        pieces, offset = [], 0
        while True:
            chunk = self.api.handle(TENANT, {"action": "chunk", "callId": CALL, "manifestId": MANIFEST, "manifestSha256": reply["manifestSha256"], "offset": offset, "length": 97})
            pieces.append(base64.b64decode(chunk["dataBase64"]))
            offset += len(pieces[-1])
            if chunk["eof"]:
                break
        self.assertEqual(b"".join(pieces), self.audio)
        self.assertEqual(chunk["sha256"], self.manifest["sha256"])

    def test_wrong_tenant_and_nonready_are_not_readable(self):
        with self.assertRaisesRegex(CaptureError, "RECORDING_NOT_FOUND"):
            self.api.handle(OTHER_TENANT, self.manifest_command())
        self.controller.db.execute("UPDATE captures SET state='failed'")
        self.controller.db.commit()
        with self.assertRaisesRegex(CaptureError, "RECORDING_NOT_READY"):
            self.api.handle(TENANT, self.manifest_command())

    def test_symlink_hash_mismatch_and_offset_limits_are_rejected(self):
        (self.output / (MANIFEST + ".json")).unlink()
        (self.output / (MANIFEST + ".json")).symlink_to("/etc/passwd")
        with self.assertRaisesRegex(CaptureError, "RECORDING_ARTIFACT_UNAVAILABLE"):
            self.api.handle(TENANT, self.manifest_command())
        (self.output / (MANIFEST + ".json")).unlink()
        self.write_artifacts()
        reply = self.api.handle(TENANT, self.manifest_command())
        command = {"action": "chunk", "callId": CALL, "manifestId": MANIFEST, "manifestSha256": "0" * 64, "offset": 0, "length": 1}
        with self.assertRaisesRegex(CaptureError, "RECORDING_MANIFEST_MISMATCH"):
            self.api.handle(TENANT, command)
        command["manifestSha256"] = reply["manifestSha256"]
        command["offset"] = len(self.audio) + 1
        with self.assertRaisesRegex(CaptureError, "INVALID_RECORDING_REQUEST"):
            self.api.handle(TENANT, command)
        command["offset"], command["length"] = 0, 65537
        with self.assertRaisesRegex(CaptureError, "INVALID_RECORDING_REQUEST"):
            self.api.handle(TENANT, command)

    def test_list_ready_is_tenant_scoped_and_paginates_by_rowid(self):
        self.add_row(call="d" * 32, manifest="e" * 32)
        self.add_row(tenant=OTHER_TENANT, call="f" * 32, manifest="0" * 32)
        page = self.api.handle(TENANT, {"action": "list-ready", "after": 0, "limit": 1})
        self.assertEqual(len(page["items"]), 1)
        self.assertIsNotNone(page["nextCursor"])
        next_page = self.api.handle(TENANT, {"action": "list-ready", "after": page["nextCursor"], "limit": 1})
        self.assertEqual(len(next_page["items"]), 1)
        self.assertIsNone(next_page["nextCursor"])
        self.assertNotIn("f" * 32, [item["callId"] for item in page["items"] + next_page["items"]])


if __name__ == "__main__":
    unittest.main()
