"""Focused recording capacity and interruption acceptance tests."""

import os
from pathlib import Path
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock
import wave

sys.path.insert(0, str(Path(__file__).parent))
from recording_capture import CaptureController, CaptureError
import recording_decode
from recording_decode import finalize_capture
from test_recording_capture import Journal, NG, Resolver, Rpc, TEN
from test_recording_decode import packet, pcap, rtp


class CapacityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for path in (self.root / "state", self.root / "spool", self.root / "spool/pcaps",
                     self.root / "spool/metadata", self.root / "out"):
            path.mkdir()
            os.chmod(path, 0o700)
        self.journal, self.rpc = Journal(), Rpc()
        self.ng = NG(self.root / "spool/pcaps")
        self.controller = None

    def tearDown(self):
        if self.controller is not None:
            self.controller.close()
        self.journal.db.close()
        self.temp.cleanup()

    def make(self, **changes):
        filesystem_size = os.statvfs(self.root / "spool").f_blocks * os.statvfs(self.root / "spool").f_frsize
        self.controller = CaptureController(self.root / "state", self.journal, self.rpc, ng=self.ng,
            spool=self.root / "spool", output=self.root / "out", call_resolver=Resolver(),
            maxSpoolBytes=filesystem_size, **changes)
        return self.controller

    @staticmethod
    def request(call_id, manifest_id):
        return {"action": "start", "callId": call_id, "manifestId": manifest_id, "binding": {
            "tenantId": "customer", "gatewayId": "https://gateway.test", "callId": call_id,
            "publicCallId": ("c" if call_id[0] != "c" else "d") * 32, "membershipId": "member"}}

    def test_simultaneous_starts_cannot_overbook_one_capture_slot(self):
        controller = self.make(maxConcurrent=1)
        calls = ["a" * 32, "b" * 32]
        manifests = ["d" * 32, "e" * 32]
        self.rpc.active.update(calls)
        gate = threading.Barrier(3)
        outcomes = []

        def start(index):
            gate.wait()
            try:
                result = controller.handle(TEN, self.request(calls[index], manifests[index]))
                outcomes.append(result["state"])
            except CaptureError as error:
                outcomes.append(error.code)

        workers = [threading.Thread(target=start, args=(index,)) for index in range(2)]
        for worker in workers:
            worker.start()
        gate.wait()
        for worker in workers:
            worker.join(2)
            self.assertFalse(worker.is_alive())
        self.assertCountEqual(outcomes, ["capturing", "RECORDING_LIMIT"])
        self.assertEqual(controller.db.execute("SELECT COUNT(*) FROM captures").fetchone()[0], 1)
        self.assertEqual(sum(call["command"] == "start recording" for call in self.ng.calls), 1)

    def test_full_spool_rejects_start_and_stops_an_existing_capture(self):
        controller = self.make(maxConcurrent=1)
        with mock.patch("recording_capture.shutil.disk_usage", return_value=type("Usage", (), {"free": 0})()):
            with self.assertRaisesRegex(CaptureError, "RECORDING_SPOOL_FULL"):
                controller.handle(TEN, self.request("a" * 32, "d" * 32))
        self.assertEqual(controller.db.execute("SELECT COUNT(*) FROM captures").fetchone()[0], 0)

        self.assertEqual(controller.handle(TEN, self.request("a" * 32, "d" * 32))["state"], "capturing")
        with mock.patch("recording_capture.shutil.disk_usage", return_value=type("Usage", (), {"free": 0})()):
            controller.tick()
        row = controller.db.execute("SELECT state,error,stop_pending FROM captures").fetchone()
        self.assertEqual(tuple(row), ("failed", "RECORDING_LIMIT_REACHED", 0))

    def test_active_capture_stops_at_exact_duration_boundary(self):
        now = [1_000_000]
        controller = self.make(maxConcurrent=1, clockwallUS=lambda: now[0], limits={
            "maxInputBytes": 1024, "maxOutputBytes": 4096, "maxDurationSeconds": 1, "maxPackets": 100})
        self.assertEqual(controller.handle(TEN, self.request("a" * 32, "d" * 32))["state"], "capturing")
        now[0] = 2_000_000
        controller.tick()
        row = controller.db.execute("SELECT state,error,stop_pending FROM captures").fetchone()
        self.assertEqual(tuple(row), ("failed", "RECORDING_LIMIT_REACHED", 0))


class DecoderFailureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.capture = self.root / "capture.pcap"
        self.sources = [{"address": "10.0.0.1", "port": 10001, "relayPort": 20001, "ssrc": 11,
                         "payloadType": 8, "codec": "PCMA", "tag": "agent"},
                        {"address": "10.0.0.2", "port": 10002, "relayPort": 20002, "ssrc": 22,
                         "payloadType": 8, "codec": "PCMA", "tag": "customer"}]
        self.binding = {"tenantId": "tenant", "gatewayId": "gateway", "membershipId": "member",
                        "callId": "a" * 32, "publicCallId": "b" * 32}
        self.epoch = {"sources": self.sources, "startedAtUs": 1_000_000, "endedAtUs": 3_000_000}
        self.limits = {"maxInputBytes": 1_000_000, "maxOutputBytes": 1_000_000,
                       "maxDurationSeconds": 20, "maxPackets": 30}

    def tearDown(self):
        self.temp.cleanup()

    def write(self, records):
        self.capture.write_bytes(pcap(records))
        os.chmod(self.capture, 0o600)

    def records_with_loss(self):
        return [(1_010_000, packet("10.0.0.1", 10001, 20001, rtp(1, 0, 11, bytes([0xD5]) * 160, 8))),
                (1_010_000, packet("10.0.0.2", 10002, 20002, rtp(1, 0, 22, bytes([0x55]) * 160, 8))),
                (1_050_000, packet("10.0.0.1", 10001, 20001, rtp(3, 320, 11, bytes([0xD5]) * 160, 8))),
                (1_050_000, packet("10.0.0.2", 10002, 20002, rtp(3, 320, 22, bytes([0x55]) * 160, 8)))]

    def test_real_pcma_with_packet_loss_writes_silence_without_swapping_legs(self):
        self.write(self.records_with_loss())
        manifest_id = "c" * 32
        finalize_capture(self.capture, self.root, manifest_id, self.binding, self.epoch, self.limits)
        with wave.open(str(self.root / (manifest_id + ".wav")), "rb") as recording:
            self.assertEqual((recording.getnchannels(), recording.getframerate(), recording.getnframes()), (2, 8000, 560))
            samples = struct.unpack("<1120h", recording.readframes(560))
        self.assertEqual((samples[80 * 2], samples[80 * 2 + 1]), (8, -8))
        self.assertEqual((samples[300 * 2], samples[300 * 2 + 1]), (0, 0))
        self.assertEqual((samples[400 * 2], samples[400 * 2 + 1]), (8, -8))

    def test_decoder_exception_removes_owned_partial_and_final_artifacts(self):
        self.write(self.records_with_loss())
        manifest_id = "d" * 32
        with mock.patch("recording_decode._pcm", side_effect=OSError("interrupted")):
            with self.assertRaisesRegex(OSError, "interrupted"):
                finalize_capture(self.capture, self.root, manifest_id, self.binding, self.epoch, self.limits)
        self.assertEqual(list(self.root.glob(".recording-*")), [])
        self.assertFalse((self.root / (manifest_id + ".wav")).exists())
        self.assertFalse((self.root / (manifest_id + ".json")).exists())


if __name__ == "__main__":
    unittest.main()
