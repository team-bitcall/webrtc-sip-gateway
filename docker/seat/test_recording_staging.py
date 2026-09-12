"""Crash recovery tests for private per-manifest decoder staging."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import recording_decode
from recording_staging import RecordingStagingError, create_staging, recover_staging
from test_recording_decode import packet, pcap, rtp, ulaw


class RecordingStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.output = self.root / "output"
        self.output.mkdir(mode=0o700)
        self.capture = self.root / "capture.pcap"
        sound = bytes(ulaw(1000) for _ in range(160))
        records = [(1_010_000, packet("10.0.0.1", 10001, 20001, rtp(1, 0, 11, sound))),
                   (1_010_000, packet("10.0.0.2", 10002, 20002, rtp(1, 0, 22, sound)))]
        self.capture.write_bytes(pcap(records))
        os.chmod(self.capture, 0o600)
        self.manifest = "a" * 32
        self.binding = {"tenantId": "tenant", "gatewayId": "gateway", "membershipId": "member",
                        "callId": "b" * 32, "publicCallId": "c" * 32}
        self.epoch = {"sources": [
            {"address": "10.0.0.1", "port": 10001, "relayPort": 20001, "ssrc": 11,
             "payloadType": 0, "codec": "PCMU", "tag": "agent"},
            {"address": "10.0.0.2", "port": 10002, "relayPort": 20002, "ssrc": 22,
             "payloadType": 0, "codec": "PCMU", "tag": "customer"}],
            "startedAtUs": 1_000_000, "endedAtUs": 2_000_000}
        self.limits = {"maxInputBytes": 1_000_000, "maxOutputBytes": 1_000_000,
                       "maxDurationSeconds": 20, "maxPackets": 30}

    def tearDown(self):
        self.temp.cleanup()

    def test_sigkill_leaves_fixed_staging_that_recovery_removes_only(self):
        marker = self.root / "decoder-entered"
        environment = dict(os.environ, PYTHONPATH=str(Path(__file__).parent), CAPTURE=str(self.capture),
            OUTPUT=str(self.output), MANIFEST=self.manifest, MARKER=str(marker),
            BINDING=json.dumps(self.binding), EPOCH=json.dumps(self.epoch), LIMITS=json.dumps(self.limits))
        script = """
import json, os, time
from pathlib import Path
import recording_decode
original = recording_decode._write_all
def interrupted(fd, data):
    os.write(fd, data[:1])
    Path(os.environ['MARKER']).write_text('entered')
    while True: time.sleep(1)
recording_decode._write_all = interrupted
recording_decode.finalize_capture(Path(os.environ['CAPTURE']), Path(os.environ['OUTPUT']),
    os.environ['MANIFEST'], json.loads(os.environ['BINDING']), json.loads(os.environ['EPOCH']),
    json.loads(os.environ['LIMITS']))
"""
        process = subprocess.Popen([sys.executable, "-c", script], env=environment,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 5
        while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(marker.exists(), "decoder did not reach staged write")
        process.kill()
        self.assertEqual(process.wait(timeout=5), -9)

        staging = self.output / (".recording-" + self.manifest)
        self.assertTrue(staging.is_dir())
        legacy = self.output / (".recording-" + self.manifest + "-999-0.part")
        legacy.write_bytes(b"legacy")
        os.chmod(legacy, 0o600)
        foreign = self.output / "foreign.wav"
        foreign.write_bytes(b"foreign")
        os.chmod(foreign, 0o600)

        self.assertTrue(recover_staging(self.output, self.manifest))
        self.assertFalse(staging.exists())
        self.assertEqual(legacy.read_bytes(), b"legacy")
        self.assertEqual(foreign.read_bytes(), b"foreign")
        self.assertEqual(self.capture.read_bytes()[:4], b"\xd4\xc3\xb2\xa1")
        self.assertTrue(recover_staging(self.output, self.manifest))

    def test_sigkill_between_publish_link_and_unlink_preserves_verified_final(self):
        marker = self.root / "audio-linked"
        environment = dict(os.environ, PYTHONPATH=str(Path(__file__).parent), CAPTURE=str(self.capture),
            OUTPUT=str(self.output), MANIFEST=self.manifest, MARKER=str(marker),
            BINDING=json.dumps(self.binding), EPOCH=json.dumps(self.epoch), LIMITS=json.dumps(self.limits))
        script = """
import json, os, time
from pathlib import Path
import recording_decode
original = Path.unlink
def interrupted(self, *args, **kwargs):
    if self.name == 'audio.part':
        Path(os.environ['MARKER']).write_text('linked')
        while True: time.sleep(1)
    return original(self, *args, **kwargs)
Path.unlink = interrupted
recording_decode.finalize_capture(Path(os.environ['CAPTURE']), Path(os.environ['OUTPUT']),
    os.environ['MANIFEST'], json.loads(os.environ['BINDING']), json.loads(os.environ['EPOCH']),
    json.loads(os.environ['LIMITS']))
"""
        process = subprocess.Popen([sys.executable, "-c", script], env=environment,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 5
        while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(marker.exists(), "decoder did not reach publication crash point")
        process.kill()
        self.assertEqual(process.wait(timeout=5), -9)

        staging = self.output / (".recording-" + self.manifest)
        staged_audio, final_audio = staging / "audio.part", self.output / (self.manifest + ".wav")
        self.assertEqual((staged_audio.stat().st_dev, staged_audio.stat().st_ino, staged_audio.stat().st_nlink),
                         (final_audio.stat().st_dev, final_audio.stat().st_ino, 2))
        self.assertTrue(recover_staging(self.output, self.manifest))
        self.assertFalse(staging.exists())
        self.assertTrue(final_audio.is_file())
        self.assertEqual(final_audio.stat().st_nlink, 1)
        self.assertFalse((self.output / (self.manifest + ".json")).exists())

    def test_unknown_or_linked_entries_fail_without_partial_removal(self):
        staging = create_staging(self.output, self.manifest)
        known = staging / "mono-0.part"
        known.write_bytes(b"known")
        os.chmod(known, 0o600)
        unknown = staging / "unexpected.part"
        unknown.write_bytes(b"unknown")
        os.chmod(unknown, 0o600)
        with self.assertRaisesRegex(RecordingStagingError, "unknown staging entry"):
            recover_staging(self.output, self.manifest)
        self.assertEqual(known.read_bytes(), b"known")
        self.assertEqual(unknown.read_bytes(), b"unknown")

        unknown.unlink()
        link = staging / "mono-1.part"
        link.symlink_to(self.capture)
        with self.assertRaises(RecordingStagingError):
            recover_staging(self.output, self.manifest)
        self.assertTrue(known.exists())
        self.assertTrue(link.is_symlink())

    def test_foreign_hardlink_is_not_mistaken_for_partial_publication(self):
        staging = create_staging(self.output, self.manifest)
        audio = staging / "audio.part"
        audio.write_bytes(b"audio")
        os.chmod(audio, 0o600)
        foreign = self.output / "foreign.wav"
        os.link(audio, foreign)
        with self.assertRaises(RecordingStagingError):
            recover_staging(self.output, self.manifest)
        self.assertEqual(audio.stat().st_nlink, 2)
        self.assertEqual(foreign.read_bytes(), b"audio")

    def test_staging_creation_failure_closes_capture_and_does_not_remove_existing_directory(self):
        staging = create_staging(self.output, self.manifest)
        sentinel = staging / "mono-0.part"
        sentinel.write_bytes(b"existing")
        os.chmod(sentinel, 0o600)
        capture_fd = os.open(self.capture, os.O_RDONLY)
        with mock.patch("recording_decode._private_file", return_value=capture_fd), \
                mock.patch("recording_decode.create_staging", side_effect=FileExistsError("occupied")), \
                mock.patch("recording_decode.remove_staging") as remove:
            with self.assertRaisesRegex(FileExistsError, "occupied"):
                recording_decode.finalize_capture(self.capture, self.output, self.manifest,
                    self.binding, self.epoch, self.limits)
            remove.assert_not_called()
        with self.assertRaises(OSError):
            os.fstat(capture_fd)
        self.assertEqual(sentinel.read_bytes(), b"existing")


if __name__ == "__main__":
    unittest.main()
