"""Focused native-subscription leg mapping and codec rollover tests."""

import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import wave

sys.path.insert(0, str(Path(__file__).parent))
from recording_decode import RecordingDecodeError, finalize_capture
from test_recording_decode import packet, pcap, rtp, ulaw


class SubscriptionMappingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.capture = self.root / "capture.pcap"
        self.sources = [
            {"address": "127.0.0.1", "port": 10001, "relayPort": 20001, "ssrc": 0,
             "payloadType": 0, "codec": "PCMU", "tag": "agent"},
            {"address": "127.0.0.1", "port": 10002, "relayPort": 20002, "ssrc": 0,
             "payloadType": 0, "codec": "PCMU", "tag": "customer"},
        ]
        self.binding = {"tenantId": "tenant", "gatewayId": "gateway", "membershipId": "member",
                        "callId": "a" * 32, "publicCallId": "b" * 32}
        self.epoch = {"captureMode": "subscription-v1", "sources": self.sources,
                      "startedAtUs": 1_000_000, "endedAtUs": 5_000_000}
        self.limits = {"maxInputBytes": 2_000_000, "maxOutputBytes": 2_000_000,
                       "maxDurationSeconds": 10, "maxPackets": 500}

    def tearDown(self):
        self.temp.cleanup()

    def write(self, records):
        self.capture.write_bytes(pcap(records))
        os.chmod(self.capture, 0o600)

    def finalize(self, records, manifest, epoch=None):
        self.write(records)
        return finalize_capture(self.capture, self.root, manifest, self.binding,
                                self.epoch if epoch is None else epoch, self.limits)

    def test_fixed_leg_tuple_survives_ssrc_payload_and_clock_rollover(self):
        positive, negative = bytes(ulaw(1000) for _ in range(160)), bytes(ulaw(-1000) for _ in range(160))
        records = [
            (1_010_000, packet("127.0.0.1", 10001, 20001, rtp(500, 12_000, 11, positive, 0))),
            (1_010_000, packet("127.0.0.1", 10002, 20002, rtp(600, 22_000, 22, negative, 0))),
            # A source restart may reset sequence and RTP clocks while changing
            # SSRC/PT; the producer's fixed tuple continues to bind the leg.
            (1_050_000, packet("127.0.0.1", 10001, 20001, rtp(1, 5, 111, bytes([0xD5]) * 160, 8))),
            (1_050_000, packet("127.0.0.1", 10002, 20002, rtp(1, 7, 222, bytes([0x55]) * 160, 8))),
        ]
        manifest = "c" * 32
        self.finalize(records, manifest)
        with wave.open(str(self.root / (manifest + ".wav")), "rb") as recording:
            self.assertEqual((recording.getnchannels(), recording.getframerate(), recording.getnframes()), (2, 8000, 560))
            samples = struct.unpack("<1120h", recording.readframes(560))
        self.assertGreater(samples[80 * 2], 500)
        self.assertLess(samples[80 * 2 + 1], -500)
        self.assertEqual((samples[400 * 2], samples[400 * 2 + 1]), (8, -8))

    def test_missing_leg_unsupported_payload_reorder_and_overlap_fail_closed(self):
        sound = bytes(ulaw(500) for _ in range(160))
        cases = [
            ("d" * 32, [(1_010_000, packet("127.0.0.1", 10001, 20001, rtp(1, 0, 11, sound, 0)))], "both recording legs"),
            ("e" * 32, [(1_010_000, packet("127.0.0.1", 10001, 20001, rtp(1, 0, 11, sound, 9)))], "unsupported subscription codec"),
            ("f" * 32, [
                (1_010_000, packet("127.0.0.1", 10001, 20001, rtp(2, 160, 11, sound, 0))),
                (1_030_000, packet("127.0.0.1", 10001, 20001, rtp(1, 0, 11, sound, 0))),
            ], "reordering"),
            ("1" * 32, [
                (1_010_000, packet("127.0.0.1", 10001, 20001, rtp(1, 0, 11, sound, 0))),
                (1_015_000, packet("127.0.0.1", 10001, 20001, rtp(1, 0, 111, bytes([0xD5]) * 160, 8))),
            ], "overlapping"),
        ]
        for manifest, records, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(RecordingDecodeError, message):
                self.finalize(records, manifest)
            self.assertFalse((self.root / (manifest + ".wav")).exists())
            self.assertFalse((self.root / (manifest + ".json")).exists())
            self.assertFalse((self.root / (".recording-" + manifest)).exists())

    def test_subscription_epoch_limit_and_legacy_identity_are_fail_closed(self):
        records = [(1_000_000 + index * 20_000,
                    packet("127.0.0.1", 10001, 20001, rtp(1, 0, index + 1, b"\xff", 0)))
                   for index in range(129)]
        with self.assertRaisesRegex(RecordingDecodeError, "subscription epoch limit"):
            self.finalize(records, "2" * 32)

        sound = bytes(ulaw(500) for _ in range(160))
        legacy = {**self.epoch, "captureMode": "pcap-v1", "sources": [
            {**self.sources[0], "ssrc": 11}, {**self.sources[1], "ssrc": 22}]}
        with self.assertRaisesRegex(RecordingDecodeError, "conflicting selected source"):
            self.finalize([
                (1_010_000, packet("127.0.0.1", 10001, 20001, rtp(1, 0, 111, sound, 0))),
                (1_010_000, packet("127.0.0.1", 10002, 20002, rtp(1, 0, 22, sound, 0))),
            ], "3" * 32, legacy)


if __name__ == "__main__":
    unittest.main()
