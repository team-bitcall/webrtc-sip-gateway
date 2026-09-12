import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import wave

sys.path.insert(0, str(Path(__file__).parent))
from recording_decode import RecordingDecodeError, _hex32, _pcm, finalize_capture


def ulaw(sample):
    sample = max(-32635, min(32635, sample))
    sign = 0x80 if sample < 0 else 0
    sample = abs(sample) + 0x84
    exponent = 7
    mask = 0x4000
    while exponent and not sample & mask:
        exponent -= 1
        mask >>= 1
    return (~(sign | exponent << 4 | ((sample >> (exponent + 3)) & 15))) & 255


def rtp(seq, timestamp, ssrc, payload, pt=0):
    return struct.pack("!BBHII", 0x80, pt, seq, timestamp, ssrc) + payload


def packet(address, source, relay, payload):
    ip = bytes(map(int, address.split(".")))
    udp = struct.pack("!HHHH", source, relay, 8 + len(payload), 0) + payload
    header = (
        b"\x45\x00"
        + struct.pack("!H", 20 + len(udp))
        + b"\x00\x00\x00\x00\x40\x11\x00\x00"
        + ip
        + b"\x7f\x00\x00\x01"
    )
    return b"\x00" * 12 + b"\x08\x00" + header + udp


def pcap(records):
    result = bytearray(
        b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    )
    for at, data in records:
        result += (
            struct.pack("<IIII", at // 1_000_000, at % 1_000_000, len(data), len(data))
            + data
        )
    return bytes(result)


class RecordingDecodeTests(unittest.TestCase):
    def test_identifiers_require_canonical_lowercase_hex(self):
        for value in ("+" + "1" * 31, " " + "1" * 31, "A" * 32, "a" * 31):
            with self.subTest(value=value), self.assertRaises(RecordingDecodeError):
                _hex32(value, "manifest id")
        self.assertEqual(_hex32("a" * 32, "manifest id"), "a" * 32)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.capture = self.root / "capture.pcap"
        self.sources = [
            {
                "address": "10.0.0.1",
                "port": 10001,
                "relayPort": 20001,
                "ssrc": 11,
                "payloadType": 0,
                "codec": "PCMU",
                "tag": "agent",
            },
            {
                "address": "10.0.0.2",
                "port": 10002,
                "relayPort": 20002,
                "ssrc": 22,
                "payloadType": 0,
                "codec": "PCMU",
                "tag": "customer",
            },
        ]
        self.binding = {
            "tenantId": "tenant",
            "gatewayId": "gateway",
            "membershipId": "member",
            "callId": "a" * 32,
            "publicCallId": "b" * 32,
        }
        self.epoch = {
            "sources": self.sources,
            "startedAtUs": 1_000_000,
            "endedAtUs": 3_000_000,
        }
        self.limits = {
            "maxInputBytes": 1_000_000,
            "maxOutputBytes": 1_000_000,
            "maxDurationSeconds": 20,
            "maxPackets": 30,
        }

    def tearDown(self):
        self.temp.cleanup()

    def write(self, records):
        self.capture.write_bytes(pcap(records))
        os.chmod(self.capture, 0o600)

    def test_finalizes_stereo_and_ignores_unrelated_packets(self):
        left = bytes(ulaw(1000) for _ in range(160))
        right = bytes(ulaw(-1000) for _ in range(160))
        records = [
            (1_010_000, packet("10.0.0.9", 101, 201, rtp(1, 0, 99, left))),
            (1_020_000, packet("10.0.0.1", 10001, 20001, rtp(1, 0, 11, left))),
            (1_040_000, packet("10.0.0.1", 10001, 20001, rtp(2, 160, 11, left))),
            (1_040_000, packet("10.0.0.2", 10002, 20002, rtp(1, 0, 22, right))),
        ]
        self.write(records)
        result = finalize_capture(
            self.capture, self.root, "c" * 32, self.binding, self.epoch, self.limits
        )
        self.assertEqual(result["sizeBytes"], 44 + 480 * 4)
        stored = json.loads((self.root / ("c" * 32 + ".json")).read_text())
        self.assertEqual(stored["sha256"], result["sha256"])
        self.assertEqual(stored["callId"], "a" * 32)
        self.assertNotIn("binding", stored)
        with wave.open(str(self.root / ("c" * 32 + ".wav")), "rb") as value:
            self.assertEqual(
                (value.getnchannels(), value.getframerate(), value.getnframes()),
                (2, 8000, 480),
            )
            frames = struct.unpack("<960h", value.readframes(480))
        self.assertGreater(
            frames[160 * 2], 500
        )  # left starts at its capture time (20ms)
        self.assertLess(frames[320 * 2 + 1], -500)  # right begins at 40ms

    def test_conflicting_selected_source_fails_without_artifacts(self):
        sound = bytes(ulaw(1000) for _ in range(160))
        self.write(
            [(1_010_000, packet("10.0.0.1", 10001, 20001, rtp(1, 0, 999, sound)))]
        )
        with self.assertRaises(RecordingDecodeError):
            finalize_capture(
                self.capture, self.root, "d" * 32, self.binding, self.epoch, self.limits
            )
        self.assertFalse(list(self.root.glob("d" * 32 + "*")))
        self.assertFalse(list(self.root.glob(".recording-*")))

    def test_reordered_selected_rtp_fails_closed(self):
        sound = bytes(ulaw(500) for _ in range(160))
        records = [
            (1_010_000, packet("10.0.0.1", 10001, 20001, rtp(2, 160, 11, sound))),
            (1_030_000, packet("10.0.0.1", 10001, 20001, rtp(1, 0, 11, sound))),
        ]
        self.write(records)
        with self.assertRaisesRegex(RecordingDecodeError, "reordering"):
            finalize_capture(
                self.capture, self.root, "e" * 32, self.binding, self.epoch, self.limits
            )

    def test_g711_standard_zero_and_full_scale_vectors(self):
        self.assertEqual(
            struct.unpack("<hh", _pcm("PCMU", bytes((0xFF, 0x80)))), (0, 32124)
        )
        self.assertEqual(
            struct.unpack("<hh", _pcm("PCMA", bytes((0xD5, 0x55)))), (8, -8)
        )

    def test_trusted_relay_nat_rebinding_fails_closed(self):
        sound = bytes(ulaw(500) for _ in range(160))
        self.write(
            [(1_010_000, packet("10.0.0.99", 10001, 20001, rtp(1, 0, 11, sound)))]
        )
        with self.assertRaisesRegex(RecordingDecodeError, "trusted relay"):
            finalize_capture(
                self.capture, self.root, "f" * 32, self.binding, self.epoch, self.limits
            )

    def test_rtp_header_extension_and_rtcp_mux_are_accepted(self):
        sound = bytes(ulaw(500) for _ in range(160))
        extended = struct.pack("!BBHIIHHI", 0x90, 0, 1, 0, 11, 0xBEDE, 1, 0) + sound
        rtcp = b"\x80\xc8" + b"\x00" * 10
        self.write(
            [
                (1_010_000, packet("10.0.0.1", 10001, 20001, extended)),
                (1_020_000, packet("10.0.0.1", 10001, 20001, rtcp)),
                (1_020_000, packet("10.0.0.2", 10002, 20002, rtp(1, 0, 22, sound))),
            ]
        )
        finalize_capture(
            self.capture, self.root, "1" * 32, self.binding, self.epoch, self.limits
        )
        self.assertTrue((self.root / ("1" * 32 + ".wav")).is_file())

    def test_preexisting_part_is_not_deleted(self):
        self.write([])
        name = ".recording-" + "2" * 32 + "-" + str(os.getpid()) + "-0.part"
        foreign = self.root / name
        foreign.write_bytes(b"keep")
        os.chmod(foreign, 0o600)
        with self.assertRaises(FileExistsError):
            finalize_capture(
                self.capture, self.root, "2" * 32, self.binding, self.epoch, self.limits
            )
        self.assertEqual(foreign.read_bytes(), b"keep")

    def test_symlink_output_root_is_rejected(self):
        self.write([])
        target = self.root / "target"
        target.mkdir()
        os.chmod(target, 0o700)
        link = self.root / "link"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(RecordingDecodeError, "symlink"):
            finalize_capture(
                self.capture, link, "3" * 32, self.binding, self.epoch, self.limits
            )


if __name__ == "__main__":
    unittest.main()
