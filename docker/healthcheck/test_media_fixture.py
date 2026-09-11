import struct
import unittest

from media_fixture import (_ng_request_frame, _ng_response, build_rtp,
                           dominant_tone, parse_rtp, pcmu_decode, pcmu_encode,
                           tone)


class MediaFixtureTests(unittest.TestCase):
    def test_ng_frames_use_cookie_prefix_and_validate_reply(self):
        cookie = b"fixture-cookie"
        self.assertEqual(_ng_request_frame({"command": "ping"}, cookie),
                         b'fixture-cookie {"command":"ping"}')
        self.assertIsNone(_ng_response(b'other {"result":"ok"}', cookie))
        self.assertEqual(_ng_response(b'fixture-cookie {"result":"pong"}', cookie),
                         {"result": "pong"})

    def test_pcmu_round_trip_preserves_sign_and_scale(self):
        for value in (-30000, -8000, -500, 0, 500, 8000, 30000):
            decoded = pcmu_decode(pcmu_encode(value))
            self.assertEqual(decoded == 0, value == 0)
            if value:
                self.assertEqual(decoded > 0, value > 0)
                self.assertLess(abs(decoded - value), max(1000, abs(value) // 8))

    def test_rtp_extension_and_padding_are_excluded_from_payload(self):
        packet = build_rtp(b"abc", 7, 160, 9, marker=True)
        packet = bytes([packet[0] | 0x30]) + packet[1:12] + struct.pack("!HH", 0xBEDE, 1) + b"abcd" + b"abc" + b"\x00\x02"
        parsed = parse_rtp(packet)
        self.assertEqual((parsed.sequence, parsed.timestamp, parsed.ssrc, parsed.payload), (7, 160, 9, b"abc"))
        self.assertTrue(parsed.marker)

    def test_tone_analysis_distinguishes_fixture_and_interloper(self):
        source, _ = dominant_tone(tone((440, 660), samples=800))
        interloper, _ = dominant_tone(tone((880,), samples=800))
        self.assertIn(source, (440, 660))
        self.assertEqual(interloper, 880)


if __name__ == "__main__":
    unittest.main()
