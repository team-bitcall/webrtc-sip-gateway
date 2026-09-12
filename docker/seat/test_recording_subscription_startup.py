import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class SubscriptionStartupTests(unittest.TestCase):
    def test_effective_rtpengine_arguments_across_recording_modes(self):
        script = (
            Path(__file__).resolve().parents[1]
            / "rootfs/etc/services.d/rtpengine/run"
        )
        body = "\n".join(script.read_text().splitlines()[1:])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stub = root / "rtpengine"
            stub.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
            stub.chmod(0o700)
            cases = [
                ({}, []),
                ({"SEAT_MODE": "managed", "SEAT_RECORDING_ENABLED": "0"}, []),
                (
                    {
                        "SEAT_MODE": "managed",
                        "SEAT_RECORDING_ENABLED": "1",
                        "SEAT_RECORDING_SPOOL_DIR": "/spool",
                    },
                    ["--recording-method=pcap"],
                ),
                (
                    {
                        "SEAT_MODE": "managed",
                        "SEAT_RECORDING_ENABLED": "1",
                        "SEAT_RECORDING_SPOOL_DIR": "/spool",
                        "SEAT_RECORDING_CAPTURE_MODE": "subscription",
                    },
                    ["--recording-method=pcap", "--interface=recording/127.0.0.1"],
                ),
            ]
            for values, expected in cases:
                environment = {
                    **os.environ,
                    **values,
                    "PATH": str(root) + os.pathsep + os.environ["PATH"],
                    "PRIVATE_IP": "10.0.0.1",
                    "PUBLIC_IP": "198.51.100.1",
                    "RTPENGINE_MIN_PORT": "30000",
                    "RTPENGINE_MAX_PORT": "30010",
                }
                result = subprocess.run(
                    ["/bin/sh", "-c", body],
                    env=environment,
                    text=True,
                    check=True,
                    capture_output=True,
                )
                argv = result.stdout.splitlines()
                primary = "--interface=10.0.0.1!198.51.100.1"
                self.assertIn(primary, argv)
                for item in expected:
                    self.assertIn(item, argv)
                    self.assertLess(argv.index(primary), argv.index(item))
                if "--interface=recording/127.0.0.1" not in expected:
                    self.assertNotIn("--interface=recording/127.0.0.1", argv)
                if "--recording-method=pcap" not in expected:
                    self.assertNotIn("--recording-method=pcap", argv)


if __name__ == "__main__":
    unittest.main()
