"""Recording flags must never alter standalone or disabled gateway startup."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class RecordingStartupTests(unittest.TestCase):
    def test_rtpengine_recording_flags_are_strictly_opt_in(self):
        script = (
            Path(__file__).resolve().parents[1] / "rootfs/etc/services.d/rtpengine/run"
        )
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "rtpengine"
            fake.write_text(
                "#!"
                + sys.executable
                + "\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n"
            )
            fake.chmod(0o700)
            environment = {
                **os.environ,
                "PATH": temporary + ":" + os.environ["PATH"],
                "PRIVATE_IP": "127.0.0.1",
                "PUBLIC_IP": "127.0.0.1",
                "RTPENGINE_MIN_PORT": "30000",
                "RTPENGINE_MAX_PORT": "30399",
                "SEAT_RECORDING_SPOOL_DIR": "/private/capture spool",
            }
            for mode, enabled, expected in [
                ("disabled", "1", False),
                ("managed", "0", False),
                ("managed", "1", True),
            ]:
                result = subprocess.run(
                    ["sh", str(script)],
                    env={
                        **environment,
                        "SEAT_MODE": mode,
                        "SEAT_RECORDING_ENABLED": enabled,
                    },
                    capture_output=True,
                    check=True,
                    text=True,
                )
                arguments = json.loads(result.stdout)
                self.assertEqual("--recording-method=pcap" in arguments, expected)
                if expected:
                    self.assertIn("--recording-dir=/private/capture spool", arguments)
                self.assertIn("--listen-ng=127.0.0.1:2223", arguments)
                self.assertIn("--port-min=30000", arguments)
