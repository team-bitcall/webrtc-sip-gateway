#!/usr/bin/env python3
"""Run the bounded five-capture native recording proof without a build."""
import argparse
from pathlib import Path
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    name = "recording-capacity-" + uuid.uuid4().hex[:12]
    created = False
    try:
        subprocess.run(["docker", "run", "-d", "--name", name, "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,size=128m", "--cpus", "2", "--memory", "768m", "--pids-limit", "128",
            "--security-opt", "no-new-privileges:true", "--mount", f"type=bind,src={source},dst=/proof,readonly",
            "--mount", f"type=bind,src={source.parent / 'seat'},dst=/seat-proof,readonly", "--entrypoint", "/bin/sh", args.image,
            "-ec", "exec /usr/bin/rtpengine --config-file=none --foreground --log-stderr --table=-1 "
            "--interface=127.0.0.1 --interface=recording/127.0.0.1 --listen-ng=127.0.0.1:2223 "
            "--port-min=30000 --port-max=30399 --num-threads=2 --media-num-threads=0"],
            check=True, stdout=subprocess.DEVNULL, timeout=15)
        created = True
        subprocess.run(["docker", "exec", name, "python3", "-u", "/proof/media/recording_capacity_fixture.py"], check=True, timeout=35)
    except Exception:
        if created: subprocess.run(["docker", "logs", "--tail", "40", name], timeout=10)
        raise
    finally:
        if created: subprocess.run(["docker", "rm", "-f", name], check=True, stdout=subprocess.DEVNULL, timeout=10)


if __name__ == "__main__": main()
