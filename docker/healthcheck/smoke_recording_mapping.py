#!/usr/bin/env python3
"""Bounded native-subscription recorder mapping proof on an isolated stock engine."""
import argparse
from pathlib import Path
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    name = 'recording-mapping-' + uuid.uuid4().hex[:12]
    created = False
    try:
        subprocess.run(['docker', 'run', '-d', '--name', name, '--network', 'none', '--read-only',
            '--tmpfs', '/tmp:rw,size=32m', '--cpus', '1', '--memory', '256m', '--pids-limit', '64',
            '--security-opt', 'no-new-privileges:true',
            '--mount', f'type=bind,src={source},dst=/proof,readonly', '--entrypoint', '/bin/sh', args.image,
            '-ec', 'exec /usr/bin/rtpengine --config-file=none --foreground --log-stderr --table=-1 '
            '--interface=127.0.0.1 --listen-ng=127.0.0.1:2223 --port-min=30000 --port-max=30399 '
            '--num-threads=2 --media-num-threads=0'], check=True, stdout=subprocess.DEVNULL, timeout=15)
        created = True
        subprocess.run(['docker', 'exec', name, 'python3', '-u', '/proof/media/subscription_recording_fixture.py'], check=True, timeout=30)
    except Exception:
        if created: subprocess.run(['docker', 'logs', '--tail', '30', name], timeout=10)
        raise
    finally:
        if created: subprocess.run(['docker', 'rm', '-f', name], check=True, stdout=subprocess.DEVNULL, timeout=10)


if __name__ == '__main__': main()
