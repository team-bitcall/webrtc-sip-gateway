#!/usr/bin/env python3
"""Run synthetic recording/listening media proof in a disposable test image.

Build healthcheck/media/Dockerfile with GATEWAY_IMAGE pointing at the candidate.
No network access, published ports, customer calls, or production configuration.
"""
import argparse
from pathlib import Path
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='Disposable image with media proof dependencies')
    parser.add_argument('--artifacts', type=Path, help='Optional new output directory for synthetic WAVs and report')
    args = parser.parse_args()
    if args.artifacts:
        args.artifacts.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parent
    seat_source = source.parent / 'seat'
    name = 'bitcall-media-proof-' + uuid.uuid4().hex[:12]
    created = False
    try:
        subprocess.run(['docker', 'run', '-d', '--name', name, '--network', 'none', '--read-only',
            '--tmpfs', '/tmp:rw,size=128m', '--cpus', '2', '--memory', '768m', '--pids-limit', '128',
            '--security-opt', 'no-new-privileges:true', '-e', 'BITCALL_MEDIA_LOOPBACK_FIXTURE=1', '--mount', f'type=bind,src={source},dst=/proof,readonly',
            '--mount', f'type=bind,src={seat_source},dst=/seat-proof,readonly',
            '--entrypoint', '/bin/sh', args.image, '-ec',
            'mkdir -p /tmp/recording /tmp/artifacts; exec /usr/bin/rtpengine --config-file=none '
            '--foreground --log-stderr --table=-1 --interface=127.0.0.1 --listen-ng=127.0.0.1:2223 '
            '--port-min=30000 --port-max=30399 --num-threads=2 --media-num-threads=0 '
            '--recording-dir=/tmp/recording --recording-method=pcap --recording-format=eth'],
            check=True, stdout=subprocess.DEVNULL, timeout=20)
        created = True
        subprocess.run(['docker', 'exec', name, 'python3', '-u', '/proof/media/scenario.py'], check=True, timeout=55)
        if args.artifacts:
            # Docker's archive API cannot reliably read a container tmpfs.
            # Copy only the known synthetic outputs through the live process.
            for filename in ('report.json', 'agent-source.wav', 'provider-source.wav',
                             'recorded-agent.wav', 'recorded-provider.wav'):
                with (args.artifacts / filename).open('xb') as output:
                    subprocess.run(['docker', 'exec', name, 'cat', '/tmp/artifacts/' + filename],
                                   stdout=output, check=True, timeout=10)
        print('PASS isolated DTLS/SRTP recording and listen-only media proof', flush=True)
    except Exception:
        if created: subprocess.run(['docker', 'logs', '--tail', '45', name], timeout=10)
        raise
    finally:
        if created: subprocess.run(['docker', 'rm', '-f', name], check=True, stdout=subprocess.DEVNULL, timeout=15)


if __name__ == '__main__':
    main()
