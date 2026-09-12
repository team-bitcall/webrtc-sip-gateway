#!/usr/bin/env python3
"""Exercise packaged recording hooks with synthetic SIP and the real private journal.

No RTPengine mutation or full seat routing is claimed here. The separate media
fixture proves capture; this check proves Kamailio serialization and guard input.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time


CONFIG = '''#!KAMAILIO
debug=1
log_stderror=yes
fork=no
children=1
auto_aliases=no
listen=udp:127.0.0.1:16061
loadmodule "tm.so"
loadmodule "sl.so"
loadmodule "rr.so"
loadmodule "pv.so"
loadmodule "textops.so"
loadmodule "dialog.so"
loadmodule "http_client.so"
loadmodule "jansson.so"
modparam("dialog", "db_mode", 0)
modparam("http_client", "connection_timeout", 2)
include_file "/hook-proof/recording-media.cfg"
request_route {
    if (!is_method("INVITE")) { sl_send_reply("200", "Ready"); exit; }
    dlg_manage();
    $dlg_var(seat_cdr_id) = $hdr(X-Fixture-ID);
    $dlg_var(recording_media_revision) = "0";
    $dlg_var(recording_media_unsafe) = "0";
    route(RECORDING_MEDIA_BEGIN);
    $var(recording_rtp_ok) = 1;
    if ($rU == "failed") { $var(recording_rtp_ok) = 0; }
    route(RECORDING_MEDIA_COMPLETE);
    if ($rU == "twice") {
        route(RECORDING_MEDIA_BEGIN);
        route(RECORDING_MEDIA_COMPLETE);
    }
    if ($rU == "unsafe") { $dlg_var(recording_media_unsafe) = "1"; }
    route(RECORDING_MEDIA_CLOSE);
    sl_send_reply("200", "Observed");
}
'''


def inside():
    sys.path.insert(0, '/seat-proof')
    from call_journal import CallJournal, JournalError
    from media_journal import MediaJournal
    from provisioning import JournalHandler

    with tempfile.TemporaryDirectory() as directory:
        journal = CallJournal(directory)
        media = MediaJournal(journal)
        server = http.server.HTTPServer(('127.0.0.1', 8882), JournalHandler)
        server.journal, server.media_journal, server.token = journal, media, 'fixture-private-token'
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        config = Path(directory) / 'kamailio.cfg'
        config.write_text(CONFIG)
        body = 'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=fixture\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n'
        checks = []
        try:
            for enabled in (True, False):
                with (Path(directory) / 'kamailio.log').open('w+') as log:
                    process = subprocess.Popen(['kamailio', '-f', str(config)], stdout=log, stderr=log,
                        env={**os.environ, 'SEAT_RECORDING_ENABLED': '1' if enabled else '0', 'SEAT_CONTROL_TOKEN': server.token})
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                            sock.bind(('127.0.0.1', 0))
                            sock.settimeout(.2)
                            port = sock.getsockname()[1]
                            def send(method, name, call_id='', payload=''):
                                request = (f'{method} sip:{name}@fixture.invalid SIP/2.0\r\n'
                                    f'Via: SIP/2.0/UDP 127.0.0.1:{port};branch=z9hG4bK-{name}-{enabled}\r\n'
                                    f'From: <sip:agent@fixture.invalid>;tag=agent-{name}\r\n'
                                    f'To: <sip:{name}@fixture.invalid>\r\nCall-ID: {name}-{enabled}\r\n'
                                    f'CSeq: 1 {method}\r\nContact: <sip:agent@127.0.0.1:{port}>\r\n'
                                    f'Max-Forwards: 70\r\nX-Fixture-ID: {call_id}\r\n'
                                    f'Content-Type: application/sdp\r\nContent-Length: {len(payload)}\r\n\r\n{payload}')
                                sock.sendto(request.encode(), ('127.0.0.1', 16061))
                                while True:
                                    reply = sock.recv(8192)
                                    if reply.startswith(b'SIP/2.0 200'): return
                            for _ in range(30):
                                if process.poll() is not None: raise RuntimeError('Kamailio startup failed')
                                try:
                                    send('OPTIONS', 'ready')
                                    break
                                except socket.timeout: time.sleep(.05)
                            else: raise RuntimeError('Kamailio readiness timeout')
                            sock.settimeout(5)
                            for name in ('safe', 'twice', 'failed', 'unsafe'):
                                _, call_id = journal.admit({'tenantId': 't_' + '1' * 64, 'seatId': 's_' + '2' * 64,
                                    'snapshotRevision': 1, 'sipCallId': f'{name}-{enabled}', 'fromTag': f'agent-{name}',
                                    'legId': '', 'destination': '+12025550100', 'requestedCallerId': None, 'effectiveCallerId': 'fixture'})
                                send('INVITE', name, call_id, body)
                                rows = journal.db.execute('SELECT metadata FROM media_observations WHERE call_id=?', (call_id,)).fetchall()
                                if not enabled:
                                    assert not rows, 'disabled hooks wrote observations'
                                    continue
                                observations = [json.loads(row['metadata']) for row in rows]
                                assert len(observations) == (2 if name == 'twice' else 1), observations
                                assert all(item['sipCode'] == 0 and item['sdpSha256'] == hashlib.sha256(body.encode()).hexdigest() for item in observations), observations
                                if name in ('safe', 'twice'):
                                    assert media.checkpoint(call_id, True)['closed']
                                else:
                                    try: media.checkpoint(call_id, True)
                                    except JournalError: pass
                                    else: raise AssertionError('unsafe evidence accepted')
                            checks.append('enabled-safe-repeat-failed-unsafe' if enabled else 'disabled-no-observations')
                    except Exception:
                        for table in ('media_observations', 'media_closures'):
                            print(table, [dict(row) for row in journal.db.execute('SELECT * FROM ' + table)], file=sys.stderr)
                        log.flush(); log.seek(0); print(log.read()[-10000:], file=sys.stderr)
                        raise
                    finally:
                        process.terminate()
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill(); process.wait(timeout=5)
        finally:
            server.shutdown(); server.server_close(); thread.join(2); journal.close()
        print('PASS recording hooks: ' + ', '.join(checks), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside: return inside()
    if not args.image: parser.error('--image is required')
    source = Path(__file__).resolve()
    docker = source.parents[1]
    subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
        '--tmpfs', '/tmp:rw,size=16m', '--tmpfs', '/run:rw,size=4m',
        '--cpus', '1', '--memory', '256m', '--pids-limit', '64',
        '--security-opt', 'no-new-privileges:true',
        '--mount', f'type=bind,src={source},dst=/proof.py,readonly',
        '--mount', f'type=bind,src={docker / "seat"},dst=/seat-proof,readonly',
        '--mount', f'type=bind,src={docker / "kamailio"},dst=/hook-proof,readonly',
        '--entrypoint', 'python3', args.image, '/proof.py', '--inside'], check=True, timeout=45)


if __name__ == '__main__':
    main()
