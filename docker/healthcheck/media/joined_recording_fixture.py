"""Externally driven native-media fixture; only the disposable pilot launcher runs it.

Uses production HTTP/Unix recording transport and real RTPengine subscriptions.
Kamailio's SIP hook and active-dialog RPC are fixture boundaries, explicitly.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import secrets
import threading
import time
import uuid
from http.server import HTTPServer

from native_recording_fixture import address, feed, until, PcmuPeer, WebRtcPeer
from call_journal import CallJournal
from media_journal import MediaJournal
from media_control import NgClient
from recording_capture import CaptureController
from recording_subscription import SubscriptionProducer
from recording_transport import RecordingTransportServer
from recording_runtime import dispatch
from provisioning import ControlHandler


def publish_ready(path, value):
    """Publish credentials and journal identity atomically inside the private root."""
    temporary = path.with_name('.ready.json.tmp')
    raw = json.dumps(value, separators=(',', ':')).encode()
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try: os.fsync(directory)
        finally: os.close(directory)
    except Exception:
        try: temporary.unlink()
        except FileNotFoundError: pass
        raise


async def main():
    root = Path('/tmp/joined-recording')
    root.mkdir(mode=0o700)
    for name in ('state', 'spool', 'spool/pcaps', 'spool/metadata', 'output'):
        (root / name).mkdir(mode=0o700)
    gateway = os.environ['BITCALL_PILOT_GATEWAY_ID']
    assert gateway.startswith('http://127.0.0.1:')
    customer, member = 'joined-pilot', 'joined-agent'
    tenant, seat = 't_' + hashlib.sha256(customer.encode()).hexdigest(), 's_' + 'b' * 64
    ng, call = NgClient(), 'joined-' + uuid.uuid4().hex
    journal = CallJournal(root / 'state')
    media = MediaJournal(journal)
    class Rpc:
        active = set()
        def active_cdr_ids(self): return set(self.active)
    rpc = Rpc()
    controller = CaptureController(root / 'state', journal, rpc, ng=ng,
        projection=lambda _: {'status': 'applied', 'validUntil': int(time.time()) + 120},
        spool=root / 'spool', output=root / 'output', media_guard=media.checkpoint)
    controller.producer = SubscriptionProducer(ng, controller.pcaps, controller.metadata,
        controller.limits['maxInputBytes'], controller.limits['maxPackets'])
    transport = RecordingTransportServer(root / 'state', lambda tenant, request: dispatch(controller, tenant, request, gateway))
    transport.open()
    closing = threading.Event()
    def serve():
        while not closing.is_set(): transport.serve_once()
    unix_thread = threading.Thread(target=serve, daemon=True)
    unix_thread.start()
    server = HTTPServer(('0.0.0.0', 8899), ControlHandler)
    server.token, server.recording_directory, server.journal = secrets.token_urlsafe(32), root / 'state', journal
    http_thread = threading.Thread(target=server.serve_forever, daemon=True)
    http_thread.start()
    browser, stopped, task = WebRtcPeer(outgoing=True, frequency=440), asyncio.Event(), None
    try:
        with PcmuPeer(ssrc=0xB001) as provider:
            source = await browser.offer()
            offer = ng.request({'command': 'offer', 'call-id': call, 'from-tag': 'agent', 'sdp': source,
                'replace': ['origin', 'session connection'], 'ICE': 'remove', 'DTLS': 'off',
                'DTLS-reverse': 'passive', 'rtcp-mux': ['demux'], 'SDES': 'off', 'transport protocol': 'RTP/AVP'})
            answer = ng.request({'command': 'answer', 'call-id': call, 'from-tag': 'agent', 'to-tag': 'provider',
                'sdp': provider.sdp(), 'ICE': 'force', 'DTLS': 'passive', 'SDES': 'off',
                'replace': ['origin', 'session connection'], 'transport protocol': 'RTP/SAVPF', 'rtcp-mux': ['offer']})
            await browser.accept_answer(answer['sdp'])
            received = []
            task = asyncio.create_task(feed(provider, [address(offer['sdp'])], stopped, received))
            await until(lambda: browser.connectionState == 'connected' and browser.audio_ready() and len(received) >= 15, 'bidirectional media')
            assert 'DTLS fingerprint verified' in str(ng.request({'command': 'query', 'call-id': call}))
            _, cdr = journal.admit({'tenantId': tenant, 'seatId': seat, 'snapshotRevision': 1,
                'sipCallId': call, 'fromTag': 'agent', 'legId': '', 'destination': '+12025550100',
                'requestedCallerId': None, 'effectiveCallerId': '+12025550101'})
            for revision, sdp in enumerate((source, provider.sdp()), 1):
                media.begin({'callId': cdr, 'revision': revision, 'method': 'INVITE', 'fromTag': 'agent',
                    'toTag': '' if revision == 1 else 'provider', 'sipCode': 0 if revision == 1 else 200,
                    'sdpSha256': hashlib.sha256(sdp.encode()).hexdigest()})
                media.complete({'callId': cdr, 'revision': revision, 'success': True})
            journal.append({'callId': cdr, 'type': 'answered', 'legId': 'provider', 'sipCode': 200, 'reason': None, 'endedBy': None})
            rpc.active.add(cdr)
            ready = {'baseUrl': gateway, 'token': server.token, 'tenantId': customer, 'projectedTenantId': tenant,
                'membershipId': member, 'seatId': seat, 'callId': cdr}
            publish_ready(root / 'ready.json', ready)
            deadline = time.monotonic() + 90
            while not (root / 'end-call').exists():
                if time.monotonic() > deadline: raise TimeoutError('pilot did not end call')
                controller.tick()
                await asyncio.sleep(.05)
            stopped.set(); await task; task = None
            await browser.close()
            ng.request({'command': 'delete', 'call-id': call, 'delete-delay': 0})
            rpc.active.clear()
            media.media_closure({'callId': cdr, 'count': 2, 'unsafe': False})
            journal.append({'callId': cdr, 'type': 'ended', 'legId': 'provider', 'sipCode': 200, 'reason': None, 'endedBy': 'agent'})
            (root / 'ended').touch()
            deadline = time.monotonic() + 90
            while not (root / 'done').exists():
                if time.monotonic() > deadline: raise TimeoutError('pilot did not complete handoff')
                controller.tick()
                await asyncio.sleep(.05)
    finally:
        stopped.set()
        if task: await task
        await browser.close()
        server.shutdown(); server.server_close(); http_thread.join(timeout=2)
        closing.set(); unix_thread.join(timeout=2); transport.close()
        controller.close(); journal.close()
        ng.request({'command': 'delete', 'call-id': call})


if __name__ == '__main__': asyncio.run(main())
