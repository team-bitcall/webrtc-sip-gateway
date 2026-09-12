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


class PilotCall:
    """Own one real media pair; per-call identities and tones expose cross-call mixing."""
    def __init__(self, index, tenant, ng, journal, media, rpc):
        self.ng, self.journal, self.media, self.rpc = ng, journal, media, rpc
        self.tenant = tenant
        self.call = 'joined-' + uuid.uuid4().hex
        self.identity = {
            'membershipId': f'joined-agent-{index}',
            'seatId': 's_' + hashlib.sha256(f'joined-agent-{index}'.encode()).hexdigest(),
            'destination': f'+120255501{index:02d}',
            'effectiveCallerId': f'+120255502{index:02d}',
            'frequency': 440 + 40 * index,
            'providerFrequency': 660 + 40 * index,
        }
        self.browser = WebRtcPeer(outgoing=True, frequency=self.identity['frequency'])
        self.provider = PcmuPeer(ssrc=0xB001 + index)
        self.stopped = asyncio.Event()
        self.task = None
        self.closed = False

    async def start(self):
        source = await self.browser.offer()
        offer = self.ng.request({'command': 'offer', 'call-id': self.call, 'from-tag': 'agent', 'sdp': source,
            'replace': ['origin', 'session connection'], 'ICE': 'remove', 'DTLS': 'off',
            'DTLS-reverse': 'passive', 'rtcp-mux': ['demux'], 'SDES': 'off', 'transport protocol': 'RTP/AVP'})
        answer = self.ng.request({'command': 'answer', 'call-id': self.call, 'from-tag': 'agent', 'to-tag': 'provider',
            'sdp': self.provider.sdp(), 'ICE': 'force', 'DTLS': 'passive', 'SDES': 'off',
            'replace': ['origin', 'session connection'], 'transport protocol': 'RTP/SAVPF', 'rtcp-mux': ['offer']})
        await self.browser.accept_answer(answer['sdp'])
        received = []
        self.task = asyncio.create_task(feed(self.provider, [address(offer['sdp'])], self.stopped, received,
                                             self.identity['providerFrequency']))
        await until(lambda: self.browser.connectionState == 'connected' and self.browser.audio_ready()
                    and len(received) >= 15, 'bidirectional media')
        assert 'DTLS fingerprint verified' in str(self.ng.request({'command': 'query', 'call-id': self.call}))
        _, cdr = self.journal.admit({'tenantId': self.tenant, 'seatId': self.identity['seatId'], 'snapshotRevision': 1,
            'sipCallId': self.call, 'fromTag': 'agent', 'legId': '', 'destination': self.identity['destination'],
            'requestedCallerId': self.identity['effectiveCallerId'], 'effectiveCallerId': self.identity['effectiveCallerId']})
        self.identity['callId'] = cdr
        for revision, sdp in enumerate((source, self.provider.sdp()), 1):
            self.media.begin({'callId': cdr, 'revision': revision, 'method': 'INVITE', 'fromTag': 'agent',
                'toTag': '' if revision == 1 else 'provider', 'sipCode': 0 if revision == 1 else 200,
                'sdpSha256': hashlib.sha256(sdp.encode()).hexdigest()})
            self.media.complete({'callId': cdr, 'revision': revision, 'success': True})
        self.journal.append({'callId': cdr, 'type': 'answered', 'legId': 'provider', 'sipCode': 200,
            'reason': None, 'endedBy': None})
        self.rpc.active.add(cdr)

    async def close(self):
        if self.closed:
            return
        self.stopped.set()
        errors = []
        if self.task:
            try:
                await self.task
            except Exception as error:
                errors.append(error)
        try:
            await self.browser.close()
        except Exception as error:
            errors.append(error)
        try:
            self.provider.close()
        except Exception as error:
            errors.append(error)
        try:
            self.ng.request({'command': 'delete', 'call-id': self.call, 'delete-delay': 0})
        except Exception as error:
            errors.append(error)
        self.rpc.active.discard(self.identity.get('callId'))
        self.closed = True
        if errors:
            raise RuntimeError('pilot media cleanup failed') from errors[0]

    async def end(self):
        await self.close()
        cdr = self.identity['callId']
        self.rpc.active.discard(cdr)
        self.media.media_closure({'callId': cdr, 'count': 2, 'unsafe': False})
        self.journal.append({'callId': cdr, 'type': 'ended', 'legId': 'provider', 'sipCode': 200,
            'reason': None, 'endedBy': 'agent'})


async def main():
    root = Path('/tmp/joined-recording')
    root.mkdir(mode=0o700)
    for name in ('state', 'spool', 'spool/pcaps', 'spool/metadata', 'output'):
        (root / name).mkdir(mode=0o700)
    gateway = os.environ['BITCALL_PILOT_GATEWAY_ID']
    assert gateway.startswith('http://127.0.0.1:')
    count = int(os.environ.get('BITCALL_PILOT_CALLS', '5'))
    assert 1 <= count <= 5
    customer = 'joined-pilot'
    tenant = 't_' + hashlib.sha256(customer.encode()).hexdigest()
    ng = NgClient()
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
    calls = [PilotCall(index, tenant, ng, journal, media, rpc) for index in range(count)]
    try:
        started = await asyncio.gather(*(call.start() for call in calls), return_exceptions=True)
        for result in started:
            if isinstance(result, BaseException):
                raise result
        ready = {'baseUrl': gateway, 'token': server.token, 'tenantId': customer, 'projectedTenantId': tenant,
            **calls[0].identity, 'calls': [call.identity for call in calls]}
        publish_ready(root / 'ready.json', ready)
        deadline = time.monotonic() + 90
        while not (root / 'end-call').exists():
            if time.monotonic() > deadline: raise TimeoutError('pilot did not end calls')
            controller.tick()
            await asyncio.sleep(.05)
        ended = await asyncio.gather(*(call.end() for call in calls), return_exceptions=True)
        for result in ended:
            if isinstance(result, BaseException):
                raise result
        (root / 'ended').touch()
        deadline = time.monotonic() + 90
        while not (root / 'done').exists():
            if time.monotonic() > deadline: raise TimeoutError('pilot did not complete handoff')
            controller.tick()
            await asyncio.sleep(.05)
    finally:
        cleanup_results = await asyncio.gather(*(call.close() for call in calls), return_exceptions=True)
        server.shutdown()
        server.server_close()
        http_thread.join(timeout=2)
        closing.set()
        unix_thread.join(timeout=2)
        transport.close()
        controller.close()
        journal.close()
        if any(isinstance(result, BaseException) for result in cleanup_results):
            raise RuntimeError('pilot peer cleanup failed')


if __name__ == '__main__': asyncio.run(main())
