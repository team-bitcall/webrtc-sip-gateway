"""Real native producer, DTLS/ICE replacement, stereo output and bounded cleanup proof."""
import asyncio
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import time
import uuid
import wave

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, '/seat-proof')
from media_fixture import PcmuPeer, parse_rtp, tone, tone_energies
from media_webrtc_peer import WebRtcPeer
from call_journal import CallJournal
from media_journal import MediaJournal
from media_control import NgClient
from recording_capture import CaptureController
from recording_subscription import SubscriptionProducer


def address(sdp):
    return (re.search(r'^c=IN IP4 ([^\r\n]+)', sdp, re.M).group(1),
            int(re.search(r'^m=audio (\d+)', sdp, re.M).group(1)))


async def until(predicate, label, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate(): return
        await asyncio.sleep(.025)
    raise AssertionError('Timed out: ' + label)


async def feed(peer, destination, stopped, received):
    peer.socket.setblocking(False)
    position = 0
    while not stopped.is_set():
        peer.send_pcm(tone([660], phase=position), destination[0], pace=False)
        position += 160
        while True:
            try: raw = peer.socket.recv(65535)
            except BlockingIOError: break
            if len(raw) >= 12 and raw[0] >> 6 == 2 and raw[1] & 127 == 0:
                received.append(parse_rtp(raw))
                del received[:-100]
        await asyncio.sleep(.02)


def energies(samples, expected):
    values = tone_energies(samples, (440, 660, 880))
    assert max(values, key=values.get) == expected, values
    for frequency, energy in values.items():
        if frequency != expected:
            assert energy < values[expected] * .03, values
    return values


async def main():
    root = Path('/tmp/native-proof')
    root.mkdir(mode=0o700)
    for name in ('state', 'spool', 'spool/pcaps', 'spool/metadata', 'output'):
        (root / name).mkdir(mode=0o700)
    ng = NgClient()
    for _ in range(20):
        try:
            assert ng.request({'command': 'ping'})['result'] == 'pong'
            break
        except Exception: await asyncio.sleep(.05)
    tenant, seat = 't_' + 'a' * 64, 's_' + 'b' * 64
    call = 'native-' + uuid.uuid4().hex
    journal = CallJournal(root / 'state')
    media = MediaJournal(journal)
    class Rpc:
        active = set()
        def active_cdr_ids(self): return set(self.active)
    rpc = Rpc()
    controller = CaptureController(root / 'state', journal, rpc, ng=ng,
        projection=lambda _tenant: {'status': 'applied', 'validUntil': int(time.time()) + 90},
        spool=root / 'spool', output=root / 'output', media_guard=media.checkpoint)
    controller.producer = SubscriptionProducer(ng, controller.pcaps, controller.metadata,
        controller.limits['maxInputBytes'], controller.limits['maxPackets'])
    browser = WebRtcPeer(outgoing=True, frequency=440)
    replacement = None
    stopped = asyncio.Event()
    task = None
    started = time.monotonic()
    try:
        with PcmuPeer(ssrc=0xB001) as provider:
            def request(value):
                reply = ng.request({'call-id': call, **value})
                assert reply.get('result') == 'ok', reply
                return reply
            async def negotiate(peer):
                source = await peer.offer()
                offer = request({'command': 'offer', 'from-tag': 'agent', 'sdp': source,
                    'replace': ['origin', 'session connection'], 'ICE': 'remove', 'DTLS': 'off',
                    'DTLS-reverse': 'passive', 'rtcp-mux': ['demux'], 'SDES': 'off', 'transport protocol': 'RTP/AVP'})
                answer = request({'command': 'answer', 'from-tag': 'agent', 'to-tag': 'provider',
                    'sdp': provider.sdp(), 'ICE': 'force', 'DTLS': 'passive', 'SDES': 'off',
                    'replace': ['origin', 'session connection'], 'transport protocol': 'RTP/SAVPF', 'rtcp-mux': ['offer']})
                await peer.accept_answer(answer['sdp'])
                return source, provider.sdp(), address(offer['sdp'])
            source, answer, destination = await negotiate(browser)
            destination = [destination]
            received = []
            task = asyncio.create_task(feed(provider, destination, stopped, received))
            await until(lambda: browser.connectionState == 'connected' and browser.audio_ready() and len(received) >= 15,
                        'initial verified DTLS/SRTP')
            assert 'DTLS fingerprint verified' in str(request({'command': 'query'}))
            _, cdr = journal.admit({'tenantId': tenant, 'seatId': seat, 'snapshotRevision': 1,
                'sipCallId': call, 'fromTag': 'agent', 'legId': '', 'destination': '+12025550100',
                'requestedCallerId': None, 'effectiveCallerId': '+12025550101'})
            def observe(revision, sdp):
                media.begin({'callId': cdr, 'revision': revision, 'method': 'INVITE',
                    'fromTag': 'agent', 'toTag': 'provider' if revision % 2 == 0 else '',
                    'sipCode': 200 if revision % 2 == 0 else 0,
                    'sdpSha256': hashlib.sha256(sdp.encode()).hexdigest()})
                media.complete({'callId': cdr, 'revision': revision, 'success': True})
            observe(1, source); observe(2, answer)
            journal.append({'callId': cdr, 'type': 'answered', 'legId': 'provider', 'sipCode': 200,
                'reason': None, 'endedBy': None})
            rpc.active.add(cdr)
            manifest = uuid.uuid4().hex
            result = controller.handle(tenant, {'action': 'start', 'callId': cdr, 'manifestId': manifest,
                'binding': {'tenantId': 'fixture', 'gatewayId': 'https://gateway.fixture.invalid',
                    'callId': cdr, 'publicCallId': uuid.uuid4().hex, 'membershipId': 'agent-fixture'}})
            assert result['state'] == 'capturing', result
            await asyncio.sleep(.8)
            controller.tick()
            assert controller.status(tenant, {'callId': cdr, 'manifestId': manifest})['state'] == 'capturing'
            # New ICE credentials, candidate port, DTLS fingerprint and SSRC under the same SIP tag.
            await browser.close()
            replacement = WebRtcPeer(outgoing=True, frequency=880)
            replacement_source, replacement_answer, replacement_destination = await negotiate(replacement)
            assert re.search(r'a=ice-ufrag:(\S+)', source).group(1) != re.search(r'a=ice-ufrag:(\S+)', replacement_source).group(1)
            assert address(source) != address(replacement_source)
            observe(3, replacement_source); observe(4, replacement_answer)
            destination[0] = replacement_destination
            await until(lambda: replacement.connectionState == 'connected' and replacement.audio_ready(),
                        'replacement verified ICE/DTLS/SRTP')
            assert 'DTLS fingerprint verified' in str(request({'command': 'query'}))
            await asyncio.sleep(.8)
            controller.tick()
            assert controller.status(tenant, {'callId': cdr, 'manifestId': manifest})['state'] == 'capturing'
            stopped.set(); await task; task = None
            await replacement.close()
            request({'command': 'delete', 'delete-delay': 0})  # Fixture owns this disposable source call.
            rpc.active.clear()
            media.media_closure({'callId': cdr, 'count': 4, 'unsafe': False})
            journal.append({'callId': cdr, 'type': 'ended', 'legId': 'provider', 'sipCode': 200,
                'reason': None, 'endedBy': 'agent'})
            result = controller.handle(tenant, {'action': 'finish', 'callId': cdr, 'manifestId': manifest})
            assert result['state'] == 'ready', result
            with wave.open(str(root / 'output' / (manifest + '.wav'))) as audio:
                assert audio.getnchannels() == 2 and audio.getframerate() == 8000
                raw = audio.readframes(audio.getnframes())
            pcm = struct.unpack('<%dh' % (len(raw) // 2), raw)
            left, right = pcm[::2], pcm[1::2]
            # Interior windows avoid transport startup/jitter tails; prove both ends before/after restart.
            energies(left[1600:4000], 440); energies(right[1600:4000], 660)
            energies(left[-4000:-1600], 880); energies(right[-4000:-1600], 660)
            assert not controller.producer._sessions
            report = {'ok': True, 'durationSeconds': round(time.monotonic() - started, 2),
                'checks': ['real-native-producer', 'verified-dtls-srtp', 'ice-port-fingerprint-ssrc-replacement',
                           'stereo-leg-identity-before-after', 'closed-media-journal', 'unsubscribed-and-fds-closed'],
                'wavBytes': len(raw) + 44}
            print(json.dumps(report), flush=True)
    finally:
        stopped.set()
        if task: await task
        await browser.close()
        if replacement: await replacement.close()
        controller.close()
        journal.close()
        ng.request({'command': 'delete', 'call-id': call})


if __name__ == '__main__': asyncio.run(main())
