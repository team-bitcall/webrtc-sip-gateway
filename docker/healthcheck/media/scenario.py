"""Synthetic WebRTC/PCMU recording and receive-only fork proof, inside a sandbox."""
import asyncio
import hashlib
import sqlite3
from collections import defaultdict
import json
from pathlib import Path
import re
import os
import socket
import signal
import struct
import subprocess
import sys
import time
import uuid
import wave

import av

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, "/seat-proof")
from media_fixture import NgClient, PcmuPeer, parse_rtp, pcmu_decode_many, tone, tone_energies, write_wav
from media_webrtc_peer import WebRtcPeer
from call_journal import CallJournal
from media_control import MediaController, MediaError
from recording_transport import forward_recording

def engine_resources():
    status = Path('/proc/1/status').read_text()
    ticks = Path('/proc/1/stat').read_text().split()
    return {'cpuSeconds': (int(ticks[13]) + int(ticks[14])) / os.sysconf('SC_CLK_TCK'),
            'peakRssKiB': int(re.search(r'^VmHWM:\s+(\d+)', status, re.M).group(1)),
            'threads': int(re.search(r'^Threads:\s+(\d+)', status, re.M).group(1)),
            'fileDescriptors': len(list(Path('/proc/1/fd').iterdir()))}


def require_tone(samples, expected):
    energies = tone_energies(samples, (440, 660, 880))
    assert len(samples) >= 1600 and max(energies, key=energies.get) == expected, energies
    assert energies[880] / max(energies[expected], 1) < .01, energies
    return energies


ARTIFACTS = Path('/tmp/artifacts')
RECORDINGS = Path('/tmp/recording')


def flags(raw):
    result = {}
    for value in raw.split():
        if value.startswith('replace-'):
            result.setdefault('replace', []).append(value[8:].replace('-', ' '))
        elif value.startswith('rtcp-mux-'):
            result.setdefault('rtcp-mux', []).append(value[9:])
        elif value == 'SDES-off': result['SDES'] = 'off'
        elif value in ('RTP/AVP', 'RTP/SAVPF'): result['transport protocol'] = value
        elif '=' in value:
            key, setting = value.split('=', 1)
            assert key in ('ICE', 'DTLS', 'DTLS-reverse'), key
            result[key] = setting
        else: raise AssertionError('Unknown packaged RTP flag: ' + value)
    return result


def audio_address(sdp):
    host = re.search(r'^c=IN IP4 ([^\r\n]+)', sdp, re.M).group(1)
    port = int(re.search(r'^m=audio (\d+)', sdp, re.M).group(1))
    return host, port


def speech(name, phrase, frequency):
    path = ARTIFACTS / (name + '-source.wav')
    subprocess.run(['espeak-ng', '-s', '145', '-w', str(path), phrase], check=True)
    resampler = av.AudioResampler(format='s16', layout='mono', rate=8000)
    samples = tone([frequency], samples=8000)
    with av.open(str(path)) as source:
        for frame in source.decode(audio=0):
            for output in resampler.resample(frame): samples.extend(output.to_ndarray().reshape(-1).tolist())
        for output in resampler.resample(None): samples.extend(output.to_ndarray().reshape(-1).tolist())
    write_wav(str(path), samples)
    return samples


def pcap_packets(path):
    """Decode bounded classic Ethernet/raw-IP PCAP without trusting packet lengths."""
    data = path.read_bytes()
    assert 24 <= len(data) <= 8 * 1024 * 1024, 'Unexpected proof PCAP size'
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>'}.get(data[:4])
    assert endian, 'Unsupported PCAP magic'
    link = struct.unpack_from(endian + 'I', data, 20)[0]
    assert link in (1, 12, 101, 228), link
    position = 24
    while position < len(data):
        assert position + 16 <= len(data), 'Truncated PCAP packet header'
        seconds, micros, captured, original = struct.unpack_from(endian + 'IIII', data, position)
        position += 16
        assert captured <= original and captured <= 65535 and position + captured <= len(data)
        raw = data[position:position + captured]; position += captured
        if link == 1:
            if len(raw) < 14 or raw[12:14] != b'\x08\x00': continue
            raw = raw[14:]
        if len(raw) < 20 or raw[0] >> 4 != 4 or raw[9] != 17: continue
        header = (raw[0] & 15) * 4
        assert header >= 20 and len(raw) >= header + 8
        udp_size = struct.unpack_from('!H', raw, header + 4)[0]
        assert 8 <= udp_size <= len(raw) - header
        payload = raw[header + 8:header + udp_size]
        if len(payload) < 12 or payload[0] >> 6 != 2 or (payload[1] & 127) != 0: continue
        source_port, destination_port = struct.unpack_from('!HH', raw, header)
        transport = (socket.inet_ntoa(raw[12:16]), source_port, destination_port)
        yield seconds + micros / 1e6, parse_rtp(payload), transport


async def wait_for(predicate, label, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate(): return
        await asyncio.sleep(.05)
    raise AssertionError('Timed out: ' + label)


async def provider_loop(peer, destination, samples, received, stop):
    peer.socket.setblocking(False)
    offset = 0; next_packet = time.monotonic()
    while not stop.is_set():
        frame = [samples[(offset + index) % len(samples)] for index in range(160)]
        peer.send_pcm(frame, destination, pace=False); offset += 160
        while True:
            try: raw = peer.socket.recv(65535)
            except BlockingIOError: break
            if len(raw) >= 12 and raw[0] >> 6 == 2 and (raw[1] & 127) == 0:
                received.append(parse_rtp(raw, time.monotonic()))
        next_packet += .02
        await asyncio.sleep(max(0, next_packet - time.monotonic()))


async def wait_for_listener_stop(listener, browser, captured):
    deadline = time.monotonic() + 3
    count = listener.received_samples
    stable_since = time.monotonic()
    provider_before, browser_before = len(captured), browser.received_samples
    while time.monotonic() < deadline:
        await asyncio.sleep(.05)
        if listener.received_samples != count:
            count = listener.received_samples
            stable_since = time.monotonic()
        elif time.monotonic() - stable_since >= .75:
            assert len(captured) > provider_before + 10, 'Provider media stopped after unsubscribe'
            assert browser.received_samples > browser_before + 1600, 'Browser media stopped after unsubscribe'
            return
    raise AssertionError('Listener media did not stop after unsubscribe')


async def main():
    started = time.monotonic(); report = {'schemaVersion': 1, 'ok': False, 'checks': []}
    ARTIFACTS.mkdir(exist_ok=True)
    agent_pcm = speech('agent', 'Agent alpha. This is the first recorded direction.', 440)
    provider_pcm = speech('provider', 'Customer bravo. This is the second recorded direction.', 660)
    route_values = re.findall(r'\$var\(rtpflags\)\s*=\s*"([^"]+)";', Path('/etc/kamailio/kamailio.cfg').read_text())
    assert len(route_values) == 2
    call = 'proof-' + uuid.uuid4().hex
    other = 'other-' + uuid.uuid4().hex
    tasks = []; stop = asyncio.Event(); captured = []
    engine_before = engine_resources()
    provider_source = tone([660], samples=8000)
    browser = WebRtcPeer(outgoing=True, max_samples=64000)
    listener = WebRtcPeer(max_samples=64000)
    expiry_listener = None
    outage_listener = None
    control_process = None
    watchdog_process = None
    capture_process = None
    with NgClient() as ng, PcmuPeer(ssrc=0xB002) as provider, PcmuPeer(ssrc=0xCC03) as distractor, PcmuPeer(ssrc=0xDD04) as other_end:
        state = Path('/tmp/seat-state')
        state.mkdir(mode=0o700)
        state.chmod(0o700)
        media_clock = [int(time.time() * 1000)]

        class FixtureRpc:
            """Fixture boundary only: production controller still validates journal and NG state."""
            def __init__(self): self.active = set()
            def active_cdr_ids(self): return set(self.active)

        rpc = FixtureRpc()
        journal = CallJournal(state, clock=lambda: media_clock[0])
        controller = MediaController(state, journal, rpc, clock=lambda: media_clock[0],
                                     projection=lambda _tenant: {"status": "applied", "validUntil": int(time.time()) + 60})
        tenant, seat = "t_" + hashlib.sha256(b"fixture-customer").hexdigest(), "s_" + "b" * 64
        actor, listener_id = "c" * 32, "d" * 32
        try:
            for _ in range(30):
                try:
                    ng.request({'command': 'ping'}); break
                except (OSError, TimeoutError): await asyncio.sleep(.1)
            else: raise AssertionError('RTPengine not ready')
            forwarded = ng.request({**flags(route_values[0]), 'command': 'offer', 'call-id': call, 'from-tag': 'agent', 'sdp': await browser.offer()})
            response = ng.request({**flags(route_values[1]), 'command': 'answer', 'call-id': call, 'from-tag': 'agent', 'to-tag': 'provider', 'sdp': provider.sdp()})
            await browser.accept_answer(response['sdp'])
            tasks.append(asyncio.create_task(provider_loop(provider, audio_address(forwarded['sdp']), provider_source, captured, stop)))
            # A second, unrelated call is recorded as well: its SSRC must never enter the first file.
            separate = ng.request({'command': 'offer', 'call-id': other, 'from-tag': 'other-a', 'sdp': distractor.sdp()})
            ng.request({'command': 'answer', 'call-id': other, 'from-tag': 'other-a', 'to-tag': 'other-b', 'sdp': other_end.sdp()})
            ng.request({'command': 'start recording', 'call-id': other})
            tasks.append(asyncio.create_task(provider_loop(distractor, audio_address(separate['sdp']), tone([880], samples=8000), [], stop)))
            await wait_for(lambda: browser.connectionState == 'connected' and len(captured) >= 15 and browser.audio_ready(), 'bidirectional DTLS/SRTP source call')
            report['sourceReadyMs'] = round((time.monotonic() - started) * 1000, 1)
            report['checks'].append('source-dtls-srtp-bidirectional')
            live = ng.request({'command': 'query', 'call-id': call})
            assert 'DTLS fingerprint verified' in str(live), 'Missing verified source DTLS fingerprint'
            source_transports = {}
            for tag in ('agent', 'provider'):
                stream = next(stream for media in live['tags'][tag]['medias'] for stream in media['streams'] if 'RTP' in stream['flags'])
                source_transports[(stream['endpoint']['address'], stream['endpoint']['port'], stream['local port'])] = tag
            assert len(source_transports) == 2
            report['sourceTransports'] = [{'tag': tag, 'sourceAddress': transport[0], 'sourcePort': transport[1], 'relayPort': transport[2]} for transport, tag in source_transports.items()]
            _context, cdr_id = journal.admit({'tenantId': tenant, 'seatId': seat, 'snapshotRevision': 1,
                                               'sipCallId': call, 'fromTag': 'agent', 'legId': '',
                                               'destination': '+12025550100', 'requestedCallerId': None,
                                               'effectiveCallerId': '+12025550101'})
            journal.append({'callId': cdr_id, 'type': 'answered', 'legId': 'provider', 'sipCode': 200,
                            'reason': None, 'endedBy': None})
            rpc.active.add(cdr_id)
            finalized = Path('/tmp/finalized')
            finalized.mkdir(mode=0o700)
            for private_path in (RECORDINGS, RECORDINGS / 'pcaps', RECORDINGS / 'metadata', RECORDINGS / 'tmp'):
                private_path.chmod(0o700)
            gateway_id = 'https://gateway.fixture.invalid'
            def scoped_id(values):
                return hashlib.sha256(json.dumps(values, separators=(',', ':')).encode()).hexdigest()[:32]
            capture_manifest_id = scoped_id(['recording-v1', gateway_id, 'fixture-customer', cdr_id])
            capture_binding = {"tenantId": "fixture-customer", "gatewayId": gateway_id,
                               "callId": cdr_id, "publicCallId": scoped_id([gateway_id, 'fixture-customer', cdr_id]),
                               "membershipId": "fixture-member"}
            (ARTIFACTS / 'capture-binding.json').write_text(json.dumps(capture_binding))
            projection_path = state / 'state.sqlite3'
            with sqlite3.connect(projection_path) as projection_db:
                projection_db.execute('CREATE TABLE tenants(tenant TEXT PRIMARY KEY, revision INTEGER, digest TEXT, valid_until INTEGER)')
                projection_db.execute('INSERT INTO tenants VALUES(?,?,?,?)', (tenant, 1, 'a' * 64, int(time.time()) + 120))
            projection_path.chmod(0o600)
            capture_rpc = {'active': [cdr_id], 'tenant': tenant, 'revision': 1, 'digest': 'a' * 64}
            (ARTIFACTS / 'capture-rpc.json').write_text(json.dumps(capture_rpc))
            capture_env = {**os.environ, 'SEAT_MODE': 'managed', 'SEAT_RECORDING_ENABLED': '1',
                'SEAT_CALL_EVENTS': '1', 'SEAT_STATE_DIR': str(state),
                'SEAT_RECORDING_SPOOL_DIR': str(RECORDINGS), 'SEAT_RECORDING_OUTPUT_DIR': str(finalized),
                'SEAT_RECORDING_GATEWAY_ID': gateway_id}
            capture_process = subprocess.Popen([sys.executable, str(Path(__file__).with_name('recording_worker_fixture.py'))], env=capture_env)
            await wait_for(lambda: (state / 'recording-capture.sock').exists() or capture_process.poll() is not None, 'capture worker startup')
            assert capture_process.poll() is None, 'capture worker failed startup'
            async def capture_command(command):
                return await asyncio.to_thread(forward_recording, state, tenant,
                    {'issuedAtMs': int(time.time() * 1000), 'command': command})
            capture_start = await capture_command({"action": "start", "callId": cdr_id,
                "manifestId": capture_manifest_id, "binding": capture_binding,
                "admission": {"seatId": seat, "snapshotRevision": 1}})
            assert capture_start['state'] == 'capturing', capture_start
            report['checks'].append('separate-capture-worker-private-transport-and-journal-binding')
            start = {'action': 'start', 'callId': cdr_id, 'listenerId': listener_id,
                     'actorId': actor, 'leaseSeconds': 15}
            try:
                controller.handle("t_" + "e" * 64, start)
            except MediaError as error:
                assert error.code == 'MEDIA_UNAVAILABLE'
            else:
                raise AssertionError('foreign tenant media start succeeded')
            subscribe_started = time.monotonic()
            requested = controller.handle(tenant, start)
            answer = await listener.answer_subscription(requested['offerSdp'])
            identity = {key: value for key, value in start.items() if key != 'leaseSeconds'}
            active_listener = controller.handle(tenant, {**identity, 'action': 'answer', 'fence': requested['fence'], 'sdp': answer})
            assert active_listener['state'] == 'listening'
            await wait_for(lambda: listener.connectionState == 'connected' and listener.audio_ready(track_count=2), 'both listen-only tracks')
            report['subscribeReadyMs'] = round((time.monotonic() - subscribe_started) * 1000, 1)
            await asyncio.sleep(.3)
            listener_tones = listener.metrics['tracks']
            assert sorted(max(item['toneEnergies'], key=item['toneEnergies'].get) for item in listener_tones) == [440, 660], listener_tones
            for item in listener_tones:
                energies = item['toneEnergies']
                assert energies[880] / max(energies.values()) < .01
            report['listenerToneTracks'] = listener_tones
            report['checks'].append('two-direction-listen-only-dtls-srtp')
            browser.set_outgoing_pcm(agent_pcm)
            provider_source[:] = provider_pcm
            await asyncio.sleep(6)
            browser.set_outgoing_pcm(tone([440], samples=8000))
            provider_source[:] = tone([660], samples=8000)
            await asyncio.sleep(.4)
            browser.clear_received()
            listener.clear_received()
            before = len(captured); injected_at = time.monotonic()
            report['injection'] = await listener.inject_unnegotiated(frames=25)
            report['spoofedSourceInjection'] = await listener.inject_unnegotiated(frames=25, ssrc=0xB002)
            await asyncio.sleep(.2)
            assert len(captured) > before + 10, 'Source media stopped during listener injection'
            assert report['injection']['packetsSent'] >= 25
            assert not any(packet.ssrc == 0xDEADBEEF for packet in captured), 'Listener media reached provider'
            provider_window = [sample for packet in captured[before:] for sample in pcmu_decode_many(packet.payload)]
            report['injection']['providerToneEnergies'] = require_tone(provider_window, 440)
            report['injection']['browserToneEnergies'] = require_tone(browser.samples, 660)
            # Inspect actual RTPengine stream counters plus decoded content below, not browser mute.
            report['listener'] = listener.metrics
            report['checks'].append('malicious-listener-srtp-sent-source-stays-active')
            stopped = controller.handle(tenant, {**identity, 'action': 'stop', 'fence': active_listener['fence']})
            assert stopped['state'] == 'ended'
            try:
                controller.handle(tenant, {**start, 'action': 'renew', 'fence': active_listener['fence'], 'leaseSeconds': 15})
            except MediaError:
                pass
            else:
                raise AssertionError('renew after stop succeeded')
            # The NG contract stops forwarding but retains the participant until
            # call teardown. Verify media stops, not an undocumented tag deletion.
            await wait_for_listener_stop(listener, browser, captured)
            listener_tag = controller._listener_tag(cdr_id, listener_id, requested['fence'])
            report['listenerRetainedAfterUnsubscribe'] = listener_tag in ng.request({'command': 'query', 'call-id': call})['tags']
            assert report['listenerRetainedAfterUnsubscribe']
            await listener.close()
            expiry_listener = WebRtcPeer(max_samples=64000)
            expiry_start = {**start, 'listenerId': 'e' * 32, 'actorId': 'f' * 32}
            expiry_offer = controller.handle(tenant, expiry_start)
            expiry_answer = await expiry_listener.answer_subscription(expiry_offer['offerSdp'])
            controller.handle(tenant, {**{key: value for key, value in expiry_start.items() if key != 'leaseSeconds'}, 'action': 'answer', 'fence': expiry_offer['fence'], 'sdp': expiry_answer})
            await wait_for(lambda: expiry_listener.connectionState == 'connected' and expiry_listener.audio_ready(track_count=2), 'expiry listener tracks')
            media_clock[0] += 15_001
            controller.sweep()
            await wait_for_listener_stop(expiry_listener, browser, captured)
            report['checks'].append('controller-tenant-journal-ng-lease-stop-and-expiry')
            await expiry_listener.close()
            # A real stopped controller cannot execute its own expiry sweep.
            # The independent process must silence only its listener.
            controller.close()
            control_process = await asyncio.create_subprocess_exec(
                sys.executable, str(Path(__file__).with_name('controller_process.py')), str(state), cdr_id,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)

            async def process_command(command):
                control_process.stdin.write((json.dumps({'tenant': tenant, 'command': command}) + '\n').encode())
                await control_process.stdin.drain()
                line = await asyncio.wait_for(control_process.stdout.readline(), 5)
                assert line, 'controller fixture exited'
                return json.loads(line)

            outage_listener = WebRtcPeer(max_samples=64000)
            outage_start = {**start, 'listenerId': '9' * 32, 'actorId': '8' * 32}
            outage_offer = await process_command(outage_start)
            outage_answer = await outage_listener.answer_subscription(outage_offer['offerSdp'])
            await process_command({**{key: value for key, value in outage_start.items() if key != 'leaseSeconds'},
                                   'action': 'answer', 'fence': outage_offer['fence'], 'sdp': outage_answer})
            await wait_for(lambda: outage_listener.audio_ready(track_count=2), 'outage listener tracks')
            os.kill(control_process.pid, signal.SIGSTOP)
            watchdog_process = await asyncio.create_subprocess_exec(
                sys.executable, '/seat-proof/media_watchdog.py',
                env={**os.environ, 'SEAT_MODE': 'managed', 'SEAT_MEDIA_ENABLED': '1',
                     'SEAT_STATE_DIR': str(state)})
            expiry_delay = max(0, (outage_offer['expiresAtMs'] - time.time() * 1000) / 1000)
            await asyncio.sleep(expiry_delay + 1.2)
            assert watchdog_process.returncode is None, 'watchdog exited during controller outage'
            await wait_for_listener_stop(outage_listener, browser, captured)
            report['checks'].append('independent-watchdog-stopped-controller-source-survives')
            report['watchdogExpiryLagMs'] = round(time.time() * 1000 - outage_offer['expiresAtMs'])
            await outage_listener.close()
            os.kill(control_process.pid, signal.SIGKILL)
            await control_process.wait()
            control_process = None
            watchdog_process.terminate()
            await watchdog_process.wait()
            watchdog_process = None
            before = len(captured)
            ng.request({'command': 'stop recording', 'call-id': call})
            await asyncio.sleep(.5)
            assert len(captured) > before + 10, 'Unsubscribe/recording stop ended source call'
            report['checks'].append('unsubscribe-recording-stop-preserve-source')
            report['source'] = browser.metrics
            assert not browser.metrics['errors'], browser.metrics
            assert not report['listener']['errors'], report['listener']
            report['providerPackets'] = len(captured)
            report['providerSsrcs'] = sorted(set(packet.ssrc for packet in captured))
            report['sourceCallId'] = call
            report['otherCallId'] = other
            report['injectionAtElapsedMs'] = round((injected_at - started) * 1000, 1)
            stop.set()
            for task in tasks: task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            media_clock[0] = int(time.time() * 1000)
            journal.append({'callId': cdr_id, 'type': 'ended', 'legId': 'provider',
                            'sipCode': 200, 'reason': None, 'endedBy': 'agent'})
            rpc.active.clear()
            capture_rpc['active'] = []
            (ARTIFACTS / 'capture-rpc.json').write_text(json.dumps(capture_rpc))
            ng.request({'command': 'delete', 'call-id': call, 'delete-delay': 0})
            capture_finished = await capture_command({'action': 'finish', 'callId': cdr_id,
                                                                 'manifestId': capture_manifest_id})
            if capture_finished['state'] != 'ready':
                # Synthetic fixture only: bounded diagnostics before cleanup.
                for entry in Path('/tmp/recording/metadata').glob('*.txt'):
                    print('fixture metadata', entry.name, oct(entry.stat().st_mode & 0o777),
                          entry.read_text()[:6000], flush=True)
            assert capture_finished['state'] == 'ready', capture_finished
            manifest = json.loads((finalized / (capture_manifest_id + '.json')).read_text())
            assert all(manifest[key] == value for key, value in capture_binding.items())
            with wave.open(str(finalized / (capture_manifest_id + '.wav')), 'rb') as audio:
                assert (audio.getnchannels(), audio.getsampwidth(), audio.getframerate()) == (2, 2, 8000)
                values = struct.unpack('<' + 'h' * 8000, audio.readframes(4000))
                for channel, frequency in enumerate((440, 660)):
                    require_tone(values[channel::2], frequency)
            report['capture'] = {'manifestId': capture_manifest_id, 'state': 'ready',
                                 'sizeBytes': manifest['sizeBytes'], 'sha256': manifest['sha256']}
            report['checks'].append('trusted-live-capture-finalized-wav-manifest')
        finally:
            stop.set()
            for task in tasks: task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await browser.close(); await listener.close()
            if expiry_listener: await expiry_listener.close()
            if outage_listener: await outage_listener.close()
            for process in (control_process, watchdog_process):
                if process is not None and process.returncode is None:
                    process.kill()
                    await process.wait()
            if capture_process:
                capture_process.terminate()
                try: capture_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    capture_process.kill(); capture_process.wait(timeout=2)
                    raise AssertionError('capture worker failed bounded shutdown')
                assert capture_process.returncode == 0, 'capture worker failed shutdown'
                assert not (state / 'recording-capture.sock').exists(), 'capture socket cleanup failed'
            controller.close(); journal.close()
            for current in (call, other):
                ng.request({'command': 'delete', 'call-id': current, 'delete-delay': 0}, allow_error=True)
                assert ng.request({'command': 'query', 'call-id': current}, allow_error=True).get('result') == 'error', 'Call cleanup incomplete'
    # Only inspect finalized files, never retain actual customer audio.
    recordings = list(RECORDINGS.rglob('*.pcap'))
    assert len(recordings) == 2, [path.name for path in recordings]
    selected = [path for path in recordings if path.name == capture_manifest_id + ".pcap"]
    assert len(selected) == 1, [path.name for path in recordings]
    other_files = [path for path in recordings if other in path.name]
    assert len(other_files) == 1 and any(packet.ssrc == 0xCC03 for _, packet, _ in pcap_packets(other_files[0]))
    # Raw ingress capture also includes the adversarial listener. Select source
    # transports established before subscription, never trust an RTP SSRC alone.
    by_leg = defaultdict(list); excluded = defaultdict(int)
    raw_packets = list(pcap_packets(selected[0]))
    assert not any(packet.ssrc == 0xCC03 for _, packet, _ in raw_packets), 'Cross-call capture contamination'
    for timestamp, packet, transport in raw_packets:
        if transport in source_transports:
            by_leg[source_transports[transport]].append(packet)
        else:
            excluded[packet.ssrc] += 1
    assert set(by_leg) == {'agent', 'provider'}, (list(by_leg), report['sourceTransports'])
    assert excluded[0xDEADBEEF] > 0 and excluded[0xB002] > 0, 'Adversarial capture selection was not exercised'
    report['excludedNonSourcePackets'] = dict(excluded)
    files = []
    for leg, packets in by_leg.items():
        ssrc = packets[0].ssrc
        samples = [sample for packet in packets for sample in pcmu_decode_many(packet.payload)]
        assert len(samples) >= 8000 * 5, (ssrc, len(samples))
        energies = require_tone(samples[:4000], 660 if leg == 'provider' else 440)
        path = ARTIFACTS / ('recorded-' + leg + '.wav')
        write_wav(str(path), samples)
        files.append({'file': path.name, 'ssrc': ssrc, 'samples': len(samples), 'seconds': round(len(samples) / 8000, 3), 'toneEnergies': energies})
    report['recordings'] = files
    report['recordingBytes'] = sum(path.stat().st_size for path in RECORDINGS.rglob('*') if path.is_file())
    report['checks'].append('both-decrypted-source-legs-decoded-cross-call-and-listener-excluded')
    report['elapsedMs'] = round((time.monotonic() - started) * 1000, 1)
    report['engineResources'] = engine_resources()
    report['engineResources']['measuredCpuSeconds'] = round(report['engineResources']['cpuSeconds'] - engine_before['cpuSeconds'], 3)
    assert report['engineResources']['peakRssKiB'] < 262144
    assert report['engineResources']['threads'] < 32 and report['engineResources']['fileDescriptors'] < 128
    report['checks'].append('source-and-listener-sessions-cleaned')
    report['ok'] = True
    (ARTIFACTS / 'report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    asyncio.run(asyncio.wait_for(main(), timeout=52))
