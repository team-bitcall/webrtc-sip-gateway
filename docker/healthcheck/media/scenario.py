"""Synthetic WebRTC/PCMU recording and receive-only fork proof, inside a sandbox."""
import asyncio
from collections import defaultdict
import json
from pathlib import Path
import re
import os
import socket
import struct
import subprocess
import sys
import time
import uuid

import av

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from media_fixture import NgClient, PcmuPeer, parse_rtp, pcmu_decode_many, tone, tone_energies, write_wav
from media_webrtc_peer import WebRtcPeer

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
    with NgClient() as ng, PcmuPeer(ssrc=0xB002) as provider, PcmuPeer(ssrc=0xCC03) as distractor, PcmuPeer(ssrc=0xDD04) as other_end:
        try:
            for _ in range(30):
                try:
                    ng.request({'command': 'ping'}); break
                except (OSError, TimeoutError): await asyncio.sleep(.1)
            else: raise AssertionError('RTPengine not ready')
            forwarded = ng.request({**flags(route_values[0]), 'command': 'offer', 'call-id': call, 'from-tag': 'agent', 'sdp': await browser.offer()})
            response = ng.request({**flags(route_values[1]), 'command': 'answer', 'call-id': call, 'from-tag': 'agent', 'to-tag': 'provider', 'sdp': provider.sdp()})
            ng.request({'command': 'start recording', 'call-id': call, 'metadata': 'task13-synthetic-call'})
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
            unknown = ng.request({'command': 'subscribe request', 'call-id': 'nonexistent', 'from-tags': ['agent'], 'to-tag': 'listener'}, allow_error=True)
            assert unknown.get('result') == 'error', unknown
            subscribe_started = time.monotonic()
            requested = ng.request({'command': 'subscribe request', 'call-id': call, 'from-tags': ['agent', 'provider'], 'to-tag': 'listener', 'flags': ['WebRTC']})
            assert requested['sdp'].count('m=audio ') == 2, 'Expected independent audio streams for both call legs'
            assert requested['sdp'].count('a=sendonly') == 2 and 'a=sendrecv' not in requested['sdp']
            listener_tag = requested.get('to-tag', 'listener')
            answer = await listener.answer_subscription(requested['sdp'])
            ng.request({'command': 'subscribe answer', 'call-id': call, 'to-tag': listener_tag, 'sdp': answer})
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
            ng.request({'command': 'unsubscribe', 'call-id': call, 'to-tag': listener_tag})
            # The NG contract stops forwarding but retains the participant until
            # call teardown. Verify media stops, not an undocumented tag deletion.
            await wait_for_listener_stop(listener, browser, captured)
            report['listenerRetainedAfterUnsubscribe'] = listener_tag in ng.request({'command': 'query', 'call-id': call})['tags']
            await listener.close()
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
        finally:
            stop.set()
            for task in tasks: task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await browser.close(); await listener.close()
            for current in (call, other):
                ng.request({'command': 'delete', 'call-id': current, 'delete-delay': 0}, allow_error=True)
                assert ng.request({'command': 'query', 'call-id': current}, allow_error=True).get('result') == 'error', 'Call cleanup incomplete'
    # Only inspect finalized files, never retain actual customer audio.
    recordings = list(RECORDINGS.rglob('*.pcap'))
    assert len(recordings) == 2, [path.name for path in recordings]
    selected = [path for path in recordings if call in path.name]
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
    asyncio.run(asyncio.wait_for(main(), timeout=45))
