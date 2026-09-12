#!/usr/bin/env python3
"""Exploratory native RTPengine subscription proof for recorder-input design.

Run inside the existing disposable media-proof container after RTPengine is up.
It never enables gateway recording or writes persistent state.
"""
import hashlib
import audioop
import re
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from media_fixture import FRAME_SAMPLES, NgClient, PcmuPeer, build_rtp, pcmu_decode_many, tone, tone_energies


CALL = "subscription-recording-" + hashlib.sha256(b"plain-rollover").hexdigest()[:16]


def audio_address(sdp):
    address = re.search(r"^c=IN IP4 ([^\r\n]+)", sdp, re.M)
    media = re.search(r"^m=audio ([0-9]+) RTP/AVP [08](?: |\r|\n)", sdp, re.M)
    assert address and media, sdp
    return address.group(1), int(media.group(1))


def collect(peer, frames=12):
    samples = []
    for _ in range(frames):
        packet = peer.receive()
        if packet.payload_type == 0:
            samples.extend(pcmu_decode_many(packet.payload))
        elif packet.payload_type == 8:
            decoded = audioop.alaw2lin(packet.payload, 2)
            samples.extend(struct.unpack("<%dh" % (len(decoded) // 2), decoded))
        else:
            raise AssertionError("unexpected recorder RTP payload type %r" % packet.payload_type)
    return samples


def dominant(samples):
    values = tone_energies(samples, (440, 660, 880))
    return max(values, key=values.get), values


def subscribe(ng, source_tag, sink, listener_tag):
    offer = ng.request({"command": "subscribe request", "call-id": CALL,
                        "from-tags": [source_tag], "to-tag": listener_tag,
                        "transport protocol": "RTP/AVP", "flags": ["codec-transcode-PCMU"]})
    assert offer.get("result") == "ok" and isinstance(offer.get("sdp"), str)
    answer = ng.request({"command": "subscribe answer", "call-id": CALL,
                         "to-tag": listener_tag, "sdp": sink.sdp().replace("sendrecv", "recvonly")})
    assert answer.get("result") == "ok"


def pcma_sdp(peer):
    return peer.sdp().replace("RTP/AVP 0", "RTP/AVP 8").replace("rtpmap:0 PCMU", "rtpmap:8 PCMA")


def send_pcma_tone(peer, frequencies, destination, frames=16):
    for frame in range(frames):
        pcm = struct.pack("<%dh" % FRAME_SAMPLES, *tone(frequencies, phase=frame * FRAME_SAMPLES))
        payload = audioop.lin2alaw(pcm, 2)
        packet = build_rtp(payload, peer.sequence, peer.timestamp, peer.ssrc, payload_type=8, marker=frame == 0)
        peer.socket.sendto(packet, destination)
        peer.sequence = (peer.sequence + 1) & 0xFFFF
        peer.timestamp = (peer.timestamp + FRAME_SAMPLES) & 0xFFFFFFFF
        time.sleep(FRAME_SAMPLES / 8000)


def main():
    with NgClient() as ng, PcmuPeer(ssrc=0xA001) as agent, PcmuPeer(ssrc=0xB001) as provider, \
            PcmuPeer() as agent_sink, PcmuPeer() as provider_sink:
        offer = ng.request({"command": "offer", "call-id": CALL, "from-tag": "agent", "sdp": agent.sdp()})
        answer = ng.request({"command": "answer", "call-id": CALL, "from-tag": "agent", "to-tag": "provider", "sdp": provider.sdp()})
        subscribe(ng, "agent", agent_sink, "record-agent")
        subscribe(ng, "provider", provider_sink, "record-provider")
        agent_destination, provider_destination = audio_address(answer["sdp"]), audio_address(offer["sdp"])
        agent.send_tone([440], agent_destination, frames=16)
        provider.send_tone([660], provider_destination, frames=16)
        assert dominant(collect(agent_sink))[0] == 440
        assert dominant(collect(provider_sink))[0] == 660

        # Same from-tag, new UDP source port and SSRC: native subscription must remain leg-bound.
        with PcmuPeer(ssrc=0xA002) as replacement:
            rollover = ng.request({"command": "offer", "call-id": CALL, "from-tag": "agent", "sdp": replacement.sdp()})
            updated = ng.request({"command": "answer", "call-id": CALL, "from-tag": "agent", "to-tag": "provider", "sdp": provider.sdp()})
            for sink in (agent_sink, provider_sink):
                while True:
                    try: sink.receive(timeout=.02)
                    except TimeoutError: break
            replacement.send_tone([880], audio_address(updated["sdp"]), frames=16)
            provider.send_tone([660], audio_address(rollover["sdp"]), frames=16)
            assert dominant(collect(agent_sink))[0] == 880
            assert dominant(collect(provider_sink))[0] == 660
        # Re-offer provider as PCMA. Recorder subscriptions remain RTP/AVP PCMU
        # and explicitly request PCMU transcoding from RTPengine.
        with PcmuPeer(ssrc=0xA003) as final_agent, PcmuPeer(ssrc=0xB002) as pcma_provider:
            pcma_offer = ng.request({"command": "offer", "call-id": CALL, "from-tag": "agent", "sdp": pcma_sdp(final_agent)})
            pcma_answer = ng.request({"command": "answer", "call-id": CALL, "from-tag": "agent", "to-tag": "provider", "sdp": pcma_sdp(pcma_provider)})
            for sink in (agent_sink, provider_sink):
                while True:
                    try: sink.receive(timeout=.02)
                    except TimeoutError: break
            send_pcma_tone(final_agent, [880], audio_address(pcma_answer["sdp"]))
            send_pcma_tone(pcma_provider, [660], audio_address(pcma_offer["sdp"]))
            assert dominant(collect(agent_sink))[0] == 880
            assert dominant(collect(provider_sink))[0] == 660
        print("plain-rtp native subscriptions: PCMU/PT0 and PCMA/PT8 recorder output decode, survive rollover, and preserve leg tones")


if __name__ == "__main__":
    main()
