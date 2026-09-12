#!/usr/bin/env python3
"""Five live native subscriptions: capacity, isolation, failure containment."""
import json
import audioop
from pathlib import Path
import re
import shutil
import struct
import sys
import threading
import time
import uuid
import wave

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, "/seat-proof")
from call_journal import CallJournal
from media_control import NgClient
from media_fixture import FRAME_SAMPLES, PcmuPeer, build_rtp, tone, tone_energies
from recording_capture import CaptureController, CaptureError
from recording_subscription import SubscriptionProducer


def address(sdp):
    match = re.search(r"^c=IN IP4 ([^\r\n]+)", sdp, re.M)
    port = re.search(r"^m=audio (\d+)", sdp, re.M)
    assert match and port, sdp
    return match.group(1), int(port.group(1))


def energies(samples, expected):
    values = tone_energies(samples, (440, 660, 880))
    assert max(values, key=values.get) == expected, values
    for frequency, energy in values.items():
        if frequency != expected:
            assert energy < values[expected] * .04, values


def pcma_sdp(peer):
    return peer.sdp().replace("RTP/AVP 0", "RTP/AVP 8").replace("rtpmap:0 PCMU", "rtpmap:8 PCMA")


def send_pcma(peer, destination, frequencies, phase, marker=False):
    pcm = struct.pack("<%dh" % FRAME_SAMPLES, *tone(frequencies, phase=phase))
    raw = build_rtp(audioop.lin2alaw(pcm, 2), peer.sequence, peer.timestamp, peer.ssrc,
                    payload_type=8, marker=marker)
    peer.socket.sendto(raw, destination)
    peer.sequence = (peer.sequence + 1) & 0xFFFF
    peer.timestamp = (peer.timestamp + FRAME_SAMPLES) & 0xFFFFFFFF


class Rpc:
    def __init__(self): self.active = set()
    def active_cdr_ids(self): return set(self.active)


def send_pair(item, stopped):
    """One writer per source call, so all ten RTP sources run concurrently."""
    phase = 0
    while not stopped.is_set():
        if item["pcma"]:
            send_pcma(item["agent"], item["agent_dest"], [440], phase)
            send_pcma(item["provider"], item["provider_dest"], [660], phase)
        else:
            item["agent"].send_pcm(tone([440], phase=phase), item["agent_dest"], pace=False)
            item["provider"].send_pcm(tone([660], phase=phase), item["provider_dest"], pace=False)
        phase += 160
        time.sleep(.02)


def main():
    root = Path("/tmp/recording-capacity-proof")
    shutil.rmtree(root, ignore_errors=True)
    for name in ("state", "spool", "spool/pcaps", "spool/metadata", "output"):
        (root / name).mkdir(parents=True, mode=0o700)
    tenant, seat = "t_" + "c" * 64, "s_" + "d" * 64
    rpc, ng, journal, controller = Rpc(), NgClient(), None, None
    peers, writers, stopped, calls = [], [], threading.Event(), []
    started = time.monotonic()
    try:
        journal = CallJournal(root / "state")
        controller = CaptureController(root / "state", journal, rpc, ng=ng,
            projection=lambda _tenant: {"status": "applied", "validUntil": int(time.time()) + 90},
            spool=root / "spool", output=root / "output", maxConcurrent=5)
        controller.producer = SubscriptionProducer(ng, controller.pcaps, controller.metadata,
            controller.limits["maxInputBytes"], controller.limits["maxPackets"])
        for number in range(6):
            agent, provider = PcmuPeer(ssrc=0xA100 + number), PcmuPeer(ssrc=0xB100 + number)
            peers.extend((agent, provider))
            pcma = number == 4
            sip = "capacity-" + uuid.uuid4().hex
            offer = ng.request({"command": "offer", "call-id": sip, "from-tag": "agent", "sdp": pcma_sdp(agent) if pcma else agent.sdp()})
            answer = ng.request({"command": "answer", "call-id": sip, "from-tag": "agent", "to-tag": "provider", "sdp": pcma_sdp(provider) if pcma else provider.sdp()})
            _, call = journal.admit({"tenantId": tenant, "seatId": seat, "snapshotRevision": 1,
                "sipCallId": sip, "fromTag": "agent", "legId": "", "destination": "+12025550100",
                "requestedCallerId": None, "effectiveCallerId": "+12025550101"})
            journal.append({"callId": call, "type": "answered", "legId": "provider", "sipCode": 200,
                "reason": None, "endedBy": None})
            rpc.active.add(call)
            calls.append({"call": call, "sip": sip, "agent": agent, "provider": provider,
                "agent_dest": address(answer["sdp"]), "provider_dest": address(offer["sdp"]),
                "manifest": uuid.uuid4().hex, "pcma": pcma})
        # RTPengine only exposes the source stream in query after it has seen
        # media. These packets precede recording and merely establish the six
        # disposable source dialogs; the actual five writers begin together.
        for item in calls:
            for frame in range(3):
                if item["pcma"]:
                    send_pcma(item["agent"], item["agent_dest"], [440], frame * 160, marker=frame == 0)
                    send_pcma(item["provider"], item["provider_dest"], [660], frame * 160, marker=frame == 0)
                else:
                    item["agent"].send_pcm(tone([440], phase=frame * 160), item["agent_dest"], pace=False, marker=frame == 0)
                    item["provider"].send_pcm(tone([660], phase=frame * 160), item["provider_dest"], pace=False, marker=frame == 0)
        for item in calls[:5]:
            result = controller.handle(tenant, {"action": "start", "callId": item["call"], "manifestId": item["manifest"],
                "binding": {"tenantId": "fixture", "gatewayId": "http://127.0.0.1", "callId": item["call"],
                    "publicCallId": uuid.uuid4().hex, "membershipId": "capacity-fixture"}})
            assert result["state"] == "capturing", result
        try:
            controller.handle(tenant, {"action": "start", "callId": calls[5]["call"], "manifestId": calls[5]["manifest"],
                "binding": {"tenantId": "fixture", "gatewayId": "http://127.0.0.1", "callId": calls[5]["call"],
                    "publicCallId": uuid.uuid4().hex, "membershipId": "capacity-fixture"}})
            raise AssertionError("sixth capture was accepted")
        except CaptureError as error:
            assert error.code == "RECORDING_LIMIT", error.code
        writers = [threading.Thread(target=send_pair, args=(item, stopped), daemon=True) for item in calls]
        for writer in writers: writer.start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if all((controller.pcaps / (item["manifest"] + ".pcap")).stat().st_size > 2000 for item in calls[:5]): break
            time.sleep(.03)
        else: raise AssertionError("five subscription writers were not active together")
        # A packet from a wrong source port kills exactly one producer session.
        doomed = calls[0]
        session = controller.producer._sessions[doomed["manifest"]]
        import socket
        intruder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            intruder.sendto(b"\x80\x00\x00\x01" + b"\0" * 8, session["sockets"][0].getsockname())
        finally:
            intruder.close()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and session["error"] is None: time.sleep(.02)
        assert session["error"] is not None, "failure injection did not reach producer"
        controller.tick()
        assert controller.status(tenant, {"action": "status", "callId": doomed["call"], "manifestId": doomed["manifest"]})["state"] == "failed"
        assert all(controller.status(tenant, {"action": "status", "callId": item["call"], "manifestId": item["manifest"]})["state"] == "capturing" for item in calls[1:5])
        sixth = calls[5]
        result = controller.handle(tenant, {"action": "start", "callId": sixth["call"], "manifestId": sixth["manifest"],
            "binding": {"tenantId": "fixture", "gatewayId": "http://127.0.0.1", "callId": sixth["call"],
                "publicCallId": uuid.uuid4().hex, "membershipId": "capacity-fixture"}})
        assert result["state"] == "capturing", result
        time.sleep(.7)
        stopped.set()
        for writer in writers: writer.join(2)
        complete = calls[1:]
        for item in calls:
            ng.request({"command": "delete", "call-id": item["sip"], "delete-delay": 0})
            rpc.active.discard(item["call"])
            journal.append({"callId": item["call"], "type": "ended", "legId": "provider", "sipCode": 200,
                "reason": None, "endedBy": "agent"})
        for item in complete:
            result = controller.handle(tenant, {"action": "finish", "callId": item["call"], "manifestId": item["manifest"]})
            assert result["state"] == "ready", result
            with wave.open(str(root / "output" / (item["manifest"] + ".wav"))) as audio:
                assert audio.getnchannels() == 2 and audio.getframerate() == 8000
                raw = audio.readframes(audio.getnframes())
            channels = struct.unpack("<%dh" % (len(raw) // 2), raw)
            assert len(channels) > 3200
            energies(channels[800:-800:2], 440); energies(channels[801:-800:2], 660)
        assert len(list((root / "output").glob("*.wav"))) == 5
        assert len(list((root / "output").glob("*.json"))) == 5
        assert not controller.producer._sessions
        print(json.dumps({"ok": True, "durationSeconds": round(time.monotonic() - started, 2),
            "checks": ["five-concurrent-native-subscriptions", "pcma-pt8-end-to-end", "sixth-rejected", "failed-session-contained", "five-stereo-artifacts", "tone-channel-isolation", "source-calls-deleted"]}), flush=True)
    finally:
        stopped.set()
        for writer in writers: writer.join(1)
        for peer in peers: peer.close()
        for item in calls:
            try: ng.request({"command": "delete", "call-id": item["sip"], "delete-delay": 0})
            except Exception: pass
        if controller: controller.close()
        if journal: journal.close()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__": main()
