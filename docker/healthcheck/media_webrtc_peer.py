"""Fixture-only aiortc peer used by disposable recording/listening proofs."""
import asyncio
import os
import struct
import re
import time
from collections import deque
from fractions import Fraction

import av
import aioice.ice
from aiortc import (MediaStreamTrack, RTCPeerConnection, RTCConfiguration,
                    RTCSessionDescription, RTCRtpSender)
from aiortc.mediastreams import MediaStreamError

from media_fixture import (FRAME_SAMPLES, SAMPLE_RATE, build_rtp,
                           pcmu_encode_many, tone, tone_energies)


if os.environ.get("BITCALL_MEDIA_LOOPBACK_FIXTURE") == "1":
    # Fixture-only network-none gathering. Default runs leave aioice untouched.
    def _fixture_loopback_addresses(use_ipv4=True, use_ipv6=True):
        return ["127.0.0.1"] if use_ipv4 else []

    aioice.ice.get_host_addresses = _fixture_loopback_addresses


class _PcmTrack(MediaStreamTrack):
    kind = "audio"

    def __init__(self, samples=None, frequency=440):
        super().__init__()
        self._samples = tuple(int(value) for value in (samples or ()))
        self._frequency = frequency
        self._position = 0
        self._next = time.monotonic()
        self._pts = 0

    def set_samples(self, samples):
        if not isinstance(samples, (list, tuple)) or not samples:
            raise ValueError("pcm_samples must be a non-empty mono sample sequence")
        self._samples = tuple(int(value) for value in samples)
        self._position = 0

    async def recv(self):
        delay = self._next - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)
        self._next = max(self._next + FRAME_SAMPLES / SAMPLE_RATE, time.monotonic())
        if self._samples:
            values = tuple(self._samples[(self._position + index) % len(self._samples)]
                           for index in range(FRAME_SAMPLES))
        else:
            values = tone((self._frequency,), phase=self._position)
        self._position += FRAME_SAMPLES
        frame = av.AudioFrame(format="s16", layout="mono", samples=FRAME_SAMPLES)
        frame.sample_rate = SAMPLE_RATE
        frame.pts = self._pts
        frame.time_base = Fraction(1, SAMPLE_RATE)
        self._pts += FRAME_SAMPLES
        frame.planes[0].update(struct.pack("<%dh" % FRAME_SAMPLES, *values))
        return frame


class WebRtcPeer:
    """A bounded peer for tests, never imported by the deployed gateway."""

    def __init__(self, outgoing=False, pcm_samples=None, frequency=440, max_samples=8000):
        if not isinstance(outgoing, bool) or not isinstance(frequency, (int, float)):
            raise TypeError("invalid fixture peer configuration")
        if not isinstance(max_samples, int) or not 160 <= max_samples <= 64000:
            raise ValueError("max_samples must be bounded")
        if pcm_samples is not None and (not isinstance(pcm_samples, (list, tuple)) or not pcm_samples):
            raise ValueError("pcm_samples must be a non-empty mono sample sequence")
        self.pc = RTCPeerConnection(RTCConfiguration(iceServers=[]))
        self._samples = deque(maxlen=max_samples)
        self._received_samples = 0
        self._tracks = {}
        self._tasks = []
        self._ready = deque(maxlen=16)
        self._errors = deque(maxlen=8)
        self._closed = False
        self._sequence = 1
        self._timestamp = 0
        self._outgoing_track = None
        self._configure_audio(outgoing, pcm_samples, frequency)
        self.pc.on("track", self._on_track)
        self.pc.on("connectionstatechange", self._on_connection_state)

    def _configure_audio(self, outgoing, pcm_samples, frequency):
        transceiver = self.pc.addTransceiver("audio", direction="sendrecv" if outgoing else "recvonly")
        codecs = RTCRtpSender.getCapabilities("audio").codecs
        pcmu = [codec for codec in codecs if codec.mimeType.lower() == "audio/pcmu"]
        if not pcmu:
            raise RuntimeError("fixture aiortc has no PCMU codec")
        transceiver.setCodecPreferences(pcmu)
        if outgoing:
            self._outgoing_track = _PcmTrack(pcm_samples, frequency)
            transceiver.sender.replaceTrack(self._outgoing_track)

    def set_outgoing_pcm(self, samples):
        if self._outgoing_track is None:
            raise RuntimeError("peer has no outgoing audio track")
        self._outgoing_track.set_samples(samples)

    def clear_received(self):
        self._samples.clear()
        for track in self._tracks.values():
            track["samples"].clear()

    def _on_connection_state(self):
        self._ready.append({"at": time.monotonic(), "connectionState": self.pc.connectionState})

    def _on_track(self, track):
        if track.kind != "audio":
            return
        key = track.id
        self._tracks[key] = {"samples": deque(maxlen=self._samples.maxlen), "first_media": None}
        self._tasks.append(asyncio.create_task(self._consume(track, key)))

    async def _consume(self, track, key):
        resampler = av.AudioResampler(format="s16", layout="mono", rate=SAMPLE_RATE)
        try:
            while True:
                frame = await track.recv()
                output = resampler.resample(frame)
                for item in output if isinstance(output, list) else [output]:
                    values = struct.unpack("<%dh" % item.samples,
                                           bytes(item.planes[0])[:item.samples * 2])
                    state = self._tracks[key]
                    if state["first_media"] is None:
                        state["first_media"] = time.monotonic()
                    state["samples"].extend(values)
                    self._samples.extend(values)
                    self._received_samples += len(values)
        except MediaStreamError:
            return
        except Exception as error:
            self._errors.append({"track": key, "type": type(error).__name__})
            raise

    async def _ice_complete(self):
        while self.pc.iceGatheringState != "complete":
            await asyncio.sleep(0.01)

    @staticmethod
    def _sdp(description):
        return description.sdp

    async def offer(self):
        await self.pc.setLocalDescription(await self.pc.createOffer())
        await self._ice_complete()
        return self._sdp(self.pc.localDescription)

    @staticmethod
    def _parser_compatible_sdp(sdp):
        # Debian aiortc 1.4 requires the optional RTCP address. Expanding the
        # RFC 3605 shorthand preserves its meaning; this is test-peer compatibility.
        address = re.search(r"^c=IN IP4 ([^\r\n]+)", sdp, re.M).group(1)
        return re.sub(r"(?m)^a=rtcp:(\d+)\r?$", r"a=rtcp:\1 IN IP4 " + address + "\r", sdp)

    async def accept_answer(self, sdp):
        await self.pc.setRemoteDescription(RTCSessionDescription(sdp=self._parser_compatible_sdp(sdp), type="answer"))

    async def answer_subscription(self, offer_sdp):
        await self.pc.setRemoteDescription(RTCSessionDescription(sdp=self._parser_compatible_sdp(offer_sdp), type="offer"))
        await self.pc.setLocalDescription(await self.pc.createAnswer())
        await self._ice_complete()
        return self._sdp(self.pc.localDescription)

    async def inject_unnegotiated(self, frequency=880, frames=15, ssrc=0xDEADBEEF):
        """Fixture-only private aiortc injection through negotiated DTLS/SRTP."""
        if not isinstance(frames, int) or not 1 <= frames <= 250:
            raise ValueError("frames must be between one and 250")
        transports = []
        for transceiver in self.pc.getTransceivers():
            transport = transceiver.receiver.transport
            if transport is not None and transport.state == "connected" and transport not in transports:
                transports.append(transport)
        if not transports:
            raise RuntimeError("no negotiated receiver transport")
        for frame_index in range(frames):
            payload = pcmu_encode_many(tone((frequency,), phase=frame_index * FRAME_SAMPLES))
            packet = build_rtp(payload, self._sequence, self._timestamp, ssrc,
                               marker=frame_index == 0)
            for transport in transports:
                await transport._send_rtp(packet)  # Fixture-only aiortc private API.
            self._sequence = (self._sequence + 1) & 0xFFFF
            self._timestamp = (self._timestamp + FRAME_SAMPLES) & 0xFFFFFFFF
            await asyncio.sleep(FRAME_SAMPLES / SAMPLE_RATE)
        return {"packetsSent": frames * len(transports), "transports": len(transports)}

    def audio_ready(self, track_count=1, min_samples=2400):
        return len(self._tracks) == track_count and all(
            len(track["samples"]) >= min_samples for track in self._tracks.values())

    @property
    def received_samples(self):
        return self._received_samples

    @property
    def samples(self):
        return list(self._samples)

    @property
    def metrics(self):
        tracks = [{"trackId": key, "sampleCount": len(value["samples"]),
                   "toneEnergies": tone_energies(value["samples"]),
                   "firstMediaAt": value["first_media"]}
                  for key, value in self._tracks.items()]
        return {"tracks": tracks, "ready": self.pc.connectionState == "connected",
                "readyEvents": list(self._ready), "errors": list(self._errors),
                "connectionState": self.pc.connectionState}

    @property
    def connectionState(self):
        return self.pc.connectionState

    async def close(self):
        if self._closed:
            return
        self._closed = True
        for task in self._tasks:
            if not task.done():
                task.cancel()
        # Consumer failures are retained in metrics; they must not skip transport cleanup.
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.pc.close()
