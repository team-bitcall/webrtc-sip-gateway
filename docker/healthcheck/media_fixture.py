"""Bounded, standard-library media proof primitives for disposable fixtures."""
import json
import math
import os
import secrets
import select
import socket
import struct
import time
import wave
from contextlib import AbstractContextManager
from dataclasses import dataclass

SAMPLE_RATE = 8000
PCMU_PAYLOAD_TYPE = 0
FRAME_SAMPLES = 160


class NgError(RuntimeError):
    pass


def _ng_request_frame(command, cookie):
    encoded = json.dumps(command, separators=(",", ":")).encode()
    if len(cookie) + 1 + len(encoded) > 65507:
        raise ValueError("NG control command is too large")
    return cookie + b" " + encoded


def _ng_response(raw, cookie):
    try:
        response_cookie, body = raw.split(b" ", 1)
        reply = json.loads(body)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NgError("NG control response was malformed") from error
    if response_cookie != cookie:
        return None
    if not isinstance(reply, dict):
        raise NgError("NG control response was not an object")
    return reply


class NgClient(AbstractContextManager):
    """Minimal JSON control client; callers choose whether an error is expected."""
    def __init__(self, host="127.0.0.1", port=2223, timeout=2):
        if not 0 < timeout <= 2:
            raise ValueError("NG control timeout must be between zero and two seconds")
        self.timeout = timeout
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect((host, port))

    def request(self, command, *, allow_error=False):
        if not isinstance(command, dict):
            raise TypeError("control command must be an object")
        value = dict(command)
        cookie = secrets.token_hex(12).encode("ascii")
        self.socket.send(_ng_request_frame(value, cookie))
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("NG control response timed out")
            readable, _, _ = select.select([self.socket], [], [], remaining)
            if not readable:
                raise TimeoutError("NG control response timed out")
            raw = self.socket.recv(65535)
            reply = _ng_response(raw, cookie)
            if reply is None:
                continue
            if reply.get("result") == "error" and not allow_error:
                raise NgError("NG control error: " + str(reply.get("error-reason", "unspecified")))
            return reply

    def close(self):
        self.socket.close()

    def __exit__(self, *_):
        self.close()


def pcmu_encode(sample):
    sample = max(-32635, min(32635, int(sample)))
    sign = 0x80 if sample < 0 else 0
    sample = -sample if sample < 0 else sample
    sample += 0x84
    exponent = 7
    mask = 0x4000
    while exponent and not sample & mask:
        exponent -= 1
        mask >>= 1
    mantissa = (sample >> (exponent + 3)) & 0x0F
    return (~(sign | (exponent << 4) | mantissa)) & 0xFF


def pcmu_decode(value):
    value = (~int(value)) & 0xFF
    sample = ((value & 0x0F) << 3) + 0x84
    sample <<= (value & 0x70) >> 4
    return (0x84 - sample) if value & 0x80 else (sample - 0x84)


def pcmu_encode_many(samples):
    return bytes(pcmu_encode(sample) for sample in samples)


def pcmu_decode_many(payload):
    return [pcmu_decode(value) for value in payload]


def tone(frequencies, samples=FRAME_SAMPLES, amplitude=9000, phase=0):
    if not frequencies or any(not 0 < value < SAMPLE_RATE / 2 for value in frequencies):
        raise ValueError("tone frequencies must be in the audio band")
    return [int(amplitude * sum(math.sin(2 * math.pi * value * (phase + index) / SAMPLE_RATE)
                                for value in frequencies) / len(frequencies))
            for index in range(samples)]


def tone_energies(samples, frequencies=(440, 660, 880)):
    values = list(samples)
    if not values:
        return {frequency: 0.0 for frequency in frequencies}
    return {frequency: (sum(value * math.cos(2 * math.pi * frequency * index / SAMPLE_RATE)
                            for index, value in enumerate(values)) ** 2
                        + sum(value * math.sin(2 * math.pi * frequency * index / SAMPLE_RATE)
                              for index, value in enumerate(values)) ** 2)
            for frequency in frequencies}


def dominant_tone(samples, frequencies=(440, 660, 880)):
    values = tone_energies(samples, frequencies)
    return max(values, key=values.get), values


def write_wav(path, samples):
    with wave.open(os.fspath(path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(SAMPLE_RATE)
        output.writeframes(struct.pack("<%dh" % len(samples), *samples))


@dataclass(frozen=True)
class RtpPacket:
    payload: bytes
    sequence: int
    timestamp: int
    ssrc: int
    payload_type: int
    marker: bool
    received_at: float | None = None


def build_rtp(payload, sequence, timestamp, ssrc, *, payload_type=PCMU_PAYLOAD_TYPE, marker=False):
    if not isinstance(payload, bytes) or not 0 <= payload_type < 128:
        raise ValueError("invalid RTP payload")
    first = 0x80
    second = payload_type | (0x80 if marker else 0)
    return struct.pack("!BBHII", first, second, sequence & 0xFFFF, timestamp & 0xFFFFFFFF,
                       ssrc & 0xFFFFFFFF) + payload


def parse_rtp(raw, received_at=None):
    if len(raw) < 12 or raw[0] >> 6 != 2:
        raise ValueError("invalid RTP header")
    padding, extension, csrcs = raw[0] & 0x20, raw[0] & 0x10, raw[0] & 0x0F
    offset = 12 + csrcs * 4
    if len(raw) < offset:
        raise ValueError("truncated RTP CSRC list")
    if extension:
        if len(raw) < offset + 4:
            raise ValueError("truncated RTP extension")
        extension_words = struct.unpack_from("!H", raw, offset + 2)[0]
        offset += 4 + extension_words * 4
        if len(raw) < offset:
            raise ValueError("truncated RTP extension data")
    end = len(raw)
    if padding:
        amount = raw[-1]
        if not amount or amount > end - offset:
            raise ValueError("invalid RTP padding")
        end -= amount
    first, second, sequence, timestamp, ssrc = struct.unpack_from("!BBHII", raw)
    return RtpPacket(raw[offset:end], sequence, timestamp, ssrc, second & 0x7F,
                     bool(second & 0x80), received_at)


class PcmuPeer(AbstractContextManager):
    """One UDP peer with explicit pacing and no worker thread."""
    def __init__(self, host="127.0.0.1", port=0, *, ssrc=None, sequence=1, timestamp=0):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((host, port))
        self.ssrc = secrets.randbits(32) if ssrc is None else ssrc
        self.sequence, self.timestamp, self.next_send = sequence, timestamp, time.monotonic()

    @property
    def address(self):
        return self.socket.getsockname()

    def sdp(self, address=None):
        host, port = address or self.address
        return ("v=0\r\no=- 0 0 IN IP4 %s\r\ns=fixture\r\nc=IN IP4 %s\r\nt=0 0\r\n"
                "m=audio %d RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n") % (host, host, port)

    def send_pcm(self, samples, destination, *, marker=False, pace=True):
        if len(samples) != FRAME_SAMPLES:
            raise ValueError("PCMU RTP frames are exactly 20 ms")
        if pace:
            delay = self.next_send - time.monotonic()
            if delay > 0:
                time.sleep(delay)
        raw = build_rtp(pcmu_encode_many(samples), self.sequence, self.timestamp, self.ssrc, marker=marker)
        self.socket.sendto(raw, destination)
        self.sequence = (self.sequence + 1) & 0xFFFF
        self.timestamp = (self.timestamp + FRAME_SAMPLES) & 0xFFFFFFFF
        self.next_send = max(self.next_send + FRAME_SAMPLES / SAMPLE_RATE, time.monotonic())

    def send_tone(self, frequencies, destination, frames=1):
        if not isinstance(frames, int) or not 1 <= frames <= 250:
            raise ValueError("tone burst must contain between one and 250 RTP frames")
        for frame in range(frames):
            self.send_pcm(tone(frequencies, phase=frame * FRAME_SAMPLES), destination, marker=frame == 0)

    def receive(self, timeout=2):
        if not 0 < timeout <= 2:
            raise ValueError("RTP receive timeout must be between zero and two seconds")
        readable, _, _ = select.select([self.socket], [], [], timeout)
        if not readable:
            raise TimeoutError("RTP receive timed out")
        raw, _ = self.socket.recvfrom(65535)
        return parse_rtp(raw, time.monotonic())

    def close(self):
        self.socket.close()

    def __exit__(self, *_):
        self.close()
