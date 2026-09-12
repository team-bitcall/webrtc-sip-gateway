"""Fail-closed, bounded classic-PCAP RTP recording finalizer.

The epoch passed here is an authoritative selection made by the caller.  This
module does not establish that trust: a changed or unsupported epoch must be
invalidated upstream.  Packets are processed in capture order.  Exact
duplicates are ignored, but reordering is rejected rather than guessed.
"""

from __future__ import annotations

from collections import deque
from contextlib import ExitStack
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import struct

RATE = 8000
WAV_HEADER = 44
MAX_DURATION = 3600
MAX_PACKET = 65535


class RecordingDecodeError(ValueError):
    pass


def _fail(message: str) -> None:
    raise RecordingDecodeError(message)


def _hex32(value: object, name: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{32}", value) is None:
        _fail("invalid " + name)
    return value


def _private_file(path: Path) -> int:
    # lstat first makes a symlink failure deterministic even on platforms
    # without O_NOFOLLOW; open/fstat closes the replacement race.
    try:
        before = path.lstat()
    except OSError as error:
        raise RecordingDecodeError("cannot stat capture") from error
    if stat.S_ISLNK(before.st_mode):
        _fail("capture may not be a symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise RecordingDecodeError("cannot open capture") from error
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
    ):
        os.close(fd)
        _fail("capture must be a private 0600 regular single-link file")
    return fd


def _private_directory(path: Path) -> Path:
    try:
        if path.is_symlink():
            _fail("output directory may not be a symlink")
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as error:
        raise RecordingDecodeError("cannot resolve output directory") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _fail("output directory must be owned private 0700")
    return resolved


def _read_exact(fd: int, size: int) -> bytes:
    parts = bytearray()
    while len(parts) < size:
        value = os.read(fd, size - len(parts))
        if not value:
            _fail("truncated PCAP")
        parts.extend(value)
    return bytes(parts)


def _decode_ulaw(value: int) -> int:
    value = (~value) & 255
    sample = ((value & 15) << 3) + 0x84
    sample <<= (value & 0x70) >> 4
    return 0x84 - sample if value & 0x80 else sample - 0x84


def _decode_alaw(value: int) -> int:
    value ^= 0x55
    sample = (value & 15) << 4
    segment = (value & 0x70) >> 4
    if segment == 0:
        sample += 8
    elif segment == 1:
        sample += 0x108
    else:
        sample += 0x108
        sample <<= segment - 1
    return sample if value & 0x80 else -sample


def _pcm(codec: str, payload: bytes) -> bytes:
    decoder = _decode_ulaw if codec == "PCMU" else _decode_alaw
    return b"".join(struct.pack("<h", decoder(byte)) for byte in payload)


def _write_all(fd: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            _fail("short output write")
        view = view[written:]


def _integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate(
    binding: object, epoch: object, limits: object
) -> tuple[dict, list[dict], int, int, int, int]:
    if not isinstance(binding, dict):
        _fail("binding must be an object")
    checked = {key: _hex32(binding.get(key), key) for key in ("callId", "publicCallId")}
    for key in ("tenantId", "gatewayId", "membershipId"):
        if (
            not isinstance(binding.get(key), str)
            or not 1 <= len(binding[key].encode()) <= 512
            or any(ord(c) < 32 or ord(c) == 127 for c in binding[key])
        ):
            _fail("invalid binding " + key)
        checked[key] = binding[key]
    if (
        not isinstance(epoch, dict)
        or not isinstance(epoch.get("sources"), list)
        or len(epoch["sources"]) != 2
    ):
        _fail("epoch requires exactly two sources")
    started, ended = epoch.get("startedAtUs"), epoch.get("endedAtUs")
    if not _integer(started) or not _integer(ended) or not 0 <= started < ended:
        _fail("invalid epoch window")
    if not isinstance(limits, dict):
        _fail("limits must be an object")
    values = [
        limits.get(key)
        for key in (
            "maxInputBytes",
            "maxOutputBytes",
            "maxDurationSeconds",
            "maxPackets",
        )
    ]
    if any(not _integer(value) or value <= 0 for value in values):
        _fail("invalid limits")
    max_in, max_out, max_seconds, max_packets = values
    if max_seconds > MAX_DURATION or ended - started > max_seconds * 1_000_000:
        _fail("duration exceeds limit")
    sources = []
    selectors = set()
    relay_ports = set()
    for item in epoch["sources"]:
        if not isinstance(item, dict):
            _fail("invalid source")
        address, port, relay, ssrc, pt, codec, tag = (
            item.get(k)
            for k in (
                "address",
                "port",
                "relayPort",
                "ssrc",
                "payloadType",
                "codec",
                "tag",
            )
        )
        try:
            address_bytes = bytes(map(int, address.split(".")))
        except (AttributeError, ValueError):
            _fail("invalid source address")
        if len(address_bytes) != 4 or any(not 0 <= x <= 255 for x in address_bytes):
            _fail("invalid source address")
        if (
            not _integer(port)
            or not _integer(relay)
            or not 1 <= port <= 65535
            or not 1 <= relay <= 65535
            or not _integer(ssrc)
            or not 0 <= ssrc <= 0xFFFFFFFF
            or not _integer(pt)
            or pt not in (0, 8)
            or codec not in ("PCMU", "PCMA")
            or not isinstance(tag, str)
            or not tag
        ):
            _fail("invalid source")
        if (pt == 0) != (codec == "PCMU"):
            _fail("payload type and codec disagree")
        selector = (address_bytes, port, relay)
        if selector in selectors or relay in relay_ports:
            _fail("ambiguous source transport")
        selectors.add(selector)
        relay_ports.add(relay)
        sources.append(
            {
                "address": address_bytes,
                "port": port,
                "relayPort": relay,
                "ssrc": ssrc,
                "payloadType": pt,
                "codec": codec,
                "tag": tag,
            }
        )
    if max_in < 24 or max_out < WAV_HEADER + 8:
        _fail("limits too small")
    return checked, sources, max_in, max_out, max_seconds, max_packets


def _rtp(payload: bytes) -> tuple[int, int, int, bytes]:
    if len(payload) < 12 or payload[0] >> 6 != 2:
        _fail("invalid RTP header")
    csrc_count = payload[0] & 15
    offset = 12 + csrc_count * 4
    if len(payload) < offset:
        _fail("truncated RTP CSRC list")
    if payload[0] & 0x10:
        if len(payload) < offset + 4:
            _fail("truncated RTP extension")
        words = struct.unpack_from("!H", payload, offset + 2)[0]
        offset += 4 + words * 4
        if len(payload) < offset:
            _fail("truncated RTP extension")
    end = len(payload)
    if payload[0] & 0x20:
        padding = payload[-1]
        if not padding or padding > end - offset:
            _fail("invalid RTP padding")
        end -= padding
    seq, timestamp, ssrc = struct.unpack_from("!HII", payload, 2)
    if end == offset:
        _fail("empty RTP payload")
    return seq, timestamp, ssrc, payload[offset:end]


def _pcap(fd: int, size: int):
    if size < 24:
        _fail("truncated PCAP header")
    header = _read_exact(fd, 24)
    magic = header[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in formats:
        _fail("unsupported PCAP magic")
    endian, scale = formats[magic]
    major, minor, _zone, _sig, snaplen, network = struct.unpack(
        endian + "HHIIII", header[4:]
    )
    if (major, minor) != (2, 4) or snaplen <= 0 or snaplen > MAX_PACKET or network != 1:
        _fail("unsupported PCAP link type")
    consumed = 24
    while consumed < size:
        if size - consumed < 16:
            _fail("truncated PCAP packet header")
        seconds, fraction, captured, original = struct.unpack(
            endian + "IIII", _read_exact(fd, 16)
        )
        consumed += 16
        if (
            fraction >= scale
            or captured != original
            or captured > snaplen
            or captured > MAX_PACKET
            or captured > size - consumed
        ):
            _fail("invalid PCAP packet length")
        raw = _read_exact(fd, captured)
        consumed += captured
        yield seconds * 1_000_000 + fraction * 1_000_000 // scale, raw


def _udp(raw: bytes):
    if len(raw) < 14 + 20 + 8 or raw[12:14] != b"\x08\x00":
        return None
    ip = raw[14:]
    if ip[0] != 0x45 or ip[9] != 17:
        _fail("unsupported IPv4 packet")
    total = struct.unpack_from("!H", ip, 2)[0]
    flags_fragment = struct.unpack_from("!H", ip, 6)[0]
    if total != len(ip) or total < 28 or flags_fragment & 0x3FFF:
        _fail("fragmented or padded IPv4 packet")
    udp_len = struct.unpack_from("!H", ip, 24)[0]
    if udp_len != total - 20 or udp_len < 8:
        _fail("invalid UDP length")
    source, destination = struct.unpack_from("!HH", ip, 20)
    return ip[12:16], source, destination, ip[28:]


def _wav_header(data_bytes: int) -> bytes:
    return struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36 + data_bytes,
        b"WAVE",
        b"fmt ",
        16,
        1,
        2,
        RATE,
        RATE * 4,
        4,
        16,
        b"data",
        data_bytes,
    )


def finalize_capture(
    pcap_path, output_directory, manifest_id32hex, binding, epoch, limits
):
    """Finalize selected two-leg RTP as an atomic stereo PCM16 WAV and manifest."""
    manifest_id = _hex32(manifest_id32hex, "manifest id")
    checked, sources, max_in, max_out, max_seconds, max_packets = _validate(
        binding, epoch, limits
    )
    capture = Path(pcap_path)
    if capture.is_symlink():
        _fail("capture may not be a symlink")
    capture = capture.resolve(strict=True)
    directory = _private_directory(Path(output_directory))
    if capture.stat().st_size > max_in:
        _fail("capture exceeds input limit")
    wav_final, manifest_final = directory / (manifest_id + ".wav"), directory / (
        manifest_id + ".json"
    )
    if wav_final.exists() or manifest_final.exists():
        _fail("recording artifacts already exist")
    fd = _private_file(capture)
    capture_size = os.fstat(fd).st_size
    if capture_size > max_in:
        os.close(fd)
        _fail("capture exceeds input limit")
    temps: list[Path] = []
    live_mono_fds: set[int] = set()
    try:
        mono = []
        for index in range(2):
            name = (
                ".recording-"
                + manifest_id
                + "-"
                + str(os.getpid())
                + "-"
                + str(index)
                + ".part"
            )
            path = directory / name
            tfd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            mono.append((path, tfd))
            live_mono_fds.add(tfd)
            temps.append(path)
        state = [
            {
                "first_cap": None,
                "first_rtp": None,
                "last_seq": None,
                "last_ts": None,
                "seen": deque(maxlen=128),
                "end": 0,
                "nonempty": False,
            }
            for _ in sources
        ]
        packet_count = 0
        common_start = epoch["startedAtUs"]
        for captured_at, raw in _pcap(fd, capture_size):
            packet_count += 1
            if packet_count > max_packets:
                _fail("packet limit exceeded")
            if not epoch["startedAtUs"] <= captured_at <= epoch["endedAtUs"]:
                continue
            parsed = _udp(raw)
            if parsed is None:
                continue
            address, source_port, relay_port, payload = parsed
            # RTCP and unrelated UDP can share a relay port; the fail-closed
            # identity rule applies once a packet presents itself as RTP.
            if not payload or payload[0] >> 6 != 2:
                continue
            # RTCP is distinguished by the RTCP packet-type range after the
            # RTP/RTCP version byte and is never audio payload.
            if len(payload) >= 2 and 192 <= payload[1] <= 223:
                continue
            candidates = [
                i
                for i, source in enumerate(sources)
                if (address, source_port, relay_port)
                == (source["address"], source["port"], source["relayPort"])
            ]
            if not candidates:
                if relay_port in {source["relayPort"] for source in sources}:
                    _fail("conflicting trusted relay source")
                continue
            index = candidates[0]
            source = sources[index]
            seq, timestamp, ssrc, encoded = _rtp(payload)
            if ssrc != source["ssrc"] or (payload[1] & 127) != source["payloadType"]:
                _fail("conflicting selected source")
            if len(encoded) > MAX_PACKET:
                _fail("oversized RTP payload")
            item = state[index]
            fingerprint = (seq, timestamp, hashlib.sha256(encoded).digest())
            same_sequence = [known for known in item["seen"] if known[0] == seq]
            if same_sequence:
                if fingerprint in same_sequence:
                    continue
                _fail("conflicting RTP duplicate")
            if (
                item["last_seq"] is not None
                and ((seq - item["last_seq"]) & 0xFFFF) >= 0x8000
            ):
                _fail("RTP reordering is unsupported")
            if (
                item["last_ts"] is not None
                and ((timestamp - item["last_ts"]) & 0xFFFFFFFF) >= 0x80000000
            ):
                _fail("RTP timestamp reordering is unsupported")
            item["seen"].append(fingerprint)
            if item["first_cap"] is None:
                item["first_cap"], item["first_rtp"] = captured_at, timestamp
            delta = (timestamp - item["first_rtp"]) & 0xFFFFFFFF
            if delta >= 0x80000000:
                _fail("RTP timestamp before source start")
            # A two-second allowance permits ordinary capture scheduling delay,
            # while rejecting a clock reset or a malicious RTP jump.
            if abs(delta - (captured_at - item["first_cap"]) * 8 // 1000) > RATE * 2:
                _fail("gross RTP clock jump")
            start = (item["first_cap"] - common_start) * RATE // 1_000_000 + delta
            end = start + len(encoded)
            if item["nonempty"] and start < item["end"]:
                _fail("overlapping RTP audio is unsupported")
            if end > max_seconds * RATE or WAV_HEADER + end * 4 > max_out:
                _fail("output limit exceeded")
            os.lseek(mono[index][1], start * 2, os.SEEK_SET)
            _write_all(mono[index][1], _pcm(source["codec"], encoded))
            item["last_seq"], item["last_ts"], item["end"], item["nonempty"] = (
                seq,
                timestamp,
                max(item["end"], end),
                True,
            )
        if not all(item["nonempty"] for item in state):
            _fail("both recording legs must contain RTP")
        frames = max(item["end"] for item in state)
        data_size = frames * 4
        if WAV_HEADER + data_size > max_out:
            _fail("output limit exceeded")
        for path, tfd in mono:
            os.ftruncate(tfd, frames * 2)
            os.fsync(tfd)
            os.close(tfd)
            live_mono_fds.discard(tfd)
        wav_temp = directory / (".recording-" + manifest_id + "-wav.part")
        outfd = os.open(wav_temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        temps.append(wav_temp)
        try:
            _write_all(outfd, _wav_header(data_size))
            with ExitStack() as stack:
                readers = [
                    stack.enter_context(open(path, "rb", buffering=0))
                    for path, _ in mono
                ]
                for _offset in range(0, frames, 8192):
                    count = min(8192, frames - _offset)
                    left, right = (reader.read(count * 2) for reader in readers)
                    interleaved = bytearray(count * 4)
                    for sample in range(count):
                        interleaved[sample * 4 : sample * 4 + 2] = left[
                            sample * 2 : sample * 2 + 2
                        ]
                        interleaved[sample * 4 + 2 : sample * 4 + 4] = right[
                            sample * 2 : sample * 2 + 2
                        ]
                    _write_all(outfd, interleaved)
            os.fsync(outfd)
        finally:
            os.close(outfd)
        with open(wav_temp, "rb") as digest_file:
            digest = hashlib.file_digest(digest_file, "sha256").hexdigest()
        manifest = {
            "schemaVersion": 1,
            **checked,
            "manifestId": manifest_id,
            "finalized": True,
            "relativeFile": wav_final.name,
            "sha256": digest,
            "sizeBytes": WAV_HEADER + data_size,
            "contentType": "audio/wav",
        }
        manifest_temp = directory / (".recording-" + manifest_id + "-manifest.part")
        mfd = os.open(manifest_temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        temps.append(manifest_temp)
        try:
            _write_all(
                mfd,
                json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
                + b"\n",
            )
            os.fsync(mfd)
        finally:
            os.close(mfd)
        os.link(wav_temp, wav_final)
        wav_temp.unlink()
        temps.remove(wav_temp)
        os.link(manifest_temp, manifest_final)
        manifest_temp.unlink()
        temps.remove(manifest_temp)
        for path in temps:
            path.unlink(missing_ok=True)
        dirfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        return manifest
    except Exception:
        for tfd in live_mono_fds:
            try:
                os.close(tfd)
            except OSError:
                pass
        for path in temps:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(fd)
