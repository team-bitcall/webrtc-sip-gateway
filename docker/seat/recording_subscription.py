"""Bounded native RTPengine subscription input for opt-in recording capture."""
import hashlib
from collections.abc import Mapping
import os
import re
import selectors
import stat
import socket
import struct
import threading
import time
from pathlib import Path


class SubscriptionError(RuntimeError):
    pass


def _fail(message):
    raise SubscriptionError(message)


def _write_all(fd, value):
    while value:
        written = os.write(fd, value)
        if written <= 0: _fail("pcap write failed")
        value = value[written:]


def _private_file(path, links=(1,), flags=os.O_RDONLY):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink not in links or stat.S_IMODE(info.st_mode) != 0o600:
        os.close(fd)
        _fail("private recording file required")
    return fd, info


def _tag(manifest, index):
    return hashlib.sha256((manifest + ":subscription:" + str(index)).encode()).hexdigest()[:32]


def _sdp(port):
    return ("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=recording\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
            "m=audio %d RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=recvonly\r\n") % port


def _offered_port(value, expected_tag, expected_source):
    if (not isinstance(value, Mapping) or value.get("result") != "ok" or value.get("to-tag") != expected_tag
            or value.get("from-tags") != [expected_source]):
        _fail("subscription request failed")
    sdp = value.get("sdp")
    if not isinstance(sdp, str) or len(sdp) > 8192:
        _fail("invalid subscription SDP")
    media = re.findall(r"^m=([^\r\n]+)", sdp, re.M)
    addresses = re.findall(r"^c=([^\r\n]+)", sdp, re.M)
    match = re.fullmatch(r"audio ([1-9][0-9]{0,4}) RTP/AVP ([0-9 ]+)", media[0]) if len(media) == 1 else None
    if (not match or not 1 <= int(match.group(1)) <= 65535
            or not set(match.group(2).split()) & {"0", "8"}
            or not addresses or any(value != "IN IP4 127.0.0.1" for value in addresses)
            or not re.search(r"^a=sendonly\r?$", sdp, re.M)):
        _fail("invalid subscription SDP")
    return int(match.group(1))


class SubscriptionProducer:
    def __init__(self, ng, pcaps, metadata, max_input_bytes, max_packets):
        if not hasattr(ng, "request") or not isinstance(max_input_bytes, int) or max_input_bytes < 24 or not isinstance(max_packets, int) or max_packets < 1:
            raise ValueError("invalid subscription producer")
        self.ng, self.pcaps, self.metadata = ng, Path(pcaps).resolve(strict=True), Path(metadata).resolve(strict=True)
        self.max_input_bytes, self.max_packets = max_input_bytes, max_packets
        self._sessions, self._lock = {}, threading.RLock()

    def _unsubscribe(self, row, index):
        tag = _tag(row["manifest_id"], index)
        reply = self.ng.request({"command": "unsubscribe", "call-id": row["sip_call_id"], "to-tag": tag})
        if isinstance(reply, dict) and reply.get("result") == "ok":
            return
        # NG's unsubscribe uses "call-ID" while query uses "call-id". Prove
        # absence through query instead of relying on command-specific wording.
        query = self.ng.request({"command": "query", "call-id": row["sip_call_id"]})
        if isinstance(query, dict) and query.get("result") == "error" and query.get("error-reason") == "Unknown call-id":
            return
        if isinstance(query, dict) and query.get("result") == "ok" and isinstance(query.get("tags"), dict) and tag not in query["tags"]:
            return
        _fail("unsubscribe failed")

    def start(self, row, tags):
        if not isinstance(row, Mapping) or not isinstance(tags, (list, tuple)) or len(tags) != 2 or len(set(tags)) != 2:
            _fail("invalid recording subscription")
        manifest = row.get("manifest_id")
        if not isinstance(manifest, str) or not re.fullmatch(r"[a-f0-9]{32}", manifest): _fail("invalid recording subscription")
        with self._lock:
            if manifest in self._sessions: return
            path = self.pcaps / (manifest + ".pcap")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            sockets, offered = [], []
            session = {"row": row, "fd": fd, "sockets": sockets, "offered": offered,
                       "stop": threading.Event(), "error": None, "bytes": 24,
                       "packets": 0, "closed": False, "thread": None}
            self._sessions[manifest] = session
            try:
                _write_all(fd, struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
                for index, source_tag in enumerate(tags):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try: sock.bind(("127.0.0.1", 0))
                    except Exception: sock.close(); raise
                    sockets.append(sock)
                    tag = _tag(manifest, index)
                    reply = self.ng.request({"command": "subscribe request", "call-id": row["sip_call_id"], "from-tags": [source_tag],
                                             "to-tag": tag, "transport protocol": "RTP/AVP", "direction": ["recording", "recording"]})
                    offered.append(_offered_port(reply, tag, source_tag))
                    answer = self.ng.request({"command": "subscribe answer", "call-id": row["sip_call_id"], "to-tag": tag, "sdp": _sdp(sock.getsockname()[1])})
                    if not isinstance(answer, dict) or answer.get("result") != "ok": _fail("subscription answer failed")
                thread = threading.Thread(target=self._receive, args=(session,), daemon=True); session["thread"] = thread
                self._sessions[manifest] = session; thread.start()
            except Exception:
                # Controller persists failed + stop_pending and retries cleanup.
                # Keep any resources whose cleanup failed attached to this row.
                try:
                    self.stop(row)
                except Exception:
                    pass
                raise

    def _receive(self, session):
        selector = selectors.DefaultSelector()
        try:
            for index, sock in enumerate(session["sockets"]): selector.register(sock, selectors.EVENT_READ, index)
            while not session["stop"].is_set():
                for key, _ in selector.select(.2):
                    payload, address = key.fileobj.recvfrom(65535)
                    if address[0] != "127.0.0.1" or address[1] != session["offered"][key.data] or len(payload) < 12 or payload[0] >> 6 != 2:
                        _fail("untrusted subscription packet")
                    if session["packets"] >= self.max_packets or len(payload) + 42 > 65535: _fail("subscription limit")
                    now = time.time(); src, dst = 10001 + key.data, 20001 + key.data
                    ip = b"\x45\x00" + struct.pack("!H", 28 + len(payload)) + b"\0\0\0\0\x40\x11\0\0\x7f\0\0\1\x7f\0\0\1"
                    udp = struct.pack("!HHHH", src, dst, 8 + len(payload), 0)
                    raw = b"\0" * 12 + b"\x08\0" + ip + udp + payload
                    record = struct.pack("<IIII", int(now), int((now % 1) * 1e6), len(raw), len(raw)) + raw
                    if session["bytes"] + len(record) > self.max_input_bytes: _fail("subscription limit")
                    _write_all(session["fd"], record)
                    session["packets"] += 1; session["bytes"] += len(record)
        except Exception as error: session["error"] = error
        finally: selector.close()

    def health(self, row):
        with self._lock:
            session = self._sessions.get(row["manifest_id"])
            if not session or session["closed"]:
                _fail("subscription missing")
            if session["error"]:
                raise session["error"]
            return True

    def stop(self, row):
        """Fence the writer, remove only our subscriptions, and persist closure.

        Returns the writer failure separately from cleanup success. The capture
        journal owns durable failure state; no lifetime per-manifest cache grows.
        """
        manifest = row["manifest_id"]
        with self._lock:
            session = self._sessions.get(manifest)
            if session and not session["closed"]:
                session["stop"].set()
                thread = session["thread"]
                if thread is not None:
                    thread.join(2)
                    if thread.is_alive():
                        _fail("subscription writer still running")
                for sock in session["sockets"]:
                    sock.close()
                # Always close the FD, even on fsync failure. The private file is
                # re-opened and synced below, including recovery after restart.
                try:
                    os.fsync(session["fd"])
                finally:
                    os.close(session["fd"])
                    session["closed"] = True
            errors = []
            for index in range(2):
                try:
                    self._unsubscribe(row, index)
                except Exception as error:
                    errors.append(error)
            if errors:
                raise errors[0]
            path = self.pcaps / (manifest + ".pcap")
            try:
                fd, _info = _private_file(path)
            except FileNotFoundError:
                pass  # A durable start intent may fail before creating its file.
            else:
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
                self._publish_metadata(row)
            self._sessions.pop(manifest, None)
            return session["error"] if session else None

    def finish(self, row):
        with self._lock:
            self.health(row)
            error = self.stop(row)
            if error:
                raise error
            return self.metadata / (row["manifest_id"] + ".meta")

    def _publish_metadata(self, row):
        manifest = row["manifest_id"]
        pcap = self.pcaps / (manifest + ".pcap")
        fd, _info = _private_file(pcap)
        os.close(fd)
        target = self.metadata / (manifest + ".meta")
        temporary = self.metadata / ("." + manifest + ".meta.tmp")
        contents = (str(pcap) + "\nbitcall-recording:" + manifest + "\n").encode()

        def inspect(path, repair_partial=False):
            try:
                fd, info = _private_file(path, links=(1, 2), flags=os.O_RDWR if repair_partial else os.O_RDONLY)
            except FileNotFoundError:
                return None
            try:
                value = os.read(fd, len(contents) + 1)
                if value != contents:
                    # Only our single-link, exact-prefix private temporary file
                    # can be completed after an interrupted bounded write.
                    if not repair_partial or info.st_nlink != 1 or not contents.startswith(value):
                        _fail("recording metadata conflict")
                    _write_all(fd, contents[len(value):])
                os.fsync(fd)
                return info
            finally:
                os.close(fd)

        existing = inspect(target)
        partial = inspect(temporary, repair_partial=existing is None)
        if existing is not None:
            if partial is not None:
                if (existing.st_dev, existing.st_ino) != (partial.st_dev, partial.st_ino) or existing.st_nlink != 2:
                    _fail("recording metadata conflict")
                os.unlink(temporary)
            elif existing.st_nlink != 1:
                _fail("recording metadata conflict")
        else:
            if partial is None:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    _write_all(fd, contents)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            elif partial.st_nlink != 1:
                _fail("recording metadata conflict")
            # Publication never overwrites a conflicting target. A crash between
            # link and unlink leaves only the known two-link pair handled above.
            os.link(temporary, target, follow_symlinks=False)
            os.unlink(temporary)
        directory = os.open(self.metadata, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return target

    def close(self):
        errors = []
        for session in list(self._sessions.values()):
            try:
                self.stop(session["row"])
            except Exception as error:
                errors.append(error)
        if errors:
            raise errors[0]
