"""Read-only, filesystem-bounded access to finalized recording artifacts."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

from recording_capture import CaptureError


HEX32 = re.compile(r"[a-f0-9]{32}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
TENANT = re.compile(r"t_[a-f0-9]{64}\Z")
MAX_MANIFEST_BYTES = 65536
MAX_CHUNK_BYTES = 65536
MANIFEST_KEYS = {
    "schemaVersion", "tenantId", "gatewayId", "callId", "publicCallId",
    "membershipId", "manifestId", "finalized", "relativeFile", "sha256",
    "sizeBytes", "contentType",
}
BINDING_KEYS = {"tenantId", "gatewayId", "callId", "publicCallId", "membershipId"}


def _error(code, status=503):
    raise CaptureError(code, status)


def _exact(value, keys):
    return isinstance(value, dict) and set(value) == set(keys)


def _private_open(path):
    """Open one immutable-looking private regular file without following links."""
    try:
        before = path.lstat()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        _error("RECORDING_ARTIFACT_UNAVAILABLE")
    info = os.fstat(fd)
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
        or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino)
    ):
        os.close(fd)
        _error("RECORDING_ARTIFACT_UNAVAILABLE")
    return fd, info.st_size


def _loads_exact(raw):
    def object_no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    return json.loads(raw.decode("utf8"), object_pairs_hook=object_no_duplicates)


class RecordingArtifacts:
    """Serve only ready artifacts selected by the private capture controller."""

    def __init__(self, controller):
        self.controller = controller

    def _command(self, tenant, command):
        if not isinstance(tenant, str) or not TENANT.fullmatch(tenant) or not isinstance(command, dict):
            _error("INVALID_RECORDING_REQUEST", 400)
        action = command.get("action")
        fields = {
            "list-ready": {"action", "after", "limit"},
            "manifest": {"action", "callId", "manifestId"},
            "chunk": {"action", "callId", "manifestId", "manifestSha256", "offset", "length"},
        }.get(action)
        if fields is None or not _exact(command, fields):
            _error("INVALID_RECORDING_REQUEST", 400)
        if action == "list-ready":
            if (type(command["after"]) is not int or command["after"] < 0
                    or type(command["limit"]) is not int or not 1 <= command["limit"] <= 25):
                _error("INVALID_RECORDING_REQUEST", 400)
        else:
            if not all(isinstance(command[k], str) and HEX32.fullmatch(command[k]) for k in ("callId", "manifestId")):
                _error("INVALID_RECORDING_REQUEST", 400)
        if action == "chunk":
            if (not isinstance(command["manifestSha256"], str) or not HEX64.fullmatch(command["manifestSha256"])
                    or type(command["offset"]) is not int or command["offset"] < 0
                    or type(command["length"]) is not int or not 1 <= command["length"] <= MAX_CHUNK_BYTES):
                _error("INVALID_RECORDING_REQUEST", 400)
        return action

    def _row(self, tenant, command):
        with self.controller.lock:
            row = self.controller.db.execute(
                "SELECT rowid,* FROM captures WHERE tenant_id=? AND call_id=? AND manifest_id=?",
                (tenant, command["callId"], command["manifestId"]),
            ).fetchone()
        if not row:
            _error("RECORDING_NOT_FOUND", 404)
        if row["state"] != "ready":
            _error("RECORDING_NOT_READY", 409)
        return row

    def _manifest(self, row):
        """Read and bind the exact persisted manifest before exposing media."""
        path = Path(self.controller.output) / (row["manifest_id"] + ".json")
        fd, size = _private_open(path)
        try:
            if size > MAX_MANIFEST_BYTES:
                _error("RECORDING_ARTIFACT_UNAVAILABLE")
            raw = bytearray()
            while len(raw) <= MAX_MANIFEST_BYTES:
                part = os.read(fd, MAX_MANIFEST_BYTES + 1 - len(raw))
                if not part:
                    break
                raw.extend(part)
            if len(raw) > MAX_MANIFEST_BYTES:
                _error("RECORDING_ARTIFACT_UNAVAILABLE")
            raw = bytes(raw)
        finally:
            os.close(fd)
        try:
            manifest = _loads_exact(raw)
            binding = _loads_exact(row["binding"].encode("utf8"))
        except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
            _error("RECORDING_ARTIFACT_UNAVAILABLE")
        if (
            not _exact(manifest, MANIFEST_KEYS)
            or not _exact(binding, BINDING_KEYS)
            or manifest["schemaVersion"] != 1
            or manifest["finalized"] is not True
            or manifest["contentType"] != "audio/wav"
            or manifest["relativeFile"] != row["manifest_id"] + ".wav"
            or type(manifest["sizeBytes"]) is not int
            or manifest["sizeBytes"] < 44
            or not isinstance(manifest["sha256"], str)
            or not HEX64.fullmatch(manifest["sha256"])
            or type(manifest["schemaVersion"]) is not int
            or any(not isinstance(binding[key], str) for key in BINDING_KEYS)
            or any(manifest.get(k) != binding.get(k) for k in BINDING_KEYS)
            or manifest["callId"] != row["call_id"]
            or manifest["manifestId"] != row["manifest_id"]
            or binding["callId"] != row["call_id"]
        ):
            _error("RECORDING_ARTIFACT_UNAVAILABLE")
        return manifest, raw, hashlib.sha256(raw).hexdigest()

    def _wav(self, row, manifest):
        path = Path(self.controller.output) / (row["manifest_id"] + ".wav")
        fd, size = _private_open(path)
        if size != manifest["sizeBytes"]:
            os.close(fd)
            _error("RECORDING_ARTIFACT_UNAVAILABLE")
        try:
            header = os.read(fd, 44)
            if (len(header) != 44 or header[:4] != b"RIFF" or header[8:12] != b"WAVE"
                    or header[12:16] != b"fmt " or header[36:40] != b"data"
                    or struct.unpack_from("<I", header, 4)[0] != size - 8
                    or struct.unpack_from("<I", header, 40)[0] != size - 44):
                _error("RECORDING_ARTIFACT_UNAVAILABLE")
        except Exception:
            os.close(fd)
            raise
        return fd, size

    def handle(self, tenant, command):
        action = self._command(tenant, command)
        if action == "list-ready":
            with self.controller.lock:
                rows = self.controller.db.execute(
                    "SELECT rowid,call_id,manifest_id FROM captures WHERE tenant_id=? AND state='ready' AND rowid>? ORDER BY rowid LIMIT ?",
                    (tenant, command["after"], command["limit"] + 1),
                ).fetchall()
            more, rows = len(rows) > command["limit"], rows[: command["limit"]]
            items = [{"cursor": row["rowid"], "callId": row["call_id"], "manifestId": row["manifest_id"]} for row in rows]
            return {"items": items, "nextCursor": items[-1]["cursor"] if more else None}
        row = self._row(tenant, command)
        manifest, raw, manifest_digest = self._manifest(row)
        if action == "manifest":
            return {"manifest": manifest, "manifestSha256": manifest_digest, "rawBase64": base64.b64encode(raw).decode("ascii")}
        if command["manifestSha256"] != manifest_digest:
            _error("RECORDING_MANIFEST_MISMATCH", 409)
        fd, size = self._wav(row, manifest)
        try:
            if command["offset"] > size:
                _error("INVALID_RECORDING_REQUEST", 400)
            os.lseek(fd, command["offset"], os.SEEK_SET)
            data = os.read(fd, min(command["length"], size - command["offset"]))
        finally:
            os.close(fd)
        return {"offset": command["offset"], "dataBase64": base64.b64encode(data).decode("ascii"), "sha256": manifest["sha256"], "sizeBytes": size, "eof": command["offset"] + len(data) == size}
