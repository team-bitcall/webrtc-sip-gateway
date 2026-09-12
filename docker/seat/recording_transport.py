"""Bounded private Unix transport for the recording worker."""

import json
import errno
import os
from pathlib import Path
import re
import socket
import stat
import time

MAX_FRAME_BYTES = 8192
MAX_REPLY_BYTES = 131072
SOCKET_NAME = "recording-capture.sock"
SAFE_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


class RecordingTransportError(Exception):
    """A safe error returned by the local recording transport."""

    def __init__(self, code="RECORDING_UNAVAILABLE", status=503):
        self.code = code
        self.status = status
        super().__init__(code)


def private_directory(directory):
    """Return an existing owner-only directory, or fail closed."""
    path = Path(directory)
    try:
        info = path.lstat()
    except OSError as error:
        raise RecordingTransportError() from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RecordingTransportError("PRIVATE_STORAGE_REQUIRED")
    return path.resolve(strict=True)


def socket_path(directory):
    """Return the fixed private recording socket path."""
    return private_directory(directory) / SOCKET_NAME


def _private_socket(path):
    try:
        info = path.lstat()
    except OSError as error:
        raise RecordingTransportError() from error
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise RecordingTransportError("PRIVATE_STORAGE_REQUIRED")
    return info


def _encode(value, maximum=MAX_FRAME_BYTES):
    try:
        data = (
            json.dumps(
                value, separators=(",", ":"), ensure_ascii=True, allow_nan=False
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError) as error:
        raise RecordingTransportError("INVALID_RECORDING_REQUEST", 400) from error
    if len(data) > maximum:
        raise RecordingTransportError("INVALID_RECORDING_REQUEST", 400)
    return data


def _decode(data, maximum=MAX_FRAME_BYTES):
    if not data.endswith(b"\n") or len(data) > maximum:
        raise RecordingTransportError("INVALID_RECORDING_REQUEST", 400)
    try:

        def unique_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate JSON key")
                value[key] = item
            return value

        value = json.loads(
            data[:-1].decode("utf-8", "strict"),
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON value")
            ),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RecordingTransportError("INVALID_RECORDING_REQUEST", 400) from error
    if not isinstance(value, dict):
        raise RecordingTransportError("INVALID_RECORDING_REQUEST", 400)
    return value


def _error_response(error):
    """Map an exception to a bounded public error without exposing its text."""
    code = getattr(error, "code", "RECORDING_UNAVAILABLE")
    status = getattr(error, "status", 503)
    if (
        not isinstance(code, str)
        or not SAFE_ERROR_CODE.fullmatch(code)
        or type(status) is not int
        or not 400 <= status <= 599
    ):
        code, status = "RECORDING_UNAVAILABLE", 503
    return {"error": {"code": code, "status": status}}


def forward_recording(directory, tenant, request):
    """Forward one bounded envelope to the owner-only recording worker."""
    if not isinstance(tenant, str) or not isinstance(request, dict):
        raise RecordingTransportError("INVALID_RECORDING_REQUEST", 400)
    path = socket_path(directory)
    _private_socket(path)
    payload = _encode({"tenantId": tenant, "request": request})
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            deadline = time.monotonic() + 5
            client.settimeout(max(0.001, deadline - time.monotonic()))
            client.connect(str(path))
            client.settimeout(max(0.001, deadline - time.monotonic()))
            client.sendall(payload)
            reply = bytearray()
            while len(reply) <= MAX_REPLY_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("recording reply deadline exceeded")
                client.settimeout(remaining)
                chunk = client.recv(min(4096, MAX_REPLY_BYTES + 1 - len(reply)))
                if not chunk:
                    break
                reply.extend(chunk)
                if b"\n" in chunk:
                    break
    except (OSError, TimeoutError) as error:
        raise RecordingTransportError() from error
    value = _decode(bytes(reply), MAX_REPLY_BYTES)
    if set(value) == {"result"}:
        return value["result"]
    error = value.get("error")
    if (
        set(value) != {"error"}
        or not isinstance(error, dict)
        or set(error) != {"code", "status"}
        or not isinstance(error["code"], str)
        or not SAFE_ERROR_CODE.fullmatch(error["code"])
        or type(error["status"]) is not int
        or not 400 <= error["status"] <= 599
    ):
        raise RecordingTransportError()
    raise RecordingTransportError(error["code"], error["status"])


class RecordingTransportServer:
    """One-request-at-a-time Unix server owned by the capture worker."""

    def __init__(self, directory, dispatch):
        self.directory = private_directory(directory)
        self.path = self.directory / SOCKET_NAME
        self.dispatch = dispatch
        self.listener = None
        self.identity = None

    def open(self):
        """Bind the fixed socket after the caller has acquired controller ownership."""
        if self.listener is not None:
            return
        if self.path.exists() or self.path.is_symlink():
            stale = _private_socket(self.path)
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(0.2)
                probe.connect(str(self.path))
            except OSError as error:
                if error.errno not in {errno.ECONNREFUSED, errno.ENOENT}:
                    raise RecordingTransportError(
                        "RECORDING_ALREADY_RUNNING"
                    ) from error
            else:
                raise RecordingTransportError("RECORDING_ALREADY_RUNNING")
            finally:
                probe.close()
            if self.path.exists() or self.path.is_symlink():
                current = _private_socket(self.path)
                if (current.st_dev, current.st_ino) != (stale.st_dev, stale.st_ino):
                    raise RecordingTransportError("RECORDING_ALREADY_RUNNING")
                os.unlink(self.path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        created = None
        try:
            listener.bind(str(self.path))
            created = self.path.lstat()
            os.chmod(self.path, 0o600)
            self.identity = _private_socket(self.path)
            listener.listen(8)
            listener.settimeout(0.2)
            self.listener = listener
        except Exception:
            listener.close()
            if created is not None:
                try:
                    current = self.path.lstat()
                    if (current.st_dev, current.st_ino) == (
                        created.st_dev,
                        created.st_ino,
                    ):
                        os.unlink(self.path)
                except FileNotFoundError:
                    pass
            raise

    def close(self):
        """Close and unlink only the exact socket this instance created."""
        if self.listener is not None:
            self.listener.close()
            self.listener = None
        if self.identity is not None:
            try:
                current = _private_socket(self.path)
                if (current.st_dev, current.st_ino) == (
                    self.identity.st_dev,
                    self.identity.st_ino,
                ):
                    os.unlink(self.path)
            except (FileNotFoundError, RecordingTransportError):
                pass
            self.identity = None

    def serve_once(self):
        """Serve at most one client and bound it to a two-second request deadline."""
        if self.listener is None:
            raise RuntimeError("server is not open")
        try:
            client, _address = self.listener.accept()
        except socket.timeout:
            return False
        with client:
            deadline = time.monotonic() + 2
            payload = bytearray()
            try:
                while len(payload) <= MAX_FRAME_BYTES:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("recording request deadline exceeded")
                    client.settimeout(remaining)
                    chunk = client.recv(min(4096, MAX_FRAME_BYTES + 1 - len(payload)))
                    if not chunk:
                        break
                    payload.extend(chunk)
                    if b"\n" in chunk:
                        break
                frame = _decode(bytes(payload))
                if (
                    set(frame) != {"tenantId", "request"}
                    or not isinstance(frame["tenantId"], str)
                    or not isinstance(frame["request"], dict)
                ):
                    raise RecordingTransportError("INVALID_RECORDING_REQUEST", 400)
                result = self.dispatch(frame["tenantId"], frame["request"])
                response = {"result": result}
            except RecordingTransportError as error:
                response = _error_response(error)
            except Exception as error:
                response = _error_response(error)
            try:
                try:
                    encoded = _encode(response, MAX_REPLY_BYTES)
                except RecordingTransportError:
                    encoded = _encode(_error_response(Exception()))
                client.sendall(encoded)
            except OSError:
                pass
        return True
