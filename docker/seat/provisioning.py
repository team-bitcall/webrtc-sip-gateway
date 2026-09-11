#!/usr/bin/env python3
"""Private, durable tenant projection; SIP workers only read local htables."""
import hashlib
import hmac
import fcntl
import http.server
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import stat
import sys
import threading
import time
import uuid

from compile_snapshot import (ID_RE, MAX_BYTES, SnapshotError, _atomic_write, _dns,
                              _no_duplicate_keys, snapshot_entries, validate_snapshot)


class ControlError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ControlError(503, "PRIVATE_STATE_REQUIRED")
    return path


def durable_state_directory(path, mountinfo=None):
    """Managed mode must survive container replacement, including revision history."""
    if not path or not os.path.isabs(path):
        raise ControlError(503, "DURABLE_STATE_REQUIRED")
    if mountinfo is None:
        mountinfo = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    target = os.path.normpath(path)
    for line in mountinfo.splitlines():
        fields, separator, filesystem = line.partition(" - ")
        parts = fields.split()
        if not separator or len(parts) < 5:
            continue
        mount = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), parts[4])
        if mount == target and filesystem.split()[0] not in ("overlay", "overlayfs", "tmpfs", "ramfs"):
            return private_directory(target)
    raise ControlError(503, "DURABLE_STATE_REQUIRED")


class KamailioRpc:
    """Owner-only Unix datagrams. Never shell arguments, HTTP RPC or secret logs."""
    def __init__(self, path="/run/kamailio/seat-rpc.sock"):
        self.path = path

    def call(self, method, *params):
        client_path = str(Path(self.path).parent / ("rpc-" + uuid.uuid4().hex))
        try:
            info = os.lstat(self.path)
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise OSError("private socket required")
            request_id = uuid.uuid4().hex
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
                client.settimeout(2)
                client.bind(client_path)
                os.chmod(client_path, 0o600)
                client.connect(self.path)
                client.send(canonical_json({"jsonrpc": "2.0", "id": request_id,
                                           "method": method, "params": list(params)}).encode())
                reply = json.loads(client.recv(16384))
            if reply.get("id") != request_id or "error" in reply:
                # Missing keys are the only expected RPC error. Other errors
                # (including failed writes) must never be acknowledged as applied.
                if method == "htable.get" and reply.get("error", {}).get("code") == 500 \
                        and reply["error"].get("message") == "Key name doesn't exist in htable.":
                    return None
                raise OSError("RPC operation failed")
            return reply.get("result")
        except (OSError, ValueError, TypeError) as error:
            raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE") from error
        finally:
            try:
                os.unlink(client_path)
            except FileNotFoundError:
                pass

    def get(self, table, key):
        result = self.call("htable.get", table, key)
        if result is None:
            return None
        # Kamailio htable.get returns a named item, not the secret-bearing table.
        if isinstance(result, dict) and isinstance(result.get("item"), dict):
            return result["item"].get("value")
        raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")

    def set(self, table, key, value):
        self.call("htable.seti" if type(value) is int else "htable.sets", table, key, value)


class TenantProjectionStore:
    """Persist accepted high-water first; switch one pointer only after staging.

    SQLite transactions protect concurrent writers; the process lock serializes
    htable staging/reconciliation. A crash can lose an acknowledgement, never the
    accepted revision. The same payload retries safely across either restart.
    """
    def __init__(self, directory, domain, rpc, clock=time.time):
        self.directory = private_directory(directory)
        self.domain = _dns(domain, "domain")
        self.rpc, self.clock = rpc, clock
        self.lock = threading.RLock()
        lock_fd = os.open(self.directory / "writer.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self.writer_lock = os.fdopen(lock_fd, "a")
        try:
            fcntl.flock(self.writer_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self.writer_lock.close()
            raise ControlError(503, "CONTROL_WRITER_ALREADY_RUNNING") from error
        path = self.directory / "state.sqlite3"
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ControlError(503, "PRIVATE_STATE_REQUIRED")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS tenants (
                tenant TEXT PRIMARY KEY, revision INTEGER NOT NULL,
                digest TEXT NOT NULL, payload TEXT NOT NULL,
                valid_until INTEGER NOT NULL, applied INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS usernames (
                username TEXT PRIMARY KEY, tenant TEXT NOT NULL, seat TEXT NOT NULL);
        """)

    def _validate(self, tenant, data, now):
        if not isinstance(tenant, str) or not ID_RE.fullmatch(tenant):
            raise ControlError(400, "INVALID_TENANT")
        if isinstance(data, dict) and type(data.get("validUntil")) is int and data["validUntil"] <= now:
            raise ControlError(409, "SNAPSHOT_EXPIRED")
        try:
            normalized = validate_snapshot(data, now)
            if normalized["domain"] != self.domain or any(
                item["tenantId"] != tenant for item in normalized["seats"] + normalized["profiles"]
            ):
                raise SnapshotError("invalid tenant scope")
            return normalized
        except (SnapshotError, UnicodeError, TypeError) as error:
            raise ControlError(400, "INVALID_SNAPSHOT") from error

    def _row(self, tenant):
        return self.db.execute("SELECT * FROM tenants WHERE tenant=?", (tenant,)).fetchone()

    def _active(self, row):
        prefix = "%s::%d::" % (row["tenant"], row["revision"])
        return (self.rpc.get("seat_meta", row["tenant"] + "::active") == str(row["revision"])
                and self.rpc.get("seat_meta", prefix + "ready") == row["digest"])

    def _stage(self, row, normalized):
        if not self._active(row):
            for table, key, value in snapshot_entries(normalized, row["tenant"]):
                self.rpc.set(table, key, value)
            if row["valid_until"] <= int(self.clock()):
                raise ControlError(409, "SNAPSHOT_EXPIRED")
            prefix = "%s::%d::" % (row["tenant"], row["revision"])
            self.rpc.set("seat_meta", prefix + "ready", row["digest"])
            self.rpc.set("seat_meta", row["tenant"] + "::active", str(row["revision"]))
            if not self._active(row):
                raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
        with self.db:
            self.db.execute("UPDATE tenants SET applied=1 WHERE tenant=? AND revision=? AND digest=?",
                            (row["tenant"], row["revision"], row["digest"]))

    def apply(self, tenant, data):
        now = int(self.clock())
        normalized = self._validate(tenant, data, now)
        payload = canonical_json(data)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        with self.lock:
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                existing = self._row(tenant)
                if existing and (normalized["revision"] < existing["revision"]
                                 or (normalized["revision"] == existing["revision"] and digest != existing["digest"])):
                    raise ControlError(409, "REVISION_CONFLICT")
                for seat in normalized["seats"]:
                    owner = self.db.execute("SELECT tenant, seat FROM usernames WHERE username=?",
                                            (seat["username"],)).fetchone()
                    if owner and (owner["tenant"] != tenant or owner["seat"] != seat["id"]):
                        raise ControlError(409, "SEAT_IDENTITY_CONFLICT")
                    self.db.execute("INSERT OR IGNORE INTO usernames VALUES (?,?,?)",
                                    (seat["username"], tenant, seat["id"]))
                if not existing or normalized["revision"] > existing["revision"]:
                    self.db.execute("INSERT INTO tenants VALUES (?,?,?,?,?,0) ON CONFLICT(tenant) DO UPDATE SET "
                                    "revision=excluded.revision,digest=excluded.digest,payload=excluded.payload,"
                                    "valid_until=excluded.valid_until,applied=0",
                                    (tenant, normalized["revision"], digest, payload, normalized["validUntil"]))
            row = self._row(tenant)
            self._stage(row, normalized)
            return self._public(row, "applied")

    @staticmethod
    def _public(row, status):
        return {"status": status, "tenantId": row["tenant"], "revision": row["revision"],
                "contentSha256": row["digest"], "validUntil": row["valid_until"]}

    def status(self, tenant):
        with self.lock:
            row = self._row(tenant)
            if not row:
                raise ControlError(404, "TENANT_NOT_PROVISIONED")
            status = "expired" if row["valid_until"] <= int(self.clock()) else (
                "applied" if self._active(row) else "pending")
            return self._public(row, status)

    def reconcile(self):
        with self.lock:
            rows = self.db.execute("SELECT * FROM tenants WHERE valid_until>?", (int(self.clock()),)).fetchall()
            for row in rows:
                normalized = self._validate(row["tenant"], json.loads(row["payload"]), int(self.clock()))
                self._stage(row, normalized)

    def close(self):
        self.db.close()
        self.writer_lock.close()


class ControlHandler(http.server.BaseHTTPRequestHandler):
    server_version = "BitcallControl"

    def log_message(self, *_args):
        pass  # HTTP requests may carry credentials; logging is aggregate-only.

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def _reply(self, code, value):
        body = canonical_json(value).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self):
        if self.headers.get("Origin") is not None:
            raise ControlError(403, "SERVER_CLIENT_REQUIRED")
        if len(self.headers.get_all("Authorization", [])) != 1 or not hmac.compare_digest(
            self.headers.get("Authorization", "").encode(), ("Bearer " + self.server.token).encode()
        ):
            raise ControlError(401, "UNAUTHORIZED")
        match = re.fullmatch(r"/v1/tenants/([A-Za-z0-9._-]{1,128})/(snapshot|status)", self.path)
        if not match:
            raise ControlError(404, "NOT_FOUND")
        tenant, action = match.groups()
        if self.command == "GET" and action == "status":
            return self.server.store.status(tenant)
        if self.command != "POST" or action != "snapshot":
            raise ControlError(405, "METHOD_NOT_ALLOWED")
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") is not None or len(lengths) != 1 \
                or not re.fullmatch(r"[0-9]{1,8}", lengths[0]):
            raise ControlError(400, "INVALID_LENGTH")
        length = int(lengths[0])
        if length < 2 or length > MAX_BYTES:
            raise ControlError(413, "SNAPSHOT_TOO_LARGE")
        if self.headers.get_content_type() != "application/json":
            raise ControlError(415, "JSON_REQUIRED")
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("short body")
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
            return self.server.store.apply(tenant, data)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise ControlError(400, "INVALID_SNAPSHOT") from error

    def _handle(self):
        try:
            self._reply(200, self._dispatch())
        except ControlError as error:
            self._reply(error.status, {"error": {"code": error.code}})
        except (OSError, sqlite3.Error):
            self._reply(503, {"error": {"code": "CONTROL_UNAVAILABLE"}})

    do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = _handle


def main():
    if os.environ.get("SEAT_MODE") != "managed":
        return 0
    os.umask(0o077)
    token = os.environ.get("SEAT_CONTROL_TOKEN", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", token):
        raise ControlError(503, "CONTROL_TOKEN_REQUIRED")
    host = os.environ.get("SEAT_CONTROL_BIND", "127.0.0.1")
    tls_cert, tls_key = os.environ.get("SEAT_CONTROL_TLS_CERT"), os.environ.get("SEAT_CONTROL_TLS_KEY")
    if host != "127.0.0.1" and not (tls_cert and tls_key):
        raise ControlError(503, "CONTROL_TLS_REQUIRED")
    directory = durable_state_directory(os.environ.get("SEAT_STATE_DIR"))
    if sys.argv[1:] == ["--init"]:
        _dns(os.environ.get("SEAT_DOMAIN", ""), "domain")
        # Kamailio 5.7 rejects an empty event-route body.  Managed mode starts
        # without authority, so keep the hook syntactically non-empty while the
        # control service restores accepted generations through private RPC.
        _atomic_write("/run/kamailio/seat-snapshot.cfg",
                      "event_route[htable:mod-init] {\n  return;\n}\n")
        return 0
    store = TenantProjectionStore(directory,
                                  os.environ.get("SEAT_DOMAIN", ""), KamailioRpc())
    server = http.server.HTTPServer((host, int(os.environ.get("SEAT_CONTROL_PORT", "8881"))), ControlHandler)
    server.store, server.token = store, token
    if tls_cert and tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(tls_cert, tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    stopped = threading.Event()

    def reconcile():
        while not stopped.is_set():
            try:
                store.reconcile()
            except (ControlError, sqlite3.Error):
                pass  # Leases expire in the SIP path even if this helper is down.
            stopped.wait(2)

    worker = threading.Thread(target=reconcile, daemon=True)
    worker.start()
    try:
        server.serve_forever()
    finally:
        stopped.set()
        worker.join(3)
        server.server_close()
        store.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ControlError, SnapshotError, OSError, ValueError):
        print("seat-control: startup unavailable; verify private configuration", file=sys.stderr)
        raise SystemExit(1)
