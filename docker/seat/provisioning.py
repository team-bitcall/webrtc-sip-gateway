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
import urllib.parse
import uuid

from call_journal import CallJournal, JournalError
from compile_snapshot import (ID_RE, MAX_BYTES, SnapshotError, USER_RE, _atomic_write, _dns,
                              _no_duplicate_keys, snapshot_entries, validate_snapshot)
from media_control import MediaController, MediaError


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

    @staticmethod
    def _receive_reply(client, inventory):
        """Receive a normal RPC response or one complete dialog inventory."""
        if not inventory:
            return client.recv(16384)
        reply, _ancillary, flags, _address = client.recvmsg(1024 * 1024)
        if flags & socket.MSG_TRUNC:
            raise OSError("truncated private RPC inventory")
        return reply

    def call(self, method, *params, inventory=False):
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
                reply = json.loads(self._receive_reply(client, inventory))
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

    def active_cdr_ids(self):
        """Read only the CDR IDs from a complete private dialog inventory."""
        result = self.call("dlg.list_ctx", inventory=True)
        # dialog:dlg.list_ctx is RPC_RET_ARRAY.  Every dialog's context is
        # printed as a ``variables`` array of one-key objects.
        if not isinstance(result, list):
            raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
        ids = set()
        for dialog in result:
            if not isinstance(dialog, dict) or not isinstance(dialog.get("variables"), list):
                raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
            for variable in dialog["variables"]:
                if not isinstance(variable, dict):
                    raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
                if "seat_cdr_id" not in variable:
                    continue
                value = variable["seat_cdr_id"]
                if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
                    raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
                ids.add(value)
        return ids

    @staticmethod
    def _tcp_connection_ids(value):
        if not isinstance(value, list):
            raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
        ids = set()
        for connection in value:
            if not isinstance(connection, dict) or type(connection.get("id")) is not int \
                    or connection["id"] <= 0 or not isinstance(connection.get("type"), str) \
                    or not isinstance(connection.get("state"), str):
                raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
            if connection["type"] in ("WS", "WSS") and connection["state"] in ("CONN_OK", "CONN_ACCEPT"):
                ids.add(connection["id"])
        return ids

    @staticmethod
    def _seat_contacts(value, domain, usernames, live_connection_ids):
        """Return only countable WSS connection IDs; discard raw registrar data."""
        if not isinstance(value, dict) or set(value) != {"Domains"} \
                or not isinstance(value["Domains"], list):
            raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
        counts = {seat_id: set() for seat_id in usernames.values()}
        expected_aors = {username: {username, username + "@" + domain}
                         for username in usernames}
        for wrapper in value["Domains"]:
            item = wrapper.get("Domain") if isinstance(wrapper, dict) and set(wrapper) == {"Domain"} else None
            if not isinstance(item, dict) or not isinstance(item.get("Domain"), str) \
                    or not isinstance(item.get("AoRs"), list):
                raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
            if item["Domain"] != "seat_location":
                continue
            for aor_entry in item["AoRs"]:
                info = aor_entry.get("Info") if isinstance(aor_entry, dict) else None
                if not isinstance(info, dict) or not isinstance(info.get("AoR"), str) \
                        or not isinstance(info.get("Contacts"), list):
                    raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
                username = next((name for name, aors in expected_aors.items()
                                 if info["AoR"] in aors), None)
                for contact_entry in info["Contacts"]:
                    contact = contact_entry.get("Contact") if isinstance(contact_entry, dict) else None
                    if not isinstance(contact, dict):
                        raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
                    if username is None:
                        continue
                    connection_id, expires, address = (contact.get("Tcpconn-Id"),
                                                       contact.get("Expires"), contact.get("Address"))
                    if type(connection_id) is not int or not isinstance(address, str) \
                            or not (type(expires) is int or expires in ("permanent", "expired", "deleted")):
                        raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
                    if (expires == "permanent" or type(expires) is int and expires > 0) \
                            and connection_id in live_connection_ids \
                            and re.search(r";transport=ws(?:[;>]|$)", address, re.I):
                        counts[usernames[username]].add(connection_id)
        return [{"seatId": seat_id, "connections": len(counts[seat_id])}
                for seat_id in sorted(counts)]

    @staticmethod
    def _seat_dialogs(value, tenant):
        if not isinstance(value, list):
            raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
        dialogs = []
        for dialog in value:
            if not isinstance(dialog, dict) or type(dialog.get("state")) is not int \
                    or dialog["state"] not in (1, 2, 3, 4, 5):
                raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
            if dialog["state"] == 5:
                continue
            if not isinstance(dialog.get("variables"), list):
                raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
            variables = {}
            for variable in dialog["variables"]:
                if not isinstance(variable, dict) or len(variable) != 1:
                    raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
                key, item = next(iter(variable.items()))
                if key in ("seat_tenant", "seat_id", "seat_cdr_id"):
                    if key in variables:
                        raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
                    variables[key] = item
            if "seat_tenant" in variables and not isinstance(variables["seat_tenant"], str):
                raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
            if variables.get("seat_tenant") != tenant:
                continue
            call_id, seat_id = variables.get("seat_cdr_id"), variables.get("seat_id")
            if not isinstance(call_id, str) or not re.fullmatch(r"[0-9a-f]{32}", call_id) \
                    or not isinstance(seat_id, str) or not ID_RE.fullmatch(seat_id):
                raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
            dialogs.append({"callId": call_id, "seatId": seat_id,
                            "state": "confirmed" if dialog["state"] >= 3 else "early"})
        unique = {}
        for dialog in dialogs:
            previous = unique.get(dialog["callId"])
            if previous is not None and previous["seatId"] != dialog["seatId"]:
                raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
            if previous is None or dialog["state"] == "confirmed":
                unique[dialog["callId"]] = dialog
        if len(unique) > 1000:
            raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
        return sorted(unique.values(), key=lambda item: item["callId"])

    def presence(self, tenant, domain, usernames):
        if not isinstance(usernames, dict) or len(usernames) > 100 \
                or any(not USER_RE.fullmatch(user) or not ID_RE.fullmatch(seat)
                       for user, seat in usernames.items()):
            raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
        contacts = self.call("ul.dump", inventory=True)
        connections = self.call("core.tcp_list", inventory=True)
        dialogs = self.call("dlg.list_ctx", inventory=True)
        registrations = self._seat_contacts(contacts, domain, usernames,
                                             self._tcp_connection_ids(connections))
        if sum(item["connections"] for item in registrations) > 1000:
            raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
        return {"registrations": registrations,
                "dialogs": self._seat_dialogs(dialogs, tenant)}


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

    @staticmethod
    def _presence_rows(value):
        if not isinstance(value, dict) or set(value) != {"registrations", "dialogs"} \
                or not isinstance(value["registrations"], list) or not isinstance(value["dialogs"], list) \
                or len(value["registrations"]) > 100 or len(value["dialogs"]) > 1000:
            raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
        registrations, dialogs = value["registrations"], value["dialogs"]
        if any(not isinstance(row, dict) or set(row) != {"seatId", "connections"}
               or not isinstance(row["seatId"], str) or not re.fullmatch(r"s_[0-9a-f]{64}", row["seatId"])
               or type(row["connections"]) is not int or not 0 <= row["connections"] <= 1000
               for row in registrations) or len({row["seatId"] for row in registrations}) != len(registrations):
            raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
        if any(not isinstance(row, dict) or set(row) != {"callId", "seatId", "state"}
               or not isinstance(row["callId"], str) or not re.fullmatch(r"[0-9a-f]{32}", row["callId"])
               or not isinstance(row["seatId"], str) or not re.fullmatch(r"s_[0-9a-f]{64}", row["seatId"])
               or row["state"] not in ("early", "confirmed") for row in dialogs) \
                or len({row["callId"] for row in dialogs}) != len(dialogs):
            raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
        return registrations, dialogs

    def presence(self, tenant, control_boot_id):
        with self.lock:
            row = self._row(tenant)
            if not row:
                raise ControlError(404, "TENANT_NOT_PROVISIONED")
            status = "expired" if row["valid_until"] <= int(self.clock()) else (
                "applied" if self._active(row) else "pending")
            try:
                payload = json.loads(row["payload"])
                seats = payload["seats"]
                usernames = {seat["username"]: seat["id"] for seat in seats}
            except (KeyError, TypeError, ValueError) as error:
                raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE") from error
            if not isinstance(seats, list) or len(seats) > 100 or len(usernames) != len(seats):
                raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
            registrations, dialogs = self._presence_rows(self.rpc.presence(tenant, self.domain, usernames))
            observed_at = int(self.clock() * 1000)
            if type(row["revision"]) is not int or row["revision"] < 1 or observed_at < 1 \
                    or not isinstance(control_boot_id, str) or not re.fullmatch(
                        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", control_boot_id):
                raise ControlError(503, "GATEWAY_STATE_UNAVAILABLE")
            return {"schemaVersion": 1, "tenantId": tenant,
                    "observedAtMs": observed_at,
                    "controlBootId": control_boot_id, "policyRevision": row["revision"],
                    "projectionStatus": status, "registrations": registrations,
                    "dialogs": dialogs}

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
        path, _, query = self.path.partition("?")
        if path == "/v1/call-events/health" and self.command == "GET":
            if self.server.journal is None: raise ControlError(404, "NOT_FOUND")
            return self.server.journal.health()
        match = re.fullmatch(r"/v1/tenants/(t_[0-9a-f]{64})/media", path)
        if match:
            if self.server.media is None: raise ControlError(404, "NOT_FOUND")
            if self.command != "POST" or query:
                raise ControlError(405, "METHOD_NOT_ALLOWED")
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") is not None or self.headers.get_content_type() != "application/json" \
                    or len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,5}", lengths[0]):
                raise ControlError(400, "INVALID_MEDIA_REQUEST")
            try:
                length = int(lengths[0])
                if not 2 <= length <= 49152:
                    raise ValueError("invalid media length")
                body = json.loads(self.rfile.read(length).decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
                return self.server.media.handle(match.group(1), body)
            except MediaError as error:
                raise ControlError(error.status, error.code) from error
            except (ValueError, UnicodeError, RecursionError) as error:
                raise ControlError(400, "INVALID_MEDIA_REQUEST") from error
        match = re.fullmatch(r"/v1/tenants/(t_[0-9a-f]{64})/presence", path)
        if match:
            if self.command != "GET":
                raise ControlError(405, "METHOD_NOT_ALLOWED")
            if query:
                raise ControlError(400, "INVALID_PRESENCE")
            return self.server.store.presence(match.group(1), self.server.control_boot_id)
        match = re.fullmatch(r"/v1/tenants/(t_[0-9a-f]{64})/call-events", path)
        if match and self.command == "GET":
            if self.server.journal is None: raise ControlError(404, "NOT_FOUND")
            try:
                values = urllib.parse.parse_qs(query, strict_parsing=True)
                if set(values) - {"after", "limit"} or len(values.get("after", [""])) > 1 or len(values.get("limit", [""])) > 1:
                    raise ValueError("duplicate or unknown query")
                after = int(values.get("after", ["0"])[0])
                limit = int(values.get("limit", ["100"])[0])
            except ValueError as error:
                raise ControlError(400, "INVALID_CALL_EVENT") from error
            if len(values.get("after", [""])) > 1 or len(values.get("limit", [""])) > 1:
                raise ControlError(400, "INVALID_CALL_EVENT")
            return self.server.journal.events(match.group(1), after, limit)
        match = re.fullmatch(r"/v1/tenants/(t_[0-9a-f]{64})/call-events/ack", path)
        if match and self.command == "POST":
            if self.server.journal is None: raise ControlError(404, "NOT_FOUND")
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") is not None or self.headers.get_content_type() != "application/json" \
                    or len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,4}", lengths[0]):
                raise ControlError(400, "INVALID_CALL_EVENT")
            try:
                length = int(lengths[0])
                if length < 2 or length > 1024: raise ValueError("invalid ack length")
                body = json.loads(self.rfile.read(length).decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
                if not isinstance(body, dict) or set(body) != {"throughSequence"}:
                    raise ValueError("invalid ack")
                return self.server.journal.acknowledge(match.group(1), body["throughSequence"])
            except (ValueError, UnicodeError, JournalError) as error:
                if isinstance(error, JournalError): raise ControlError(error.status, error.code)
                raise ControlError(400, "INVALID_CALL_EVENT") from error
        match = re.fullmatch(r"/v1/tenants/([A-Za-z0-9._-]{1,128})/(snapshot|status)", path)
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
        except JournalError as error:
            self._reply(error.status, {"error": {"code": error.code}})
        except (OSError, sqlite3.Error):
            self._reply(503, {"error": {"code": "CONTROL_UNAVAILABLE"}})

    do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = _handle


class JournalHandler(http.server.BaseHTTPRequestHandler):
    """Separate loopback-only append surface used by Kamailio, never externally exposed."""
    server_version = "BitcallJournal"
    def log_message(self, *_args):
        pass
    def _reply(self, status, value):
        body = canonical_json(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        try:
            if len(self.headers.get_all("Authorization", [])) != 1 or not hmac.compare_digest(
                    self.headers.get("Authorization", "").encode(), ("Bearer " + self.server.token).encode()):
                raise ControlError(401, "UNAUTHORIZED")
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") is not None or len(lengths) != 1:
                raise ControlError(400, "INVALID_CALL_EVENT")
            if self.headers.get_content_type() != "application/json":
                raise ControlError(415, "JSON_REQUIRED")
            length = int(lengths[0])
            if not 2 <= length <= 4096:
                raise ControlError(400, "INVALID_CALL_EVENT")
            body = json.loads(self.rfile.read(length).decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
            if self.path == "/v1/call-events/admit":
                _context, call_id = self.server.journal.admit(body)
                result = {"schemaVersion": 1, "callId": call_id}
            elif self.path == "/v1/call-events/append":
                result = self.server.journal.append(body)
            else:
                raise ControlError(404, "NOT_FOUND")
            self._reply(200, result)
        except JournalError as error:
            self._reply(error.status, {"error": {"code": error.code}})
        except ControlError as error:
            self._reply(error.status, {"error": {"code": error.code}})
        except (ValueError, UnicodeError):
            self._reply(400, {"error": {"code": "INVALID_CALL_EVENT"}})
        except (OSError, sqlite3.Error):
            self._reply(503, {"error": {"code": "CONTROL_UNAVAILABLE"}})


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
    events_enabled = os.environ.get("SEAT_CALL_EVENTS") == "1"
    journal = CallJournal(directory) if events_enabled else None
    media_enabled = os.environ.get("SEAT_MEDIA_ENABLED") == "1"
    if media_enabled and journal is None:
        raise ControlError(503, "MEDIA_UNAVAILABLE")
    media = None
    if media_enabled:
        maximum = int(os.environ.get("SEAT_MEDIA_MAX_LISTENERS", "1"))
        maximum_tenant = int(os.environ.get("SEAT_MEDIA_MAX_TENANT_SESSIONS", "100"))
        maximum_total = int(os.environ.get("SEAT_MEDIA_MAX_TOTAL_SESSIONS", "1000"))
        media = MediaController(directory, journal, store.rpc, maximum=maximum,
                                maximum_tenant=maximum_tenant, maximum_total=maximum_total,
                                projection=store.status)
    server = http.server.HTTPServer((host, int(os.environ.get("SEAT_CONTROL_PORT", "8881"))), ControlHandler)
    server.store, server.journal, server.media, server.token = store, journal, media, token
    server.control_boot_id = str(uuid.uuid4())
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
                pass
            if journal:
                try:
                    # Never infer a terminal event from helper restart or RPC
                    # failure. Only a complete private dialog inventory is used.
                    journal.reconcile_active(store.rpc.active_cdr_ids())
                    journal.compact()
                except (ControlError, JournalError, sqlite3.Error):
                    pass
            if media:
                try:
                    media.sweep()
                except (MediaError, sqlite3.Error):
                    pass
            stopped.wait(2)

    worker = threading.Thread(target=reconcile, daemon=True)
    worker.start()
    journal_server = journal_worker = None
    if journal:
        journal_server = http.server.ThreadingHTTPServer(("127.0.0.1", 8882), JournalHandler)
        journal_server.journal, journal_server.token = journal, token
        journal_worker = threading.Thread(target=journal_server.serve_forever, daemon=True)
        journal_worker.start()
    try:
        server.serve_forever()
    finally:
        stopped.set()
        worker.join(3)
        if journal_server:
            journal_server.shutdown(); journal_worker.join(3); journal_server.server_close()
        server.server_close()
        store.close()
        if journal: journal.close()
        if media: media.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ControlError, SnapshotError, OSError, ValueError):
        print("seat-control: startup unavailable; verify private configuration", file=sys.stderr)
        raise SystemExit(1)
