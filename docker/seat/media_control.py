"""Private, leased RTPengine listen-only subscriptions for managed seat calls."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import select
import secrets
import socket
import sqlite3
import stat
import threading
import time


HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX_ACTOR = re.compile(r"[0-9a-f]{32}(?:[0-9a-f]{32})?\Z")
TENANT = re.compile(r"t_[0-9a-f]{64}\Z")
TAG = re.compile(r"[A-Za-z0-9._!%*+`'~()<>:/?{}\-]{1,128}\Z")


class MediaError(Exception):
    def __init__(self, code, status=503):
        self.code, self.status = code, status
        super().__init__(code)


def _json(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()


class NgClient:
    """Bounded local RTPengine NG client; never emits request or response bodies."""
    def __init__(self, host="127.0.0.1", port=2223, timeout=2):
        self.address, self.timeout = (host, port), timeout
        if not 0 < timeout <= 2:
            raise ValueError("invalid NG timeout")

    def request(self, value):
        if not isinstance(value, dict):
            raise MediaError("MEDIA_UNAVAILABLE")
        cookie = secrets.token_hex(12).encode("ascii")
        body = _json(value)
        if len(cookie) + len(body) + 1 > 65507:
            raise MediaError("MEDIA_UNAVAILABLE")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.connect(self.address)
            client.send(cookie + b" " + body)
            deadline = time.monotonic() + self.timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MediaError("MEDIA_UNAVAILABLE")
                readable, _, _ = select.select([client], [], [], remaining)
                if not readable:
                    raise MediaError("MEDIA_UNAVAILABLE")
                raw = client.recv(65535)
                try:
                    returned, reply_body = raw.split(b" ", 1)
                    reply = json.loads(reply_body)
                except (ValueError, UnicodeError, json.JSONDecodeError) as error:
                    raise MediaError("MEDIA_UNAVAILABLE") from error
                if returned != cookie:
                    continue
                if not isinstance(reply, dict):
                    raise MediaError("MEDIA_UNAVAILABLE")
                return reply


class MediaController:
    """Durable lease state with bounded listener tags per still-live source call.

    RTPengine retains an unsubscribed participant until source call teardown;
    the per-call bound prevents repeated monitor toggles exhausting that pool.
    """
    def __init__(self, directory, journal, rpc, *, clock=lambda: int(time.time() * 1000), ng=None,
                 maximum=1, maximum_tenant=100, maximum_total=1000, projection=None):
        if journal is None or not 1 <= maximum <= 5:
            raise MediaError("MEDIA_UNAVAILABLE")
        self.journal, self.rpc, self.clock = journal, rpc, clock
        if not 1 <= maximum_tenant <= maximum_total <= 10000 or projection is None:
            raise MediaError("MEDIA_UNAVAILABLE")
        self.ng, self.maximum, self.lock = ng or NgClient(), maximum, threading.RLock()
        self.maximum_tenant, self.maximum_total, self.projection = maximum_tenant, maximum_total, projection
        self.recovered = False
        directory = Path(directory)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise MediaError("MEDIA_UNAVAILABLE")
        path = directory / "media-control.sqlite3"
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise MediaError("MEDIA_UNAVAILABLE")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS sessions (
          tenant_id TEXT NOT NULL, call_id TEXT NOT NULL, listener_id TEXT NOT NULL,
          actor_id TEXT NOT NULL, listener_tag TEXT NOT NULL, sip_call_id TEXT NOT NULL,
          source_tags TEXT NOT NULL, state TEXT NOT NULL, fence INTEGER NOT NULL,
          expires_at INTEGER NOT NULL, offer_sdp TEXT, answer_hash TEXT, updated_at INTEGER NOT NULL,
          PRIMARY KEY (tenant_id, listener_id))""")
        self.db.execute("CREATE INDEX IF NOT EXISTS media_call_state ON sessions(tenant_id,call_id,state)")

    def close(self):
        self.db.close()

    @staticmethod
    def _identity(tenant, value, action):
        fields = {"action", "callId", "listenerId", "actorId"}
        expected = {
            "start": fields | {"leaseSeconds"},
            "answer": fields | {"fence", "sdp"},
            "renew": fields | {"fence", "leaseSeconds"},
            "stop": fields | {"fence"},
            "status": fields,
        }
        if not isinstance(value, dict) or value.get("action") not in expected or set(value) != expected[value["action"]]:
            raise MediaError("INVALID_MEDIA_REQUEST", 400)
        if not TENANT.fullmatch(tenant) or not all(isinstance(value[key], str) for key in ("callId", "listenerId", "actorId")) \
                or not HEX32.fullmatch(value["callId"]) or not HEX32.fullmatch(value["listenerId"]) \
                or not HEX_ACTOR.fullmatch(value["actorId"]):
            raise MediaError("INVALID_MEDIA_REQUEST", 400)
        if "leaseSeconds" in value and (type(value["leaseSeconds"]) is not int or not 15 <= value["leaseSeconds"] <= 30):
            raise MediaError("INVALID_MEDIA_REQUEST", 400)
        if "fence" in value and (type(value["fence"]) is not int or value["fence"] < 1):
            raise MediaError("INVALID_MEDIA_REQUEST", 400)
        if "sdp" in value and (not isinstance(value["sdp"], str) or not 1 <= len(value["sdp"]) <= 32768
                              or any(ord(char) < 9 or ord(char) == 127 for char in value["sdp"])
                              or not value["sdp"].startswith("v=0") or "m=audio " not in value["sdp"]):
            raise MediaError("INVALID_MEDIA_REQUEST", 400)
        return value

    @staticmethod
    def _offer_sdp(value):
        return isinstance(value, str) and 1 <= len(value) <= 32768 and value.startswith("v=0") \
            and value.count("m=audio ") == 2 and value.count("a=sendonly") == 2 \
            and "a=sendrecv" not in value and "a=recvonly" not in value \
            and "m=application " not in value and "m=video " not in value

    @staticmethod
    def _answer_sdp(value):
        return value.count("m=audio ") == 2 and value.count("a=recvonly") == 2 \
            and all(marker not in value for marker in ("a=sendonly", "a=sendrecv", "m=application ", "m=video "))

    @staticmethod
    def _listener_tag(call_id, listener_id, fence):
        """A new listener incarnation cannot share a cleanup target with an old one."""
        return hashlib.sha256((call_id + ":" + listener_id + ":" + str(fence)).encode("ascii")).hexdigest()

    @staticmethod
    def _answer_hash(sdp):
        return hashlib.sha256(sdp.encode("utf-8")).hexdigest()

    def _call(self, tenant, call_id):
        """Resolve all RTPengine identifiers only from durable, trusted evidence."""
        try:
            projection = self.projection(tenant)
        except Exception as error:
            raise MediaError("MEDIA_UNAVAILABLE") from error
        if not isinstance(projection, dict) or projection.get("status") != "applied" \
                or type(projection.get("validUntil")) is not int \
                or projection["validUntil"] * 1000 <= self.clock():
            raise MediaError("MEDIA_UNAVAILABLE")
        with self.journal.lock:
            row = self.journal.db.execute("SELECT context, terminal FROM calls WHERE call_id=? AND tenant_id=?",
                                          (call_id, tenant)).fetchone()
            if not row or row["terminal"]:
                raise MediaError("MEDIA_UNAVAILABLE")
            try:
                context = json.loads(row["context"])
                events = [json.loads(item["payload"]) for item in self.journal.db.execute(
                    "SELECT payload FROM events WHERE call_id=? ORDER BY sequence", (call_id,))]
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                raise MediaError("MEDIA_UNAVAILABLE") from error
        answers = {event.get("legId") for event in events if event.get("type") == "answered"
                   and isinstance(event.get("legId"), str) and event.get("legId")}
        if len(answers) != 1 or any(event.get("type") in {"ended", "uncertain"} for event in events):
            raise MediaError("MEDIA_UNAVAILABLE")
        sip_call_id, from_tag = context.get("sipCallId"), context.get("fromTag")
        to_tag = next(iter(answers))
        if not isinstance(sip_call_id, str) or not TAG.fullmatch(from_tag or "") or not TAG.fullmatch(to_tag):
            raise MediaError("MEDIA_UNAVAILABLE")
        try:
            active = self.rpc.active_cdr_ids()
        except Exception as error:
            raise MediaError("MEDIA_UNAVAILABLE") from error
        if call_id not in active:
            raise MediaError("MEDIA_UNAVAILABLE")
        query = self.ng.request({"command": "query", "call-id": sip_call_id})
        tags = query.get("tags")
        if query.get("result") != "ok" or not isinstance(tags, dict) or not 2 <= len(tags) <= 64 \
                or not all(isinstance(tag, str) and TAG.fullmatch(tag) and isinstance(item, dict)
                           for tag, item in tags.items()) \
                or from_tag not in tags or to_tag not in tags:
            raise MediaError("MEDIA_UNAVAILABLE")
        return sip_call_id, [from_tag, to_tag]

    def _row(self, tenant, listener):
        return self.db.execute("SELECT * FROM sessions WHERE tenant_id=? AND listener_id=?", (tenant, listener)).fetchone()

    @staticmethod
    def _reply(row):
        value = {"schemaVersion": 1, "callId": row["call_id"], "listenerId": row["listener_id"],
                 "state": row["state"], "fence": row["fence"], "expiresAtMs": row["expires_at"]}
        if row["state"] == "negotiating" and row["offer_sdp"]:
            value["offerSdp"] = row["offer_sdp"]
        return value

    def _check_owner(self, row, value):
        if row["call_id"] != value["callId"] or not hmac.compare_digest(row["actor_id"], value["actorId"]):
            raise MediaError("MEDIA_FORBIDDEN", 403)

    def _unsubscribe(self, row):
        reply = self.ng.request({"command": "unsubscribe", "call-id": row["sip_call_id"], "to-tag": row["listener_tag"]})
        if reply.get("result") == "ok":
            return
        if reply.get("result") == "error" and reply.get("error-reason") == "Unknown call-id":
            return
        if reply.get("result") != "ok":
            raise MediaError("MEDIA_UNAVAILABLE")

    def handle(self, tenant, value):
        with self.lock:
            value = self._identity(tenant, value, value.get("action") if isinstance(value, dict) else "")
            action = value["action"]
            if action == "start": return self.start(tenant, value)
            if action == "answer": return self.answer(tenant, value)
            if action == "renew": return self.renew(tenant, value)
            if action == "stop": return self.stop(tenant, value)
            return self.status(tenant, value)

    def start(self, tenant, value):
        if not self.recovered:
            self.sweep(recovering=True)
            if not self.recovered:
                raise MediaError("MEDIA_UNAVAILABLE")
        sip_call_id, tags = self._call(tenant, value["callId"])
        now, expires = self.clock(), self.clock() + value["leaseSeconds"] * 1000
        with self.lock, self.db:
            row = self._row(tenant, value["listenerId"])
            if row:
                self._check_owner(row, value)
                if row["state"] in {"negotiating", "listening"} and row["expires_at"] > now:
                    return self._reply(row)
                raise MediaError("MEDIA_CONFLICT", 409)
            active_states = "('starting','negotiating','answering','listening','stopping')"
            active = self.db.execute("SELECT COUNT(*) AS value FROM sessions WHERE tenant_id=? AND call_id=? AND state IN " + active_states, (tenant, value["callId"])).fetchone()["value"]
            if active >= self.maximum:
                raise MediaError("MEDIA_LIMIT", 409)
            if self.db.execute("SELECT COUNT(*) AS value FROM sessions WHERE tenant_id=? AND call_id=?", (tenant, value["callId"])).fetchone()["value"] >= 64:
                raise MediaError("MEDIA_LIMIT", 409)
            if self.db.execute("SELECT COUNT(*) AS value FROM sessions", ()).fetchone()["value"] >= self.maximum_total \
                    or self.db.execute("SELECT COUNT(*) AS value FROM sessions WHERE tenant_id=?", (tenant,)).fetchone()["value"] >= self.maximum_tenant:
                raise MediaError("MEDIA_LIMIT", 409)
            actor = self.db.execute("SELECT 1 FROM sessions WHERE tenant_id=? AND call_id=? AND actor_id=? AND state IN " + active_states, (tenant, value["callId"], value["actorId"])).fetchone()
            if actor:
                raise MediaError("MEDIA_CONFLICT", 409)
            fence = secrets.randbelow(2**31 - 1) + 1
            tag = self._listener_tag(value["callId"], value["listenerId"], fence)
            self.db.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (tenant, value["callId"], value["listenerId"], value["actorId"], tag, sip_call_id, json.dumps(tags), "starting", fence, expires, None, None, now))
        cleanup = False
        try:
            reply = self.ng.request({"command": "subscribe request", "call-id": sip_call_id,
                                     "from-tags": tags, "to-tag": tag, "flags": ["WebRTC"]})
            offer = reply.get("sdp")
            if reply.get("result") != "ok" or not self._offer_sdp(offer):
                raise MediaError("MEDIA_UNAVAILABLE")
            cleanup = False
            with self.lock, self.db:
                updated = self.db.execute("UPDATE sessions SET state='negotiating', offer_sdp=?, updated_at=? WHERE tenant_id=? AND listener_id=? AND state='starting' AND fence=? AND expires_at>?", (offer, self.clock(), tenant, value["listenerId"], fence, self.clock())).rowcount
                if updated != 1:
                    cleanup = True
                else:
                    row = self._row(tenant, value["listenerId"])
                    if row and row["state"] == "negotiating":
                        return self._reply(row)
            if cleanup:
                self._unsubscribe({"sip_call_id": sip_call_id, "listener_tag": tag})
                raise MediaError("MEDIA_UNAVAILABLE")
        except (MediaError, OSError, sqlite3.Error):
            if cleanup:
                raise
            # A request may have reached RTPengine before a malformed reply or
            # local persistence error. Best-effort cleanup never affects source
            # legs and the durable row is removed only while still unexposed.
            try:
                self.ng.request({"command": "unsubscribe", "call-id": sip_call_id, "to-tag": tag})
            except MediaError:
                pass
            with self.db:
                self.db.execute("UPDATE sessions SET state='stopping', updated_at=? WHERE tenant_id=? AND listener_id=?", (self.clock(), tenant, value["listenerId"]))
            row = self._row(tenant, value["listenerId"])
            try:
                self._unsubscribe(row)
            except MediaError:
                raise MediaError("MEDIA_UNAVAILABLE")
            with self.db:
                self.db.execute("UPDATE sessions SET state='ended', offer_sdp=NULL, updated_at=? WHERE tenant_id=? AND listener_id=?", (self.clock(), tenant, value["listenerId"]))
            raise MediaError("MEDIA_UNAVAILABLE")
        raise MediaError("MEDIA_UNAVAILABLE")

    def answer(self, tenant, value):
        self._call(tenant, value["callId"])
        if not self._answer_sdp(value["sdp"]):
            raise MediaError("INVALID_MEDIA_REQUEST", 400)
        digest = self._answer_hash(value["sdp"])
        with self.lock, self.db:
            row = self._row(tenant, value["listenerId"])
            if not row: raise MediaError("MEDIA_FORBIDDEN", 403)
            self._check_owner(row, value)
            if row["fence"] != value["fence"]: raise MediaError("MEDIA_FORBIDDEN", 403)
            if row["expires_at"] <= self.clock(): raise MediaError("MEDIA_CONFLICT", 409)
            if row["state"] == "listening":
                if hmac.compare_digest(row["answer_hash"] or "", digest): return self._reply(row)
                raise MediaError("MEDIA_CONFLICT", 409)
            if row["state"] != "negotiating": raise MediaError("MEDIA_CONFLICT", 409)
            updated = self.db.execute("UPDATE sessions SET state='answering', updated_at=? WHERE tenant_id=? AND listener_id=? AND state='negotiating' AND fence=? AND expires_at>?", (self.clock(), tenant, value["listenerId"], value["fence"], self.clock())).rowcount
            if updated != 1: raise MediaError("MEDIA_CONFLICT", 409)
        try:
            reply = self.ng.request({"command": "subscribe answer", "call-id": row["sip_call_id"],
                                     "to-tag": row["listener_tag"], "sdp": value["sdp"]})
            if reply.get("result") != "ok": raise MediaError("MEDIA_UNAVAILABLE")
            cleanup = False
            with self.lock, self.db:
                updated = self.db.execute("UPDATE sessions SET state='listening', answer_hash=?, updated_at=? WHERE tenant_id=? AND listener_id=? AND state='answering' AND fence=? AND expires_at>?", (digest, self.clock(), tenant, value["listenerId"], value["fence"], self.clock())).rowcount
                if updated != 1:
                    cleanup = True
                else:
                    return self._reply(self._row(tenant, value["listenerId"]))
            if cleanup:
                self._unsubscribe(row)
                raise MediaError("MEDIA_UNAVAILABLE")
        except MediaError:
            with self.lock, self.db:
                self.db.execute("UPDATE sessions SET state='negotiating', updated_at=? WHERE tenant_id=? AND listener_id=? AND state='answering'", (self.clock(), tenant, value["listenerId"]))
            raise

    def renew(self, tenant, value):
        self._call(tenant, value["callId"])
        with self.lock, self.db:
            row = self._row(tenant, value["listenerId"])
            if not row: raise MediaError("MEDIA_FORBIDDEN", 403)
            self._check_owner(row, value)
            if row["fence"] != value["fence"] or row["state"] not in {"negotiating", "listening"} or row["expires_at"] <= self.clock():
                raise MediaError("MEDIA_CONFLICT", 409)
            expires = self.clock() + value["leaseSeconds"] * 1000
            self.db.execute("UPDATE sessions SET expires_at=?, updated_at=? WHERE tenant_id=? AND listener_id=?", (expires, self.clock(), tenant, value["listenerId"]))
            return self._reply(self._row(tenant, value["listenerId"]))

    def stop(self, tenant, value):
        with self.lock, self.db:
            row = self._row(tenant, value["listenerId"])
            if not row: raise MediaError("MEDIA_NOT_FOUND", 404)
            self._check_owner(row, value)
            if row["fence"] != value["fence"]: raise MediaError("MEDIA_FORBIDDEN", 403)
            if row["state"] == "ended": return self._reply(row)
            self.db.execute("UPDATE sessions SET state='stopping', updated_at=? WHERE tenant_id=? AND listener_id=?", (self.clock(), tenant, value["listenerId"]))
        try:
            self._unsubscribe(row)
        except MediaError:
            raise
        with self.lock, self.db:
            self.db.execute("UPDATE sessions SET state='ended', offer_sdp=NULL, updated_at=? WHERE tenant_id=? AND listener_id=?", (self.clock(), tenant, value["listenerId"]))
            return self._reply(self._row(tenant, value["listenerId"]))

    def status(self, tenant, value):
        with self.lock:
            row = self._row(tenant, value["listenerId"])
            if not row: raise MediaError("MEDIA_NOT_FOUND", 404)
            self._check_owner(row, value)
            return self._reply(row)

    def sweep(self, recovering=False):
        """Expire or reconcile sessions; failures remain stopping and consume capacity."""
        with self.lock:
            try:
                active = self.rpc.active_cdr_ids()
            except Exception:
                active = None
            now = self.clock()
            with self.db:
                rows = self.db.execute("SELECT * FROM sessions WHERE state IN ('starting','negotiating','answering','listening','stopping')").fetchall()
                for row in rows:
                    if recovering or row["expires_at"] <= now or active is not None and row["call_id"] not in active:
                        self.db.execute("UPDATE sessions SET state='stopping', updated_at=? WHERE tenant_id=? AND listener_id=?", (now, row["tenant_id"], row["listener_id"]))
            for row in rows:
                if recovering or row["expires_at"] <= now or active is not None and row["call_id"] not in active or row["state"] == "stopping":
                    try:
                        self._unsubscribe(row)
                    except MediaError:
                        continue
                    with self.db:
                        self.db.execute("UPDATE sessions SET state='ended', offer_sdp=NULL, updated_at=? WHERE tenant_id=? AND listener_id=?", (self.clock(), row["tenant_id"], row["listener_id"]))
            self.recovered = active is not None and not self.db.execute("SELECT 1 FROM sessions WHERE state='stopping'").fetchone()
            # App audit history is durable elsewhere. Retain terminal fences
            # while their source call is active; afterwards old requests fail
            # the journal/dialog gate and cannot recreate a subscription.
            if active is not None:
                with self.db:
                    finished = self.db.execute("SELECT tenant_id,listener_id,call_id FROM sessions WHERE state='ended' AND updated_at<?", (now - 300000,)).fetchall()
                    for row in finished:
                        if row['call_id'] not in active:
                            self.db.execute("DELETE FROM sessions WHERE tenant_id=? AND listener_id=? AND state='ended'", (row['tenant_id'], row['listener_id']))
