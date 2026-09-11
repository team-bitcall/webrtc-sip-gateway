"""Private, durable gateway call-event journal.

The journal never parses SIP.  Kamailio supplies a small, already-sanitised
admission context once, then lifecycle hooks append typed evidence by call ID.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time

EVENT_TYPES = {"admitted", "progress", "answered", "failed", "ended", "uncertain"}
REASONS = {"normal", "cancelled", "busy", "rejected", "no_answer", "timeout", "transport_error", "upstream_failure", "dialog_timeout"}
ENDED_BY = {"agent", "upstream", "gateway"}
TENANT_RE = re.compile(r"t_[0-9a-f]{64}\Z")
SEAT_RE = re.compile(r"s_[0-9a-f]{64}\Z")
HEX_RE = re.compile(r"[0-9a-f]{32}\Z")
DESTINATION_RE = re.compile(r"[+]?[0-9*#]{1,32}\Z")
USER_RE = re.compile(r"[A-Za-z0-9+._-]{1,128}\Z")


class JournalError(Exception):
    def __init__(self, code, status=503):
        self.code, self.status = code, status
        super().__init__(code)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _safe_text(value, maximum, field, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise JournalError("INVALID_CALL_EVENT", 400)
    return value


def _positive(value):
    if type(value) is not int or value < 1:
        raise JournalError("INVALID_CALL_EVENT", 400)
    return value


class CallJournal:
    """Own SQLite connection: no lock is shared with snapshot reconciliation."""
    def __init__(self, directory, clock=lambda: int(time.time() * 1000), max_pending=10000, terminal_reserve=100):
        self.directory = Path(directory)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise JournalError("PRIVATE_STATE_REQUIRED")
        if type(max_pending) is not int or type(terminal_reserve) is not int or not 1 <= terminal_reserve < max_pending:
            raise JournalError("JOURNAL_CONFIG_INVALID")
        self.clock, self.max_pending, self.terminal_reserve = clock, max_pending, terminal_reserve
        self.lock = threading.RLock()
        path = self.directory / "call-journal.sqlite3"
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise JournalError("PRIVATE_STATE_REQUIRED")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS calls (
            call_id TEXT PRIMARY KEY, admission_key TEXT UNIQUE NOT NULL,
            tenant_id TEXT NOT NULL, seat_id TEXT NOT NULL, context TEXT NOT NULL,
            terminal INTEGER NOT NULL DEFAULT 0, terminal_at INTEGER, created_at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
            call_id TEXT NOT NULL, tenant_id TEXT NOT NULL, semantic_key TEXT UNIQUE NOT NULL,
            payload TEXT NOT NULL, occurred_at INTEGER NOT NULL, acked_at INTEGER,
            FOREIGN KEY(call_id) REFERENCES calls(call_id));
          CREATE TABLE IF NOT EXISTS tenant_state (
            tenant_id TEXT PRIMARY KEY, exported_through INTEGER NOT NULL DEFAULT 0,
            acknowledged_through INTEGER NOT NULL DEFAULT 0);
          CREATE INDEX IF NOT EXISTS events_tenant_sequence ON events(tenant_id, sequence);
        """)
        if "acked_at" not in {row[1] for row in self.db.execute("PRAGMA table_info(events)")}:
            self.db.execute("ALTER TABLE events ADD COLUMN acked_at INTEGER")
        if "terminal_at" not in {row[1] for row in self.db.execute("PRAGMA table_info(calls)")}:
            self.db.execute("ALTER TABLE calls ADD COLUMN terminal_at INTEGER")

    def close(self):
        self.db.close()

    @staticmethod
    def _admission_key(value):
        return hashlib.sha256(_canonical([value["tenantId"], value["seatId"], value["sipCallId"], value["fromTag"]]).encode()).hexdigest()

    def _context(self, value):
        required = {"tenantId", "seatId", "snapshotRevision", "occurredAtMs", "startedAtMs", "sipCallId", "fromTag", "legId", "destination", "requestedCallerId", "effectiveCallerId"}
        if not isinstance(value, dict) or set(value) != required:
            raise JournalError("INVALID_CALL_EVENT", 400)
        if not isinstance(value["tenantId"], str) or not isinstance(value["seatId"], str) \
                or not TENANT_RE.fullmatch(value["tenantId"]) or not SEAT_RE.fullmatch(value["seatId"]):
            raise JournalError("INVALID_CALL_EVENT", 400)
        _positive(value["snapshotRevision"])
        for field in ("occurredAtMs", "startedAtMs"):
            if type(value[field]) is not int or value[field] < 0:
                raise JournalError("INVALID_CALL_EVENT", 400)
        _safe_text(value["sipCallId"], 255, "sipCallId")
        _safe_text(value["fromTag"], 128, "fromTag")
        _safe_text(value["legId"], 128, "legId", empty=True)
        if not isinstance(value["destination"], str) or not DESTINATION_RE.fullmatch(value["destination"]):
            raise JournalError("INVALID_CALL_EVENT", 400)
        if value["requestedCallerId"] is not None and (not isinstance(value["requestedCallerId"], str) or not DESTINATION_RE.fullmatch(value["requestedCallerId"])):
            raise JournalError("INVALID_CALL_EVENT", 400)
        if not isinstance(value["effectiveCallerId"], str) or not USER_RE.fullmatch(value["effectiveCallerId"]):
            raise JournalError("INVALID_CALL_EVENT", 400)
        return dict(value)

    def _event(self, context, call_id, event_type, occurred_at, leg_id="", sip_code=None, reason=None, ended_by=None):
        if event_type not in EVENT_TYPES or type(occurred_at) is not int or occurred_at < 0:
            raise JournalError("INVALID_CALL_EVENT", 400)
        if not isinstance(leg_id, str) or len(leg_id) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in leg_id):
            raise JournalError("INVALID_CALL_EVENT", 400)
        if sip_code is not None and (type(sip_code) is not int or not 100 <= sip_code <= 699):
            raise JournalError("INVALID_CALL_EVENT", 400)
        if reason is not None and reason not in REASONS:
            raise JournalError("INVALID_CALL_EVENT", 400)
        if ended_by is not None and ended_by not in ENDED_BY:
            raise JournalError("INVALID_CALL_EVENT", 400)
        return {"schemaVersion": 1, "eventId": None, "sequence": None, "callId": call_id,
          "tenantId": context["tenantId"], "seatId": context["seatId"], "snapshotRevision": context["snapshotRevision"],
          "type": event_type, "occurredAtMs": occurred_at, "startedAtMs": context["startedAtMs"],
          "sipCallId": context["sipCallId"], "fromTag": context["fromTag"], "legId": leg_id,
          "destination": context["destination"], "requestedCallerId": context["requestedCallerId"],
          "effectiveCallerId": context["effectiveCallerId"], "sipCode": sip_code, "reason": reason, "endedBy": ended_by}

    def _append(self, context, call_id, event_type, occurred_at, leg_id="", sip_code=None, reason=None, ended_by=None):
        event = self._event(context, call_id, event_type, occurred_at, leg_id, sip_code, reason, ended_by)
        semantic = hashlib.sha256(_canonical([call_id, event_type, leg_id, sip_code, reason, ended_by]).encode()).hexdigest()
        existing = self.db.execute("SELECT payload FROM events WHERE semantic_key=?", (semantic,)).fetchone()
        if existing:
            return json.loads(existing["payload"])
        event_id = os.urandom(16).hex()
        event["eventId"] = event_id
        cursor = self.db.execute("INSERT INTO events(event_id,call_id,tenant_id,semantic_key,payload,occurred_at) VALUES (?,?,?,?,?,?)",
                                 (event_id, call_id, context["tenantId"], semantic, _canonical(event), occurred_at))
        event["sequence"] = cursor.lastrowid
        self.db.execute("UPDATE events SET payload=? WHERE sequence=?", (_canonical(event), event["sequence"]))
        if event_type in {"failed", "ended", "uncertain"}:
            self.db.execute("UPDATE calls SET terminal=1, terminal_at=COALESCE(terminal_at, ?) WHERE call_id=?", (occurred_at, call_id))
        return event

    def admit(self, value):
        if not isinstance(value, dict) or set(value) != {"tenantId", "seatId", "snapshotRevision", "sipCallId", "fromTag", "legId", "destination", "requestedCallerId", "effectiveCallerId"}:
            raise JournalError("INVALID_CALL_EVENT", 400)
        now = int(self.clock())
        value = {**value, "occurredAtMs": now, "startedAtMs": now}
        context = self._context(value)
        key = self._admission_key(context)
        with self.lock, self.db:
            row = self.db.execute("SELECT call_id, context FROM calls WHERE admission_key=?", (key,)).fetchone()
            if row:
                return json.loads(row["context"]), row["call_id"]
            pending = self.db.execute("SELECT COUNT(*) AS value FROM events WHERE acked_at IS NULL").fetchone()["value"]
            if pending >= self.max_pending - self.terminal_reserve:
                raise JournalError("JOURNAL_CAPACITY")
            call_id = os.urandom(16).hex()
            self.db.execute("INSERT INTO calls(call_id,admission_key,tenant_id,seat_id,context,created_at) VALUES (?,?,?,?,?,?)",
                            (call_id, key, context["tenantId"], context["seatId"], _canonical(context), context["occurredAtMs"]))
            self._append(context, call_id, "admitted", context["occurredAtMs"], context["legId"])
            return context, call_id

    def append(self, value):
        required = {"callId", "type", "legId", "sipCode", "reason", "endedBy"}
        if not isinstance(value, dict) or set(value) != required or not isinstance(value["callId"], str) or not HEX_RE.fullmatch(value["callId"]):
            raise JournalError("INVALID_CALL_EVENT", 400)
        with self.lock, self.db:
            row = self.db.execute("SELECT context FROM calls WHERE call_id=?", (value["callId"],)).fetchone()
            if not row:
                raise JournalError("CALL_NOT_FOUND", 404)
            semantic = hashlib.sha256(_canonical([value["callId"], value["type"], value["legId"], value["sipCode"], value["reason"], value["endedBy"]]).encode()).hexdigest()
            existing = self.db.execute("SELECT payload FROM events WHERE semantic_key=?", (semantic,)).fetchone()
            if existing:
                return json.loads(existing["payload"])
            pending = self.db.execute("SELECT COUNT(*) AS value FROM events WHERE acked_at IS NULL").fetchone()["value"]
            terminal = value["type"] in {"failed", "ended", "uncertain"}
            if pending >= self.max_pending or (not terminal and pending >= self.max_pending - self.terminal_reserve):
                raise JournalError("JOURNAL_CAPACITY")
            return self._append(json.loads(row["context"]), value["callId"], value["type"], int(self.clock()),
                                value["legId"], value["sipCode"], value["reason"], value["endedBy"])

    def events(self, tenant_id, after=0, limit=100):
        if not TENANT_RE.fullmatch(tenant_id) or type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise JournalError("INVALID_CALL_EVENT", 400)
        with self.lock:
            rows = self.db.execute("SELECT payload FROM events WHERE tenant_id=? AND sequence>? ORDER BY sequence LIMIT ?", (tenant_id, after, limit + 1)).fetchall()
        values = [json.loads(row["payload"]) for row in rows[:limit]]
        if values:
            with self.lock, self.db:
                self.db.execute("INSERT INTO tenant_state(tenant_id,exported_through) VALUES (?,?) ON CONFLICT(tenant_id) DO UPDATE SET exported_through=MAX(exported_through,excluded.exported_through)",
                                (tenant_id, values[-1]["sequence"]))
        return {"schemaVersion": 1, "tenantId": tenant_id, "events": values,
                "nextSequence": values[-1]["sequence"] if values else after, "hasMore": len(rows) > limit}

    def acknowledge(self, tenant_id, through):
        if not TENANT_RE.fullmatch(tenant_id) or type(through) is not int or through < 0:
            raise JournalError("INVALID_CALL_EVENT", 400)
        with self.lock, self.db:
            state = self.db.execute("SELECT exported_through, acknowledged_through FROM tenant_state WHERE tenant_id=?", (tenant_id,)).fetchone()
            exported = state["exported_through"] if state else 0
            acknowledged = state["acknowledged_through"] if state else 0
            if through > exported:
                raise JournalError("ACK_OUT_OF_RANGE", 409)
            through = max(through, acknowledged)
            self.db.execute("INSERT INTO tenant_state(tenant_id,exported_through,acknowledged_through) VALUES (?,?,?) ON CONFLICT(tenant_id) DO UPDATE SET acknowledged_through=MAX(acknowledged_through,excluded.acknowledged_through)",
                            (tenant_id, exported, through))
            self.db.execute("UPDATE events SET acked_at=COALESCE(acked_at, ?) WHERE tenant_id=? AND sequence<=?",
                            (int(self.clock()), tenant_id, through))
        return {"schemaVersion": 1, "tenantId": tenant_id, "acknowledgedSequence": through}

    def health(self):
        with self.lock:
            pending = self.db.execute("SELECT COUNT(*) AS value FROM events WHERE acked_at IS NULL").fetchone()["value"]
        return {"ready": pending < self.max_pending - self.terminal_reserve,
                "degraded": pending >= self.max_pending - self.terminal_reserve,
                "pending": pending, "capacity": self.max_pending, "terminalReserve": self.terminal_reserve}

    def reconcile_active(self, active_call_ids, grace_ms=10_000):
        """Only an authoritative Kamailio dialog inventory may mark restart uncertainty."""
        if not isinstance(active_call_ids, set) or type(grace_ms) is not int or grace_ms < 0 \
                or not all(isinstance(item, str) and HEX_RE.fullmatch(item) for item in active_call_ids):
            raise JournalError("INVALID_CALL_EVENT", 400)
        with self.lock, self.db:
            rows = self.db.execute("SELECT call_id, context FROM calls WHERE terminal=0").fetchall()
            now = int(self.clock())
            for row in rows:
                context = json.loads(row["context"])
                if row["call_id"] not in active_call_ids and now - context["startedAtMs"] >= grace_ms:
                    pending = self.db.execute("SELECT COUNT(*) AS value FROM events WHERE acked_at IS NULL").fetchone()["value"]
                    # Preserve the existing call context and degraded state if a
                    # full durable queue cannot accept another terminal marker.
                    if pending >= self.max_pending:
                        return
                    self._append(context, row["call_id"], "uncertain", now,
                                 reason="transport_error", ended_by="gateway")

    def compact(self, retention_ms=7 * 24 * 60 * 60 * 1000):
        if type(retention_ms) is not int or retention_ms < 1:
            raise JournalError("JOURNAL_CONFIG_INVALID")
        cutoff = int(self.clock()) - retention_ms
        with self.lock, self.db:
            self.db.execute("DELETE FROM events WHERE acked_at IS NOT NULL AND acked_at<=? AND call_id IN "
                            "(SELECT call_id FROM calls WHERE terminal=1 AND terminal_at<=?)", (cutoff, cutoff))
            self.db.execute("DELETE FROM calls WHERE terminal=1 AND terminal_at<=? AND NOT EXISTS "
                            "(SELECT 1 FROM events WHERE events.call_id=calls.call_id)", (cutoff,))
