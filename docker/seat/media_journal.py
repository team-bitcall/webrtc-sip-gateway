"""Bounded, SDP-free media negotiation evidence for recording safety gates."""

import hashlib
import json
import re

from call_journal import JournalError


HEX = re.compile(r"[a-f0-9]{32}\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
METHODS = {"INVITE", "UPDATE", "ACK", "PRACK"}


def _fail(code="INVALID_MEDIA_EVENT", status=400):
    raise JournalError(code, status)


def _exact(value, fields):
    return isinstance(value, dict) and set(value) == set(fields)


def _canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class MediaJournal:
    """Every begin is a unique negotiation attempt; duplicates poison evidence."""
    def __init__(self, journal):
        self.journal = journal
        with journal.lock, journal.db:
            journal.db.executescript("""
              CREATE TABLE IF NOT EXISTS media_observations (
                call_id TEXT NOT NULL, revision INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','applied','failed')),
                fingerprint TEXT NOT NULL, metadata TEXT NOT NULL, observed_at INTEGER NOT NULL,
                PRIMARY KEY(call_id,revision), FOREIGN KEY(call_id) REFERENCES calls(call_id));
              CREATE TABLE IF NOT EXISTS media_closures (
                call_id TEXT PRIMARY KEY NOT NULL, count INTEGER NOT NULL, unsafe INTEGER NOT NULL,
                fingerprint TEXT NOT NULL, closed_at INTEGER NOT NULL, FOREIGN KEY(call_id) REFERENCES calls(call_id));
            """)

    def _call(self, call_id, permit_terminal=False):
        if not isinstance(call_id, str) or not HEX.fullmatch(call_id):
            _fail()
        row = self.journal.db.execute("SELECT tenant_id,terminal FROM calls WHERE call_id=?", (call_id,)).fetchone()
        if not row:
            _fail("CALL_NOT_FOUND", 404)
        if row["terminal"] and not permit_terminal:
            _fail("MEDIA_EVIDENCE_CLOSED", 409)
        return row

    @staticmethod
    def _begin(value):
        fields = {"callId", "revision", "method", "fromTag", "toTag", "sipCode", "sdpSha256"}
        if not _exact(value, fields) or not isinstance(value["callId"], str) or not HEX.fullmatch(value["callId"]):
            _fail()
        if type(value["revision"]) is not int or not 1 <= value["revision"] <= 128:
            _fail()
        if not isinstance(value["method"], str) or value["method"] not in METHODS or not all(isinstance(value[key], str) and len(value[key]) <= 128 and all(ord(c) >= 32 and ord(c) != 127 for c in value[key]) for key in ("fromTag", "toTag")):
            _fail()
        if type(value["sipCode"]) is not int or (value["sipCode"] != 0 and not 100 <= value["sipCode"] <= 699):
            _fail()
        if not isinstance(value["sdpSha256"], str) or not SHA.fullmatch(value["sdpSha256"]):
            _fail()
        return value

    def begin(self, value):
        value = self._begin(value)
        fingerprint = hashlib.sha256(_canon(value).encode()).hexdigest()
        with self.journal.lock, self.journal.db:
            call = self._call(value["callId"], permit_terminal=True)
            closure = self.journal.db.execute("SELECT 1 FROM media_closures WHERE call_id=?", (value["callId"],)).fetchone()
            if closure:
                self.journal.db.execute("UPDATE media_closures SET unsafe=1 WHERE call_id=?", (value["callId"],))
                self.journal.db.commit()
                _fail("MEDIA_EVIDENCE_CLOSED", 409)
            if call["terminal"]:
                _fail("MEDIA_EVIDENCE_CLOSED", 409)
            old = self.journal.db.execute("SELECT status,fingerprint FROM media_observations WHERE call_id=? AND revision=?", (value["callId"], value["revision"])).fetchone()
            if old:
                self.journal.db.execute("UPDATE media_observations SET status='failed' WHERE call_id=? AND revision=?", (value["callId"], value["revision"]))
                self.journal.db.commit()
                _fail("MEDIA_EVIDENCE_CONFLICT", 409)
            maximum = self.journal.db.execute("SELECT COALESCE(MAX(revision),0) FROM media_observations WHERE call_id=?", (value["callId"],)).fetchone()[0]
            if value["revision"] != maximum + 1:
                _fail("MEDIA_EVIDENCE_CONFLICT", 409)
            if self.journal.db.execute("SELECT COUNT(*) FROM media_observations").fetchone()[0] >= self.journal.max_pending * 128:
                _fail("JOURNAL_CAPACITY", 503)
            self.journal.db.execute("INSERT INTO media_observations VALUES(?,?,?,?,?,?)", (value["callId"], value["revision"], "pending", fingerprint, _canon(value), int(self.journal.clock())))
        return {"revision": value["revision"], "status": "pending"}

    def complete(self, value):
        if not _exact(value, {"callId", "revision", "success"}) or not isinstance(value.get("callId"), str) or not HEX.fullmatch(value["callId"]) or type(value.get("revision")) is not int or not 1 <= value["revision"] <= 128 or type(value.get("success")) is not bool:
            _fail()
        wanted = "applied" if value["success"] else "failed"
        with self.journal.lock, self.journal.db:
            self._call(value["callId"])
            row = self.journal.db.execute("SELECT status FROM media_observations WHERE call_id=? AND revision=?", (value["callId"], value["revision"])).fetchone()
            if not row:
                _fail("MEDIA_EVIDENCE_MISSING", 409)
            if row["status"] == "pending":
                self.journal.db.execute("UPDATE media_observations SET status=? WHERE call_id=? AND revision=?", (wanted, value["callId"], value["revision"]))
            elif row["status"] != wanted:
                _fail("MEDIA_EVIDENCE_CONFLICT", 409)
        return {"revision": value["revision"], "status": wanted}

    def media_closure(self, value):
        if not _exact(value, {"callId", "count", "unsafe"}) or not isinstance(value.get("callId"), str) or not HEX.fullmatch(value["callId"]) or type(value.get("count")) is not int or not 0 <= value["count"] <= 128 or type(value.get("unsafe")) is not bool:
            _fail()
        fingerprint = hashlib.sha256(_canon(value).encode()).hexdigest()
        with self.journal.lock, self.journal.db:
            self._call(value["callId"], permit_terminal=True)
            row = self.journal.db.execute("SELECT count,unsafe,fingerprint FROM media_closures WHERE call_id=?", (value["callId"],)).fetchone()
            if row:
                if row["fingerprint"] != fingerprint:
                    self.journal.db.execute("UPDATE media_closures SET unsafe=1 WHERE call_id=?", (value["callId"],))
                    self.journal.db.commit()
                    _fail("MEDIA_EVIDENCE_CONFLICT", 409)
                if row["unsafe"]:
                    _fail("MEDIA_EVIDENCE_INCOMPLETE", 409)
            else:
                self.journal.db.execute("INSERT INTO media_closures VALUES(?,?,?,?,?)", (value["callId"], value["count"], int(value["unsafe"]), fingerprint, int(self.journal.clock())))
        return {"count": value["count"], "unsafe": value["unsafe"]}

    def checkpoint(self, call_id, require_closed=False):
        return media_checkpoint(self.journal, call_id, require_closed)


def media_checkpoint(journal, call_id, require_closed=False):
    """Read existing evidence only; safe for the capture runtime's RO journal."""
    if type(require_closed) is not bool or not isinstance(call_id, str) or not HEX.fullmatch(call_id):
        _fail()
    with journal.lock:
        call = journal.db.execute("SELECT 1 FROM calls WHERE call_id=?", (call_id,)).fetchone()
        if not call:
            _fail("CALL_NOT_FOUND", 404)
        rows = journal.db.execute("SELECT revision,status,fingerprint FROM media_observations WHERE call_id=? ORDER BY revision LIMIT 129", (call_id,)).fetchall()
        if not rows or len(rows) > 128 or [row["revision"] for row in rows] != list(range(1, len(rows) + 1)) or any(row["status"] != "applied" for row in rows):
            _fail("MEDIA_EVIDENCE_INCOMPLETE", 409)
        closure = journal.db.execute("SELECT count,unsafe FROM media_closures WHERE call_id=?", (call_id,)).fetchone()
        if (closure and (closure["unsafe"] or closure["count"] != len(rows))) or (require_closed and not closure):
            _fail("MEDIA_EVIDENCE_INCOMPLETE", 409)
        return {"revision": rows[-1]["revision"], "digest": hashlib.sha256(_canon([[row["revision"], row["fingerprint"]] for row in rows]).encode()).hexdigest(), "closed": bool(closure and closure["count"] == len(rows) and not closure["unsafe"])}
