"""Opt-in, bounded disposal of terminal failed/stored recording state."""

import json
import os
from pathlib import Path
import time
import re

from recording_capture import CaptureError
from recording_cleanup import _path, _private_identity, _remove

HEX = re.compile(r"[a-f0-9]{32}\Z")


def _fail(code="RECORDING_RETENTION_PENDING", status=503):
    raise CaptureError(code, status)


class RecordingRetention:
    """No retention occurs unless both explicit durations are supplied by runtime wiring."""
    def __init__(self, controller, failed_after_s=None, stored_after_s=None, clock=time.time):
        self.controller, self.clock = controller, clock
        self.failed_after_s, self.stored_after_s = failed_after_s, stored_after_s
        if failed_after_s is None and stored_after_s is None:
            self.enabled = False
            return
        if any(type(value) is not int or not 1 <= value <= 365 * 24 * 3600 for value in (failed_after_s, stored_after_s)):
            raise ValueError("explicit bounded retention durations required")
        self.enabled = True
        with controller.lock, controller.db:
            controller.db.execute("CREATE TABLE IF NOT EXISTS recording_retention(manifest_id TEXT PRIMARY KEY,kind TEXT NOT NULL CHECK(kind IN ('failed','stored')),inventory TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','done')),created_at INTEGER NOT NULL)")
            controller.db.execute("CREATE TABLE IF NOT EXISTS recording_retention_cursor(id INTEGER PRIMARY KEY CHECK(id=1),cursor INTEGER NOT NULL)")
            controller.db.execute("INSERT OR IGNORE INTO recording_retention_cursor VALUES(1,0)")

    def _gone(self, row):
        try:
            active = self.controller.rpc.active_cdr_ids()
            if not isinstance(active, (set, list, tuple)) or not all(isinstance(value, str) and HEX.fullmatch(value) for value in active):
                return False
            if not isinstance(row["sip_call_id"], str) or not row["sip_call_id"]:
                return False
            query = self.controller.ng.request({"command": "query", "call-id": row["sip_call_id"]})
        except Exception:
            return False
        return row["call_id"] not in active and isinstance(query, dict) and query.get("result") == "error" and query.get("error-reason") == "Unknown call-id"

    def _journal_terminal(self, row, allow_pruned):
        with self.controller.journal.lock:
            call = self.controller.journal.db.execute("SELECT terminal FROM calls WHERE call_id=?", (row["call_id"],)).fetchone()
        return bool(call and call["terminal"] == 1) or (allow_pruned and not call)

    def _empty_native_failed(self, row):
        """Prove this is an interrupted native start with no file to remove."""
        try:
            epoch = json.loads(row["epoch"])
        except (IndexError, KeyError, TypeError, ValueError):
            return False
        manifest = row["manifest_id"]
        if (
            not isinstance(epoch, dict)
            or epoch.get("captureMode") != "subscription-v1"
            or row["pcap"] != manifest + ".pcap"
            or row["metadata"] is not None
            or row["publication"] is not None
        ):
            return False
        paths = (
            Path(self.controller.pcaps) / (manifest + ".pcap"),
            Path(self.controller.metadata) / (manifest + ".meta"),
            Path(self.controller.metadata) / ("." + manifest + ".meta.tmp"),
            Path(self.controller.output) / (manifest + ".wav"),
            Path(self.controller.output) / (manifest + ".json"),
            Path(self.controller.output) / (".recording-" + manifest),
        )
        return not any(path.exists() or path.is_symlink() for path in paths)

    def _inventory_failed(self, row):
        if self._empty_native_failed(row):
            return []
        pcap = _path(self.controller, row, "pcap", row["pcap"])
        metadata = self.controller._metadata_file(row, pcap).name
        values = []
        for role, name in (("pcap", row["pcap"]), ("metadata", metadata)):
            values.append({"role": role, "path": name, **_private_identity(_path(self.controller, row, role, name))})
        wav, manifest = Path(self.controller.output) / (row["manifest_id"] + ".wav"), Path(self.controller.output) / (row["manifest_id"] + ".json")
        present = [("wav", wav), ("manifest", manifest)]
        present = [(role, path) for role, path in present if path.exists() or path.is_symlink()]
        receipt = None
        try:
            receipt = json.loads(row["publication"]) if row["publication"] else None
        except (TypeError, ValueError):
            _fail("RECORDING_RETENTION_PENDING")
        if receipt is not None:
            if not isinstance(receipt, dict) or set(receipt) != {"wav", "manifest"}:
                _fail("RECORDING_RETENTION_PENDING")
            for role, path in present:
                expected = receipt.get(role)
                actual = _private_identity(path)
                if not isinstance(expected, dict) or set(expected) != {"dev", "ino", "size", "uid", "mode"} or any(type(expected[key]) is not int or expected[key] < 0 for key in expected) or any(actual[key] != expected[key] for key in expected):
                    _fail("RECORDING_RETENTION_PENDING")
                values.append({"role": role, "path": path.name, **actual})
        elif present:
            if {role for role, _path_value in present} != {"wav", "manifest"}:
                _fail("RECORDING_RETENTION_PENDING")
            from recording_artifacts import RecordingArtifacts
            reader = RecordingArtifacts(self.controller)
            checked, _raw, _digest = reader._manifest(row)
            fd, _size = reader._wav(row, checked); os.close(fd)
            for role, name in (("wav", wav.name), ("manifest", manifest.name)):
                values.append({"role": role, "path": name, **_private_identity(_path(self.controller, row, role, name))})
        if len(values) > 4 or len({value["role"] for value in values}) != len(values):
            _fail("RECORDING_RETENTION_PENDING")
        return values

    def _eligible(self, row, now):
        kind = "failed" if row["state"] == "failed" else "stored" if row["state"] == "stored" else None
        if not kind or now - (row["ended_us"] or row["started_us"]) < (self.failed_after_s if kind == "failed" else self.stored_after_s) * 1_000_000:
            return None
        if row["stop_pending"] or not self._gone(row):
            return None
        cleanup = self.controller.db.execute("SELECT state FROM recording_cleanup WHERE manifest_id=?", (row["manifest_id"],)).fetchone()
        if kind == "failed":
            if cleanup or not self._journal_terminal(row, False): return None
            try:
                from recording_staging import recover_staging
                if not recover_staging(Path(self.controller.output), row["manifest_id"]): return None
            except Exception:
                return None
            try: inventory = self._inventory_failed(row)
            except CaptureError: return None
        else:
            if not cleanup or cleanup["state"] != "stored" or not self._journal_terminal(row, True): return None
            inventory = []
        return kind, inventory

    def _complete(self, row, intent):
        try: entries = json.loads(intent["inventory"])
        except (TypeError, ValueError): _fail()
        expected = {"failed": {"pcap", "metadata", "wav", "manifest"}, "stored": set()}[intent["kind"]] if intent["kind"] in {"failed", "stored"} else None
        roles = {entry.get("role") for entry in entries if isinstance(entry, dict)} if isinstance(entries, list) else set()
        empty_native = intent["kind"] == "failed" and not entries and self._empty_native_failed(row)
        if (not isinstance(entries, list) or expected is None
                or (intent["kind"] == "failed" and not empty_native and not {"pcap", "metadata"} <= roles <= expected)
                or (intent["kind"] == "stored" and entries)
                or len(entries) > 4 or len(roles) != len(entries)): _fail()
        if not self._gone(row) or not self._journal_terminal(row, intent["kind"] == "stored"):
            _fail()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"role", "path", "dev", "ino", "size", "uid", "mode"}: _fail()
            if entry["role"] not in expected or any(type(entry[key]) is not int or entry[key] < 0 for key in ("dev", "ino", "size", "uid", "mode")): _fail()
            _remove(self.controller, row, entry)
        for directory in (Path(self.controller.output), Path(self.controller.pcaps), Path(self.controller.metadata)):
            fd = None
            try:
                fd = os.open(directory, os.O_RDONLY); os.fsync(fd)
            except OSError: _fail()
            finally:
                if fd is not None: os.close(fd)
        with self.controller.db:
            self.controller.db.execute("DELETE FROM recording_cleanup WHERE manifest_id=?", (row["manifest_id"],))
            self.controller.db.execute("DELETE FROM captures WHERE manifest_id=?", (row["manifest_id"],))
            self.controller.db.execute("DELETE FROM recording_retention WHERE manifest_id=?", (row["manifest_id"],))

    def sweep(self, limit=5):
        if not self.enabled: return {"processed": 0}
        if type(limit) is not int or not 1 <= limit <= 5: raise ValueError("bounded sweep required")
        processed, now = 0, int(self.clock() * 1_000_000)
        with self.controller.lock:
            cursor = self.controller.db.execute("SELECT cursor FROM recording_retention_cursor WHERE id=1").fetchone()[0]
            rows = self.controller.db.execute("SELECT rowid AS retention_rowid,* FROM captures WHERE state IN ('failed','stored') ORDER BY CASE WHEN rowid>? THEN 0 ELSE 1 END,rowid LIMIT ?", (cursor, limit)).fetchall()
            for row in rows:
                intent = self.controller.db.execute("SELECT * FROM recording_retention WHERE manifest_id=?", (row["manifest_id"],)).fetchone()
                if not intent:
                    eligible = self._eligible(row, now)
                    if not eligible: continue
                    kind, inventory = eligible
                    with self.controller.db:
                        self.controller.db.execute("INSERT INTO recording_retention VALUES(?,?,?,?,?)", (row["manifest_id"], kind, json.dumps(inventory, sort_keys=True, separators=(",", ":")), "pending", now))
                    intent = self.controller.db.execute("SELECT * FROM recording_retention WHERE manifest_id=?", (row["manifest_id"],)).fetchone()
                try:
                    self._complete(row, intent); processed += 1
                except CaptureError:
                    pass
            if rows:
                with self.controller.db:
                    self.controller.db.execute("UPDATE recording_retention_cursor SET cursor=? WHERE id=1", (rows[-1]["retention_rowid"],))
        return {"processed": processed}
