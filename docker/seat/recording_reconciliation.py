"""Durable terminal capture fences; no quota proof from a timeout or a 404."""
import hashlib
import json
from pathlib import Path
import re

from recording_capture import CaptureError

HEX = re.compile(r"[a-f0-9]{32}\Z")
TENANT = re.compile(r"t_[a-f0-9]{64}\Z")
KEYS = {"tenantId", "gatewayId", "callId", "publicCallId", "membershipId"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def initialize(controller):
    with controller.lock, controller.db:
        controller.db.execute("""CREATE TABLE IF NOT EXISTS recording_reconciliations(
            call_id TEXT PRIMARY KEY, manifest_id TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL,
            binding TEXT NOT NULL, inventory TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending','released')))""")


def blocked(controller, call_id, manifest_id):
    initialize(controller)
    return controller.db.execute(
        "SELECT 1 FROM recording_reconciliations WHERE call_id=? OR manifest_id=?",
        (call_id, manifest_id),
    ).fetchone() is not None


class RecordingReconciliation:
    def __init__(self, controller):
        self.controller = controller
        initialize(controller)

    def _paths(self, manifest):
        c = self.controller
        return [Path(c.pcaps) / (manifest + ".pcap"),
                Path(c.metadata) / (manifest + ".meta"),
                Path(c.metadata) / ("." + manifest + ".meta.tmp"),
                Path(c.output) / (manifest + ".wav"),
                Path(c.output) / (manifest + ".json"),
                Path(c.output) / (".recording-" + manifest)]

    def reconcile(self, tenant, command):
        if (not isinstance(tenant, str) or not TENANT.fullmatch(tenant)
                or not isinstance(command, dict)
                or set(command) != {"action", "callId", "manifestId", "binding"}
                or command["action"] != "reconcile"
                or not all(isinstance(command[k], str) and HEX.fullmatch(command[k])
                           for k in ("callId", "manifestId"))):
            raise CaptureError("INVALID_RECORDING_REQUEST", 400)
        b = command["binding"]
        if (not isinstance(b, dict) or set(b) != KEYS
                or any(not isinstance(v, str) or not v or v != v.strip()
                       or len(v.encode()) > 512 or any(ord(ch) < 32 or ord(ch) == 127 for ch in v)
                       for v in b.values())
                or b["callId"] != command["callId"]):
            raise CaptureError("INVALID_RECORDING_REQUEST", 400)
        call_id, manifest = command["callId"], command["manifestId"]
        if (tenant != "t_" + hashlib.sha256(b["tenantId"].encode()).hexdigest()
                or b["publicCallId"] != digest([b["gatewayId"], b["tenantId"], call_id])[:32]
                or manifest != digest(["recording-v1", b["gatewayId"], b["tenantId"], call_id])[:32]):
            raise CaptureError("RECORDING_BINDING_MISMATCH", 409)
        raw = canonical(b)
        response = {"version": 1, "tenantId": tenant, "callId": call_id,
                    "manifestId": manifest, "bindingSha256": digest(b), "state": "pending"}
        c = self.controller
        with c.lock:
            intent = c.db.execute(
                "SELECT * FROM recording_reconciliations WHERE call_id=? OR manifest_id=?",
                (call_id, manifest),
            ).fetchone()
            if intent:
                if (intent["tenant_id"] != tenant or intent["call_id"] != call_id
                        or intent["manifest_id"] != manifest or intent["binding"] != raw):
                    raise CaptureError("RECORDING_RECONCILIATION_CONFLICT", 409)
                if intent["state"] == "released":
                    return {**response, "state": "released"}
            row = c.db.execute("SELECT * FROM captures WHERE call_id=? OR manifest_id=?",
                               (call_id, manifest)).fetchone()
            if row and (row["call_id"] != call_id or row["manifest_id"] != manifest
                        or row["tenant_id"] != tenant or canonical(json.loads(row["binding"])) != raw):
                raise CaptureError("RECORDING_RECONCILIATION_CONFLICT", 409)
            with c.journal.lock:
                terminal = c.journal.db.execute(
                    "SELECT terminal FROM calls WHERE call_id=? AND tenant_id=?", (call_id, tenant)
                ).fetchone()
            # A previously persisted intent proves terminality even after journal compaction.
            if not intent and (not terminal or terminal["terminal"] != 1):
                return response
            try:
                active = c.rpc.active_cdr_ids()
                if not isinstance(active, (set, list, tuple)) or any(not isinstance(v, str) or not HEX.fullmatch(v) for v in active) or call_id in active:
                    return response
            except Exception:
                return response
            inventory = []
            helper = None
            if row:
                if row["state"] != "failed" or row["stop_pending"] or row["publication"]:
                    return response
                if any(p.exists() or p.is_symlink() for p in self._paths(manifest)[3:]):
                    return response
                if c.db.execute("SELECT 1 FROM recording_cleanup WHERE manifest_id=?", (manifest,)).fetchone():
                    return response
                from recording_retention import RecordingRetention
                # Reuse the guarded cleanup implementation, never its timed sweep.
                helper = RecordingRetention(c, 1, 1)
                if not helper._gone(row) or not helper._journal_terminal(row, False):
                    return response
                try:
                    inventory = json.loads(intent["inventory"]) if intent else helper._inventory_failed(row)
                except (CaptureError, ValueError, TypeError):
                    return response
            elif any(p.exists() or p.is_symlink() for p in self._paths(manifest)):
                return response
            if not intent:
                with c.db:
                    c.db.execute("INSERT INTO recording_reconciliations VALUES(?,?,?,?,?,?)",
                                 (call_id, manifest, tenant, raw, canonical(inventory), "pending"))
            if row:
                try:
                    helper._complete(row, {"kind": "failed", "inventory": canonical(inventory)})
                except (CaptureError, OSError):
                    return response
            if any(p.exists() or p.is_symlink() for p in self._paths(manifest)):
                return response
            with c.db:
                c.db.execute("UPDATE recording_reconciliations SET state='released' WHERE call_id=?",
                             (call_id,))
            return {**response, "state": "released"}
