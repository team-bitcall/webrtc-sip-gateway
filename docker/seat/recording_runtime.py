#!/usr/bin/env python3
"""Separately supervised, private runtime for managed recording capture."""

import os
from pathlib import Path
import signal
import sqlite3
import stat
import threading
import time
from urllib.parse import quote

from media_control import NgClient
from recording_capture import CaptureController
from media_journal import media_checkpoint
from recording_retention import RecordingRetention
from recording_subscription import SubscriptionProducer
from recording_transport import (
    RecordingTransportError,
    RecordingTransportServer,
    private_directory,
)


class RuntimeConfigError(Exception):
    """Configuration is insufficient to enable recording."""


def enabled(environ=None):
    """Recordings are opt-in only for managed gateways."""
    environ = os.environ if environ is None else environ
    return (
        environ.get("SEAT_MODE") == "managed"
        and environ.get("SEAT_RECORDING_ENABLED") == "1"
    )


def _readonly_database(path):
    try:
        before = path.lstat()
    except OSError as error:
        raise RuntimeConfigError("private SQLite database required") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise RuntimeConfigError("private SQLite database required")
    connection = None
    try:
        connection = sqlite3.connect(
            "file:" + quote(str(path)) + "?mode=ro",
            uri=True,
            check_same_thread=False,
        )
        after = path.lstat()
        if (
            stat.S_ISLNK(after.st_mode)
            or not stat.S_ISREG(after.st_mode)
            or after.st_uid != os.geteuid()
            or after.st_nlink != 1
            or stat.S_IMODE(after.st_mode) != 0o600
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise RuntimeConfigError("private SQLite database required")
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
            raise RuntimeConfigError("read-only SQLite connection required")
        return connection
    except Exception:
        if connection is not None:
            connection.close()
        raise


class ReadOnlyJournal:
    """The small CaptureController journal interface backed by SQLite read-only mode."""

    def __init__(self, directory):
        self.directory = private_directory(directory)
        self.lock = threading.RLock()
        self.db = _readonly_database(self.directory / "call-journal.sqlite3")

    def close(self):
        self.db.close()


class ReadOnlyProjection:
    """Read a projection and verify its active revision and digest through RPC."""

    def __init__(self, directory, rpc, clock=time.time):
        self.directory = private_directory(directory)
        self.rpc = rpc
        self.clock = clock
        self.lock = threading.RLock()
        self.db = _readonly_database(self.directory / "state.sqlite3")

    def close(self):
        self.db.close()

    def __call__(self, tenant):
        with self.lock:
            row = self.db.execute(
                "SELECT tenant,revision,digest,valid_until FROM tenants WHERE tenant=?",
                (tenant,),
            ).fetchone()
        if not row:
            raise RuntimeConfigError("tenant projection missing")
        prefix = "%s::%d::" % (row["tenant"], row["revision"])
        try:
            active = self.rpc.get("seat_meta", row["tenant"] + "::active")
            ready = self.rpc.get("seat_meta", prefix + "ready")
        except Exception as error:
            raise RuntimeConfigError("projection state unavailable") from error
        status = (
            "applied"
            if active == str(row["revision"]) and ready == row["digest"]
            else "pending"
        )
        return {
            "status": status,
            "tenantId": row["tenant"],
            "revision": row["revision"],
            "contentSha256": row["digest"],
            "validUntil": row["valid_until"],
        }


def _retention_config(environ):
    names = ("SEAT_RECORDING_FAILED_RETENTION_SECONDS", "SEAT_RECORDING_STORED_RETENTION_SECONDS")
    values = [environ.get(name) for name in names]
    if all(value is None for value in values):
        return None
    if any(not isinstance(value, str) or not value.isascii() or not value.isdigit()
           or not 1 <= int(value) <= 365 * 24 * 3600 for value in values):
        raise RuntimeConfigError("both recording retention durations must be explicit seconds within 1 year")
    return {"failed_after_s": int(values[0]), "stored_after_s": int(values[1])}


def load_config(environ=None):
    """Validate all recording paths before any capture worker starts."""
    environ = os.environ if environ is None else environ
    if not enabled(environ):
        return None
    if environ.get("SEAT_CALL_EVENTS") != "1":
        raise RuntimeConfigError("SEAT_CALL_EVENTS=1 is required")
    required = (
        "SEAT_STATE_DIR",
        "SEAT_RECORDING_SPOOL_DIR",
        "SEAT_RECORDING_OUTPUT_DIR",
        "SEAT_RECORDING_GATEWAY_ID",
    )
    if any(not environ.get(name) for name in required):
        raise RuntimeConfigError("recording configuration is incomplete")
    if any(not Path(environ[name]).is_absolute() for name in required[:3]):
        raise RuntimeConfigError("recording paths must be absolute")
    try:
        from recording_storage import prepare_storage
        from recording_binding import validate_gateway_id

        prepare_storage(environ)
        gateway_id = validate_gateway_id(environ["SEAT_RECORDING_GATEWAY_ID"])
    except Exception as error:
        raise RuntimeConfigError(
            "recording storage or gateway identity is invalid"
        ) from error
    mode = environ.get("SEAT_RECORDING_CAPTURE_MODE", "pcap")
    if mode not in {"pcap", "subscription"}:
        raise RuntimeConfigError("unsupported recording capture mode")
    state = private_directory(environ["SEAT_STATE_DIR"])
    spool = private_directory(environ["SEAT_RECORDING_SPOOL_DIR"])
    output = private_directory(environ["SEAT_RECORDING_OUTPUT_DIR"])
    return {"state": state, "spool": spool, "output": output, "gateway_id": gateway_id,
            "retention": _retention_config(environ), "capture_mode": mode}


def dispatch(controller, tenant, request, gateway_id, now_ms=None, validator=None):
    """Validate the forwarded envelope, then execute the existing capture command."""
    if not isinstance(request, dict):
        raise RecordingTransportError("INVALID_RECORDING_REQUEST", 400)
    if isinstance(request.get("command"), dict) and request["command"].get("action") in {"list-ready", "manifest", "chunk", "acknowledge"}:
        from recording_binding import validate_recording_envelope
        from recording_artifacts import RecordingArtifacts
        command = validate_recording_envelope(tenant, request, int(time.time() * 1000) if now_ms is None else now_ms)
        return RecordingArtifacts(controller).handle(tenant, command)
    if validator is None:
        from recording_binding import validate_capture_request

        validator = validate_capture_request
    command = validator(
        controller,
        tenant,
        request,
        gateway_id,
        int(time.time() * 1000) if now_ms is None else now_ms,
    )
    return controller.handle(tenant, command)


class RecordingRuntime:
    """Own controller lifecycle, periodic bounded finalization, and Unix transport."""

    def __init__(self, config, rpc=None, ng=None, validator=None):
        self.config = config
        self.rpc = rpc
        self.journal = None
        self.projection = None
        self.controller = None
        self.server = None
        self.retention = None
        self.validator = validator
        self.stopping = False
        self.last_tick = 0.0
        self.failure_counts = {"periodic": 0, "finish": 0, "transport": 0, "retention": 0}
        try:
            if self.rpc is None:
                from provisioning import KamailioRpc

                self.rpc = KamailioRpc()
            self.journal = ReadOnlyJournal(config["state"])
            self.projection = ReadOnlyProjection(config["state"], self.rpc)
            self.controller = CaptureController(
                config["state"],
                self.journal,
                self.rpc,
                projection=self.projection,
                ng=ng if ng is not None else NgClient(),
                spool=config["spool"],
                output=config["output"],
                media_guard=lambda call_id, require_closed=False: media_checkpoint(self.journal, call_id, require_closed),
            )
            if config.get("capture_mode", "pcap") == "subscription":
                self.controller.producer = SubscriptionProducer(
                    self.controller.ng, self.controller.pcaps, self.controller.metadata,
                    self.controller.limits["maxInputBytes"], self.controller.limits["maxPackets"],
                )
            self.retention = RecordingRetention(self.controller, **(config.get("retention") or {}))
            self.server = RecordingTransportServer(
                config["state"],
                lambda tenant, request: dispatch(
                    self.controller,
                    tenant,
                    request,
                    config["gateway_id"],
                    validator=self.validator,
                ),
            )
        except Exception:
            self.close()
            raise

    def _failed(self, operation):
        """Retain bounded aggregate health without logging request details."""
        self.failure_counts[operation] = min(
            self.failure_counts[operation] + 1, 1_000_000
        )

    def start(self):
        """Recover under the capture lock before publishing the private socket."""
        self.controller.recover()
        self.server.open()

    def periodic(self):
        """Retry cleanup and at most five trusted, still-capturing finalizations."""
        try:
            self.controller.tick()
            with self.controller.lock:
                rows = self.controller.db.execute(
                    "SELECT tenant_id,call_id,manifest_id FROM captures WHERE state='capturing' "
                    "ORDER BY started_us LIMIT 5"
                ).fetchall()
        except Exception:
            self._failed("periodic")
            return
        for row in rows:
            try:
                self.controller.finish(
                    row["tenant_id"],
                    {
                        "action": "finish",
                        "callId": row["call_id"],
                        "manifestId": row["manifest_id"],
                    },
                )
            except Exception:
                self._failed("finish")

        if self.retention is not None:
            try:
                self.retention.sweep(limit=5)
            except Exception:
                self._failed("retention")

    def run(self):
        """Run without TCP listeners; all work remains local and bounded."""
        self.start()
        while not self.stopping:
            try:
                self.server.serve_once()
            except Exception:
                self._failed("transport")
                time.sleep(0.05)
            if time.monotonic() - self.last_tick >= 1:
                self.last_tick = time.monotonic()
                self.periodic()

    def close(self):
        self.stopping = True
        for resource in (self.server, self.controller, self.projection, self.journal):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass
        self.server = self.controller = self.projection = self.journal = None


def main():
    """Run only when managed recordings are explicitly enabled."""
    config = load_config()
    if config is None:
        return 0
    runtime = RecordingRuntime(config)

    def stop(_signum, _frame):
        runtime.stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        runtime.run()
    finally:
        runtime.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
