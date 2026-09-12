"""Durable, restart-safe removal of recordings acknowledged by durable storage."""

import json
import os
from pathlib import Path
import stat

from recording_capture import CaptureError


MAX_SIZE = 5 * 1024 * 1024 * 1024


def _fail(code, status=503):
    raise CaptureError(code, status)


def _private_identity(path):
    try:
        before = path.lstat()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        _fail("RECORDING_ARTIFACT_UNAVAILABLE")
    try:
        info = os.fstat(fd)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino)
        ):
            _fail("RECORDING_ARTIFACT_UNAVAILABLE")
        return {
            "dev": info.st_dev, "ino": info.st_ino, "size": info.st_size,
            "uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode),
        }
    finally:
        os.close(fd)


def _path(controller, row, role, name):
    expected = {
        "wav": (Path(controller.output), row["manifest_id"] + ".wav"),
        "manifest": (Path(controller.output), row["manifest_id"] + ".json"),
        "pcap": (Path(controller.pcaps), row["manifest_id"] + ".pcap"),
        "metadata": (Path(controller.metadata), name),
    }.get(role)
    if expected is None or not isinstance(name, str) or Path(name).name != name:
        _fail("RECORDING_ARTIFACT_UNAVAILABLE")
    directory, fixed_name = expected
    if name != fixed_name:
        _fail("RECORDING_ARTIFACT_UNAVAILABLE")
    return directory / name


def _inventory(controller, row):
    # Metadata was discovered while finalizing. Older ready rows get the same
    # bounded marker/first-line validation before an acknowledgement can exist.
    metadata = row["metadata"]
    pcap = _path(controller, row, "pcap", row["pcap"])
    selected = controller._metadata_file(row, pcap).name
    if metadata and metadata != selected:
        _fail("RECORDING_ARTIFACT_UNAVAILABLE")
    metadata = selected
    names = {
        "wav": row["manifest_id"] + ".wav",
        "manifest": row["manifest_id"] + ".json",
        "pcap": row["pcap"],
        "metadata": metadata,
    }
    entries = []
    for role in ("wav", "manifest", "pcap", "metadata"):
        path = _path(controller, row, role, names[role])
        identity = _private_identity(path)
        entries.append({"role": role, "path": names[role], **identity})
    return entries, metadata


def _same_receipt(saved, command):
    return (
        saved["manifest_sha256"] == command["manifestSha256"]
        and saved["wav_sha256"] == command["sha256"]
        and saved["size_bytes"] == command["sizeBytes"]
    )


def _remove(controller, row, entry):
    path = _path(controller, row, entry["role"], entry["path"])
    try:
        current = path.lstat()
    except FileNotFoundError:
        return  # A durable intent makes an earlier crash's completed unlink safe.
    except OSError:
        _fail("RECORDING_CLEANUP_PENDING")
    identity = _private_identity(path)
    if (identity["dev"], identity["ino"], identity["size"], identity["uid"], identity["mode"]) != (
        entry["dev"], entry["ino"], entry["size"], entry["uid"], entry["mode"]
    ) or (current.st_dev, current.st_ino) != (entry["dev"], entry["ino"]):
        _fail("RECORDING_CLEANUP_PENDING")
    try:
        os.unlink(path)
    except OSError:
        _fail("RECORDING_CLEANUP_PENDING")


def _complete(controller, row, cleanup):
    try:
        entries = json.loads(cleanup["inventory"])
    except (TypeError, ValueError):
        _fail("RECORDING_CLEANUP_PENDING")
    if not isinstance(entries, list) or len(entries) != 4:
        _fail("RECORDING_CLEANUP_PENDING")
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"role", "path", "dev", "ino", "size", "uid", "mode"}:
            _fail("RECORDING_CLEANUP_PENDING")
        if entry["role"] not in {"wav", "manifest", "pcap", "metadata"} or any(
            type(entry[key]) is not int or entry[key] < 0 for key in ("dev", "ino", "size", "uid", "mode")
        ):
            _fail("RECORDING_CLEANUP_PENDING")
    if {entry["role"] for entry in entries} != {"wav", "manifest", "pcap", "metadata"}:
        _fail("RECORDING_CLEANUP_PENDING")
    for entry in entries:
        _remove(controller, row, entry)
    for directory in (Path(controller.output), Path(controller.pcaps), Path(controller.metadata)):
        fd = None
        try:
            fd = os.open(directory, os.O_RDONLY)
            os.fsync(fd)
        except OSError:
            _fail("RECORDING_CLEANUP_PENDING")
        finally:
            if fd is not None:
                os.close(fd)
    with controller.db:
        controller.db.execute("UPDATE recording_cleanup SET state='stored' WHERE manifest_id=?", (row["manifest_id"],))
        controller.db.execute("UPDATE captures SET state='stored',error=NULL WHERE manifest_id=?", (row["manifest_id"],))
    return True


def acknowledge(controller, tenant, command):
    """Serialize receipt creation and cleanup for direct callers as well as transport RPC."""
    with controller.lock:
        return _acknowledge(controller, tenant, command)


def _acknowledge(controller, tenant, command):
    """Persist a matching durable receipt before any local artifact can be unlinked."""
    from recording_artifacts import RecordingArtifacts

    reader = RecordingArtifacts(controller)
    row = reader._row(tenant, command, ready_only=False)
    existing = controller.db.execute("SELECT * FROM recording_cleanup WHERE manifest_id=?", (row["manifest_id"],)).fetchone()
    if existing:
        if (
            existing["tenant_id"] != tenant or existing["call_id"] != row["call_id"]
            or not _same_receipt(existing, command)
        ):
            _fail("RECORDING_ACK_MISMATCH", 409)
        if existing["state"] == "stored":
            return {"callId": row["call_id"], "manifestId": row["manifest_id"], "state": "stored"}
    else:
        if row["state"] != "ready":
            _fail("RECORDING_NOT_READY", 409)
        manifest, _raw, manifest_sha = reader._manifest(row)
        fd, size = reader._wav(row, manifest)
        os.close(fd)
        if (
            command["manifestSha256"] != manifest_sha
            or command["sha256"] != manifest["sha256"]
            or command["sizeBytes"] != size
        ):
            _fail("RECORDING_ACK_MISMATCH", 409)
        inventory, metadata = _inventory(controller, row)
        with controller.db:
            controller.db.execute("UPDATE captures SET metadata=? WHERE manifest_id=?", (metadata, row["manifest_id"]))
            controller.db.execute(
                "INSERT INTO recording_cleanup(manifest_id,tenant_id,call_id,manifest_sha256,wav_sha256,size_bytes,inventory,state) VALUES(?,?,?,?,?,?,?,'pending')",
                (row["manifest_id"], tenant, row["call_id"], command["manifestSha256"], command["sha256"], command["sizeBytes"], json.dumps(inventory, sort_keys=True, separators=(",", ":"))),
            )
        existing = controller.db.execute("SELECT * FROM recording_cleanup WHERE manifest_id=?", (row["manifest_id"],)).fetchone()
    try:
        done = existing["state"] == "stored" or _complete(controller, row, existing)
    except CaptureError:
        done = False
    return {"callId": row["call_id"], "manifestId": row["manifest_id"], "state": "stored" if done else "cleanup_pending"}


def resume(controller, limit=5):
    """Retry a bounded set of previously acknowledged cleanup intents."""
    cursor = controller.db.execute("SELECT cursor FROM recording_cleanup_cursor WHERE id=1").fetchone()[0]
    rows = controller.db.execute(
        "SELECT c.rowid AS cleanup_rowid,c.*,r.inventory,r.state AS cleanup_state FROM recording_cleanup r JOIN captures c ON c.manifest_id=r.manifest_id WHERE r.state='pending' ORDER BY CASE WHEN c.rowid>? THEN 0 ELSE 1 END,c.rowid LIMIT ?",
        (cursor, limit),
    ).fetchall()
    for row in rows:
        try:
            _complete(controller, row, row)
        except CaptureError:
            pass
    if rows:
        with controller.db:
            controller.db.execute("UPDATE recording_cleanup_cursor SET cursor=? WHERE id=1", (rows[-1]["cleanup_rowid"],))
