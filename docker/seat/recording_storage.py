"""Prepare only explicitly configured, private and filesystem-bounded capture storage."""

import os
from pathlib import Path
import stat

from recording_binding import validate_gateway_id
from recording_capture import CaptureError

MAX_SPOOL_BYTES = 128 * 1024 * 1024


def private_directory(value):
    try:
        path = Path(value)
        info = path.lstat()
        if (
            not path.is_absolute()
            or path.resolve() != path
            or not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError()
    except (TypeError, ValueError, OSError):
        raise CaptureError("PRIVATE_STORAGE_REQUIRED", 503) from None
    return path


def prepare_storage(environment):
    if (
        environment.get("SEAT_MODE") != "managed"
        or environment.get("SEAT_RECORDING_ENABLED") != "1"
    ):
        return
    if environment.get("SEAT_CALL_EVENTS") != "1":
        raise CaptureError("RECORDING_CALL_EVENTS_REQUIRED", 503)
    validate_gateway_id(environment.get("SEAT_RECORDING_GATEWAY_ID"))
    spool = private_directory(environment.get("SEAT_RECORDING_SPOOL_DIR"))
    output = private_directory(environment.get("SEAT_RECORDING_OUTPUT_DIR"))
    if spool == output or spool in output.parents or output in spool.parents:
        raise CaptureError("RECORDING_STORAGE_OVERLAP", 503)
    filesystem = os.statvfs(spool)
    if filesystem.f_blocks * filesystem.f_frsize > MAX_SPOOL_BYTES:
        raise CaptureError("SPOOL_FILESYSTEM_UNBOUNDED", 503)
    for name in ("pcaps", "metadata", "tmp"):
        child = spool / name
        child.mkdir(mode=0o700, exist_ok=True)
        private_directory(child)


if __name__ == "__main__":
    try:
        prepare_storage(os.environ)
    except CaptureError as error:
        raise SystemExit(error.code) from None
