"""Private per-manifest recording staging and bounded restart recovery."""

import os
from pathlib import Path
import re
import stat


HEX32 = re.compile(r"[a-f0-9]{32}\Z")
FILES = frozenset({"mono-0.part", "mono-1.part", "audio.part", "manifest.part"})


class RecordingStagingError(ValueError):
    pass


def _private_directory(path, mode=0o700):
    try:
        before = path.lstat()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise RecordingStagingError("private staging unavailable") from error
    info = os.fstat(fd)
    if (stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != mode
            or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino)):
        os.close(fd)
        raise RecordingStagingError("private staging invalid")
    return fd


def _name(manifest_id):
    if not isinstance(manifest_id, str) or not HEX32.fullmatch(manifest_id):
        raise RecordingStagingError("invalid manifest id")
    return ".recording-" + manifest_id


def create_staging(output_directory, manifest_id):
    """Create one non-reusable 0700 staging directory beneath a private output."""
    output = Path(output_directory)
    parent = _private_directory(output)
    name = _name(manifest_id)
    created = None
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
        created = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
        os.fchmod(created, 0o700)
        os.close(created)
        created = None
        os.fsync(parent)
    except Exception:
        if created is not None:
            os.close(created)
        os.close(parent)
        raise
    os.close(parent)
    staging = output / name
    fd = _private_directory(staging)
    os.close(fd)
    return staging


def _private_file_at(directory_fd, name):
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        file_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    except OSError as error:
        raise RecordingStagingError("invalid staging entry") from error
    try:
        info = os.fstat(file_fd)
        if (stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino)):
            raise RecordingStagingError("invalid staging entry")
        return info
    finally:
        os.close(file_fd)


def _validated_entries(staging, output, manifest_id):
    fd = _private_directory(staging)
    output_fd = None
    try:
        names = os.listdir(fd)
        if len(names) != len(set(names)) or any(name not in FILES for name in names):
            raise RecordingStagingError("unknown staging entry")
        for name in names:
            info = _private_file_at(fd, name)
            if info.st_nlink == 1:
                continue
            final_name = {"audio.part": manifest_id + ".wav", "manifest.part": manifest_id + ".json"}.get(name)
            if info.st_nlink != 2 or final_name is None:
                raise RecordingStagingError("invalid staging entry")
            if output_fd is None:
                output_fd = _private_directory(output)
            final = _private_file_at(output_fd, final_name)
            if final.st_nlink != 2 or (final.st_dev, final.st_ino) != (info.st_dev, info.st_ino):
                raise RecordingStagingError("invalid published staging link")
        return fd, names
    except Exception:
        os.close(fd)
        raise
    finally:
        if output_fd is not None:
            os.close(output_fd)


def remove_staging(output_directory, manifest_id):
    """Remove only a completely validated fixed staging directory."""
    output = Path(output_directory)
    stage_name = _name(manifest_id)
    staging = output / stage_name
    try:
        staging.lstat()
    except FileNotFoundError:
        return False
    parent = _private_directory(output)
    stage_fd = None
    try:
        stage_fd, names = _validated_entries(staging, output, manifest_id)
        for entry_name in names:
            os.unlink(entry_name, dir_fd=stage_fd)
        os.fsync(stage_fd)
        os.close(stage_fd)
        stage_fd = None
        os.rmdir(stage_name, dir_fd=parent)
        os.fsync(parent)
        return True
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        os.close(parent)


def recover_staging(output_directory, manifest_id):
    """Reclaim fixed staging after the caller proves stop and capture ownership.

    Absence is already recovered. Legacy PID-named files are deliberately
    outside this recovery boundary.
    """
    remove_staging(output_directory, manifest_id)
    return True
