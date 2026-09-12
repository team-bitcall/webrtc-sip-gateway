#!/usr/bin/env python3
"""Independent, bounded cleanup for expired RTPengine listener subscriptions.

This is deliberately a best-effort expiry guard, not a native RTPengine TTL.
It only issues ``unsubscribe`` for its listener tag and never deletes a call.
"""
import argparse
import os
from pathlib import Path
import sqlite3
import stat
import time

from media_control import MediaError, NgClient, TAG


class MediaWatchdog:
    def __init__(self, directory, *, ng=None, clock=lambda: int(time.time() * 1000)):
        directory = Path(directory)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise MediaError("MEDIA_UNAVAILABLE")
        path = directory / "media-control.sqlite3"
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise MediaError("MEDIA_UNAVAILABLE")
        self.db = sqlite3.connect(path, timeout=.05)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout=50")
        self.ng, self.clock = ng or NgClient(), clock
        self.cursor = 0

    def close(self):
        self.db.close()

    def _unsubscribe(self, row):
        if not isinstance(row["sip_call_id"], str) or not isinstance(row["listener_tag"], str) \
                or not TAG.fullmatch(row["listener_tag"]):
            return False
        try:
            reply = self.ng.request({"command": "unsubscribe", "call-id": row["sip_call_id"],
                                     "to-tag": row["listener_tag"]})
        except (MediaError, OSError):
            return False
        return reply.get("result") == "ok" or (
            reply.get("result") == "error" and reply.get("error-reason") == "Unknown call-id")

    def sweep(self):
        """One bounded pass; completed tombstones are retried until pruned."""
        now = self.clock()
        try:
            rows = self.db.execute("SELECT rowid AS db_rowid, * FROM sessions WHERE rowid>? AND state IN "
                                   "('starting','negotiating','answering','listening','stopping','ended') "
                                   "ORDER BY rowid LIMIT 32", (self.cursor,)).fetchall()
            if not rows and self.cursor:
                self.cursor = 0
                rows = self.db.execute("SELECT rowid AS db_rowid, * FROM sessions WHERE state IN "
                                       "('starting','negotiating','answering','listening','stopping','ended') "
                                       "ORDER BY rowid LIMIT 32").fetchall()
        except sqlite3.Error:
            return 0
        if rows:
            self.cursor = rows[-1]["db_rowid"]
        cleaned = 0
        for row in rows:
            state, expired = row["state"], row["expires_at"] <= now
            if state != "ended" and state != "stopping" and not expired:
                continue
            if state not in ("stopping", "ended"):
                try:
                    with self.db:
                        changed = self.db.execute("UPDATE sessions SET state='stopping', updated_at=? "
                                                  "WHERE tenant_id=? AND listener_id=? AND fence=? "
                                                  "AND state=? AND expires_at<=?", (now, row["tenant_id"], row["listener_id"],
                                                                                      row["fence"], state, now)).rowcount
                    if changed != 1:
                        continue
                except sqlite3.Error:
                    continue
            if not self._unsubscribe(row):
                continue
            if state != "ended":
                try:
                    with self.db:
                        changed = self.db.execute("UPDATE sessions SET state='ended', offer_sdp=NULL, updated_at=? "
                                                  "WHERE tenant_id=? AND listener_id=? AND fence=? AND state='stopping'",
                                                  (now, row["tenant_id"], row["listener_id"], row["fence"])).rowcount
                    cleaned += changed
                except sqlite3.Error:
                    continue
        return cleaned


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if os.environ.get("SEAT_MODE") != "managed" or os.environ.get("SEAT_MEDIA_ENABLED") != "1":
        return 0
    guard = MediaWatchdog(os.environ.get("SEAT_STATE_DIR", ""))
    try:
        if args.once:
            guard.sweep()
            return 0
        while True:
            guard.sweep()
            time.sleep(1)
    finally:
        guard.close()


if __name__ == "__main__":
    raise SystemExit(main())
