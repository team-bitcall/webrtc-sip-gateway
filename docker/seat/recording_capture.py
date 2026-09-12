"""Private fail-closed RTPengine capture producer."""

import fcntl, json, os, re, shutil, sqlite3, stat, threading, time
from pathlib import Path
from itertools import islice
from urllib.parse import urlsplit
from recording_decode import finalize_capture

try:
    from media_control import resolve_media_call
except ImportError:
    resolve_media_call = None
HEX = re.compile(r"[0-9a-f]{32}\Z")
TENANT = re.compile(r"t_[0-9a-f]{64}\Z")


class CaptureError(Exception):
    def __init__(self, code, status=503):
        self.code, self.status = code, status
        super().__init__(code)


def _dir(v):
    p = Path(v)
    try:
        i = p.lstat()
    except OSError as e:
        raise CaptureError("RECORDING_UNAVAILABLE") from e
    if (
        stat.S_ISLNK(i.st_mode)
        or not stat.S_ISDIR(i.st_mode)
        or i.st_uid != os.geteuid()
        or stat.S_IMODE(i.st_mode) != 0o700
    ):
        raise CaptureError("PRIVATE_STORAGE_REQUIRED")
    return p.resolve(strict=True)


def _fd(p, flags):
    f = os.open(p, flags | getattr(os, "O_NOFOLLOW", 0), 0o600)
    i = os.fstat(f)
    if (
        not stat.S_ISREG(i.st_mode)
        or i.st_uid != os.geteuid()
        or i.st_nlink != 1
        or stat.S_IMODE(i.st_mode) != 0o600
    ):
        os.close(f)
        raise CaptureError("PRIVATE_STORAGE_REQUIRED")
    return f


def _read(p, maximum=65536):
    try:
        before = p.lstat()
        f = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        raise CaptureError("RECORDING_METADATA_MISSING") from e
    try:
        after = os.fstat(f)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(after.st_mode)
            or after.st_uid != os.geteuid()
            or after.st_nlink != 1
            or before.st_size > maximum
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise CaptureError("RECORDING_METADATA_INVALID")
        os.fchmod(f, 0o600)
        b = os.read(f, maximum + 1)
        if len(b) > maximum:
            raise CaptureError("RECORDING_METADATA_INVALID")
        return b
    finally:
        os.close(f)


class CaptureController:
    def __init__(
        self,
        directory,
        journal,
        rpc,
        projection=None,
        ng=None,
        *,
        spool,
        output,
        call_resolver=None,
        limits=None,
        clockwallUS=lambda: int(time.time() * 1e6),
        maxSpoolBytes=128 * 1024 * 1024,
        maxConcurrent=5,
        maxJobs=100,
    ):
        self.lock = threading.RLock()
        self.db = None
        self.owner = None
        self.closed = False
        try:
            self.directory, self.spool, self.output = (
                _dir(directory),
                _dir(spool),
                _dir(output),
            )
            self.pcaps, self.metadata = _dir(self.spool / "pcaps"), _dir(
                self.spool / "metadata"
            )
            self.journal, self.rpc, self.projection, self.ng, self.call_resolver = (
                journal,
                rpc,
                projection,
                ng,
                call_resolver,
            )
            self.clock = clockwallUS
            self.max_spool, self.max_concurrent, self.max_jobs = (
                maxSpoolBytes,
                maxConcurrent,
                maxJobs,
            )
            self.limits = limits or {
                "maxInputBytes": 16 * 1024 * 1024,
                "maxOutputBytes": 32 * 1024 * 1024,
                "maxDurationSeconds": 600,
                "maxPackets": 100000,
            }
            self._config()
            self.owner = _fd(
                self.directory / "recording-capture.lock", os.O_CREAT | os.O_RDWR
            )
            try:
                fcntl.flock(self.owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as e:
                raise CaptureError("RECORDING_ALREADY_RUNNING") from e
            dbp = self.directory / "recording-captures.sqlite3"
            if dbp.exists() or dbp.is_symlink():
                i = dbp.lstat()
                if (
                    stat.S_ISLNK(i.st_mode)
                    or not stat.S_ISREG(i.st_mode)
                    or i.st_uid != os.geteuid()
                    or stat.S_IMODE(i.st_mode) != 0o600
                ):
                    raise CaptureError("PRIVATE_STORAGE_REQUIRED")
            f = _fd(dbp, os.O_CREAT | os.O_RDWR)
            os.close(f)
            self.db = sqlite3.connect(dbp, check_same_thread=False)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS captures(call_id TEXT UNIQUE NOT NULL,manifest_id TEXT UNIQUE NOT NULL,tenant_id TEXT NOT NULL,binding TEXT NOT NULL,sip_call_id TEXT,epoch TEXT,pcap TEXT,metadata TEXT,state TEXT NOT NULL,started_us INTEGER NOT NULL,ended_us INTEGER,error TEXT,stop_pending INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(manifest_id))"""
            )
            if "stop_pending" not in {
                x[1] for x in self.db.execute("PRAGMA table_info(captures)")
            }:
                with self.db:
                    self.db.execute(
                        "ALTER TABLE captures ADD COLUMN stop_pending INTEGER NOT NULL DEFAULT 0"
                    )
            if "metadata" not in {x[1] for x in self.db.execute("PRAGMA table_info(captures)")}:
                with self.db:
                    self.db.execute("ALTER TABLE captures ADD COLUMN metadata TEXT")
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS recording_cleanup(manifest_id TEXT PRIMARY KEY NOT NULL,tenant_id TEXT NOT NULL,call_id TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,wav_sha256 TEXT NOT NULL,size_bytes INTEGER NOT NULL,inventory TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','stored')))"""
            )
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS recording_cleanup_cursor(id INTEGER PRIMARY KEY CHECK(id=1),cursor INTEGER NOT NULL)"
            )
            self.db.execute("INSERT OR IGNORE INTO recording_cleanup_cursor(id,cursor) VALUES(1,0)")
            # Publish schema migrations and the retry cursor before the runtime
            # can accept a private transport request.
            self.db.commit()
            self.recovered = False
        except Exception:
            self._release()
            raise

    def _config(self):
        L = self.limits
        vals = (
            [
                L.get(k)
                for k in (
                    "maxInputBytes",
                    "maxOutputBytes",
                    "maxDurationSeconds",
                    "maxPackets",
                )
            ]
            if isinstance(L, dict)
            and set(L)
            == {"maxInputBytes", "maxOutputBytes", "maxDurationSeconds", "maxPackets"}
            else []
        )
        if (
            self.ng is None
            or self.journal is None
            or self.rpc is None
            or any(
                type(x) is not int
                for x in (self.max_spool, self.max_concurrent, self.max_jobs, *vals)
            )
            or not 24 <= self.max_spool <= 1024**4
            or not 1 <= self.max_concurrent <= 5
            or not 1 <= self.max_jobs <= 1000
            or len(vals) != 4
            or not 24 <= vals[0] <= 1024**3
            or not 52 <= vals[1] <= 2 * 1024**3
            or not 1 <= vals[2] <= 3600
            or not 1 <= vals[3] <= 10_000_000
            or vals[0] > self.max_spool
        ):
            raise CaptureError("RECORDING_UNAVAILABLE")
        if (
            os.statvfs(self.spool).f_blocks * os.statvfs(self.spool).f_frsize
            > self.max_spool
        ):
            raise CaptureError("SPOOL_FILESYSTEM_UNBOUNDED")

    def _release(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.owner is not None:
            fcntl.flock(self.owner, fcntl.LOCK_UN)
            os.close(self.owner)
            self.owner = None

    def close(self):
        with self.lock:
            if not self.closed:
                self.closed = True
                self._release()

    def _err(self, c, s=409):
        raise CaptureError(c, s)

    @staticmethod
    def _opaque(v):
        return (
            isinstance(v, str)
            and 1 <= len(v.encode()) <= 128
            and all(ord(c) >= 32 and ord(c) != 127 for c in v)
        )

    @staticmethod
    def _origin(v):
        if not isinstance(v, str):
            return False
        try:
            p = urlsplit(v)
            port = p.port
        except (TypeError, ValueError):
            return False
        return (
            len(v) <= 512
            and p.scheme in {"https", "http"}
            and bool(p.hostname)
            and not p.username
            and not p.password
            and p.path == ""
            and not p.query
            and not p.fragment
            and (p.scheme != "http" or p.hostname == "127.0.0.1")
            and (port is None or 1 <= port <= 65535)
        )

    def _identity(self, t, v):
        if (
            not TENANT.fullmatch(t or "")
            or not isinstance(v, dict)
            or v.get("action") not in {"start", "status", "finish"}
        ):
            self._err("INVALID_RECORDING_REQUEST", 400)
        req = {"action", "callId", "manifestId"} | (
            {"binding"} if v["action"] == "start" else set()
        )
        if set(v) != req or not all(
            isinstance(v.get(k), str) and HEX.fullmatch(v[k])
            for k in ("callId", "manifestId")
        ):
            self._err("INVALID_RECORDING_REQUEST", 400)
        return v

    def _binding(self, call, b):
        if (
            not isinstance(b, dict)
            or set(b)
            != {"tenantId", "gatewayId", "callId", "publicCallId", "membershipId"}
            or b.get("callId") != call
            or not isinstance(b.get("publicCallId"), str)
            or not HEX.fullmatch(b["publicCallId"])
            or not self._opaque(b.get("tenantId"))
            or not self._opaque(b.get("membershipId"))
            or not self._origin(b.get("gatewayId"))
        ):
            self._err("INVALID_RECORDING_REQUEST", 400)
        return b

    def _reply(self, r):
        return {
            "manifestId": r["manifest_id"],
            "callId": r["call_id"],
            "state": r["state"],
            **({"errorCode": r["error"]} if r["error"] else {}),
        }

    def handle(self, t, b):
        with self.lock:
            v = self._identity(t, b)
            if not self.recovered:
                self.recover()
            return {"start": self.start, "status": self.status, "finish": self.finish}[
                v["action"]
            ](t, v)

    def status(self, t, v):
        with self.lock:
            r = self.db.execute(
                "SELECT * FROM captures WHERE manifest_id=? AND call_id=? AND tenant_id=?",
                (v["manifestId"], v["callId"], t),
            ).fetchone()
            if not r:
                self._err("RECORDING_NOT_FOUND", 404)
            return self._reply(r)

    def _resolve(self, t, c):
        try:
            if self.call_resolver:
                return (
                    self.call_resolver.resolve_call(t, c)
                    if hasattr(self.call_resolver, "resolve_call")
                    else self.call_resolver(t, c)
                )
            if not resolve_media_call:
                raise RuntimeError()
            return resolve_media_call(
                t,
                c,
                journal=self.journal,
                rpc=self.rpc,
                projection=self.projection,
                ng=self.ng,
                clock=lambda: self.clock() // 1000,
            )
        except Exception as e:
            raise CaptureError("RECORDING_UNAVAILABLE") from e

    def _source(self, q, tags):
        if (
            not isinstance(q, dict)
            or q.get("result") != "ok"
            or not isinstance(q.get("tags"), dict)
            or not isinstance(tags, (list, tuple))
            or len(tags) != 2
            or len(set(tags)) != 2
        ):
            self._err("RECORDING_MEDIA_UNAVAILABLE")
        out = []
        for tag in tags:
            leg = q["tags"].get(tag)
            ms = leg.get("medias") if isinstance(leg, dict) else None
            if not isinstance(ms, list) or len(ms) != 1 or not isinstance(ms[0], dict):
                self._err("RECORDING_MEDIA_UNAVAILABLE")
            m = ms[0]
            streams = m.get("streams")
            rtp = [
                s
                for s in streams or []
                if isinstance(s, dict) and "RTP" in s.get("flags", [])
            ]
            if (
                m.get("type") != "audio"
                or m.get("codec") not in {"PCMU/8000", "PCMA/8000"}
                or not isinstance(streams, list)
                or len(rtp) != 1
            ):
                self._err("RECORDING_MEDIA_UNAVAILABLE")
            s = rtp[0]
            flags = s.get("flags", [])
            media_flags = m.get("flags", [])
            ep = s.get("endpoint")
            a = ep.get("address") if isinstance(ep, dict) else None
            p = ep.get("port") if isinstance(ep, dict) else None
            relay = s.get("local port")
            ssrc = s.get("SSRC")
            try:
                parts = a.split(".")
                valid = len(parts) == 4 and all(
                    x.isdigit() and 0 <= int(x) <= 255 for x in parts
                )
            except AttributeError:
                valid = False
            if (
                not isinstance(flags, list)
                or not isinstance(media_flags, list)
                or (
                    "DTLS-SRTP" in media_flags
                    and "DTLS fingerprint verified" not in flags
                )
                or not valid
                or any(type(x) is not int or not 1 <= x <= 65535 for x in (p, relay))
                or type(ssrc) is not int
                or not 0 <= ssrc <= 0xFFFFFFFF
            ):
                self._err("RECORDING_MEDIA_UNAVAILABLE")
            codec = m["codec"].split("/")[0]
            out.append(
                {
                    "address": a,
                    "port": p,
                    "relayPort": relay,
                    "ssrc": ssrc,
                    "payloadType": 0 if codec == "PCMU" else 8,
                    "codec": codec,
                    "tag": tag,
                }
            )
        return out

    def _available(self):
        return (
            min(shutil.disk_usage(self.spool).free, self.max_spool)
            >= self.limits["maxInputBytes"]
        )

    def _stop(self, r):
        try:
            reply = self.ng.request(
                {"command": "stop recording", "call-id": r["sip_call_id"]}
            )
            ok = isinstance(reply, dict) and (
                reply.get("result") == "ok"
                or (
                    reply.get("result") == "error"
                    and reply.get("error-reason") == "Unknown call-id"
                )
            )
        except Exception:
            ok = False
        if ok:
            with self.db:
                self.db.execute(
                    "UPDATE captures SET stop_pending=0 WHERE manifest_id=?",
                    (r["manifest_id"],),
                )
        return ok

    def start(self, t, v):
        with self.lock:
            b = self._binding(v["callId"], v["binding"])
            canon = json.dumps(b, sort_keys=True, separators=(",", ":"))
            r = self.db.execute(
                "SELECT * FROM captures WHERE manifest_id=? OR call_id=?",
                (v["manifestId"], v["callId"]),
            ).fetchone()
            if r:
                if (
                    r["manifest_id"] == v["manifestId"]
                    and r["call_id"] == v["callId"]
                    and r["tenant_id"] == t
                    and r["binding"] == canon
                ):
                    return self._reply(r)
                self._err("RECORDING_CONFLICT")
            if self.db.execute(
                "SELECT 1 FROM captures WHERE stop_pending=1 LIMIT 1"
            ).fetchone():
                self._err("RECORDING_CLEANUP_PENDING")
            if not self._available():
                self._err("RECORDING_SPOOL_FULL")
            if (
                self.db.execute("SELECT COUNT(*) n FROM captures").fetchone()["n"]
                >= self.max_jobs
                or self.db.execute(
                    "SELECT COUNT(*) n FROM captures WHERE state IN ('starting','capturing')"
                ).fetchone()["n"]
                >= self.max_concurrent
            ):
                self._err("RECORDING_LIMIT")
            sip, tags = self._resolve(t, v["callId"])
            query = self.ng.request({"command": "query", "call-id": sip})
            sources = self._source(query, tags)
            if query.get("recording") not in (None, False, 0, "no", "off"):
                self._err("RECORDING_CONFLICT")
            now = self.clock()
            epoch = {
                "sources": sources,
                "startedAtUs": now,
                "endedAtUs": now + self.limits["maxDurationSeconds"] * 1000000,
            }
            pcap = self.pcaps / (v["manifestId"] + ".pcap")
            if pcap.exists() or pcap.is_symlink():
                self._err("RECORDING_CONFLICT")
            with self.db:
                self.db.execute(
                    "INSERT INTO captures(call_id,manifest_id,tenant_id,binding,sip_call_id,epoch,pcap,state,started_us) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        v["callId"],
                        v["manifestId"],
                        t,
                        canon,
                        sip,
                        json.dumps(epoch),
                        pcap.name,
                        "starting",
                        now,
                    ),
                )
            try:
                reply = self.ng.request(
                    {
                        "command": "start recording",
                        "call-id": sip,
                        "recording-file": str(pcap),
                        "metadata": "bitcall-recording:" + v["manifestId"],
                    }
                )
                if not isinstance(reply, dict) or reply.get("result") != "ok":
                    raise CaptureError("RECORDING_UNAVAILABLE")
                with self.db:
                    self.db.execute(
                        "UPDATE captures SET state='capturing' WHERE manifest_id=?",
                        (v["manifestId"],),
                    )
            except Exception:
                with self.db:
                    self.db.execute(
                        "UPDATE captures SET state='failed',error='RECORDING_START_FAILED',stop_pending=1 WHERE manifest_id=?",
                        (v["manifestId"],),
                    )
                self._stop(
                    self.db.execute(
                        "SELECT * FROM captures WHERE manifest_id=?", (v["manifestId"],)
                    ).fetchone()
                )
            return self._reply(
                self.db.execute(
                    "SELECT * FROM captures WHERE manifest_id=?", (v["manifestId"],)
                ).fetchone()
            )

    def _ended(self, c):
        with self.journal.lock:
            term = self.journal.db.execute(
                "SELECT terminal FROM calls WHERE call_id=?", (c,)
            ).fetchone()
            rows = self.journal.db.execute(
                "SELECT payload,occurred_at FROM events WHERE call_id=? ORDER BY sequence",
                (c,),
            ).fetchall()
        try:
            es = [(json.loads(r["payload"]), r["occurred_at"]) for r in rows]
        except Exception as e:
            raise CaptureError("RECORDING_CALL_NOT_COMPLETE") from e
        ended = [at for e, at in es if e.get("type") == "ended"]
        if (
            not term
            or term["terminal"] != 1
            or not ended
            or any(e.get("type") == "uncertain" for e, _ in es)
        ):
            self._err("RECORDING_CALL_NOT_COMPLETE")
        return max(ended) * 1000

    def _metadata_file(self, r, p):
        marker = "bitcall-recording:" + r["manifest_id"]
        matches = []
        try:
            with os.scandir(self.metadata) as iterator:
                entries = list(islice(iterator, self.max_jobs + 1))
        except OSError as e:
            raise CaptureError("RECORDING_METADATA_MISSING") from e
        if len(entries) > self.max_jobs:
            self._err("RECORDING_METADATA_INVALID")
        for entry in entries:
            try:
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    continue
                raw = _read(Path(entry.path))
                lines = raw.decode("utf8", "strict").splitlines()
            except (CaptureError, UnicodeError):
                continue
            if marker in lines:
                matches.append((Path(entry.path), raw, lines))
        if len(matches) != 1:
            self._err(
                "RECORDING_METADATA_MISSING"
                if not matches
                else "RECORDING_METADATA_INVALID"
            )
        path, raw, lines = matches[0]
        if (
            not raw.endswith(b"\n")
            or not lines
            or lines[0] != str(p)
            or lines.count(marker) != 1
            or any(x.startswith("SDP mode:") for x in lines)
        ):
            self._err("RECORDING_METADATA_INVALID")
        return path

    def _files(self, r):
        try:
            p = self.pcaps / r["pcap"]
            before = p.lstat()
            f = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            i = os.fstat(f)
            if (
                p.resolve().parent != self.pcaps
                or stat.S_ISLNK(before.st_mode)
                or not stat.S_ISREG(i.st_mode)
                or i.st_uid != os.geteuid()
                or i.st_nlink != 1
                or (i.st_dev, i.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise OSError()
            os.fchmod(f, 0o600)
            os.close(f)
            return p, self._metadata_file(r, p)
        except CaptureError:
            raise
        except Exception as e:
            try:
                os.close(f)
            except Exception:
                pass
            raise CaptureError("RECORDING_CAPTURE_INVALID") from e

    def finish(self, t, v):
        with self.lock:
            r = self.db.execute(
                "SELECT * FROM captures WHERE manifest_id=? AND call_id=? AND tenant_id=?",
                (v["manifestId"], v["callId"], t),
            ).fetchone()
            if not r:
                self._err("RECORDING_NOT_FOUND", 404)
            if r["state"] in {"ready", "stored", "failed"}:
                return self._reply(r)
            ended = self._ended(r["call_id"])
            try:
                active = self.rpc.active_cdr_ids()
                q = self.ng.request({"command": "query", "call-id": r["sip_call_id"]})
            except Exception as e:
                raise CaptureError("RECORDING_CALL_NOT_COMPLETE") from e
            if r["call_id"] in active or not (
                isinstance(q, dict)
                and q.get("result") == "error"
                and q.get("error-reason") == "Unknown call-id"
            ):
                self._err("RECORDING_CALL_NOT_COMPLETE")
            try:
                p, metadata = self._files(r)
                epoch = json.loads(r["epoch"])
                epoch["endedAtUs"] = ended
                if (
                    not epoch["startedAtUs"]
                    < ended
                    <= epoch["startedAtUs"]
                    + self.limits["maxDurationSeconds"] * 1000000
                ):
                    self._err("RECORDING_CAPTURE_INVALID")
                with self.db:
                    self.db.execute(
                        "UPDATE captures SET state='finalizing',ended_us=?,epoch=?,metadata=? WHERE manifest_id=?",
                        (ended, json.dumps(epoch), metadata.name, r["manifest_id"]),
                    )
                finalize_capture(
                    p,
                    self.output,
                    r["manifest_id"],
                    json.loads(r["binding"]),
                    epoch,
                    self.limits,
                )
                with self.db:
                    self.db.execute(
                        "UPDATE captures SET state='ready',error=NULL WHERE manifest_id=?",
                        (r["manifest_id"],),
                    )
            except CaptureError as e:
                with self.db:
                    self.db.execute(
                        "UPDATE captures SET state='failed',error=? WHERE manifest_id=?",
                        (e.code, r["manifest_id"]),
                    )
            except Exception:
                with self.db:
                    self.db.execute(
                        "UPDATE captures SET state='failed',error='RECORDING_FINALIZE_FAILED' WHERE manifest_id=?",
                        (r["manifest_id"],),
                    )
            return self._reply(
                self.db.execute(
                    "SELECT * FROM captures WHERE manifest_id=?", (r["manifest_id"],)
                ).fetchone()
            )

    def recover(self):
        with self.lock:
            with self.db:
                rows = self.db.execute(
                    "SELECT * FROM captures WHERE state IN ('starting','capturing','finalizing') OR stop_pending=1"
                ).fetchall()
                for r in rows:
                    if r["state"] in {"starting", "capturing", "finalizing"}:
                        self.db.execute(
                            "UPDATE captures SET state='failed',error='RECORDING_RESTART_UNSAFE',stop_pending=1 WHERE manifest_id=?",
                            (r["manifest_id"],),
                        )
            for r in self.db.execute(
                "SELECT * FROM captures WHERE stop_pending=1"
            ).fetchall():
                self._stop(r)
            self.recovered = True

    def tick(self):
        with self.lock:
            from recording_cleanup import resume

            resume(self, 5)
            for r in self.db.execute(
                "SELECT * FROM captures WHERE stop_pending=1 AND state!='ready'"
            ).fetchall():
                self._stop(r)
            now = self.clock()
            for r in self.db.execute(
                "SELECT * FROM captures WHERE state='capturing'"
            ).fetchall():
                try:
                    oversize = (self.pcaps / r["pcap"]).exists() and (
                        self.pcaps / r["pcap"]
                    ).stat().st_size > self.limits["maxInputBytes"]
                except OSError:
                    oversize = True
                e = json.loads(r["epoch"])
                if (
                    now
                    >= e["startedAtUs"] + self.limits["maxDurationSeconds"] * 1000000
                    or not self._available()
                    or oversize
                ):
                    with self.db:
                        self.db.execute(
                            "UPDATE captures SET state='failed',error='RECORDING_LIMIT_REACHED',stop_pending=1 WHERE manifest_id=?",
                            (r["manifest_id"],),
                        )
                    self._stop(
                        self.db.execute(
                            "SELECT * FROM captures WHERE manifest_id=?",
                            (r["manifest_id"],),
                        ).fetchone()
                    )
