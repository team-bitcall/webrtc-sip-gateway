#!/usr/bin/env python3
"""Validate and compile a bounded SEAT snapshot into Kamailio htable config."""
import argparse
import json
import os
import re
import stat
import sys
import tempfile
import time

MAX_BYTES = 4 * 1024 * 1024
MAX_SEATS = 10_000
MAX_PROFILES = 1_000
ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
USER_RE = re.compile(r"^[A-Za-z0-9+._-]{1,128}$")
HA1_RE = re.compile(r"^[0-9a-fA-F]{32}$")
DNS_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
PROXY_RE = re.compile(r"^sip:([a-z0-9.-]+):(\d{1,5});transport=(udp|tcp|tls)$")


class SnapshotError(ValueError):
    pass


def _fail(path):
    raise SnapshotError("invalid " + path)


def _keys(value, expected, path):
    if not isinstance(value, dict) or set(value) != set(expected):
        _fail(path)


def _string(value, path, limit=1024, pattern=None):
    if not isinstance(value, str) or not value or len(value) > limit:
        _fail(path)
    if pattern and not pattern.fullmatch(value):
        _fail(path)
    return value


def _integer(value, path):
    if type(value) is not int:
        _fail(path)
    return value


def _boolean(value, path):
    if type(value) is not bool:
        _fail(path)
    return value


def _dns(value, path):
    value = _string(value, path, 253)
    if value != value.lower() or not DNS_RE.fullmatch(value):
        _fail(path)
    return value


def _proxy(value, path):
    value = _string(value, path, 512)
    match = PROXY_RE.fullmatch(value)
    if not match:
        _fail(path)
    host, port, _transport = match.groups()
    try:
        port_number = int(port)
    except ValueError:
        _fail(path)
    if not 1 <= port_number <= 65535:
        _fail(path)
    # An IPv4 address is also accepted by this grammar. DNS labels remain strict.
    is_ipv4 = re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host)
    if not is_ipv4 and not DNS_RE.fullmatch(host):
        _fail(path)
    if is_ipv4 and any(int(octet) > 255 for octet in host.split(".")):
        _fail(path)
    return value, host


def validate_snapshot(data, now=None):
    """Return a normalized snapshot or raise SnapshotError without echoing values."""
    if now is None:
        now = int(time.time())
    now = _integer(now, "clock")
    _keys(
        data,
        ("schemaVersion", "revision", "issuedAt", "validUntil", "domain", "profiles", "seats"),
        "snapshot",
    )
    if _integer(data["schemaVersion"], "schemaVersion") != 1:
        _fail("schemaVersion")
    revision = _integer(data["revision"], "revision")
    issued_at = _integer(data["issuedAt"], "issuedAt")
    valid_until = _integer(data["validUntil"], "validUntil")
    if (
        revision <= 0
        or revision > 2**53 - 1
        or issued_at < 0
        or issued_at > now + 30
        or valid_until <= issued_at
        or valid_until <= now
        or valid_until > issued_at + 300
    ):
        _fail("lease")
    domain = _dns(data["domain"], "domain")
    profiles_in, seats_in = data["profiles"], data["seats"]
    if not isinstance(profiles_in, list) or len(profiles_in) > MAX_PROFILES:
        _fail("profiles")
    if not isinstance(seats_in, list) or len(seats_in) > MAX_SEATS:
        _fail("seats")

    profiles, profile_ids = [], set()
    for index, item in enumerate(profiles_in):
        path = "profiles[%d]" % index
        _keys(
            item,
            ("id", "tenantId", "enabled", "username", "realm", "requestDomain", "outboundProxy", "credential", "fromUser"),
            path,
        )
        profile_id = _string(item["id"], path + ".id", pattern=ID_RE)
        tenant_id = _string(item["tenantId"], path + ".tenantId", pattern=ID_RE)
        if profile_id in profile_ids:
            _fail(path + ".id")
        profile_ids.add(profile_id)
        request_domain = _dns(item["requestDomain"], path + ".requestDomain")
        proxy, proxy_host = _proxy(item["outboundProxy"], path + ".outboundProxy")
        if domain == request_domain or domain == proxy_host:
            _fail(path + ".upstream")
        credential = item["credential"]
        _keys(credential, ("kind", "value"), path + ".credential")
        kind = _string(credential["kind"], path + ".credential.kind", 16)
        if kind not in ("password", "ha1"):
            _fail(path + ".credential.kind")
        credential_value = _string(credential["value"], path + ".credential.value", 4096)
        if kind == "ha1" and not HA1_RE.fullmatch(credential_value):
            _fail(path + ".credential.value")
        profiles.append(
            {
                "id": profile_id,
                "tenantId": tenant_id,
                "enabled": _boolean(item["enabled"], path + ".enabled"),
                "username": _string(item["username"], path + ".username", pattern=USER_RE),
                "realm": _dns(item["realm"], path + ".realm"),
                "requestDomain": request_domain,
                "outboundProxy": proxy,
                "credential": {
                    "kind": kind,
                    "value": credential_value.lower() if kind == "ha1" else credential_value,
                },
                "fromUser": _string(item["fromUser"], path + ".fromUser", pattern=USER_RE),
            }
        )

    profile_by_id = {item["id"]: item for item in profiles}
    seats, seat_ids, usernames = [], set(), set()
    for index, item in enumerate(seats_in):
        path = "seats[%d]" % index
        _keys(item, ("id", "tenantId", "username", "profileId", "enabled", "ha1"), path)
        seat_id = _string(item["id"], path + ".id", pattern=ID_RE)
        username = _string(item["username"], path + ".username", pattern=USER_RE)
        tenant_id = _string(item["tenantId"], path + ".tenantId", pattern=ID_RE)
        profile_id = _string(item["profileId"], path + ".profileId", pattern=ID_RE)
        if seat_id in seat_ids or username in usernames:
            _fail(path + ".identity")
        if (
            profile_id not in profile_by_id
            or profile_by_id[profile_id]["tenantId"] != tenant_id
        ):
            _fail(path + ".profileId")
        ha1 = _string(item["ha1"], path + ".ha1", 32)
        if not HA1_RE.fullmatch(ha1):
            _fail(path + ".ha1")
        seat_ids.add(seat_id)
        usernames.add(username)
        seats.append(
            {
                "id": seat_id,
                "tenantId": tenant_id,
                "username": username,
                "profileId": profile_id,
                "enabled": _boolean(item["enabled"], path + ".enabled"),
                "ha1": ha1.lower(),
            }
        )
    return {
        "revision": revision,
        "validUntil": valid_until,
        "domain": domain,
        "profiles": profiles,
        "seats": seats,
    }


def _set_string(table, key, value):
    encoded = value.encode("utf-8").hex()
    return '$var(seat_value) = "%s";\n$var(seat_value) = $(var(seat_value){s.decode.hexa});\n$sht(%s=>%s) = $var(seat_value);' % (encoded, table, key)


def _set_int(table, key, value):
    return "$sht(%s=>%s) = %d;" % (table, key, value)


def snapshot_entries(normalized, tenant_id):
    """One immutable tenant generation. The active pointer is deliberately separate."""
    prefix = "%s::%d::" % (tenant_id, normalized["revision"])
    entries = [("seat_meta", prefix + "domain", normalized["domain"]),
               ("seat_meta", prefix + "valid_until", normalized["validUntil"])]
    for seat in normalized["seats"]:
        if seat["tenantId"] != tenant_id:
            continue
        seat_prefix = prefix + seat["username"] + "::"
        entries.append(("seat_index", seat["username"], tenant_id))
        for field, value in (
            ("id", seat["id"]),
            ("tenant", seat["tenantId"]),
            ("profile", seat["profileId"]),
            ("ha1", seat["ha1"]),
        ):
            entries.append(("seat_users", seat_prefix + field, value))
        entries.append(("seat_users", seat_prefix + "enabled", int(seat["enabled"])))
    for profile in normalized["profiles"]:
        if profile["tenantId"] != tenant_id:
            continue
        profile_prefix = prefix + profile["id"] + "::"
        fields = (
            ("tenant", profile["tenantId"]),
            ("username", profile["username"]),
            ("realm", profile["realm"]),
            ("request_domain", profile["requestDomain"]),
            ("outbound_proxy", profile["outboundProxy"]),
            ("credential_kind", profile["credential"]["kind"]),
            ("credential", profile["credential"]["value"]),
            ("from_user", profile["fromUser"]),
        )
        for field, value in fields:
            entries.append(("seat_profiles", profile_prefix + field, value))
        entries.append(("seat_profiles", profile_prefix + "enabled", int(profile["enabled"])))
    return entries


def render_snapshot(normalized):
    """Render the same generation layout used by runtime provisioning."""
    lines = ["#!KAMAILIO", "# Generated by compile_snapshot.py; do not edit.",
             "event_route[htable:mod-init] {"]
    tenants = sorted({item["tenantId"] for item in normalized["profiles"] + normalized["seats"]})
    for tenant in tenants:
        entries = snapshot_entries(normalized, tenant)
        entries.append(("seat_meta", tenant + "::active", str(normalized["revision"])))
        for table, key, value in entries:
            setter = _set_int if type(value) is int else _set_string
            lines.append("  " + setter(table, key, value))
    lines.append("}")
    return "\n".join(lines) + "\n"


def _read_snapshot(path):
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o077 or info.st_size > MAX_BYTES:
            _fail("input file")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            actual = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(actual.st_mode)
                or actual.st_size > MAX_BYTES
                or actual.st_mode & 0o077
                or actual.st_uid not in (0, os.geteuid())
                or (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino)
            ):
                _fail("input file")
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            _fail("input file")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _fail("input file")


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("snapshot")
        result[key] = value
    return result


def _atomic_write(path, content):
    directory = os.path.dirname(os.path.abspath(path))
    fd, temporary = tempfile.mkstemp(prefix=".seat-snapshot.", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compile a protected SEAT snapshot")
    parser.add_argument("--input", required=True, help="protected snapshot JSON path")
    parser.add_argument("--output", required=True, help="generated Kamailio config path")
    parser.add_argument("--expected-domain", help="required canonical seat domain for startup")
    parser.add_argument("--dry-run", action="store_true", help="validate only; print non-secret metadata")
    args = parser.parse_args(argv)
    try:
        normalized = validate_snapshot(_read_snapshot(args.input))
        if (
            args.expected_domain is not None
            and normalized["domain"] != _dns(args.expected_domain, "expected domain")
        ):
            _fail("expected domain")
        if args.dry_run:
            print(
                json.dumps(
                    {
                        "domain": normalized["domain"],
                        "revision": normalized["revision"],
                        "validUntil": normalized["validUntil"],
                        "profiles": len(normalized["profiles"]),
                        "seats": len(normalized["seats"]),
                    },
                    sort_keys=True,
                )
            )
        else:
            _atomic_write(args.output, render_snapshot(normalized))
    except SnapshotError as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
