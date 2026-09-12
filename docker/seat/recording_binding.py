"""Validate authenticated application intent against local gateway admission.

Transport authentication belongs to the existing private control API. A short
request window rejects stale commands; immutable capture IDs make retries
idempotent. This module never accepts an arbitrary media path or SIP identity.
"""

import hashlib
import json
import re
from urllib.parse import urlsplit

from recording_capture import CaptureError

HEX = re.compile(r"[a-f0-9]{32}\Z")
SEAT = re.compile(r"s_[a-f0-9]{64}\Z")
TENANT = re.compile(r"t_[a-f0-9]{64}\Z")


def _reject():
    raise CaptureError("INVALID_RECORDING_REQUEST", 400)


def _exact(value, keys):
    return isinstance(value, dict) and set(value) == set(keys)


def _text(value, maximum):
    return (
        isinstance(value, str)
        and 0 < len(value.encode("utf8")) <= maximum
        and all(ord(character) >= 32 and ord(character) != 127 for character in value)
    )


def validate_gateway_id(value):
    """Require the same canonical origin the backend uses to identify this gateway."""
    try:
        parsed = urlsplit(value)
        valid = (
            _text(value, 512)
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
            and parsed.scheme in {"https", "http"}
            and (parsed.scheme == "https" or parsed.hostname == "127.0.0.1")
            and (parsed.port is None or 1 <= parsed.port <= 65535)
        )
    except (ValueError, TypeError, UnicodeError):
        valid = False
    if not valid:
        raise CaptureError("RECORDING_GATEWAY_ID_INVALID", 503)
    return value


def _digest_array(values):
    return hashlib.sha256(
        json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def validate_recording_envelope(tenant, request, now_ms):
    """Validate the private request deadline shared by capture and artifact reads."""
    if (
        not isinstance(tenant, str)
        or not TENANT.fullmatch(tenant)
        or not _exact(request, ("issuedAtMs", "command"))
    ):
        _reject()
    issued = request["issuedAtMs"]
    if type(issued) is not int or not now_ms - 30_000 <= issued <= now_ms + 5_000:
        raise CaptureError("RECORDING_REQUEST_EXPIRED", 409)
    return request["command"]


def validate_capture_request(controller, tenant, request, gateway_id, now_ms):
    """Return a controller command only after binding/deadline verification."""
    validate_recording_envelope(tenant, request, now_ms)
    command = request["command"]
    if not isinstance(command, dict) or command.get("action") not in {
        "start",
        "status",
        "finish",
    }:
        _reject()
    fields = {"action", "callId", "manifestId"}
    if command["action"] == "start":
        fields |= {"binding", "admission"}
        if "maxOutputBytes" in command:
            fields.add("maxOutputBytes")
    if not _exact(command, fields) or not all(
        isinstance(command.get(key), str) and HEX.fullmatch(command[key])
        for key in ("callId", "manifestId")
    ):
        _reject()
    if command["action"] != "start":
        return dict(command)
    if "maxOutputBytes" in command and (type(command["maxOutputBytes"]) is not int
            or not 44 <= command["maxOutputBytes"] <= 5 * 1024 * 1024 * 1024):
        _reject()
    binding, admission = command["binding"], command["admission"]
    if not _exact(
        binding, ("tenantId", "gatewayId", "callId", "publicCallId", "membershipId")
    ):
        _reject()
    try:
        valid_text = _text(binding["tenantId"], 128) and _text(
            binding["membershipId"], 128
        )
    except UnicodeError:
        valid_text = False
    if (
        not valid_text
        or binding["gatewayId"] != gateway_id
        or binding["callId"] != command["callId"]
        or not _exact(admission, ("seatId", "snapshotRevision"))
        or not isinstance(admission["seatId"], str)
        or not SEAT.fullmatch(admission["seatId"])
        or type(admission["snapshotRevision"]) is not int
        or admission["snapshotRevision"] < 1
    ):
        _reject()
    projected_tenant = "t_" + hashlib.sha256(binding["tenantId"].encode()).hexdigest()
    public_id = _digest_array([gateway_id, binding["tenantId"], command["callId"]])[:32]
    manifest_id = _digest_array(
        ["recording-v1", gateway_id, binding["tenantId"], command["callId"]]
    )[:32]
    if (
        tenant != projected_tenant
        or binding["publicCallId"] != public_id
        or command["manifestId"] != manifest_id
    ):
        raise CaptureError("RECORDING_BINDING_MISMATCH", 409)
    with controller.journal.lock:
        row = controller.journal.db.execute(
            "SELECT context FROM calls WHERE call_id=? AND tenant_id=?",
            (command["callId"], tenant),
        ).fetchone()
    try:
        context = json.loads(row["context"]) if row else None
    except (ValueError, TypeError):
        context = None
    if (
        not isinstance(context, dict)
        or context.get("seatId") != admission["seatId"]
        or context.get("snapshotRevision") != admission["snapshotRevision"]
    ):
        raise CaptureError("RECORDING_BINDING_MISMATCH", 409)
    # Internal membership is resolved from the backend's immutable historical
    # seat binding. The gateway proves the corresponding admission, not email/login.
    return {key: value for key, value in command.items() if key != "admission"}
