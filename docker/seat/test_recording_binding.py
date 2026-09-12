import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

from call_journal import CallJournal
from recording_binding import validate_capture_request, validate_gateway_id
from recording_capture import CaptureError
from recording_storage import prepare_storage


def digest(values):
    return hashlib.sha256(
        json.dumps(values, separators=(",", ":")).encode()
    ).hexdigest()


class RecordingBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.journal = CallJournal(self.temp.name, clock=lambda: 1000)
        self.tenant = "customer"
        self.projected = "t_" + hashlib.sha256(self.tenant.encode()).hexdigest()
        self.gateway = "https://gateway.example.test"
        self.seat = "s_" + "a" * 64
        _, self.call = self.journal.admit(
            {
                "tenantId": self.projected,
                "seatId": self.seat,
                "snapshotRevision": 7,
                "sipCallId": "synthetic",
                "fromTag": "agent",
                "legId": "",
                "destination": "+12025550100",
                "requestedCallerId": None,
                "effectiveCallerId": "+12025550101",
            }
        )
        self.controller = SimpleNamespace(journal=self.journal)
        self.command = {
            "action": "start",
            "callId": self.call,
            "manifestId": digest(
                ["recording-v1", self.gateway, self.tenant, self.call]
            )[:32],
            "binding": {
                "tenantId": self.tenant,
                "gatewayId": self.gateway,
                "callId": self.call,
                "publicCallId": digest([self.gateway, self.tenant, self.call])[:32],
                "membershipId": "member",
            },
            "admission": {"seatId": self.seat, "snapshotRevision": 7},
        }

    def tearDown(self):
        self.journal.close()
        self.temp.cleanup()

    def validate(self, command=None, issued=1000, tenant=None):
        return validate_capture_request(
            self.controller,
            tenant or self.projected,
            {"issuedAtMs": issued, "command": command or self.command},
            self.gateway,
            1000,
        )

    def test_derives_scoped_identity_and_strips_transport_admission(self):
        command = self.validate()
        self.assertNotIn("admission", command)
        self.assertEqual(command["binding"], self.command["binding"])
        self.assertEqual(command, self.validate())

    def test_rejects_cross_tenant_gateway_and_historical_seat_revision(self):
        changes = [
            ("binding", "tenantId", "other"),
            ("binding", "gatewayId", "https://other.example"),
            ("binding", "publicCallId", "0" * 32),
            ("admission", "seatId", "s_" + "b" * 64),
            ("admission", "snapshotRevision", 8),
        ]
        for section, field, value in changes:
            command = copy.deepcopy(self.command)
            command[section][field] = value
            with self.subTest(field=field), self.assertRaises(CaptureError):
                self.validate(command)
        with self.assertRaises(CaptureError):
            self.validate(tenant="t_" + "f" * 64)

    def test_rejects_stale_future_and_rebound_intents(self):
        for issued in (-30001, 6001, True):
            with self.subTest(issued=issued), self.assertRaises(CaptureError):
                self.validate(issued=issued)
        command = copy.deepcopy(self.command)
        command["manifestId"] = "0" * 32
        with self.assertRaises(CaptureError):
            self.validate(command)
        command = {
            key: value
            for key, value in self.command.items()
            if key in ("callId", "manifestId")
        }
        command["action"] = "status"
        self.assertEqual(self.validate(command), command)

    def test_storage_disabled_is_noop_and_unbounded_spool_is_rejected(self):
        prepare_storage({})
        with tempfile.TemporaryDirectory() as output:
            environment = {
                "SEAT_MODE": "managed",
                "SEAT_RECORDING_ENABLED": "1",
                "SEAT_CALL_EVENTS": "1",
                "SEAT_RECORDING_GATEWAY_ID": self.gateway,
                "SEAT_RECORDING_SPOOL_DIR": str(Path(self.temp.name).resolve()),
                "SEAT_RECORDING_OUTPUT_DIR": str(Path(output).resolve()),
            }
            with self.assertRaises(CaptureError) as error:
                prepare_storage(environment)
            self.assertEqual(error.exception.code, "SPOOL_FILESYSTEM_UNBOUNDED")
        for invalid in (
            "http://example.test",
            "https://example.test/path",
            "https://user:pass@example.test",
        ):
            with self.assertRaises(CaptureError):
                validate_gateway_id(invalid)
