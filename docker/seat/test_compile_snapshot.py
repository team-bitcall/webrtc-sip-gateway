import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compile_snapshot import SnapshotError, _atomic_write, _read_snapshot, render_snapshot, validate_snapshot


NOW = 1_700_000_000


def snapshot():
    return {
        "schemaVersion": 1,
        "revision": 7,
        "issuedAt": NOW - 2,
        "validUntil": NOW + 120,
        "domain": "seats.example.test",
        "profiles": [
            {
                "id": "profile-a",
                "tenantId": "tenant-a",
                "enabled": True,
                "username": "upstream-a",
                "realm": "carrier.example.test",
                "requestDomain": "carrier.example.test",
                "outboundProxy": "sip:proxy.carrier.test:5061;transport=tls",
                "credential": {"kind": "password", "value": "super-secret"},
                "fromUser": "caller+1",
            }
        ],
        "seats": [
            {
                "id": "seat-a",
                "tenantId": "tenant-a",
                "username": "alice+1",
                "profileId": "profile-a",
                "enabled": True,
                "ha1": "0123456789abcdef0123456789abcdef",
            }
        ],
    }


class SnapshotValidationTests(unittest.TestCase):
    def test_schema_and_strict_types_are_enforced(self):
        for key, value in (
            ("schemaVersion", 2),
            ("revision", True),
            ("issuedAt", "1700000000"),
        ):
            data = snapshot()
            data[key] = value
            with self.assertRaises(SnapshotError):
                validate_snapshot(data, NOW)
        data = snapshot()
        data["seats"][0]["unexpected"] = "x"
        with self.assertRaises(SnapshotError):
            validate_snapshot(data, NOW)

    def test_tenant_cannot_reference_another_tenants_profile(self):
        data = snapshot()
        data["seats"][0]["tenantId"] = "tenant-b"
        with self.assertRaises(SnapshotError):
            validate_snapshot(data, NOW)

    def test_replay_lease_has_tight_future_and_expiry_bounds(self):
        for issued, valid in (
            (NOW + 31, NOW + 100),
            (NOW - 400, NOW - 1),
            (NOW, NOW + 301),
        ):
            data = snapshot()
            data["issuedAt"] = issued
            data["validUntil"] = valid
            with self.assertRaises(SnapshotError):
                validate_snapshot(data, NOW)

    def test_profile_upstream_cannot_be_the_seat_realm(self):
        data = snapshot()
        data["profiles"][0]["requestDomain"] = data["domain"]
        with self.assertRaises(SnapshotError):
            validate_snapshot(data, NOW)

    def test_profile_ha1_and_duplicate_json_keys_are_rejected(self):
        data = snapshot()
        data["profiles"][0]["credential"] = {"kind": "ha1", "value": "not-an-md5"}
        with self.assertRaises(SnapshotError):
            validate_snapshot(data, NOW)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaises(SnapshotError):
                _read_snapshot(str(path))
        data = snapshot()
        data["profiles"][0]["outboundProxy"] = "sip:seats.example.test:5060;transport=udp"
        with self.assertRaises(SnapshotError):
            validate_snapshot(data, NOW)


class RenderingTests(unittest.TestCase):
    def test_secret_and_control_text_are_hex_encoded_before_config_interpolation(self):
        data = snapshot()
        data["profiles"][0]["credential"]["value"] = 'p"; $sht(evil=>key)=1; #'
        rendered = render_snapshot(validate_snapshot(data, NOW))
        self.assertNotIn('p"; $sht(evil', rendered)
        self.assertIn(data["profiles"][0]["credential"]["value"].encode().hex(), rendered)
        self.assertIn("$(var(seat_value){s.decode.hexa})", rendered)
        self.assertIn("$sht(seat_users=>tenant-a::7::alice+1::enabled) = 1;", rendered)


class FileSafetyTests(unittest.TestCase):
    def test_input_permissions_and_atomic_output_privacy(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "snapshot.json"
            output_path = Path(directory) / "snapshot.cfg"
            input_path.write_text(json.dumps(snapshot()), encoding="utf-8")
            os.chmod(input_path, 0o644)
            with self.assertRaises(SnapshotError):
                _read_snapshot(str(input_path))
            os.chmod(input_path, 0o600)
            self.assertEqual(_read_snapshot(str(input_path))["revision"], 7)
            _atomic_write(str(output_path), "safe\n")
            self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o600)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "safe\n")


if __name__ == "__main__":
    unittest.main()
