import json
import errno
import os
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from recording_capture import CaptureError
from recording_runtime import (
    RuntimeConfigError,
    ReadOnlyProjection,
    RecordingRuntime,
    _retention_config,
    enabled,
    load_config,
)
from recording_transport import (
    RecordingTransportError,
    RecordingTransportServer,
    forward_recording,
)


class RecordingTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp", prefix="recording-")
        self.directory = Path(self.temp.name) / "state"
        self.directory.mkdir(mode=0o700)
        os.chmod(self.directory, 0o700)

    def tearDown(self):
        self.temp.cleanup()

    def _serve(self, server):
        thread = threading.Thread(target=server.serve_once)
        thread.start()
        return thread

    def _open(self, server):
        try:
            server.open()
        except PermissionError as error:
            if error.errno in {errno.EPERM, errno.EACCES}:
                self.skipTest("the desktop sandbox disallows AF_UNIX bind")
            raise

    def test_forward_result_and_error_are_bounded(self):
        server = RecordingTransportServer(
            self.directory,
            lambda tenant, request: {"tenant": tenant, "ok": request["ok"]},
        )
        self._open(server)
        thread = self._serve(server)
        self.assertEqual(
            forward_recording(self.directory, "t", {"ok": True}),
            {"tenant": "t", "ok": True},
        )
        thread.join(2)
        server.close()

        def denied(_tenant, _request):
            raise CaptureError("RECORDING_NOT_FOUND", 404)

        server = RecordingTransportServer(self.directory, denied)
        self._open(server)
        thread = self._serve(server)
        with self.assertRaises(RecordingTransportError) as caught:
            forward_recording(self.directory, "t", {})
        self.assertEqual(
            (caught.exception.code, caught.exception.status),
            ("RECORDING_NOT_FOUND", 404),
        )
        thread.join(2)
        server.close()

    def test_malformed_and_oversize_frames_fail_without_dispatch(self):
        calls = []
        server = RecordingTransportServer(
            self.directory, lambda *args: calls.append(args)
        )
        self._open(server)
        for raw in (
            b"not-json\n",
            b'{"tenantId":"a","tenantId":"b","request":{}}\n',
            b'{"tenantId":"a","request":{"value":NaN}}\n',
            b"x" * 8193,
        ):
            thread = self._serve(server)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(server.path))
                client.sendall(raw)
                reply = json.loads(client.recv(8192))
            self.assertEqual(reply["error"]["code"], "INVALID_RECORDING_REQUEST")
            thread.join(2)
        self.assertEqual(calls, [])
        server.close()

    def test_open_never_unlinks_a_live_workers_socket(self):
        owner = RecordingTransportServer(self.directory, lambda *_args: {})
        self._open(owner)
        contender = RecordingTransportServer(self.directory, lambda *_args: {})
        with self.assertRaisesRegex(
            RecordingTransportError, "RECORDING_ALREADY_RUNNING"
        ):
            contender.open()
        self.assertTrue(owner.path.exists())
        contender.close()
        owner.close()

    def test_dispatch_exception_attributes_cannot_leak_as_error_codes(self):
        class UnsafeError(Exception):
            code = "secret/path/customer"
            status = 418

        server = RecordingTransportServer(
            self.directory, lambda *_args: (_ for _ in ()).throw(UnsafeError())
        )
        self._open(server)
        thread = self._serve(server)
        with self.assertRaises(RecordingTransportError) as caught:
            forward_recording(self.directory, "t", {})
        self.assertEqual(
            (caught.exception.code, caught.exception.status),
            ("RECORDING_UNAVAILABLE", 503),
        )
        thread.join(2)
        server.close()


class ProjectionTests(unittest.TestCase):
    class Rpc:
        def __init__(self):
            self.values = {"t::active": "7", "t::7::ready": "d" * 64}

        def get(self, _table, key):
            return self.values.get(key)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name) / "state"
        self.directory.mkdir(mode=0o700)
        os.chmod(self.directory, 0o700)
        database = sqlite3.connect(self.directory / "state.sqlite3")
        database.execute(
            "CREATE TABLE tenants (tenant TEXT, revision INTEGER, digest TEXT, valid_until INTEGER)"
        )
        database.execute(
            "INSERT INTO tenants VALUES (?,?,?,?)", ("t", 7, "d" * 64, 9999999999)
        )
        database.commit()
        database.close()
        os.chmod(self.directory / "state.sqlite3", 0o600)

    def tearDown(self):
        self.temp.cleanup()

    def test_readonly_projection_requires_live_revision_and_digest(self):
        rpc = self.Rpc()
        projection = ReadOnlyProjection(self.directory, rpc)
        self.assertEqual(projection("t")["status"], "applied")
        rpc.values["t::7::ready"] = "wrong"
        self.assertEqual(projection("t")["status"], "pending")
        with self.assertRaises(sqlite3.OperationalError):
            projection.db.execute("DELETE FROM tenants")
        projection.close()


class RuntimeTests(unittest.TestCase):
    def test_default_off_and_incomplete_enabled_configuration(self):
        self.assertFalse(enabled({}))
        self.assertIsNone(load_config({"SEAT_MODE": "managed"}))
        with self.assertRaises(Exception):
            load_config(
                {
                    "SEAT_MODE": "managed",
                    "SEAT_RECORDING_ENABLED": "1",
                    "SEAT_CALL_EVENTS": "1",
                }
            )

    def test_capture_mode_defaults_to_pcap_and_only_subscription_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("state", "spool", "output"):
                directory = root / name
                directory.mkdir(mode=0o700)
                os.chmod(directory, 0o700)
            base = {
                "SEAT_MODE": "managed",
                "SEAT_RECORDING_ENABLED": "1",
                "SEAT_CALL_EVENTS": "1",
                "SEAT_STATE_DIR": str(root / "state"),
                "SEAT_RECORDING_SPOOL_DIR": str(root / "spool"),
                "SEAT_RECORDING_OUTPUT_DIR": str(root / "output"),
                "SEAT_RECORDING_GATEWAY_ID": "https://gateway.test",
            }
            with (
                mock.patch("recording_storage.prepare_storage"),
                mock.patch(
                    "recording_binding.validate_gateway_id",
                    return_value="https://gateway.test",
                ),
            ):
                self.assertEqual(load_config(base)["capture_mode"], "pcap")
                self.assertEqual(
                    load_config(
                        {**base, "SEAT_RECORDING_CAPTURE_MODE": "subscription"}
                    )["capture_mode"],
                    "subscription",
                )
                with self.assertRaises(RuntimeConfigError):
                    load_config({**base, "SEAT_RECORDING_CAPTURE_MODE": "invalid"})

    def test_periodic_finishes_only_five_capturing_rows(self):
        class Controller:
            def __init__(self):
                self.lock = threading.RLock()
                self.db = sqlite3.connect(":memory:")
                self.db.row_factory = sqlite3.Row
                self.db.execute(
                    "CREATE TABLE captures (tenant_id, call_id, manifest_id, state, started_us)"
                )
                for number in range(6):
                    self.db.execute(
                        "INSERT INTO captures VALUES (?,?,?,?,?)",
                        ("t", str(number), str(number), "capturing", number),
                    )
                self.db.execute(
                    "INSERT INTO captures VALUES (?,?,?,?,?)",
                    ("t", "x", "x", "ready", 9),
                )
                self.finished = []
                self.ticked = False

            def tick(self):
                self.ticked = True

            def finish(self, tenant, command):
                self.finished.append((tenant, command))

        runtime = RecordingRuntime.__new__(RecordingRuntime)
        runtime.controller = Controller()
        runtime.retention = None
        runtime.periodic()
        self.assertTrue(runtime.controller.ticked)
        self.assertEqual(
            [item[1]["callId"] for item in runtime.controller.finished],
            ["0", "1", "2", "3", "4"],
        )

    def test_constructor_stage_failures_close_every_created_resource(self):
        class Resource:
            def __init__(self, *args, **kwargs):
                self.closed = False

            def close(self):
                self.closed = True

        config = {
            "state": Path("/unused"),
            "spool": Path("/unused"),
            "output": Path("/unused"),
            "gateway_id": "https://gateway.example.test",
        }
        for failed_stage, expected_created in (
            ("projection", 1),
            ("controller", 2),
            ("server", 3),
        ):
            with self.subTest(stage=failed_stage):
                created = []

                def build(stage):
                    if stage == failed_stage:
                        raise RuntimeError(stage + " failed")
                    resource = Resource()
                    created.append(resource)
                    return resource

                with (
                    mock.patch(
                        "recording_runtime.ReadOnlyJournal",
                        side_effect=lambda *_args, **_kwargs: build("journal"),
                    ),
                    mock.patch(
                        "recording_runtime.ReadOnlyProjection",
                        side_effect=lambda *_args, **_kwargs: build("projection"),
                    ),
                    mock.patch(
                        "recording_runtime.CaptureController",
                        side_effect=lambda *_args, **_kwargs: build("controller"),
                    ),
                    mock.patch(
                        "recording_runtime.RecordingTransportServer",
                        side_effect=lambda *_args, **_kwargs: build("server"),
                    ),
                ):
                    with self.assertRaisesRegex(RuntimeError, failed_stage + " failed"):
                        RecordingRuntime(config, rpc=object(), ng=object())
                self.assertEqual(len(created), expected_created)
                self.assertTrue(all(resource.closed for resource in created))

    def test_periodic_failure_is_counted_without_escaping(self):
        class Controller:
            def tick(self):
                raise OSError("temporary failure")

        runtime = RecordingRuntime.__new__(RecordingRuntime)
        runtime.controller = Controller()
        runtime.failure_counts = {"periodic": 0, "finish": 0, "transport": 0}
        runtime.periodic()
        self.assertEqual(runtime.failure_counts["periodic"], 1)


class RetentionConfigurationTests(unittest.TestCase):
    def test_retention_requires_both_explicit_bounded_durations(self):
        self.assertIsNone(_retention_config({}))
        failed = "SEAT_RECORDING_FAILED_RETENTION_SECONDS"
        stored = "SEAT_RECORDING_STORED_RETENTION_SECONDS"
        self.assertEqual(
            _retention_config({failed: "86400", stored: "604800"}),
            {"failed_after_s": 86400, "stored_after_s": 604800},
        )
        for values in (
            {failed: "1"},
            {failed: "0", stored: "1"},
            {failed: "1", stored: "31536001"},
            {failed: "١", stored: "1"},
        ):
            with self.assertRaises(RuntimeConfigError):
                _retention_config(values)


if __name__ == "__main__":
    unittest.main()
