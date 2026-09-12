import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from call_journal import CallJournal
from recording_capture import CaptureController, CaptureError
from recording_reconciliation import RecordingReconciliation, canonical, digest
import test_recording_retention as fixture


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.journal = CallJournal(self.temp.name, clock=lambda: 1000)
        self.tenant = 't_' + hashlib.sha256(b'customer').hexdigest()
        _, self.call = self.journal.admit({
            'tenantId': self.tenant, 'seatId': fixture.SEAT, 'snapshotRevision': 1,
            'sipCallId': 'sip', 'fromTag': 'from', 'legId': '', 'destination': '+1',
            'requestedCallerId': None, 'effectiveCallerId': 'user'})
        self.c = fixture.Controller(Path(self.temp.name), self.journal)
        self.c.db.execute('ALTER TABLE captures ADD COLUMN binding TEXT')
        self.c.db.commit()
        self.binding = {'tenantId': 'customer', 'gatewayId': 'https://gateway.test',
                        'callId': self.call, 'membershipId': 'member',
                        'publicCallId': digest(['https://gateway.test', 'customer', self.call])[:32]}
        self.manifest = digest(['recording-v1', 'https://gateway.test', 'customer', self.call])[:32]
        self.command = {'action': 'reconcile', 'callId': self.call,
                        'manifestId': self.manifest, 'binding': self.binding}
        self.service = RecordingReconciliation(self.c)

    def tearDown(self):
        self.c.db.close()
        self.journal.close()
        self.temp.cleanup()

    def terminal(self):
        self.journal.append({'callId': self.call, 'type': 'ended', 'legId': '',
                             'sipCode': 200, 'reason': 'normal', 'endedBy': 'agent'})

    def test_absent_terminal_release_survives_reopen_and_blocks_late_start(self):
        self.terminal()
        result = self.service.reconcile(self.tenant, self.command)
        self.assertEqual(result['state'], 'released')
        self.c.db.close()
        self.c = fixture.Controller(Path(self.temp.name), self.journal)
        self.assertEqual(RecordingReconciliation(self.c).reconcile(self.tenant, self.command), result)
        def reject(code):
            raise CaptureError(code, 409)
        self.c._err = reject
        with self.assertRaisesRegex(CaptureError, 'RECORDING_RECONCILED'):
            CaptureController.start(self.c, self.tenant, self.command)
        changed = {**self.command, 'binding': {**self.binding, 'membershipId': 'other'}}
        with self.assertRaises(CaptureError):
            RecordingReconciliation(self.c).reconcile(self.tenant, changed)

    def test_active_pending_has_no_fence_and_wrong_tenant_rejected(self):
        self.assertEqual(self.service.reconcile(self.tenant, self.command)['state'], 'pending')
        self.assertIsNone(self.c.db.execute('SELECT 1 FROM recording_reconciliations').fetchone())
        with self.assertRaises(CaptureError):
            self.service.reconcile('t_' + 'f' * 64, self.command)

    def failed(self):
        self.terminal()
        pcap = self.c.pcaps / (self.manifest + '.pcap')
        meta = self.c.metadata / (self.manifest + '.meta')
        pcap.write_bytes(b'raw')
        meta.write_text(str(pcap) + '\nbitcall-recording:' + self.manifest + '\n')
        os.chmod(pcap, 0o600)
        os.chmod(meta, 0o600)
        self.c.db.execute('INSERT INTO captures VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                          (self.call, self.manifest, self.tenant, 'sip', pcap.name, meta.name,
                           'failed', 0, 0, 0, None, canonical(self.binding)))
        self.c.db.commit()
        return pcap, meta

    def test_failed_raw_cleanup_is_durable_and_replayable(self):
        pcap, meta = self.failed()
        with mock.patch.object(fixture.RecordingRetention, '_complete', side_effect=OSError('interrupted')):
            self.assertEqual(self.service.reconcile(self.tenant, self.command)['state'], 'pending')
        self.assertTrue(pcap.exists())
        self.assertEqual(self.service.reconcile(self.tenant, self.command)['state'], 'released')
        self.assertFalse(pcap.exists())
        self.assertFalse(meta.exists())
        self.assertIsNone(self.c.db.execute('SELECT 1 FROM captures').fetchone())

    def test_replaced_failed_artifact_stays_pending(self):
        pcap, meta = self.failed()
        with mock.patch.object(fixture.RecordingRetention, '_complete', side_effect=OSError('interrupted')):
            self.service.reconcile(self.tenant, self.command)
        meta.rename(meta.with_suffix('.held'))
        meta.write_bytes(b'foreign')
        os.chmod(meta, 0o600)
        self.assertEqual(self.service.reconcile(self.tenant, self.command)['state'], 'pending')
        self.assertEqual(meta.read_bytes(), b'foreign')

    def test_ready_capture_and_stray_artifact_are_never_released(self):
        pcap, _meta = self.failed()
        self.c.db.execute("UPDATE captures SET state='ready'")
        self.c.db.commit()
        self.assertEqual(self.service.reconcile(self.tenant, self.command)['state'], 'pending')
        self.assertTrue(pcap.exists())
        self.assertIsNone(self.c.db.execute('SELECT 1 FROM recording_reconciliations').fetchone())
