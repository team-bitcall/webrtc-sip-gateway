import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from recording_subscription import SubscriptionError, SubscriptionProducer, _offered_port


MANIFEST = "a" * 32
ROW = {"manifest_id": MANIFEST, "sip_call_id": "sip-call", "pcap": MANIFEST + ".pcap"}


class Ng:
    def request(self, value):
        if value["command"] == "unsubscribe": return {"result": "ok"}
        return {"result": "ok", "tags": {}}


class FlakyNg(Ng):
    def __init__(self): self.calls, self.failed = [], False
    def request(self, value):
        self.calls.append(value)
        if value["command"] == "unsubscribe" and not self.failed:
            self.failed = True
            return {"result": "error", "error-reason": "temporary"}
        if value["command"] == "query": return {"result": "ok", "tags": {self.calls[-2]["to-tag"]: {}}}
        return super().request(value)


class StartFailNg(Ng):
    def __init__(self): self.requests = 0
    def request(self, value):
        if value["command"] == "subscribe request":
            self.requests += 1
            if self.requests == 2: raise SubscriptionError("second subscription failed")
            return {"result": "ok", "to-tag": value["to-tag"], "from-tags": value["from-tags"],
                    "sdp": "v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\na=sendonly\r\n"}
        if value["command"] == "subscribe answer": return {"result": "ok"}
        return super().request(value)


class SubscriptionTests(unittest.TestCase):
    def test_crash_metadata_prefix_and_known_hardlink_pair_recover(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pcaps, metadata = root / 'pcaps', root / 'metadata'
            pcaps.mkdir(mode=0o700); metadata.mkdir(mode=0o700)
            pcap = pcaps / (MANIFEST + '.pcap')
            pcap.touch(mode=0o600)
            producer = SubscriptionProducer(Ng(), pcaps, metadata, 1024, 10)
            partial = metadata / ('.' + MANIFEST + '.meta.tmp')
            target = metadata / (MANIFEST + '.meta')
            expected = (str(pcap.resolve()) + '\nbitcall-recording:' + MANIFEST + '\n').encode()
            partial.touch(mode=0o600); partial.write_bytes(expected[:10])
            producer.stop(ROW)  # Fresh process, no in-memory session.
            self.assertEqual(target.read_bytes(), expected)
            os.link(target, partial)
            producer.stop(ROW)
            self.assertFalse(partial.exists())
            self.assertEqual(target.stat().st_nlink, 1)
            target.unlink()
            foreign = root / 'foreign'
            foreign.touch(mode=0o600); foreign.write_bytes(expected)
            target.symlink_to(foreign)
            with self.assertRaises(OSError): producer.stop(ROW)
            self.assertEqual(foreign.read_bytes(), expected)

    def test_slow_writer_keeps_fd_and_cleanup_pending(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'pcaps').mkdir(); (root / 'metadata').mkdir()
            producer = SubscriptionProducer(Ng(), root / 'pcaps', root / 'metadata', 1024, 10)
            worker = mock.Mock()
            worker.is_alive.return_value = True
            session = {'row': ROW, 'closed': False, 'thread': worker, 'stop': mock.Mock(),
                       'sockets': [], 'fd': 7654321, 'error': None}
            producer._sessions[MANIFEST] = session
            with mock.patch('recording_subscription.os.close') as close:
                with self.assertRaisesRegex(SubscriptionError, 'still running'):
                    producer.stop(ROW)
                close.assert_not_called()
            self.assertIs(producer._sessions[MANIFEST], session)
            self.assertFalse(session['closed'])

    def test_offer_must_bind_exact_source_and_listener(self):
        sdp = "v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 1234 RTP/AVP 0\r\na=sendonly\r\n"
        self.assertEqual(_offered_port({"result": "ok", "sdp": sdp, "to-tag": "x", "from-tags": ["a"]}, "x", "a"), 1234)
        for value in ({"result": "ok", "sdp": sdp, "to-tag": "x", "from-tags": ["b"]}, {"result": "ok", "sdp": sdp, "from-tags": ["a"]}):
            with self.assertRaises(SubscriptionError): _offered_port(value, "x", "a")

    def test_finish_publishes_private_exact_metadata_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); pcaps, metadata = root / "pcaps", root / "metadata"
            pcaps.mkdir(); metadata.mkdir(); os.chmod(pcaps, 0o700); os.chmod(metadata, 0o700)
            pcap = pcaps / (MANIFEST + ".pcap"); pcap.write_bytes(b"pcap"); os.chmod(pcap, 0o600)
            producer = SubscriptionProducer(Ng(), pcaps, metadata, 1024, 10)
            target = producer._publish_metadata(ROW)
            expected = (str(pcap.resolve()) + "\nbitcall-recording:" + MANIFEST + "\n").encode()
            self.assertEqual(target.read_bytes(), expected)
            self.assertEqual(producer._publish_metadata(ROW), target)
            target.write_bytes(b"wrong")
            with self.assertRaises(SubscriptionError): producer._publish_metadata(ROW)

    def test_health_requires_live_session(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "pcaps").mkdir(); (root / "metadata").mkdir()
            producer = SubscriptionProducer(Ng(), root / "pcaps", root / "metadata", 1024, 10)
            with self.assertRaises(SubscriptionError): producer.health(ROW)

    def test_stop_attempts_both_tags_and_can_retry_after_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "pcaps").mkdir(); (root / "metadata").mkdir()
            ng = FlakyNg(); producer = SubscriptionProducer(ng, root / "pcaps", root / "metadata", 1024, 10)
            with self.assertRaises(SubscriptionError): producer.stop(ROW)
            self.assertEqual(len([item for item in ng.calls if item["command"] == "unsubscribe"]), 2)
            producer.stop(ROW)

    def test_partial_metadata_is_recovered_only_when_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); pcaps, metadata = root / "pcaps", root / "metadata"
            pcaps.mkdir(); metadata.mkdir(); os.chmod(pcaps, 0o700); os.chmod(metadata, 0o700)
            pcap = pcaps / (MANIFEST + ".pcap"); pcap.write_bytes(b"pcap"); os.chmod(pcap, 0o600)
            expected = (str(pcap.resolve()) + "\nbitcall-recording:" + MANIFEST + "\n").encode()
            temporary_meta = metadata / ("." + MANIFEST + ".meta.tmp"); temporary_meta.write_bytes(expected); os.chmod(temporary_meta, 0o600)
            target = SubscriptionProducer(Ng(), pcaps, metadata, 1024, 10)._publish_metadata(ROW)
            self.assertEqual(target.read_bytes(), expected)

    def test_partial_start_closes_and_marks_retained_pcap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); pcaps, metadata = root / "pcaps", root / "metadata"
            pcaps.mkdir(); metadata.mkdir(); os.chmod(pcaps, 0o700); os.chmod(metadata, 0o700)
            producer = SubscriptionProducer(StartFailNg(), pcaps, metadata, 4096, 10)
            try:
                with self.assertRaises(SubscriptionError): producer.start(ROW, ("agent", "remote"))
            except PermissionError:
                self.skipTest("sandbox blocks disposable loopback UDP bind")
            self.assertTrue((pcaps / (MANIFEST + ".pcap")).is_file())
            self.assertIn(("bitcall-recording:" + MANIFEST).encode(), (metadata / (MANIFEST + ".meta")).read_bytes())

    def test_writer_error_does_not_block_cleanup_but_remains_visible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); pcaps, metadata = root / "pcaps", root / "metadata"
            pcaps.mkdir(); metadata.mkdir(); os.chmod(pcaps, 0o700); os.chmod(metadata, 0o700)
            producer = SubscriptionProducer(Ng(), pcaps, metadata, 1024, 10)
            producer._sessions[MANIFEST] = {"row": ROW, "closed": True, "error": SubscriptionError("writer failed")}
            producer.stop(ROW)
            with self.assertRaises(SubscriptionError): producer.health(ROW)
            with self.assertRaises(SubscriptionError): producer.finish(ROW)


if __name__ == "__main__":
    unittest.main()
