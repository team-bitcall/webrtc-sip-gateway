"""Pipe-only controller subprocess for isolated failure injection; never installed."""
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, '/seat-proof')
from call_journal import CallJournal
from media_control import MediaController

if os.environ.get('BITCALL_MEDIA_LOOPBACK_FIXTURE') != '1':
    raise SystemExit('isolated fixture required')

class FixtureRpc:
    def active_cdr_ids(self):
        return {sys.argv[2]}

journal = CallJournal(Path(sys.argv[1]))
controller = MediaController(Path(sys.argv[1]), journal, FixtureRpc(),
    projection=lambda _tenant: {'status': 'applied', 'validUntil': int(time.time()) + 60})
try:
    for line in sys.stdin:
        request = json.loads(line)
        reply = controller.handle(request['tenant'], request['command'])
        print(json.dumps(reply), flush=True)
finally:
    controller.close()
    journal.close()
