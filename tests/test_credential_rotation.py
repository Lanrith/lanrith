"""Controller qualification against a disposable peer authorization table."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from lanrith import release


def rotation_module():
    path = Path(__file__).resolve().parents[1]/'scripts/qualify-credential-rotation.py'
    spec = importlib.util.spec_from_file_location('credential_rotation', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rotation = rotation_module()


class RotationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for slot, sequence, identity in [('candidate', 2, 'new'), ('fallback', 1, 'old')]:
            metadata = self.root/slot/'usr/share/lanrith'
            metadata.mkdir(parents=True)
            core = release.canonical({'schema': 1, 'credentials': [{'reference': 'ingest', 'format': 'log-password',
                'parameters': {}, 'path': '/usr/lib/lanrith/credentials/core/ingest'}], 'units': ['alloy.service']})
            (metadata/'credentials.json').write_bytes(core)
            (metadata/'installed.json').write_bytes(release.canonical({'image_id': 'fixture',
                'configuration_sha256': str(sequence)*64, 'uki_name': f'fixture_{sequence}.efi',
                'deployment_sequence': sequence, 'credential_catalog_sha256': hashlib.sha256(core).hexdigest()}))
            (self.root/slot/'token').write_text(identity)
        self.inventories = rotation.slots(self.root/'candidate', self.root/'fallback')
        self.plan = copy.deepcopy(self.inventories)
        for row in self.plan.values():
            row['peers']['ingest'] = {'replicated-ingest': 'overlap', 'single-ingest': 'reversal'}
        self.probe = self.root/'authenticate'
        self.probe.write_text('''#!/usr/bin/python3
import json,sys
from pathlib import Path
root=Path(__file__).parent
request=json.load(sys.stdin)
slot=root/(root/'booted').read_text()
installed=json.loads((slot/'usr/share/lanrith/installed.json').read_text())
identity={key:installed[key] for key in ('image_id','deployment_sequence','configuration_sha256','uki_name')}
allowed=json.loads((root/'peer-table').read_text())[request['peer']]
if allowed is None:
    sys.exit(1)
authenticated=(slot/'token').read_text() in allowed
print(json.dumps({'identity':identity,'challenge':request['challenge'],
                  'outcome':'authenticated' if authenticated else 'denied'}))
''')
        self.probe.chmod(0o700)

    def check(self, phase, booted, overlap, single):
        (self.root/'booted').write_text(booted)
        (self.root/'peer-table').write_text(json.dumps({'replicated-ingest': overlap, 'single-ingest': single}))
        return rotation.check(self.plan, self.inventories, phase, self.probe)

    def test_two_supported_slots_single_peer_reversal_and_retirement(self):
        new = self.check('candidate', 'candidate', ['new', 'old'], ['new'])
        with self.assertRaisesRegex(ValueError, 'single-ingest'):
            self.check('fallback', 'fallback', ['new', 'old'], ['new'])
        old = self.check('fallback', 'fallback', ['new', 'old'], ['old'])
        self.assertNotEqual(old['results'][0]['challenge'], new['results'][0]['challenge'])
        with self.assertRaisesRegex(ValueError, 'replicated-ingest'):
            self.check('fallback', 'fallback', ['new'], ['old'])
        self.check('restored-candidate', 'candidate', ['new', 'old'], ['new'])
        self.check('retired-fallback', 'fallback', ['new'], ['new'])
        self.check('retired-candidate', 'candidate', ['new'], ['new'])

    def test_wrong_boot_transport_failure_stale_catalog_incomplete_plan(self):
        with self.assertRaisesRegex(ValueError, 'authentication differs'):
            self.check('fallback', 'candidate', ['new', 'old'], ['new'])
        with self.assertRaisesRegex(ValueError, 'unavailable'):
            self.check('retired-fallback', 'fallback', None, ['new'])
        self.plan['candidate']['peers']['ingest'] = {}
        with self.assertRaisesRegex(ValueError, 'peer identities'):
            self.check('fallback', 'fallback', ['old'], ['old'])
        (self.root/'fallback/usr/share/lanrith/credentials.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'catalog differs'):
            rotation.slots(self.root/'candidate', self.root/'fallback')
