"""Owner integrations cannot replace boot or access authority through the file overlay."""

import hashlib
from pathlib import Path
import tempfile
import unittest

from lanrith import extensions
from lanrith.release import canonical, file_record, ReleaseError


class IntegrationTests(unittest.TestCase):
    def make(self, root, name='etc/frr/frr.conf'):
        source = root / 'root' / name
        source.parent.mkdir(parents=True)
        source.write_text('! synthetic configuration\n')
        source.chmod(0o644)
        record = file_record(source)
        record.pop('name')
        value = {'schema': 1, 'id': 'routing', 'features': ['bgp'],
                 'health_units': ['frr.service'], 'files': {name: {**record, 'mode': 0o644}}}
        encoded = canonical(value)
        (root / 'extension.json').write_bytes(encoded)
        return hashlib.sha256(encoded).hexdigest()

    def test_binds_integrations_and_feature_implementation_to_reviewed_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pin = self.make(root)
            self.assertEqual(extensions.admit(root, pin)['id'], 'routing')
            config = {'extensions': ['routing'], 'services': {'bgp': {'enabled': True, 'configuration': 'routing'}}}
            target = root / 'destination'
            result = extensions.overlay(config, {'routing': (root, pin)}, target)
            self.assertEqual(result['digests'], {'routing': pin})
            self.assertTrue((target / 'etc/frr/frr.conf').is_file())
            (root / 'root/etc/frr/frr.conf').write_text('changed\n')
            with self.assertRaises(ReleaseError):
                extensions.admit(root, pin)

    def test_protected_files_and_uninventoried_content_fail_closed(self):
        for name in ('etc/ssh/sshd_config', 'etc/sudoers.d/root', 'usr/bin/lanrith-runtime',
                     'usr/share/lanrith/owner.crt', 'usr/lib/repart.d/10-root.conf'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                pin = self.make(root, name)
                with self.assertRaises(ReleaseError):
                    extensions.admit(root, pin)

    def test_missing_extension_or_unimplemented_feature_cannot_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pin = self.make(root)
            config = {'extensions': ['routing'], 'services': {'policy': {'enabled': True, 'configuration': 'routing'}}}
            for selected in ({}, {'routing': (root, pin)}):
                with self.assertRaises(ReleaseError):
                    extensions.overlay(config, selected, root / 'output')

    def test_base_binaries_cannot_be_replaced_as_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pin = self.make(root, 'usr/bin/openssl')
            config = {'extensions': ['routing'], 'services': {}}
            with self.assertRaises(ReleaseError):
                extensions.overlay(config, {'routing': (root, pin)}, root/'output', base_files={'usr/bin/openssl'})
