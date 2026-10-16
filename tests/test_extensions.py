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
        for name in ('etc/ssh/sshd_config', 'etc/sudoers.d/root', 'etc/passwd', 'etc/group', 'usr/bin/lanrith-runtime',
                     'usr/share/lanrith/owner.crt', 'usr/lib/repart.d/10-root.conf'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                pin = self.make(root, name)
                with self.assertRaises(ReleaseError):
                    extensions.admit(root, pin)

    def test_owner_service_identities_are_locked_and_cannot_alias_core_authority(self):
        accounts = {'passwd': b'root:*:0:0:root:/root:/bin/bash\nadmin:x:982:982:Admin:/home/admin:/bin/bash\n',
                    'group': b'root:x:0:\nadmin:x:982:\n'}
        selected = extensions.identity_declarations({'users': [{'name': 'owner-service', 'uid': 2000, 'gid': 2000}],
            'groups': [{'name': 'owner-service', 'gid': 2000, 'members': ['admin']}]})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extensions.account_overlay(accounts, [selected], root)
            self.assertTrue((root/'etc/passwd').read_bytes().startswith(accounts['passwd']))
            self.assertIn('owner-service:*:2000:2000:', (root/'etc/passwd').read_text())
            self.assertIn('/usr/sbin/nologin', (root/'etc/passwd').read_text())
            self.assertIn('owner-service:x:2000:admin', (root/'etc/group').read_text())
        for uid, gid in ((0, 2000), (True, 2000), (2000, 0)):
            with self.subTest(uid=uid, gid=gid), self.assertRaises(ReleaseError):
                extensions.identity_declarations({'users': [{'name': 'owner-service', 'uid': uid, 'gid': gid}]})
        for change in ({'uid': 982}, {'name': 'admin'}, {'gid': 2001}):
            changed = {**selected, 'users': [{**selected['users'][0], **change}]}
            with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ReleaseError):
                extensions.account_overlay(accounts, [changed], Path(temporary))

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

    def test_disabled_features_do_not_activate_integrations_and_feature_units_are_independent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make(root)
            import json
            value = json.loads((root/'extension.json').read_text())
            value.update(features=['bgp', 'policy'], health_units=[],
                         health_units_by_feature={'bgp': ['frr.service'], 'policy': ['owner-policy.service']})
            encoded = canonical(value)
            (root/'extension.json').write_bytes(encoded)
            pin = hashlib.sha256(encoded).hexdigest()
            selected = {'routing': (root, pin)}
            config = {'extensions': ['routing'], 'services': {'bgp': {'enabled': False, 'configuration': 'routing'}}}
            self.assertEqual(extensions.overlay(config, selected, root/'disabled')['health_units'], [])
            config['services']['bgp']['enabled'] = True
            self.assertEqual(extensions.overlay(config, selected, root/'enabled')['health_units'], ['frr.service'])
