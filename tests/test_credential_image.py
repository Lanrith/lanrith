"""Image credentials are complete at build time and belong to the booted slot."""

import base64
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from lanrith import build, config, credential_config, credential_image, credential_operation
from lanrith import credential_values, systemd_credential
from lanrith.release import ReleaseError
from test_credential_catalog import declaration, snmp_credentials
from test_authoritative import declaration as dns_declaration
from test_routing import declaration as routing_declaration
from test_intent import minimal


def fixture(root, value=None):
    value = config.normalize(declaration() if value is None else value)
    native = {'tsig-base64': base64.b64encode(b'fake-test-key-for-image-only-00000')+b'\n',
              'bgp-token': b'synthetic-bgp-secret\n', 'radius-secret': b'A'*32+b'\n',
              'directory-password': b'synthetic-directory-password\n',
              'log-password': b'synthetic-log-password\n'}
    value['credentials'] = {}
    for item in credential_config.catalog(value)['credentials']:
        raw = native.get(item['format'])
        if item['format'] == 'snmp-user':
            raw = snmp_credentials.configuration({'username': 'synthetic-monitor',
                'auth_protocol': 'SHA-256', 'priv_protocol': 'AES',
                'auth_password': 'synthetic-auth-password', 'priv_password': 'synthetic-priv-password'},
                item['parameters']['header'])
        path = root/item['reference']
        path.write_bytes(raw)
        path.chmod(0o600)
        value['credentials'][item['reference']] = {'file': str(path)}
    return value


class ImageCredentialsTests(unittest.TestCase):
    def test_missing_credentials_fail_before_any_build_workspace_is_created(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'; base.write_bytes(b'synthetic')
            with self.assertRaisesRegex(ReleaseError, 'active service'):
                build.assembly(declaration(), base, root/'work', version='0.1.0', sequence=1)
            self.assertFalse((root/'work').exists())

    def test_all_native_credentials_are_in_root_without_upload_or_source_yaml(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = fixture(root)
            selected = credential_image.resolve(value, {})
            self.assertEqual(len(selected), 9)
            base = root/'base.tar'; base.write_bytes(b'synthetic')
            build.assembly(value, base, root/'work', version='0.1.0', sequence=1)
            tree = root/'work/mkosi.extra'
            installed = json.loads((tree/'usr/share/lanrith/installed.json').read_bytes())
            self.assertEqual(installed['credential_delivery'], 'image')
            for item in credential_config.catalog(value)['credentials']:
                path = tree/item['path'].lstrip('/')
                self.assertEqual(path.read_bytes(), selected[item['reference']])
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertFalse(any(p.suffix in ('.yaml', '.yml') for p in tree.rglob('*')))
            self.assertFalse((tree/'usr/lib/systemd/system/lanrith-credentials.socket').exists())
            self.assertFalse((tree/'etc/systemd/system/sockets.target.wants/lanrith-credentials.socket').is_symlink())
            gate = (tree/'usr/lib/systemd/system/lanrith-credential-ready.service').read_text()
            self.assertIn('TimeoutStartSec=30s', gate)
            self.assertNotIn('setup', gate)
            for path in tree.rglob('*'):
                if path.is_file() and not path.is_symlink():
                    self.assertNotIn(str(root).encode(), path.read_bytes(), str(path.relative_to(tree)))
            snmp = (tree/'usr/lib/systemd/system/snmpd.service').read_text()
            self.assertNotIn('ReadWritePaths=/var/lib/snmp /usr/', snmp)
            self.assertIn('-c /usr/lib/lanrith/credentials/core/monitor_user/snmpd.conf', snmp)

    def test_missing_and_malformed_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = fixture(root)
            for change in ('missing', 'malformed', 'inline'):
                candidate = copy.deepcopy(value)
                if change == 'missing':
                    candidate['credentials'].pop('ingest')
                elif change == 'malformed':
                    (root/'vpn_bgp').write_bytes(b'bad\nrouter bgp 42')
                else:
                    candidate['credentials']['ingest'] = {'value': 'must-not-appear-in-error'}
                with self.subTest(change=change), self.assertRaises(ValueError) as raised:
                    credential_image.resolve(config.normalize(candidate), {})
                self.assertNotIn('must-not-appear', str(raised.exception))
                (root/'vpn_bgp').write_bytes(b'synthetic-bgp-secret\n')

    def test_disabling_consumers_ignores_retained_secret_sources(self):
        cases = ((('services', 'dns', 'authoritative'), {'first_tsig', 'second_tsig'}),
                 (('routing', 'bgp'), {'vpn_bgp'}),
                 (('identity', 'radius'), {'radius_wired', 'radius_wireless', 'radius_upstream'}),
                 (('observability', 'logs'), {'ingest'}),
                 (('observability', 'snmp'), {'monitor_user'}))
        for route, removed in cases:
            with self.subTest(feature=route), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                value = fixture(root)
                selected = value
                for key in route:
                    selected = selected[key]
                selected['enabled'] = False
                # These references remain configured, but no source file exists.
                for reference in removed:
                    (root/reference).unlink()
                value = config.normalize(value)
                resolved = credential_image.resolve(value, {})
                self.assertEqual(set(resolved), set(value['credentials'])-removed)
                self.assertEqual(credential_image.validate(value, {}, resolved), resolved)
                bundle = root/'bundle'
                bundle.write_bytes(credential_image.encode(resolved)); bundle.chmod(0o600)
                self.assertEqual(credential_image.load(bundle, value, {}), resolved)
                with self.assertRaisesRegex(ReleaseError, 'credential set'):
                    credential_image.validate(value, {}, {**resolved, next(iter(removed)): b'unused-secret'})
                base = root/'base.tar'; base.write_bytes(b'synthetic')
                build.assembly(value, base, root/'work', version='0.1.0', sequence=1)
                tree = root/'work/mkosi.extra'
                catalog = json.loads((tree/'usr/share/lanrith/credentials.json').read_bytes())
                self.assertEqual({i['reference'] for i in catalog['credentials']}, set(resolved))
                for reference in removed:
                    self.assertFalse((tree/'usr/lib/lanrith/credentials/core'/reference).exists())
                if route == ('identity', 'radius'):
                    self.assertFalse((tree/'etc/freeradius/3.0/sites-enabled/lanrith_mab_fallback').exists())

    def test_basic_router_ignores_all_unused_sources_and_emits_no_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = minimal()
            value['credentials'] = {'unused': {'file': str(root/'not-present')}}
            base = root/'base.tar'; base.write_bytes(b'synthetic')
            with patch.object(credential_image, 'private_read') as read:
                build.assembly(value, base, root/'work', version='0.1.0', sequence=1)
                read.assert_not_called()
            tree = root/'work/mkosi.extra'
            self.assertFalse((tree/'usr/share/lanrith/credentials.json').exists())
            self.assertFalse((tree/'usr/lib/lanrith/credentials').exists())
            self.assertFalse((tree/'usr/lib/systemd/system/lanrith-credential-ready.service').exists())

    def test_global_dns_disable_removes_authoritative_credentials_and_boot_dependencies(self):
        from lanrith import runtime_plan, service_plane
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = fixture(root, dns_declaration())
            value['services']['dns']['enabled'] = False
            for reference in value['credentials']:
                (root/reference).unlink()
            value = config.normalize(value)
            base = root/'base.tar'; base.write_bytes(b'synthetic')
            with patch.object(credential_image, 'private_read') as read:
                build.assembly(value, base, root/'work', version='0.1.0', sequence=1)
                read.assert_not_called()
            tree = root/'work/mkosi.extra'
            self.assertFalse((tree/'usr/share/lanrith/credentials.json').exists())
            self.assertFalse((tree/'etc/bind/named.conf').exists())
            self.assertFalse((tree/'usr/lib/systemd/system/lanrith-credential-ready.service').exists())
            self.assertNotIn('authoritative', service_plane.topology(value)['endpoints'])
            self.assertNotIn('named.service', runtime_plan.required_units(value))
            self.assertNotIn('unbound.service', runtime_plan.required_units(value))
            value['translation'] = {'nat64': {'enabled': True}}
            self.assertNotIn('lanrith-dns64-private.service', runtime_plan.required_units(config.normalize(value)))

    def test_source_custody_and_staged_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = fixture(root)
            selected = credential_image.resolve(value, {})
            bundle = root/'bundle'; bundle.write_bytes(credential_image.encode(selected)); bundle.chmod(0o600)
            self.assertEqual(credential_image.load(bundle, value, {}), selected)
            path = root/'ingest'
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                credential_image.resolve(value, {})
            path.chmod(0o600)
            link = root/'linked'; link.symlink_to(path)
            value['credentials']['ingest']['file'] = str(link)
            with self.assertRaises(ValueError):
                credential_image.resolve(value, {})
            value['credentials']['ingest']['file'] = str(path)
            os.link(path, root/'hardlink')
            with self.assertRaises(ValueError):
                credential_image.resolve(value, {})

    def test_slot_rotation_changes_identity_and_rollback_reads_old_image_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = fixture(root)
            first = credential_image.resolve(value, {})
            (root/'ingest').write_bytes(b'synthetic-rotated-password\n')
            second = credential_image.resolve(value, {})
            self.assertNotEqual(credential_image.digest(first), credential_image.digest(second))
            self.assertNotEqual(config.effective_digest(value, {}, credential_digest=credential_image.digest(first)),
                                config.effective_digest(value, {}, credential_digest=credential_image.digest(second)))
            catalog = credential_config.catalog(value)
            for supplied in (first, second, first):
                def read(path, maximum, uid):
                    item = next(i for i in catalog['credentials'] if i['path'] == str(path))
                    return supplied[item['reference']]
                with patch.object(credential_operation, 'catalog', return_value=catalog), \
                        patch.object(systemd_credential, 'read', side_effect=read), \
                        patch.object(credential_operation.credential_store, 'Store') as store, \
                        patch.object(credential_operation.time, 'sleep') as sleep:
                    self.assertTrue(credential_operation.wait_ready({'credential_delivery': 'image'}))
                    store.assert_not_called()
                    sleep.assert_not_called()
            with patch.object(credential_operation, 'catalog', return_value=catalog), \
                    patch.object(systemd_credential, 'read', side_effect=FileNotFoundError), \
                    patch.object(credential_operation.time, 'sleep') as sleep:
                with self.assertRaises(FileNotFoundError):
                    credential_operation.wait_ready({'credential_delivery': 'image'})
                sleep.assert_not_called()

    def test_no_credentials_needed_for_minimal_router_and_no_runtime_mutation(self):
        self.assertEqual(credential_image.resolve(config.normalize(minimal()), {}), {})
        for action in ('status', 'stage', 'commit'):
            with self.assertRaisesRegex(ReleaseError, 'new image'):
                credential_operation.execute({'credential_delivery': 'image'}, {'action': action})

    def test_basic_disabled_and_unused_integrations_build_without_secret_files_or_gate(self):
        disabled = declaration()
        disabled['services']['dns']['authoritative']['enabled'] = False
        disabled['routing']['bgp']['enabled'] = False
        disabled['identity']['policy']['enabled'] = False
        disabled['identity']['radius']['enabled'] = False
        disabled['identity']['radius']['fallback']['enabled'] = False
        disabled['access']['rules'] = []
        for feature in ('logs', 'snmp'):
            disabled['observability'][feature]['enabled'] = False
        # The directory remains declared and enabled, but has no consumer.
        unused_directory = minimal()
        unused_directory['identity'] = {'directories': disabled['identity']['directories']}
        unused_directory['credentials'] = {'directory_bind': {'file': '/run/unused-directory-secret'}}
        static_dns = dns_declaration()
        static_dns['services']['dns']['authoritative'].pop('writers')
        pinned_bgp = routing_declaration()
        pinned_bgp['routing']['bgp']['peer_groups'].pop('vpn')
        explicit_disabled = minimal()
        explicit_disabled.update({
            'services': {'dns': {'authoritative': {'enabled': False}}},
            'routing': {'bgp': {'enabled': False}},
            'identity': {'policy': {'enabled': False}, 'radius': {'enabled': False}},
            'observability': {'logs': {'enabled': False}, 'snmp': {'enabled': False}}})
        for name, value in (('basic', minimal()), ('disabled', disabled),
                            ('explicit-disabled', explicit_disabled), ('unused-directory', unused_directory),
                            ('static-dns', static_dns), ('pinned-bgp', pinned_bgp)):
            with self.subTest(configuration=name), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(credential_image, 'private_read') as read:
                root = Path(temporary)
                base = root/'base.tar'; base.write_bytes(b'synthetic')
                normalized = config.normalize(value)
                self.assertEqual(credential_image.resolve(normalized, {}), {})
                build.assembly(value, base, root/'work', version='0.1.0', sequence=1)
                read.assert_not_called()
                tree = root/'work/mkosi.extra'
                installed = json.loads((tree/'usr/share/lanrith/installed.json').read_bytes())
                self.assertIsNone(installed['credential_catalog_sha256'])
                self.assertFalse((tree/'usr/lib/lanrith/credentials').exists())
                self.assertFalse(any('lanrith-credential' in p.name for p in
                                     (tree/'etc/systemd/system').rglob('*')))
                self.assertFalse((tree/'usr/lib/systemd/system/lanrith-credential-ready.service').exists())
                self.assertTrue((tree/'etc/unbound/unbound.conf.d/lanrith.conf').is_file())
                self.assertTrue((tree/'etc/chrony/chrony.conf').is_file())
                self.assertTrue((tree/'etc/kea/kea-dhcp4.conf').is_file())
                if name == 'static-dns':
                    self.assertTrue((tree/'etc/bind/named.conf').is_file())
                if name == 'pinned-bgp':
                    self.assertTrue((tree/'etc/frr/frr.conf').is_file())

    def test_each_used_credential_is_required_before_reading_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = fixture(root)
            for reference in value['credentials']:
                candidate = copy.deepcopy(value)
                candidate['credentials'].pop(reference)
                with self.subTest(reference=reference), \
                        patch.object(credential_image, 'private_read') as read:
                    with self.assertRaisesRegex(ReleaseError, 'active service'):
                        credential_image.resolve(candidate, {})
                    read.assert_not_called()

    def test_removing_a_dns_writer_removes_only_its_credential(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = fixture(root)
            value['services']['dns']['authoritative']['writers'].pop('second')
            (root/'second_tsig').unlink()
            selected = credential_image.resolve(config.normalize(value), {})
            self.assertEqual(set(selected), set(value['credentials'])-{'second_tsig'})
            self.assertIn('first_tsig', selected)
            self.assertEqual(len(selected), 8)


if __name__ == '__main__':
    unittest.main()
