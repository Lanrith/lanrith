"""Provisioning exposes only active image-owned bindings and native grammars."""

import base64
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from lanrith import config, credential_config, credential_values, logs_runtime, policy_runtime, radius_runtime, routing_runtime
from lanrith.release import ReleaseError
from test_intent import minimal
from test_radius import declaration as radius_declaration
from test_authoritative import declaration as dns_declaration
from test_routing import declaration as routing_declaration

HELPERS = Path(__file__).parents[1]/'mkosi/base/mkosi.extra/usr/lib/lanrith'
sys.path.insert(0, str(HELPERS))
import snmp_credentials


def declaration():
    value = radius_declaration()
    value['services'] = dns_declaration()['services']
    route = routing_declaration()
    value['groups'].update(route['groups'])
    value['routing'] = route['routing']
    value['observability'] = {
        'logs': {'enabled': True, 'endpoint': 'https://192.168.10.31/otlp',
                 'tls_server_name': 'logs.example.test', 'username': 'synthetic-router', 'credential': 'ingest'},
        'snmp': {'enabled': True, 'username': 'synthetic-monitor', 'credential': 'monitor_user',
                 'clients': [{'network': 'home', 'addresses': 'fd42:1234:5678:10::50'}]},
    }
    return value


class CredentialCatalogTests(unittest.TestCase):
    def test_catalog_projects_all_active_native_consumers_without_source_or_values(self):
        value = config.normalize(declaration())
        catalog = credential_config.catalog(value)
        self.assertEqual(len(catalog['credentials']), 9)
        self.assertEqual({item['format'] for item in catalog['credentials']}, credential_config.FORMATS)
        self.assertEqual([item['reference'] for item in catalog['credentials']], sorted(
            ['first_tsig', 'second_tsig', 'vpn_bgp', 'directory_bind', 'radius_wired', 'radius_wireless',
             'radius_upstream', 'ingest', 'monitor_user']))
        snmp = next(item for item in catalog['credentials'] if item['format'] == 'snmp-user')
        self.assertEqual(snmp['parameters']['username'], 'synthetic-monitor')
        self.assertEqual(snmp['path'], '/var/lib/lanrith/snmp/snmpd.conf')
        self.assertTrue(set(catalog['units']) <= credential_config.UNITS)
        encoded = credential_config.encoded(value)
        self.assertEqual(json.loads(encoded), catalog)
        for content in ('access', 'base_dn', 'bind_dn', 'hardware', 'networks', 'groups', 'authorized_keys'):
            self.assertNotIn(('"'+content+'"').encode(), encoded)
        self.assertEqual(credential_config.catalog(config.normalize(minimal())),
                         {'schema': 1, 'credentials': [], 'units': []})

    def test_disabling_each_consumer_removes_its_secret_requirements(self):
        original = config.normalize(declaration())
        for route, removed in ((('services', 'dns', 'authoritative'), {'first_tsig', 'second_tsig'}),
                               (('routing', 'bgp'), {'vpn_bgp'}),
                               (('identity', 'policy'), {'directory_bind'}),
                               (('identity', 'radius'), {'radius_wired', 'radius_wireless', 'radius_upstream'}),
                               (('observability', 'logs'), {'ingest'}),
                               (('observability', 'snmp'), {'monitor_user'})):
            value = copy.deepcopy(original)
            selected = value
            for key in route:
                selected = selected[key]
            selected['enabled'] = False
            actual = {item['reference'] for item in credential_config.catalog(value)['credentials']}
            self.assertEqual(actual, {i['reference'] for i in credential_config.catalog(original)['credentials']}-removed)

    def test_render_and_assembly_emit_metadata_and_runtime_grammar_without_the_compiler(self):
        from lanrith import build
        value = declaration()
        files = config.render(value)
        self.assertEqual(json.loads(files['usr/share/lanrith/credentials.json']),
                         credential_config.catalog(config.normalize(value)))
        self.assertNotIn('usr/share/lanrith/credentials.json', config.render(minimal()))
        self.assertIn('usr/lib/systemd/system/lanrith-credentials.socket', files)
        self.assertNotIn('usr/lib/systemd/system/lanrith-credentials.socket', config.render(minimal()))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic base input')
            build.assembly(minimal(), base, root/'work', version='0.1.0', sequence=12)
            tree = root/'work/mkosi.extra/usr/lib/lanrith'
            self.assertTrue((tree/'lanrith/credential_values.py').is_file())
            self.assertTrue((tree/'lanrith/credential_store.py').is_file())
            self.assertTrue((tree/'snmp_credentials.py').is_file())
            for name in ('snmp_service.py', 'credential_runtime.py', 'systemd_service.py'):
                self.assertTrue((tree/name).is_file())
            self.assertFalse((tree/'lanrith/credential_config.py').exists())

    def test_runtime_catalog_refuses_extra_commands_units_and_format_parameters(self):
        original = credential_config.catalog(config.normalize(declaration()))
        for change in ({'schema': True}, {'units': ['ssh.service']}, {'source_yaml': 'owner.yaml'}):
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                credential_values.validate_catalog({**original, **change})
        for change in ({'format': 'shell'}, {'parameters': {'command': 'anything'}}, {'path': '/etc/shadow'},
                       {'path': '/var/lib/arbitrary-owner/../escape'}, {'reference': 'other\nname'}):
            value = copy.deepcopy(original)
            value['credentials'][0].update(change)
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                credential_values.validate_catalog(value)

    def test_private_paths_are_bound_but_overlapping_or_control_state_paths_are_refused(self):
        value = config.normalize(declaration())
        value['runtime'] = {'credentials': {'ingest': '/var/lib/arbitrary-owner/secrets/ingest'}}
        item = next(i for i in credential_config.catalog(value)['credentials'] if i['reference'] == 'ingest')
        self.assertEqual(item['path'], value['runtime']['credentials']['ingest'])
        for path in ('/var/lib/lanrith/image-operation.json', '/var/lib/secret',
                     '/var/lib/lanrith/credential-provisioning/committed.json',
                     '/var/lib/arbitrary-owner/.lock', '/var/lib/arbitrary-owner/.activation.lock',
                     '/var/lib/arbitrary-owner/.provisioning-write-credential',
                     '/var/lib/arbitrary-owner/../escape'):
            value['runtime']['credentials']['ingest'] = path
            with self.subTest(path=path), self.assertRaises(ReleaseError):
                credential_config.catalog(value)
        value['runtime']['credentials'] = {'ingest': '/var/lib/arbitrary-owner/keys',
                                           'directory_bind': '/var/lib/arbitrary-owner/keys/bind'}
        with self.assertRaises(ReleaseError):
            credential_config.catalog(value)

    def test_shared_references_require_identical_native_grammars(self):
        value = config.normalize(declaration())
        value['identity']['radius']['clients']['wireless']['credential'] = 'radius_wired'
        self.assertEqual(len(credential_config.catalog(value)['credentials']), 8)
        value['observability']['logs']['credential'] = 'directory_bind'
        with self.assertRaises(ReleaseError):
            credential_config.catalog(value)

    def test_every_native_grammar_rejects_directive_and_encoding_substitution(self):
        valid = {'tsig-base64': base64.b64encode(b'x'*32)+b'\n', 'bgp-token': b'bounded-token_123\n',
                 'radius-secret': b'A'*32+b'\n', 'directory-password': 'bounded-UTF8-ä'.encode()+b'\n',
                 'log-password': b'bounded-log-password\n'}
        invalid = {'tsig-base64': (b'not-base64', base64.b64encode(b'x'*15), b'AAAA\nAAAA'),
                   'bgp-token': (b'A'*81, b'good\nrouter bgp 1', b'"break"'),
                   'radius-secret': (b'A'*31, b'A'*257, b'{"shared_secret":"'+b'A'*32+b'","command":"x"}',
                                     b'{"shared_secret":"'+b'A'*32+b'","shared_secret":"'+b'B'*32+b'"}'),
                   'directory-password': (b'\x00', b'\xff', b'A'*4097),
                   'log-password': (b'good\nbad', b'good\rbad', b'\x00', b'A'*4097)}
        for kind, raw in valid.items():
            item = {'format': kind, 'parameters': {}}
            self.assertEqual(credential_values.validate(item, raw), raw.removesuffix(b'\n'))
            for bad in (*invalid[kind], b'', b'\n', b'x'*4098):
                with self.subTest(kind=kind, raw=bad), self.assertRaises(credential_values.CredentialValueError):
                    credential_values.validate(item, bad)
        item = {'format': 'radius-secret', 'parameters': {}}
        self.assertEqual(credential_values.validate(item, b'{"shared_secret":"'+b'A'*32+b'"}\n'), b'A'*32)

    def test_password_and_radius_validation_agree_with_the_actual_runtime_readers(self):
        for kind, consumer, inputs in (
                ('log-password', lambda: logs_runtime.credential('reference'),
                 (b'valid-value\n', b'bad\nvalue', b'bad\x00value', b'A'*4096+b'\n', b'A'*4097)),
                ('radius-secret', lambda: radius_runtime.credential('reference'),
                 (b'A'*32, b'A'*31, b'A'*256+b'\n', b'{"shared_secret":"'+b'A'*32+b'"}')),
                ('directory-password', lambda: policy_runtime.credential({'directory': {'credential_name': 'reference'}}),
                 (b'valid-value\n', b'\x00', b'\xff', b'A'*4096+b'\n', b'A'*4097))):
            for raw in inputs:
                item = {'format': kind, 'parameters': {}}
                with self.subTest(kind=kind, raw=raw), mock.patch.dict(os.environ, CREDENTIALS_DIRECTORY='/unused'), \
                        mock.patch.object(logs_runtime, 'read', return_value=raw), \
                        mock.patch.object(logs_runtime, 'read_credential', return_value=raw), \
                        mock.patch.object(logs_runtime.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=997)), \
                        mock.patch.object(radius_runtime, 'read', return_value=raw), \
                        mock.patch.object(policy_runtime, 'read', return_value=raw):
                    try:
                        expected = credential_values.validate(item, raw)
                    except ValueError:
                        with self.assertRaises(ValueError):
                            consumer()
                    else:
                        actual = consumer()
                        self.assertEqual(actual.encode('utf-8') if isinstance(actual, str) else actual, expected)

    def test_snmp_uses_the_existing_native_grammar_and_binds_the_image_username(self):
        secret = {'username': 'synthetic-monitor', 'auth_protocol': 'SHA-256', 'priv_protocol': 'AES',
                  'auth_password': 'synthetic-auth-password', 'priv_password': 'synthetic-priv-password'}
        item = {'format': 'snmp-user', 'parameters': {'username': secret['username'], 'header': snmp_credentials.HEADER}}
        raw = snmp_credentials.configuration(secret)
        self.assertEqual(credential_values.validate(item, raw), raw)
        item['parameters']['username'] = 'other-monitor'
        with self.assertRaises(credential_values.CredentialValueError):
            credential_values.validate(item, raw)

    @unittest.skipUnless(os.geteuid() == 0, 'The native routing reader requires actual root-owned metadata.')
    def test_bgp_grammar_agrees_with_native_materialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root/'reference', root/'frr.conf'
            manifest = {'schema': 1, 'template': 'neighbor PEER password @LANRITH_BGP_0@\n',
                        'credentials': {'@LANRITH_BGP_0@': 'reference'}}
            item = {'format': 'bgp-token', 'parameters': {}}
            for raw in (b'A', b'A'*80+b'\n', b'A'*81, b'good\nrouter bgp 1', b'\xff'):
                source.write_bytes(raw)
                source.chmod(0o600)
                with self.subTest(raw=raw):
                    try:
                        expected = credential_values.validate(item, raw)
                    except ValueError:
                        with self.assertRaises(ValueError):
                            routing_runtime.materialize(manifest, root, target)
                    else:
                        routing_runtime.materialize(manifest, root, target)
                        self.assertIn(expected, target.read_bytes())


if __name__ == '__main__':
    unittest.main()
