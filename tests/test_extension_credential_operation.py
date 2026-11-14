"""Image-bound extension authority, optional readiness and fixed consumers."""

from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import socket
import struct
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import build, config, credential_operation as core, credential_store, extensions, image_operation, runtime
from lanrith import extension_credential_config as generation, extension_credential_operation as operation
from lanrith.release import ReleaseError, canonical, file_record
import test_extension_credentials as fixtures
from test_extension_credentials import catalog, encoded
from test_intent import minimal


def manifest(root, *, features=(), health=False, credentials=True):
    files = {'usr/lib/systemd/system/example-app.service':
        '[Service]\nType=oneshot\nExecStart=/usr/bin/true\n'}
    for name, text in files.items():
        path = root/'root'/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o644)
    value = {'schema': 1, 'id': 'example-addon', 'features': list(features),
        'health_units': ['example-app.service'] if health else [], 'start_units': ['example-app.service'],
        'files': {name: {key: file_record(root/'root'/name)[key] for key in ('sha256', 'size')} |
                 {'mode': 0o644} for name in files}}
    if credentials:
        value['credentials'] = [{'name': 'bootstrap', 'format': 'json', 'consumers': ['example-app.service']}]
    path = root/'extension.json'
    path.write_bytes(canonical(value))
    return file_record(path)['sha256']


class ExtensionCredentialAdmissionTests(unittest.TestCase):
    def test_assembly_binds_native_catalog_and_readers_without_yaml_or_compiler(self):
        for root_access in ('enabled', 'disabled'):
            with self.subTest(root_access=root_access), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root/'extension'
                source.mkdir()
                pin = manifest(source)
                base = root/'base.tar'
                with tarfile.open(base, 'w'):
                    pass
                value = minimal()
                value['administration']['root_access'] = root_access
                value['extensions'] = ['example-addon']
                build.assembly(value, base, root/'assembly', version='0.1.0', sequence=12,
                               integrations={'example-addon': (source, pin)})
                tree = root/'assembly/mkosi.extra'
                installed = json.loads((tree/'usr/share/lanrith/installed.json').read_bytes())
                raw = (tree/'usr/share/lanrith/extension-credentials/example-addon.json').read_bytes()
                self.assertEqual(installed['extension_credential_catalogs'], {'example-addon': {
                    'sha256': credential_store.digest(raw), 'core_required': False}})
                self.assertEqual(installed['integration_health_units'], [])
                self.assertIsNone(installed['credential_catalog_sha256'])
                self.assertEqual(json.loads(raw), catalog())
                self.assertTrue((tree/'usr/lib/systemd/system/sockets.target.wants/'
                    'lanrith-extension-credential-example-addon.socket').is_symlink())
                self.assertIn(' -I\n', (tree/'usr/bin/lanrith-extension-credentials').read_text())
                for name in ('extension_credential_values', 'extension_credential_operation'):
                    self.assertTrue((tree/'usr/lib/lanrith/lanrith'/(name+'.py')).is_file())
                for name in ('extension_credential_config', 'config', 'intent', 'extensions'):
                    self.assertFalse((tree/'usr/lib/lanrith/lanrith'/(name+'.py')).exists())
                self.assertFalse(any(path.suffix in ('.yaml', '.yml') for path in tree.rglob('*')))
                if root_access == 'disabled':
                    self.assertFalse(any((tree/'etc/sudoers.d').glob('*')))
                native = (tree/'etc/systemd/system/example-app.service.d/'
                          '50-lanrith-extension-credentials.conf').read_text()
                self.assertIn('LoadCredential=bootstrap:/var/lib/lanrith/extension-credentials/example-addon/bootstrap', native)

    def test_disabled_provider_and_undeclared_slots_emit_no_provisioning_state_or_units(self):
        for credentials, features in ((True, ('dns',)), (False, ())):
            with self.subTest(credentials=credentials, features=features), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                pin = manifest(root, features=features, credentials=credentials)
                value = config.normalize(minimal())
                value['extensions'] = ['example-addon']
                value['services']['dns']['enabled'] = False
                output = root/'output'
                result = extensions.overlay(value, {'example-addon': (root, pin)}, output)
                self.assertEqual(result['credential_catalogs'], {})
                self.assertFalse((output/'usr/share/lanrith/extension-credentials').exists())
                self.assertFalse(any('extension-credential' in path.name for path in output.rglob('*')))

    def test_selected_feature_and_explicit_health_require_admission_before_core_boot(self):
        for feature in (False, True):
            with self.subTest(feature=feature), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                pin = manifest(root, features=('dns',) if feature else (), health=True)
                value = config.normalize(minimal())
                value['extensions'] = ['example-addon']
                if feature:
                    value['services']['dns']['configuration'] = 'example-addon'
                output = root/'output'
                result = extensions.overlay(value, {'example-addon': (root, pin)}, output)
                self.assertTrue(result['credential_catalogs']['example-addon']['core_required'])
                setup = (output/'usr/lib/systemd/system/lanrith-extension-credential-example-addon-setup.service').read_text()
                self.assertNotIn('Requires=boot-complete.target', setup)

    def test_consumers_cannot_reference_base_or_other_extensions_or_shadow_generated_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pin = manifest(root)
            value = config.normalize(minimal())
            value['extensions'] = ['example-addon']
            with self.assertRaisesRegex(ReleaseError, 'base package'):
                extensions.overlay(value, {'example-addon': (root, pin)}, root/'collision',
                    base_files={'usr/lib/systemd/system/example-app.service'})
            document = json.loads((root/'extension.json').read_bytes())
            document['credentials'][0]['consumers'] = ['some-other.service']
            (root/'extension.json').write_bytes(canonical(document))
            with self.assertRaisesRegex(ReleaseError, 'owned'):
                extensions.admit(root, file_record(root/'extension.json')['sha256'])
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            path = output/'etc/systemd/system/example-app.service.d/50-lanrith-extension-credentials.conf'
            path.parent.mkdir(parents=True)
            path.write_text('[Service]\nLoadCredential=other:/etc/shadow\n')
            with self.assertRaisesRegex(ReleaseError, 'conflicts'):
                generation.install([('example-addon', catalog(), False)], output, 'admin')


class ExtensionCredentialProtocolTests(unittest.TestCase):
    def test_request_has_no_path_unit_format_or_extension_override_and_respects_bounds(self):
        selected = {'schema': 1, 'action': 'stage', 'configuration_sha256': 'a'*64,
                    'credentials': encoded({'bootstrap': b'{"token":"synthetic"}'})}
        self.assertEqual(operation.request(canonical(selected)), selected)
        for key, value in (('extension', 'other-addon'), ('units', ['ssh.service']), ('path', '/etc/shadow'),
                           ('format', 'directory-password')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                operation.request(canonical({**selected, key: value}))
        for credentials in ({}, encoded({str(i): b'{}' for i in range(17)}),
                            {'bootstrap': 'YR=='}, {'../other': 'e30='}, {'bootstrap': 'a'*90000}):
            with self.subTest(size=len(credentials)), self.assertRaises(ValueError):
                operation.request(canonical({**selected, 'credentials': credentials}))
        for raw in (b'{}', b'{}\n{}\n', b'{"schema":1,"schema":1}\n', b'\xff\n',
                    b'x'*(credential_store.LIMIT+1)):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                operation.request(raw)

    def test_root_and_other_uid_are_rejected_before_request_parsing(self):
        connection = SimpleNamespace(getsockopt=lambda *_: struct.pack('3i', 123, 1702, 1701))
        with patch.object(image_operation, 'policy', return_value={'operator': 'fixture-operator'}), \
                patch.object(operation.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1701)), \
                patch.object(core, 'receive') as receive:
            for uid in (0, 1702):
                connection.getsockopt = lambda *_, selected=uid: struct.pack('3i', 123, selected, 1701)
                with self.subTest(uid=uid), self.assertRaisesRegex(ReleaseError, 'Caller'):
                    operation.serve(connection, 'example-addon')
            receive.assert_not_called()

    def test_cli_values_use_stdin_and_failures_are_redacted(self):
        stream = SimpleNamespace(buffer=io.BytesIO(canonical(encoded({'bootstrap': b'{"a":"synthetic-marker"}'}))))
        with patch.object(operation.sys, 'stdin', stream), patch.object(operation, 'client', return_value={}) as client, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(operation.main(['example-addon', 'stage', 'a'*64]), 0)
        self.assertEqual(client.call_args.args[0], 'example-addon')
        self.assertEqual(client.call_args.args[1]['credentials'], encoded({'bootstrap': b'{"a":"synthetic-marker"}'}))
        output = io.StringIO()
        with patch.object(operation, 'client', side_effect=ValueError('synthetic-marker')), redirect_stderr(output):
            self.assertEqual(operation.main(['example-addon', 'status']), 1)
        self.assertNotIn('synthetic-marker', output.getvalue())

    def test_namespaces_have_fixed_socket_names_and_index_is_strict(self):
        self.assertEqual(operation.socket_path('example-addon'), '/run/lanrith-extension-credentials.example-addon.sock')
        for index in ({'../other': {'sha256': 'a'*64, 'core_required': False}},
                      {'example-addon': {'sha256': 'a'*64, 'core_required': 1}},
                      {'example-addon': {'sha256': 'a'*64, 'core_required': False, 'path': '/etc/shadow'}}):
            with self.subTest(index=index), self.assertRaises(ValueError):
                operation.index({'extension_credential_catalogs': index})
        with self.assertRaises(ValueError):
            generation.render('example-addon', catalog(), 'admin\nSocketMode=0666', core_required=False)


@unittest.skipUnless(os.geteuid() == 0, 'Real credential filesystem custody requires root.')
class ExtensionCredentialExecutionTests(unittest.TestCase):
    setUp = fixtures.ExtensionCredentialStoreTests.setUp

    def prepare(self, *, required=False):
        self.installed['extension_credential_catalogs'] = {'example-addon': {'sha256': 'a'*64, 'core_required': required}}
        self.store = credential_store.Store(self.installed, catalog(), root=self.root, extension='example-addon')
        for selected in (patch.object(operation, 'store_for', return_value=self.store),
                         patch.object(operation, 'core_accepted', return_value=True)):
            selected.start()
            self.addCleanup(selected.stop)
        controller = patch.object(core, 'control')
        self.control = controller.start()
        self.addCleanup(controller.stop)

    def stage(self, raw=b'{"token":"synthetic"}', **changes):
        return operation.execute(self.installed, 'example-addon', {'schema': 1, 'action': 'stage',
            'configuration_sha256': 'a'*64, 'credentials': encoded({'bootstrap': raw}), **changes})

    def test_optional_setup_waits_for_current_core_acceptance_without_creating_state(self):
        self.prepare()
        with patch.object(operation, 'core_accepted', return_value=False):
            result = operation.execute(self.installed, 'example-addon', {'schema': 1, 'action': 'status'})
            self.assertEqual(result['phase'], 'needs-core-acceptance')
            with self.assertRaisesRegex(ReleaseError, 'core acceptance'):
                self.stage()
        self.control.assert_not_called()
        self.assertFalse(self.store.control.exists())

    def test_optional_bootstrap_repair_and_commit_never_control_core_units(self):
        self.prepare()
        first = self.stage()
        repaired = self.stage(b'{"token":"corrected"}')
        with self.assertRaises(ValueError):
            operation.execute(self.installed, 'example-addon', {'action': 'commit',
                'transaction_id': first['transaction_id']})
        result = operation.execute(self.installed, 'example-addon', {'action': 'commit',
            'transaction_id': repaired['transaction_id']})
        self.assertEqual(result['phase'], 'committed')
        self.assertTrue(all(set(call.args[1]) <= {'example-app.service', operation.ready_unit('example-addon')}
                            for call in self.control.call_args_list))
        self.control.reset_mock()
        self.assertEqual(self.stage(b'{ "token": "corrected" }')['phase'], 'committed')
        for raw, changes in ((b'bad', {}), (b'{"token":"rotated"}', {}), (b'{}', {'configuration_sha256': 'b'*64})):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.stage(raw, **changes)
        self.control.assert_not_called()

    def test_required_extension_can_bootstrap_before_acceptance_and_commit_wakes_checks_only(self):
        self.prepare(required=True)
        with patch.object(operation, 'core_accepted', return_value=False):
            staged = self.stage()
            self.assertFalse(operation.ready(self.installed, 'example-addon'))
            self.assertTrue(operation.ready(self.installed, 'example-addon', committed=False))
            self.assertFalse(operation.required_ready(self.installed))
            operation.execute(self.installed, 'example-addon', {'action': 'commit',
                'transaction_id': staged['transaction_id']})
        self.assertTrue(operation.required_ready(self.installed))
        self.assertTrue(any(call.args[0] == 'start' and 'lanrith-image-completion.service' in call.args[1]
                            for call in self.control.call_args_list))
        self.assertFalse(any(call.args[0] == 'stop' and set(call.args[1]) & set(core.OBSERVERS)
                             for call in self.control.call_args_list))

    def test_catalog_digest_ownership_and_namespace_must_match_installed_image(self):
        raw = canonical(catalog())
        directory = self.root/'catalogs'
        directory.mkdir()
        path = directory/'example-addon.json'
        path.write_bytes(raw)
        path.chmod(0o644)
        selected = {**self.installed, 'extension_credential_catalogs': {'example-addon': {
            'sha256': credential_store.digest(raw), 'core_required': False}}}
        with patch.object(operation, 'CATALOGS', directory):
            self.assertEqual(operation.catalog(selected, 'example-addon'), catalog())
            empty = canonical({'schema': 1, 'credentials': [], 'units': []})
            path.write_bytes(empty)
            wrong = copy.deepcopy(selected)
            wrong['extension_credential_catalogs']['example-addon']['sha256'] = credential_store.digest(empty)
            with self.assertRaisesRegex(ReleaseError, 'empty'):
                operation.catalog(wrong, 'example-addon')
            with self.assertRaises(ValueError):
                operation.catalog(selected, 'other-addon')
            path.write_bytes(raw+b' ')
            with self.assertRaises(ValueError):
                operation.catalog(selected, 'example-addon')
            path.unlink()
            path.symlink_to('/etc/passwd')
            with self.assertRaises(OSError):
                operation.catalog(selected, 'example-addon')

    def test_required_extension_is_part_of_shared_readiness_but_optional_is_independent(self):
        self.prepare(required=True)
        self.store.setup()
        with patch.object(core, 'catalog', return_value={'credentials': []}), patch.object(core, 'ready', return_value=True), \
                patch.object(core.time, 'monotonic', side_effect=(0, 1)):
            self.assertFalse(core.wait_ready(self.installed, deadline_seconds=1))
        self.installed['extension_credential_catalogs']['example-addon']['core_required'] = False
        with patch.object(core, 'catalog', return_value={'credentials': []}):
            self.assertTrue(core.wait_ready(self.installed))

    def test_runtime_health_cannot_bypass_uncommitted_required_extension(self):
        self.prepare(required=True)
        self.store.setup()
        with patch.object(runtime, 'installed', return_value=self.installed), \
                patch.object(core, 'ready', return_value=True), patch.object(runtime.factory, 'secure_boot') as boot:
            with self.assertRaisesRegex(ReleaseError, 'Required extension credentials'):
                runtime.health()
            boot.assert_not_called()

    def test_persisted_acceptance_requires_current_boot_observation(self):
        observed = {'schema': 1, 'accepted': True, 'boot_complete': True, 'image_id': 'synthetic-router',
                    'deployment_sequence': 12, 'boot_id': 'current-boot'}
        with patch.object(image_operation, 'accepted_identity', return_value=image_operation.identity(self.installed)), \
                patch.object(operation, 'read', side_effect=lambda *_: canonical(observed)), \
                patch.object(Path, 'read_text', return_value='current-boot\n'):
            self.assertTrue(operation.core_accepted(self.installed))
            for changes in ({'boot_id': 'old-boot'}, {'deployment_sequence': 11}, {'accepted': False},
                            {'boot_complete': 1}, {'schema': True}, {'image_id': 'other-router'}):
                previous = copy.deepcopy(observed)
                observed.update(changes)
                self.assertFalse(operation.core_accepted(self.installed))
                observed.clear()
                observed.update(previous)
