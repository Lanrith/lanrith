"""Extension secret custody stays independent from core and other extensions."""

import base64
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from lanrith import credential_store, credential_values, extension_credential_values as values
from lanrith.release import ReleaseError, canonical


def catalog(extension='example-addon', names=('bootstrap',), units=('example-app.service',)):
    return values.declarations(extension, [
        {'name': name, 'format': 'json', 'consumers': list(units)} for name in names],
        {'usr/lib/systemd/system/'+unit for unit in units})


def encoded(selected):
    return {name: base64.b64encode(raw).decode('ascii') for name, raw in selected.items()}


class ExtensionCredentialValuesTests(unittest.TestCase):
    def test_paths_and_service_readers_are_derived_and_descriptor_bound(self):
        selected = catalog(units=('example-worker.service', 'example-app.service'))
        item = selected['credentials'][0]
        self.assertEqual(item['path'], '/var/lib/lanrith/extension-credentials/example-addon/bootstrap')
        self.assertEqual(item['parameters'], {'consumers': ['example-app.service', 'example-worker.service']})
        self.assertEqual(values.validate_catalog('example-addon', selected), selected)
        changed = catalog(units=('example-worker.service',))
        self.assertNotEqual(credential_store.binding(item), credential_store.binding(changed['credentials'][0]))
        for key, value in (('path', '/var/lib/another-app/bootstrap'), ('format', 'directory-password'),
                           ('reference', '../bootstrap'), ('parameters', {})):
            wrong = copy.deepcopy(selected)
            wrong['credentials'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                values.validate_catalog('example-addon', wrong)
        with self.assertRaises(ValueError):
            values.validate_catalog('other-addon', selected)

    def test_only_unique_bounded_owned_literal_service_files_can_receive_credentials(self):
        bad_units = ([], ['example-app.service']*2, ['example@.service'], ['../other.service'],
                     ['example.socket'], ['lanrith-health.service'], ['systemd-user.service'],
                     ['a.service\nExecStart=/bin/sh'], ['unit'+str(i)+'.service' for i in range(65)])
        for units in bad_units:
            with self.subTest(units=units), self.assertRaises(ValueError):
                catalog(units=units)
        with self.assertRaisesRegex(ReleaseError, 'owned'):
            values.declarations('example-addon', [{'name': 'bootstrap', 'format': 'json',
                'consumers': ['other.service']}], {'usr/lib/systemd/system/example-app.service'})
        for names in (('bootstrap', 'bootstrap'), tuple('slot'+str(i) for i in range(17))):
            with self.subTest(names=names), self.assertRaises(ValueError):
                catalog(names=names)
        for extension in ('../other', '', 'Example', 'a'*49, 'example/other', 'other\n'):
            with self.subTest(extension=extension), self.assertRaises(ValueError):
                catalog(extension=extension)
        extra = catalog()
        extra['units'].append('other.service')
        with self.assertRaises(ValueError):
            values.validate_catalog('example-addon', extra)

    def test_json_object_grammar_bounds_and_redacts_invalid_values(self):
        item = catalog()['credentials'][0]
        raw = b'{ "account": "synthetic", "nested": [true, null, 3.5] }\n'
        self.assertEqual(values.validate(item, raw), b'{"account":"synthetic","nested":[true,null,3.5]}\n')
        invalid = (b'', b'null', b'[]', b'"secret-marker"', b'{"a":1,"a":2}',
                   b'{"secret-marker":NaN}', b'{"a":Infinity}', b'{"a":1e999}',
                   b'{"a":"\\ud800"}', b'{"a":"\xff"}', b'{"a":"\x00"}',
                   b'{"secret-marker":', b'{"a":'+b'['*1024+b'0'+b']'*1024+b'}',
                   canonical({'a': 'x'*values.VALUE_LIMIT}),
                   canonical({'a': [0]*values.NODE_LIMIT}),
                   canonical({'a': [0]*10, 'b': [[[0]]]})+b'x')
        for raw in invalid:
            with self.subTest(size=len(raw)), self.assertRaisesRegex(
                    credential_values.CredentialValueError, r'^Extension credential does not match its JSON bounds\.$'):
                values.validate(item, raw)
        nested = 0
        for _ in range(values.DEPTH_LIMIT+1):
            nested = [nested]
        with self.assertRaises(ValueError):
            values.validate(item, canonical({'nested': nested}))
        maximum = b'{"key":"'+b'x'*(values.VALUE_LIMIT-10)+b'"}'
        self.assertEqual(len(maximum), values.VALUE_LIMIT)
        self.assertEqual(values.decoded(encoded({'bootstrap': maximum})['bootstrap']), maximum)
        self.assertTrue(values.validate(item, maximum))
        for text in ('', 'YR==', 'YQ==\n', '!!!!', 'a'*(values.ENCODED_LIMIT+1),
                     base64.b64encode(maximum+b' ').decode()):
            with self.subTest(size=len(text)), self.assertRaises(ValueError):
                values.decoded(text)

    def test_core_catalog_cannot_claim_extension_state_or_consumer_grammar(self):
        for path in ('/var/lib/lanrith/extension-credentials/example-addon/bootstrap',
                     '/var/lib/lanrith/extension-credential-provisioning/example-addon/pending.json'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                credential_values.validate_catalog({'schema': 1, 'credentials': [{'reference': 'bootstrap',
                    'format': 'log-password', 'path': path, 'parameters': {}}], 'units': ['alloy.service']})
        with self.assertRaises(ValueError):
            credential_values.validate_catalog(catalog())


@unittest.skipUnless(os.geteuid() == 0, 'Credential custody requires real root-owned files.')
class ExtensionCredentialStoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lanrith-extension-credentials-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root/'var').mkdir(mode=0o700)
        self.installed = {'image_id': 'synthetic-router', 'deployment_sequence': 12,
            'uki_name': 'synthetic-router_12.efi', 'configuration_sha256': 'a'*64,
            'state_directory': '/var/lib/lanrith'}

    def store(self, extension='example-addon', selected=None, image=None):
        result = credential_store.Store(image or self.installed, selected or catalog(extension),
                                        root=self.root, extension=extension)
        result.setup()
        return result

    def stage(self, store, selected=None, **kwargs):
        with store.lock():
            return store.stage(encoded(selected or {'bootstrap': b'{"token":"synthetic-marker"}\n'}), **kwargs)

    def commit(self, store, selected):
        with store.lock():
            return store.commit(selected['transaction_id'])

    def test_bootstrap_is_private_and_independent_from_core_and_other_extensions(self):
        first, other = self.store(), self.store('other-addon')
        staged = self.stage(first)
        self.assertEqual(staged['phase'], 'prepared')
        self.assertFalse(first.admitted())
        self.assertEqual(other.status()['phase'], 'needs-input')
        with other.lock():
            self.assertFalse(other.resume())
            with self.assertRaises(ValueError):
                other.commit(staged['transaction_id'])
        self.assertEqual(self.commit(first, staged)['phase'], 'committed')
        self.assertFalse((self.root/'var/lib/lanrith/credential-provisioning').exists())
        self.assertNotEqual(first.control, other.control)
        secret = first.path(first.items['bootstrap']['path'])
        self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(secret.parent.stat().st_mode), 0o700)
        self.assertNotIn(b'synthetic-marker', canonical(first.status()))
        self.assertNotIn(credential_store.digest(secret.read_bytes()).encode(), canonical(first.status()))

    def test_all_sixteen_maximum_sized_json_slots_fit_the_durable_transaction(self):
        names = tuple('slot'+str(i) for i in range(16))
        store = self.store(selected=catalog(names=names))
        raw = b'{"key":"'+b'x'*(values.VALUE_LIMIT-10)+b'"}'
        staged = self.stage(store, {name: raw for name in names})
        self.assertLess((store.control/'pending.json').stat().st_size, credential_store.LIMIT)
        self.assertEqual(self.commit(store, staged)['phase'], 'committed')
        self.assertTrue(all(store.path(item['path']).read_bytes() == raw for item in store.items.values()))

    def test_reader_change_needs_new_admission_and_fallback_values_cannot_be_rotated(self):
        first = self.store()
        staged = self.stage(first)
        self.commit(first, staged)
        changed = self.store(selected=catalog(units=('example-app.service', 'example-audit.service')))
        self.assertFalse(changed.admitted())
        staged = self.stage(changed, {'bootstrap': b'{ "token" : "synthetic-marker" }'})
        self.assertEqual(changed.path(changed.items['bootstrap']['path']).read_bytes(),
                         b'{"token":"synthetic-marker"}\n')
        self.commit(changed, staged)
        self.assertTrue(first.admitted())
        with self.assertRaisesRegex(ReleaseError, 'fallback'):
            self.stage(changed, {'bootstrap': b'{"token":"different"}'}, allow_replace=True)
        self.assertTrue(changed.admitted())

    def test_partial_write_recovers_only_the_matching_namespace_image_and_catalog(self):
        selected = catalog(names=('first', 'second'))
        store = self.store(selected=selected)
        original = store.write

        def interrupted(path, raw):
            if path == store.path(store.items['second']['path']):
                raise OSError('synthetic interruption')
            return original(path, raw)

        with patch.object(store, 'write', side_effect=interrupted), self.assertRaises(OSError):
            self.stage(store, {'first': b'{"a":1}', 'second': b'{"b":2}'})
        self.assertEqual(store.status()['phase'], 'writing')
        following = {**self.installed, 'deployment_sequence': 13, 'uki_name': 'synthetic-router_13.efi'}
        other_image = self.store(selected=selected, image=following)
        with other_image.lock():
            self.assertFalse(other_image.resume())
        recovered = self.store(selected=selected)
        with recovered.lock():
            self.assertTrue(recovered.resume())
        self.assertEqual(self.commit(recovered, recovered.status())['phase'], 'committed')

    def test_namespace_catalogs_and_histories_cannot_cross_custody(self):
        first, other = self.store(), self.store('other-addon')
        staged = self.stage(first)
        self.commit(first, staged)
        for record in ('owned.json', 'admitted.json'):
            destination = other.control/record
            destination.write_bytes((first.control/record).read_bytes())
            destination.chmod(0o600)
            with self.subTest(record=record), other.lock(), self.assertRaises(ValueError):
                other.inventory(record, admitted=record == 'admitted.json')
            destination.unlink()
        with self.assertRaises(ValueError):
            credential_store.Store(self.installed, catalog(), root=self.root, extension='other-addon')

    def test_hardlinked_or_symlinked_secret_cannot_be_staged_or_admitted(self):
        store = self.store()
        staged = self.stage(store)
        path = store.path(store.items['bootstrap']['path'])
        linked = self.root/'linked'
        os.link(path, linked)
        with self.assertRaises(ValueError):
            self.commit(store, staged)
        linked.unlink()
        target = self.root/'target'
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(OSError):
            self.stage(store)
        self.assertEqual(target.read_bytes(), b'{"token":"synthetic-marker"}\n')

    def test_history_capacity_is_checked_before_staging_changes_files(self):
        first = self.store()
        staged = self.stage(first)
        self.commit(first, staged)
        changed = self.store(selected=catalog(units=('example-audit.service',)))
        before = {path: path.read_bytes() for path in first.control.iterdir() if path.is_file()}
        with patch.object(credential_store, 'HISTORY_LIMIT', 1), changed.lock(), self.assertRaisesRegex(
                ReleaseError, 'history'):
            changed.preflight(encoded({'bootstrap': b'{"token":"synthetic-marker"}'}))
        self.assertEqual(before, {path: path.read_bytes() for path in first.control.iterdir() if path.is_file()})
