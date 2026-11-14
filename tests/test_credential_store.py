"""Real protected files, interrupted writes and fallback credential identity."""

import base64
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from lanrith import credential_store as provisioning
from lanrith.credential_values import FORMAT_UNITS
from lanrith.release import ReleaseError, canonical

HELPERS = Path(__file__).parents[1]/'mkosi/base/mkosi.extra/usr/lib/lanrith'
sys.path.insert(0, str(HELPERS))
import snmp_credentials
from snmp_service import State as SNMPState


def item(name, kind='log-password', *, path=None, parameters=None):
    return {'reference': name, 'format': kind, 'parameters': parameters or {},
            'path': path or '/var/lib/synthetic-owner/credentials/'+name}


def catalog(*items):
    return {'schema': 1, 'credentials': sorted(items, key=lambda row: row['reference']),
            'units': sorted(set().union(*(FORMAT_UNITS[row['format']] for row in items)))}


def encoded(values):
    return {name: base64.b64encode(raw).decode('ascii') for name, raw in values.items()}


@unittest.skipUnless(os.geteuid() == 0, 'Credential state requires real root-owned files.')
class CredentialStoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lanrith-credential-store-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root/'var').mkdir(mode=0o700)
        self.installed = {'image_id': 'synthetic-router', 'deployment_sequence': 12,
            'uki_name': 'synthetic-router_12.efi', 'configuration_sha256': 'a'*64,
            'state_directory': '/var/lib/lanrith'}

    def store(self, selected=None, *, image=None):
        value = provisioning.Store(image or self.installed, selected or catalog(item('first'), item('second')),
                                   root=self.root)
        value.setup()
        return value

    @staticmethod
    def stage(store, values, **kwargs):
        with store.lock():
            return store.stage(encoded(values), **kwargs)

    @staticmethod
    def commit(store, selected):
        with store.lock():
            return store.commit(selected['transaction_id'])

    def private(self, path, raw):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)

    def full_catalog(self):
        definitions = [item('bind_update', 'tsig-base64'), item('bgp_peer', 'bgp-token'),
                       item('directory', 'directory-password'), item('logs'), item('radius', 'radius-secret'),
                       item('snmp', 'snmp-user', path='/var/lib/synthetic-owner/snmp/snmpd.conf',
                            parameters={'username': 'synthetic-monitor', 'header': snmp_credentials.HEADER})]
        raw = {'bind_update': base64.b64encode(b'x'*32)+b'\n', 'bgp_peer': b'synthetic-token\n',
               'directory': b'directory-value\n\n', 'logs': b'log-value\n',
               'radius': b'{"shared_secret":"'+b'R'*32+b'"}\n',
               'snmp': snmp_credentials.configuration({'username': 'synthetic-monitor', 'auth_protocol': 'SHA-256',
                   'priv_protocol': 'AES', 'auth_password': 'synthetic-auth-password',
                   'priv_password': 'synthetic-privacy-password'})}
        return catalog(*definitions), raw

    def test_complete_set_is_prepared_before_explicit_commit_and_native_bytes_are_preserved(self):
        selected, values = self.full_catalog()
        store = self.store(selected)
        self.assertEqual(store.status()['phase'], 'needs-input')
        status = self.stage(store, values)
        self.assertEqual(status['phase'], 'prepared')
        self.assertFalse(store.admitted())
        for row in selected['credentials']:
            path = store.path(row['path'])
            self.assertEqual(path.read_bytes(), values[row['reference']])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(self.commit(store, status)['phase'], 'committed')
        self.assertTrue(store.admitted())
        self.assertFalse((store.control/'pending.json').exists())
        self.assertEqual(self.commit(store, status)['phase'], 'committed')
        exposed = canonical(store.status())
        for raw in values.values():
            self.assertNotIn(raw.strip(), exposed)
            self.assertNotIn(provisioning.digest(raw).encode(), exposed)

    def test_unknown_partial_and_invalid_values_fail_before_any_native_recovery_or_write(self):
        store = self.store()
        for values in ({}, {'first': b'value'}, {'first': b'value', 'second': b'bad\nvalue'},
                       {'first': b'value', 'second': b'value', 'unknown': b'value'}):
            with self.subTest(values=values), store.lock(), patch.object(store, 'native_locks') as native, \
                    self.assertRaises(ValueError):
                store.stage(encoded(values))
            native.assert_not_called()
            self.assertFalse((store.control/'pending.json').exists())
        for bad in ('!!!!', 'YQ==\n', 'YR==', '', 'a'*8193):
            with self.subTest(encoded=bad), store.lock(), self.assertRaises(ValueError):
                store.stage({'first': bad, 'second': 'YQ=='})

    def test_initial_uncommitted_set_can_be_corrected_but_old_commit_cannot_admit_it(self):
        store = self.store()
        first = self.stage(store, {'first': b'wrong', 'second': b'value'})
        with self.assertRaisesRegex(ReleaseError, 'fallback'):
            self.stage(store, {'first': b'correct', 'second': b'value'})
        corrected = self.stage(store, {'first': b'correct', 'second': b'value'}, allow_replace=True)
        self.assertNotEqual(first['transaction_id'], corrected['transaction_id'])
        with self.assertRaisesRegex(ReleaseError, 'stale'):
            self.commit(store, first)
        self.assertFalse(store.admitted())
        self.assertEqual(self.commit(store, corrected)['phase'], 'committed')

    def test_committed_values_are_immutable_even_when_initial_replace_flag_is_true(self):
        store = self.store()
        staged = self.stage(store, {'first': b'first', 'second': b'second'})
        self.commit(store, staged)
        for replace in (False, True):
            with self.subTest(replace=replace), self.assertRaisesRegex(ReleaseError, 'fallback'):
                self.stage(store, {'first': b'changed', 'second': b'second'}, allow_replace=replace)
        self.assertEqual(store.path(store.items['first']['path']).read_bytes(), b'first')
        self.assertTrue(store.admitted())
        self.assertEqual(self.stage(store, {'first': b'first\n', 'second': b'second'})['phase'], 'committed')
        self.assertFalse((store.control/'pending.json').exists())

    def test_equivalent_radius_encoding_preserves_existing_fallback_file(self):
        store = self.store(catalog(item('radius', 'radius-secret')))
        raw = b'{"shared_secret":"'+b'A'*32+b'"}\n'
        first = self.stage(store, {'radius': raw})
        self.commit(store, first)
        self.assertEqual(self.stage(store, {'radius': b'A'*32})['phase'], 'committed')
        self.assertEqual(store.path(store.items['radius']['path']).read_bytes(), raw)

    def test_ordinary_update_carries_admitted_bindings_without_staging(self):
        store = self.store()
        staged = self.stage(store, {'first': b'first', 'second': b'second'})
        self.commit(store, staged)
        image = {**self.installed, 'deployment_sequence': 13, 'uki_name': 'synthetic-router_13.efi',
                 'configuration_sha256': 'b'*64}
        updated = self.store(store.catalog, image=image)
        self.assertEqual(updated.status()['phase'], 'committed')
        self.assertIsNone(updated.status()['transaction_id'])

    def test_update_addition_and_changed_paths_retain_old_bindings_for_fallback(self):
        old = self.store(catalog(item('first')))
        status = self.stage(old, {'first': b'first'})
        self.commit(old, status)
        original = old.path(old.items['first']['path'])
        moved = item('first', path='/var/lib/synthetic-owner/credentials/moved-first')
        updated = self.store(catalog(moved, item('second')))
        staged = self.stage(updated, {'first': b'first', 'second': b'second'})
        self.commit(updated, staged)
        self.assertEqual(original.read_bytes(), b'first')
        self.assertTrue(old.admitted())
        self.assertTrue(updated.admitted())
        self.assertEqual(len(updated.inventory('admitted.json', admitted=True)), 3)

    def test_same_path_under_new_reference_cannot_change_a_fallback_value(self):
        old = self.store(catalog(item('first')))
        self.commit(old, self.stage(old, {'first': b'original'}))
        updated = self.store(catalog(item('renamed', path=old.items['first']['path'])))
        with self.assertRaisesRegex(ReleaseError, 'fallback'):
            self.stage(updated, {'renamed': b'changed'}, allow_replace=True)
        self.commit(updated, self.stage(updated, {'renamed': b'original'}))
        self.assertTrue(old.admitted())

    def test_mid_write_crash_resumes_only_after_all_native_values_are_revalidated(self):
        store = self.store()
        write = store.write
        second = store.path(store.items['second']['path'])
        def crash(path, raw):
            if path == second:
                raise OSError('synthetic interruption')
            write(path, raw)
        with patch.object(store, 'write', side_effect=crash), self.assertRaises(OSError):
            self.stage(store, {'first': b'first', 'second': b'second'})
        self.assertEqual(store.status()['phase'], 'writing')
        self.assertFalse(store.admitted())
        restarted = self.store()
        with restarted.lock():
            self.assertTrue(restarted.resume())
        self.assertEqual(restarted.status()['phase'], 'prepared')
        self.commit(restarted, restarted.status())
        self.assertTrue(restarted.admitted())

    def test_crash_before_registry_write_is_resumable_and_abandoned_created_files_are_recognized(self):
        store = self.store()
        save = store.save
        def crash(name, value):
            if name == 'owned.json':
                raise OSError('synthetic registry interruption')
            save(name, value)
        with patch.object(store, 'save', side_effect=crash), self.assertRaises(OSError):
            self.stage(store, {'first': b'first', 'second': b'second'})
        with store.lock():
            store.resume()
        self.assertEqual(len(store.inventory('owned.json')), 2)
        self.assertTrue(store.prepared())
        # A later profile may abandon a staged binding without treating it as
        # unrelated state, but ownership alone never grants boot readiness.
        later = self.store(catalog(item('third')))
        self.assertFalse(later.admitted())
        self.assertEqual(self.stage(later, {'third': b'third'})['phase'], 'prepared')

    def test_foreign_pending_journal_is_not_replayed_or_deleted_by_fallback_confirmation(self):
        old = self.store(catalog(item('first')))
        accepted = self.stage(old, {'first': b'first'})
        self.commit(old, accepted)
        image = {**self.installed, 'configuration_sha256': 'b'*64,
                 'deployment_sequence': 13, 'uki_name': 'synthetic-router_13.efi'}
        candidate = self.store(catalog(item('first'), item('second')), image=image)
        self.stage(candidate, {'first': b'first', 'second': b'second'})
        pending = (candidate.control/'pending.json').read_bytes()
        with old.lock():
            self.assertFalse(old.resume())
        self.assertEqual(self.commit(old, accepted)['phase'], 'committed')
        self.assertEqual((candidate.control/'pending.json').read_bytes(), pending)
        self.assertEqual(candidate.status()['phase'], 'prepared')

    def test_commit_after_crash_at_each_durable_boundary_is_idempotent(self):
        for boundary in ('receipt.json', 'admitted.json', 'unlink'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                isolated = Path(temporary)
                (isolated/'var').mkdir(mode=0o700)
                store = provisioning.Store(self.installed, catalog(item('first')), root=isolated)
                store.setup()
                staged = self.stage(store, {'first': b'first'})
                save, remove = store.save, store.remove
                def crash_save(name, value):
                    save(name, value)
                    if name == boundary:
                        raise OSError('synthetic durable write interruption')
                def crash_remove(name):
                    remove(name)
                    if boundary == 'unlink':
                        raise OSError('synthetic unlink interruption')
                with patch.object(store, 'save', side_effect=crash_save), \
                        patch.object(store, 'remove', side_effect=crash_remove), self.assertRaises(OSError):
                    self.commit(store, staged)
                self.assertEqual(self.commit(store, staged)['phase'], 'committed')
                self.assertFalse((store.control/'pending.json').exists())

    def test_changed_staged_file_wrong_transaction_and_invalid_lock_cannot_commit(self):
        store = self.store()
        for operation in (lambda: store.stage(encoded({'first': b'a', 'second': b'b'})),
                          store.resume, lambda: store.commit('a'*32)):
            with self.assertRaisesRegex(ReleaseError, 'lock|Locked'):
                operation()
        staged = self.stage(store, {'first': b'first', 'second': b'second'})
        self.private(store.path(store.items['second']['path']), b'changed')
        with self.assertRaisesRegex(ReleaseError, 'stale'):
            self.commit(store, staged)
        with store.lock(), self.assertRaises(ReleaseError):
            store.commit('not-a-transaction')
        self.assertFalse(store.admitted())

    def test_second_process_lock_and_native_snmp_activation_lock_block_without_modification(self):
        selected, values = self.full_catalog()
        store = self.store(selected)
        other = self.store(selected)
        with store.lock(), self.assertRaisesRegex(ValueError, 'busy'):
            with other.lock():
                self.fail('A second store acquired the same lock')
        snmp = next(row for row in selected['credentials'] if row['format'] == 'snmp-user')
        path = store.path(snmp['path']).parent/'.activation.lock'
        self.private(path, b'')
        with path.open('rb') as held:
            fcntl.flock(held, fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, 'busy'):
                self.stage(store, values)
        self.assertFalse((store.control/'pending.json').exists())
        self.assertEqual(self.stage(store, values)['phase'], 'prepared')

    def test_native_snmp_interrupted_activation_is_recovered_before_provisioning(self):
        selected, values = self.full_catalog()
        store = self.store(selected)
        snmp = next(row for row in selected['credentials'] if row['format'] == 'snmp-user')
        native = SNMPState(store.path(snmp['path']).parent, header=snmp['parameters']['header'])
        with native.lock():
            native.begin({'snmpd.conf': None}, {'snmpd.conf': values['snmp']})
            native.phase('writing')
            native.install({'snmpd.conf': values['snmp']})
        staged = self.stage(store, values)
        self.assertFalse(native.pending.exists())
        self.assertEqual(store.path(snmp['path']).read_bytes(), values['snmp'])
        self.assertEqual(self.commit(store, staged)['phase'], 'committed')

    def test_native_recovery_cannot_substitute_a_prepared_set_at_commit(self):
        selected, values = self.full_catalog()
        store = self.store(selected)
        staged = self.stage(store, values)
        snmp = next(row for row in selected['credentials'] if row['format'] == 'snmp-user')
        native = SNMPState(store.path(snmp['path']).parent, header=snmp['parameters']['header'])
        changed = values['snmp'].replace(b'synthetic-auth-password', b'changed-auth-password')
        with native.lock():
            native.begin({'snmpd.conf': changed}, {'snmpd.conf': values['snmp']})
            native.phase('writing')
        with self.assertRaisesRegex(ReleaseError, 'stopped consumers'):
            self.commit(store, staged)
        self.assertFalse(store.admitted())
        self.assertEqual(native.read(native.root/'snmpd.conf'), values['snmp'])
        self.assertTrue(native.pending.exists())

    def test_missing_prepared_file_is_not_ready_and_retry_can_restore_the_set(self):
        store = self.store()
        self.stage(store, {'first': b'first', 'second': b'second'})
        store.path(store.items['second']['path']).unlink()
        self.assertFalse(store.prepared())
        self.assertEqual(store.status()['phase'], 'writing')
        with store.lock():
            self.assertTrue(store.resume())
        self.assertTrue(store.prepared())

    def test_corrupt_pending_scope_and_encoding_never_replay(self):
        store = self.store()
        self.stage(store, {'first': b'first', 'second': b'second'})
        original = store.record('pending.json')
        for change in ({'catalog_sha256': 'b'*64}, {'transaction_id': 'bad'}, {'phase': 'accepted'},
                       {'values': {'first': '!!!!', 'second': 'YQ=='}}, {'command': 'unapproved'}):
            with self.subTest(change=change), store.lock():
                store.save('pending.json', {**original, **change})
                with self.assertRaises(ValueError):
                    store.resume()
                self.assertFalse(store.admitted())
        # A valid pending set selected by a different catalog is retained but
        # cannot be replayed by the running image.
        changed = json.loads(canonical(original))
        changed['catalog']['credentials'][0]['path'] += '-other'
        changed['catalog_sha256'] = provisioning.digest(canonical(changed['catalog']))
        with store.lock():
            store.save('pending.json', changed)
            self.assertFalse(store.resume())
        self.assertFalse(store.path(changed['catalog']['credentials'][0]['path']).exists())

    def test_wrong_uid_mode_hardlinks_and_symlinks_are_rejected(self):
        store = self.store(catalog(item('first')))
        path = store.path(store.items['first']['path'])
        for changed in ('mode', 'uid', 'hardlink', 'symlink', 'fifo'):
            with self.subTest(changed=changed):
                self.private(path, b'first')
                other = self.root/'unrelated'
                if changed == 'mode':
                    path.chmod(0o640)
                elif changed == 'uid':
                    os.chown(path, 65534, 65534)
                elif changed == 'hardlink':
                    os.link(path, other)
                elif changed == 'symlink':
                    path.rename(other)
                    path.symlink_to(other)
                else:
                    path.unlink()
                    os.mkfifo(path, 0o600)
                with self.assertRaises((ValueError, OSError)):
                    self.stage(store, {'first': b'first'}, allow_replace=True)
                path.unlink()
                other.unlink(missing_ok=True)
        parent = path.parent
        parent.chmod(0o777)
        with self.assertRaises(ReleaseError):
            self.stage(store, {'first': b'first'})
        parent.chmod(0o700)
        parent.rename(parent.with_name('pinned'))
        parent.symlink_to(parent.with_name('pinned'))
        with self.assertRaises(OSError):
            self.stage(store, {'first': b'first'})

    def test_foreign_state_and_unsafe_control_metadata_are_preserved(self):
        store = self.store(catalog(item('first')))
        foreign = store.path(store.items['first']['path']).parent/'unrelated-data'
        self.private(foreign, b'do-not-modify')
        with self.assertRaisesRegex(ReleaseError, 'unrelated'):
            self.stage(store, {'first': b'first'})
        self.assertEqual(foreign.read_bytes(), b'do-not-modify')
        foreign.unlink()
        temporary = foreign.with_name('.provisioning-write-abandoned')
        self.private(temporary, b'incomplete-write')
        self.assertEqual(self.stage(store, {'first': b'first'})['phase'], 'prepared')
        self.assertFalse(temporary.exists())
        (store.control/'pending.json').chmod(0o644)
        with self.assertRaisesRegex(ReleaseError, 'metadata'):
            store.status()

    def test_inventory_is_typed_and_owned_records_never_confer_admission(self):
        store = self.store(catalog(item('first')))
        self.private(store.path(store.items['first']['path']), b'first')
        row = store.items['first']
        with store.lock():
            store.save('owned.json', {'schema': 1, 'bindings': {provisioning.binding(row): row}})
        self.assertFalse(store.admitted())
        for invalid in ({'schema': True, 'bindings': {}}, {'schema': 1, 'bindings': {'a'*64: row}},
                        {'schema': 1, 'bindings': {provisioning.binding(row): {**row, 'command': 'anything'}}}):
            with self.subTest(invalid=invalid), store.lock():
                store.save('owned.json', invalid)
                with self.assertRaises(ReleaseError):
                    store.stage(encoded({'first': b'first'}))

    def test_write_and_record_scope_are_fixed_and_source_catalog_cannot_mutate_store(self):
        selected = catalog(item('first'))
        store = self.store(selected)
        selected['credentials'][0]['path'] = '/etc/shadow'
        self.assertNotEqual(store.items['first']['path'], '/etc/shadow')
        for operation in (lambda: store.write(self.root/'etc/shadow', b'value'),
                          lambda: store.save('caller-selected.json', {}),
                          lambda: store.remove('admitted.json'), lambda: store.record('../outside')):
            with self.assertRaises(ReleaseError):
                operation()

    def test_empty_profile_is_ready_without_creating_any_credential_state(self):
        store = provisioning.Store(self.installed, catalog(), root=self.root)
        self.assertEqual(store.status(), {'schema': 1, 'required': False, 'configuration_sha256': 'a'*64,
            'phase': 'committed', 'references': [], 'transaction_id': None})
        self.assertFalse(store.control.exists())


if __name__ == '__main__':
    unittest.main()
