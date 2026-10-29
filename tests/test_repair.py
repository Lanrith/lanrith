"""Offline slot inspection never treats names, mutable data or media as trust."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lanrith import build, config, release, repair, update


class RepairInspectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.secrets = tempfile.TemporaryDirectory(prefix='lanrith-repair-test-')
        cls.addClassCleanup(cls.secrets.cleanup)
        cls.key = Path(cls.secrets.name)/'key'
        cls.certificate = Path(cls.secrets.name)/'cert'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=synthetic-repair-test', '-keyout', str(cls.key), '-out', str(cls.certificate)],
                       check=True, capture_output=True)
        cls.key.chmod(0o600)

    def setUp(self):
        guard = patch.object(repair, 'require_readonly_esp')
        guard.start(); self.addCleanup(guard.stop)
        temp = tempfile.TemporaryDirectory(prefix='lanrith-repair-case-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)/'release'
        self.root.mkdir()
        self.esp = Path(temp.name)/'esp'
        (self.esp/'EFI/Linux').mkdir(parents=True)
        self.disk = '/dev/synthetic'
        self.files = {'uki': 'lanrith_17.efi'}
        self.rows = []
        self.device_bytes = {}
        self.extents = []
        for index, role in enumerate(update.PARTITION_ROLES, 1):
            uuid = f'12345678-1234-1234-1234-{index:012d}'
            self.files[role] = f'lanrith_17_{uuid}.{role}.raw'
            device = f'/dev/synthetic{index}'
            data = f'synthetic-{role}'.encode()
            self.device_bytes[device] = data
            self.rows.append({'disk': self.disk, 'device': device, 'number': index, 'type': update.GUIDS[role],
                              'label': f'l_17_{role.replace("-", "_")}', 'uuid': uuid, 'size': 512,
                              'mounted': False})
            self.extents.append((index, index+1, device))
        for role, name in self.files.items():
            (self.root/name).write_bytes(f'synthetic-{role}'.encode())
        (self.esp/'EFI/Linux/lanrith_17+2-1.efi').write_bytes((self.root/self.files['uki']).read_bytes())
        manifest = release.unsigned_manifest(self.root, purpose='update', version='0.1.0', sequence=17,
                                              configuration_sha256='a'*64, files=self.files)
        (self.root/'release.json').write_bytes(release.canonical(manifest))
        release.sign(self.root, self.key)
        self.layout = {'sector': 512, 'extents': self.extents}

    def inspect(self, *, rows=None, data=None, layout=None):
        rows = self.rows if rows is None else rows
        data = self.device_bytes if data is None else data
        layout = self.layout if layout is None else layout
        def digest(device, size):
            self.assertEqual(size, len(data[device]))
            return hashlib.sha256(data[device]).hexdigest()
        with patch.object(update, 'boot_esp', return_value=self.esp), \
                patch.object(update, 'geometry', return_value=rows), \
                patch.object(repair, 'disk_layout', return_value=layout), \
                patch.object(repair, 'partition_digest', side_effect=digest):
            return repair.inspect_slot(self.root, self.certificate, image_id='lanrith', disk=self.disk, esp=self.esp)

    def test_valid_signed_slot_is_only_an_observation(self):
        result = self.inspect()
        self.assertEqual(result['uki_name'], 'lanrith_17+2-1.efi')
        self.assertEqual(result['deployment_sequence'], 17)
        self.assertFalse(result['authorized_to_boot'])

    def test_signed_artifact_and_installed_partition_tampering_are_rejected(self):
        data = dict(self.device_bytes)
        data['/dev/synthetic2'] = b'X'*len(data['/dev/synthetic2'])
        with self.assertRaises(release.ReleaseError):
            self.inspect(data=data)
        path = self.root/self.files['root']
        path.write_bytes(path.read_bytes()+b'x')
        with self.assertRaises(release.ReleaseError):
            self.inspect()

    def test_missing_busy_ambiguous_or_undersized_partitions_are_rejected(self):
        cases = []
        rows = copy.deepcopy(self.rows); rows[0]['mounted'] = True; cases.append(rows)
        rows = copy.deepcopy(self.rows); rows[0]['size'] = 1; cases.append(rows)
        rows = copy.deepcopy(self.rows); rows[0]['disk'] = '/dev/other'; cases.append(rows)
        rows = copy.deepcopy(self.rows); rows[0]['label'] = 'wrong'; cases.append(rows)
        rows = copy.deepcopy(self.rows); rows[1]['uuid'] = rows[0]['uuid']; cases.append(rows)
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(release.ReleaseError):
                self.inspect(rows=rows)

    def test_unknown_or_multiple_boot_entries_and_untrusted_certificate_fail(self):
        (self.esp/'EFI/Linux/lanrith_17.efi').write_bytes((self.root/self.files['uki']).read_bytes())
        with self.assertRaises(release.ReleaseError):
            self.inspect()
        (self.esp/'EFI/Linux/lanrith_17.efi').unlink()
        with self.assertRaises(release.ReleaseError):
            repair.inspect_slot(self.root, self.root/'certificate', image_id='lanrith', disk=self.disk, esp=self.esp)

    def test_unrelated_release_authority_cannot_authenticate_the_slot(self):
        other_key = Path(self.secrets.name)/'other-key'
        other_certificate = Path(self.secrets.name)/'other-cert'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=synthetic-unrelated-authority', '-keyout', str(other_key),
                        '-out', str(other_certificate)], check=True, capture_output=True)
        with self.assertRaises(release.ReleaseError):
            repair.inspect_slot(self.root, other_certificate, image_id='lanrith', disk=self.disk, esp=self.esp)

    def test_boot_symlink_and_changed_geometry_are_rejected(self):
        uki = self.esp/'EFI/Linux/lanrith_17+2-1.efi'
        uki.unlink()
        uki.symlink_to(self.root/self.files['uki'])
        with self.assertRaises(release.ReleaseError):
            self.inspect()
        uki.unlink()
        uki.write_bytes((self.root/self.files['uki']).read_bytes())
        changed = copy.deepcopy(self.rows)
        changed[0]['uuid'] = 'abcdefab-1234-1234-1234-123456789abc'
        with patch.object(update, 'boot_esp', return_value=self.esp), \
                patch.object(update, 'geometry', side_effect=[self.rows, changed]), \
                patch.object(repair, 'disk_layout', return_value=self.layout), \
                patch.object(repair, 'partition_digest', side_effect=lambda device, size:
                             hashlib.sha256(self.device_bytes[device][:size]).hexdigest()), \
                self.assertRaisesRegex(release.ReleaseError, 'changed during inspection'):
            repair.inspect_slot(self.root, self.certificate, image_id='lanrith', disk=self.disk, esp=self.esp)

    def test_overlapping_or_out_of_bounds_gpt_is_rejected(self):
        table = {'label': 'gpt', 'device': self.disk, 'unit': 'sectors', 'sectorsize': 512,
                 'firstlba': 34, 'lastlba': 1000,
                 'partitions': [{'node': '/dev/synthetic1', 'start': 40, 'size': 50},
                                {'node': '/dev/synthetic2', 'start': 90, 'size': 20}]}
        def command(args):
            return '512512' if args[0] == 'blockdev' else json.dumps({'partitiontable': table})
        with patch.object(update, 'command', side_effect=command):
            self.assertEqual(len(repair.disk_layout(self.disk)['extents']), 2)
        for start, size in ((89, 20), (990, 20), (0, 20)):
            changed = copy.deepcopy(table);changed['partitions'][1].update(start=start, size=size)
            def command(args):
                return '512512' if args[0] == 'blockdev' else json.dumps({'partitiontable': changed})
            with self.subTest(start=start), patch.object(update, 'command', side_effect=command), \
                    self.assertRaises(release.ReleaseError):
                repair.disk_layout(self.disk)

    def test_partition_reader_rejects_non_block_files_and_unsafe_paths(self):
        with self.assertRaises(release.ReleaseError):
            repair.partition_digest('/tmp/not-a-device', 32)
        with patch.object(repair.os, 'open', return_value=0), patch.object(repair.os, 'fdopen') as fdopen:
            fdopen.return_value.__enter__.return_value.fileno.return_value = 0
            with patch.object(repair.os, 'fstat') as fstat:
                fstat.return_value.st_mode = 0o100600
                with self.assertRaises(release.ReleaseError):
                    repair.partition_digest('/dev/synthetic1', 32)

    def test_partition_reader_hashes_only_signed_bytes_and_rejects_truncation(self):
        with tempfile.TemporaryDirectory(prefix='lanrith-repair-reader-') as temporary:
            path = Path(temporary)/'synthetic-partition'
            path.write_bytes(b'signed-bytes' + b'padding')
            native_open = os.open
            with patch.object(repair.os, 'open', side_effect=lambda *args: native_open(path, os.O_RDONLY)), \
                    patch.object(repair.os, 'fstat') as fstat:
                fstat.return_value.st_mode = 0o060000
                self.assertEqual(repair.partition_digest('/dev/synthetic1', len(b'signed-bytes')),
                                 hashlib.sha256(b'signed-bytes').hexdigest())
                with self.assertRaisesRegex(release.ReleaseError, 'truncated'):
                    repair.partition_digest('/dev/synthetic1', 100)


class RecoveryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='lanrith-contract-test-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.key, cls.cert = cls.root/'key', cls.root/'cert'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=synthetic-contract-test', '-keyout', str(cls.key), '-out', str(cls.cert)],
                       check=True, capture_output=True)
        cls.key.chmod(0o600)

    def setUp(self):
        guard = patch.object(repair, 'require_readonly_esp')
        guard.start(); self.addCleanup(guard.stop)
        temp = tempfile.TemporaryDirectory(prefix='lanrith-contract-case-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.contract = {'schema': 1, 'machine_id': '1'*32,
                         'state': {'dns': {'writes': 'dns-v1', 'reads': ['dns-v1']}},
                         'trust': {'generation': 1, 'transition': 'steady', 'authorities':
                                   {'manifest': '2'*64, 'secure_boot': '3'*64,
                                    'verity': '4'*64, 'pcr_policy': '5'*64}}}
        self.retained = copy.deepcopy(self.contract)
        self.current = self.make_release('current', 18, self.contract)
        self.previous = self.make_release('previous', 17, self.contract)

    def make_release(self, name, sequence, contract):
        root = self.root/name
        root.mkdir()
        files = {'uki': f'lanrith_{sequence}.efi'}
        for index, role in enumerate(update.PARTITION_ROLES, 1):
            uuid = f'12345678-1234-1234-1234-{index:012d}'
            files[role] = f'lanrith_{sequence}_{uuid}.{role}.raw'
        for role, name in files.items():
            (root/name).write_bytes(('synthetic-'+role).encode())
        manifest = release.unsigned_manifest(root, purpose='update', version='0.1.0', sequence=sequence,
                                             configuration_sha256='a'*64, files=files,
                                             image_contract=contract)
        (root/'release.json').write_bytes(release.canonical(manifest))
        release.sign(root, self.key)
        return root

    def test_signed_binding_records_exact_artifacts_without_authorizing_boot(self):
        result = repair.signed_fallback_binding(self.previous, self.cert, image_id='lanrith')
        manifest = json.loads((self.previous/'release.json').read_bytes())
        artifacts = {item['role']: item for item in manifest['artifacts']}
        self.assertFalse(result['authorized_to_boot'])
        self.assertEqual(result['fallback']['sequence'], 17)
        self.assertEqual(result['fallback']['uki_sha256'], artifacts['uki']['sha256'])
        from lanrith import tpm_migration
        transition = {'schema': 1, 'phase': 'enroll', 'luks_uuid': 'abcdefab-1234-1234-1234-123456789abc',
                      'legacy_tokens': {'0': {'sha256': 'f'*64, 'keyslot': '0'}}, 'fallback': result['fallback']}
        self.assertEqual(tpm_migration.validate(transition), transition)
        from lanrith import early_failure
        binding = {'disk_by_id': '/dev/disk/by-id/synthetic-disk',
                   'esp_uuid': 'abcdefab-1234-1234-1234-123456789abc', 'release': result['fallback']}
        self.assertEqual(early_failure.validate_fallback_binding(binding, image='lanrith', current_sequence=18), binding)
        for index, role in enumerate(update.PARTITION_ROLES, 1):
            self.assertEqual(result['fallback']['partitions'][role],
                {'label': f'l_17_{role.replace("-", "_")}',
                 'uuid': f'12345678-1234-1234-1234-{index:012d}',
                 'size': artifacts[role]['size'], 'sha256': artifacts[role]['sha256']})
        (self.previous/artifacts['root']['name']).write_bytes(b'tampered')
        with self.assertRaises(release.ReleaseError):
            repair.signed_fallback_binding(self.previous, self.cert, image_id='lanrith')

    def test_assembly_binds_only_an_authenticated_older_release(self):
        value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
        base = self.root/'base.tar'
        base.write_bytes(b'synthetic-test-input')
        from lanrith import boot_policy
        manifest = json.loads((self.previous/'release.json').read_bytes())
        manifest['image_contract'] = boot_policy.contract(value, base, self.cert,
            boot_policy.public_key(self.key, self.cert), {})
        (self.previous/'release.json').write_bytes(release.canonical(manifest))
        (self.previous/'release.json.sig').unlink()
        release.sign(self.previous, self.key)
        options = {'fallback_release': self.previous, 'fallback_disk_by_id': '/dev/disk/by-id/synthetic-disk',
                   'fallback_esp_uuid': 'abcdefab-1234-1234-1234-123456789abc'}
        workspace = self.root/'assembly'
        build.assembly(value, base, workspace, version='0.1.0', sequence=18,
                       certificate=self.cert, private_key=self.key, **options)
        initrd = workspace/'mkosi.images/initrd/mkosi.extra'
        embedded = json.loads((initrd/'usr/share/lanrith/initrd-failure.json').read_bytes())
        self.assertEqual(embedded['fallback_binding']['release'],
                         repair.signed_fallback_binding(self.previous, self.cert, image_id='lanrith')['fallback'])
        self.assertEqual(embedded['fallback_binding']['disk_by_id'], options['fallback_disk_by_id'])
        self.assertFalse(any(p.suffix in ('.yaml', '.yml') for p in initrd.rglob('*')))
        from lanrith import early_failure
        self.assertFalse(early_failure.FALLBACK_AUTHENTICATION_QUALIFIED)
        cases = (({'fallback_release': self.previous}, 18),
                 ({**options, 'fallback_disk_by_id': '/dev/disk/by-id/synthetic-part1'}, 18),
                 (options, 17))
        for index, (bad, sequence) in enumerate(cases):
            rejected = self.root/f'rejected-{index}'
            with self.subTest(index=index), self.assertRaises(release.ReleaseError):
                build.assembly(value, base, rejected, version='0.1.0', sequence=sequence,
                               certificate=self.cert, private_key=self.key, **bad)
            self.assertFalse(rejected.exists())
        manifest = json.loads((self.previous/'release.json').read_bytes())
        root = next(x for x in manifest['artifacts'] if x['role'] == 'root')
        (self.previous/root['name']).write_bytes(b'tampered')
        rejected = self.root/'tampered'
        with self.assertRaises(release.ReleaseError):
            build.assembly(value, base, rejected, version='0.1.0', sequence=18,
                           certificate=self.cert, private_key=self.key, **options)
        self.assertFalse(rejected.exists())

    def test_signed_compatible_contracts_remain_observations_only(self):
        result = repair.inspect_contracts(self.current, self.previous, self.cert,
                                          image_id='lanrith', retained=self.retained)
        self.assertEqual((result['current_sequence'], result['fallback_sequence']), (18, 17))
        self.assertFalse(result['retained_state_authenticated'])
        self.assertFalse(result['authorized_to_boot'])

    def test_missing_state_unknown_retained_format_and_wrong_machine_fail(self):
        for change in ('missing', 'unknown', 'machine', 'trust'):
            state = copy.deepcopy(self.retained)
            if change == 'missing': state['state'] = {'other': {'writes': 'other-v1', 'reads': ['other-v1']}}
            if change == 'unknown': state['state']['dns'] = {'writes': 'dns-v2', 'reads': ['dns-v2']}
            if change == 'machine': state['machine_id'] = 'a'*32
            if change == 'trust': state['trust']['generation'] = 2
            with self.subTest(change=change), self.assertRaises(release.ReleaseError):
                repair.inspect_contracts(self.current, self.previous, self.cert, image_id='lanrith', retained=state)

    def test_retained_disabled_component_must_be_readable_by_fallback(self):
        contract = copy.deepcopy(self.contract)
        contract['state']['legacy'] = {'writes': 'legacy-v1', 'reads': ['legacy-v1']}
        previous = self.make_release('with-legacy', 16, contract)
        retained = copy.deepcopy(self.retained)
        retained['state']['legacy'] = {'writes': 'legacy-v2', 'reads': ['legacy-v2']}
        with self.assertRaisesRegex(release.ReleaseError, 'Fallback cannot read retained state'):
            repair.inspect_contracts(self.current, previous, self.cert, image_id='lanrith', retained=retained)
        retained['state']['legacy'] = {'writes': 'legacy-v1', 'reads': ['legacy-v1']}
        self.assertFalse(repair.inspect_contracts(self.current, previous, self.cert,
                                                   image_id='lanrith', retained=retained)['authorized_to_boot'])

    def test_unreadable_fallback_trust_change_and_nonolder_release_fail(self):
        for change in ('format', 'trust', 'sequence'):
            contract = copy.deepcopy(self.contract)
            if change == 'format': contract['state']['dns'] = {'writes': 'dns-v2', 'reads': ['dns-v2']}
            if change == 'trust': contract['trust']['authorities']['pcr_policy'] = 'a'*64
            previous = self.make_release(change, 18 if change == 'sequence' else 16, contract)
            with self.subTest(change=change), self.assertRaises(release.ReleaseError):
                repair.inspect_contracts(self.current, previous, self.cert,
                                         image_id='lanrith', retained=self.retained)

    def test_signed_releases_and_installed_slot_are_compared_together(self):
        from lanrith import recovery_state
        manifest = json.loads((self.previous/'release.json').read_bytes())
        artifacts = {item['role']: item for item in manifest['artifacts']}
        esp = self.root/'esp'
        (esp/'EFI/Linux').mkdir(parents=True)
        (esp/'EFI/Linux'/artifacts['uki']['name']).write_bytes((self.previous/artifacts['uki']['name']).read_bytes())
        rows, extents, contents = [], [], {}
        for index, role in enumerate(update.PARTITION_ROLES, 1):
            item = artifacts[role]
            uuid = f'12345678-1234-1234-1234-{index:012d}'
            device = f'/dev/synthetic{index}'
            contents[device] = (self.previous/item['name']).read_bytes()
            rows.append({'disk': '/dev/synthetic', 'device': device, 'number': index,
                         'type': update.GUIDS[role], 'label': f'l_17_{role.replace("-", "_")}',
                         'uuid': uuid, 'size': 512, 'mounted': False})
            extents.append((index, index+1, device))
        with patch.object(recovery_state, 'retained_contract', return_value=self.retained), \
                patch.object(update, 'boot_esp', return_value=esp), \
                patch.object(update, 'geometry', return_value=rows), \
                patch.object(repair, 'disk_layout', return_value={'sector': 512, 'extents': extents}), \
                patch.object(repair, 'partition_digest', side_effect=lambda device, size:
                             hashlib.sha256(contents[device][:size]).hexdigest()):
            result = recovery_state.assess_fallback(self.current, self.previous, self.cert,
                image_id='lanrith', disk='/dev/synthetic', esp=esp, state_mount=Path('/state'))
        self.assertEqual(result['fallback_sequence'], 17)
        self.assertFalse(result['retained_state_authenticated'])
        self.assertFalse(result['authorized_to_boot'])

    def test_signed_metadata_and_payload_tampering_fail(self):
        manifest = json.loads((self.previous/'release.json').read_bytes())
        root_name = next(item['name'] for item in manifest['artifacts'] if item['role'] == 'root')
        (self.previous/root_name).write_bytes(b'tampered')
        with self.assertRaises(release.ReleaseError):
            repair.inspect_contracts(self.current, self.previous, self.cert,
                                     image_id='lanrith', retained=self.retained)
        with self.assertRaises(release.ReleaseError):
            repair.inspect_contracts(self.current, self.current, self.cert,
                                     image_id='lanrith', retained=self.retained)


class CombinedRecoveryObservationTests(unittest.TestCase):
    def test_observation_composes_state_signed_contract_and_slot_without_boot_authority(self):
        from lanrith import recovery_state
        contracts = {'current_sequence': 18, 'fallback_sequence': 17, 'fallback_manifest_sha256': 'a'*64,
                     'retained_state_authenticated': False, 'authorized_to_boot': False}
        slot = {'deployment_sequence': 17, 'uki_name': 'lanrith_17.efi',
                'manifest_sha256': 'a'*64, 'authorized_to_boot': False}
        with patch.object(recovery_state, 'retained_contract', return_value={'synthetic': True}) as state, \
                patch.object(repair, 'inspect_contracts', return_value=contracts) as compare, \
                patch.object(repair, 'inspect_slot', return_value=slot) as inspect:
            result = recovery_state.assess_fallback(Path('/current'), Path('/fallback'), Path('/authority'),
                                            image_id='lanrith', disk='/dev/test', esp=Path('/esp'),
                                            state_mount=Path('/state'))
        state.assert_called_once_with(Path('/state'))
        self.assertEqual(compare.call_args.kwargs['retained'], {'synthetic': True})
        inspect.assert_called_once()
        self.assertFalse(result['authorized_to_boot'])
        self.assertFalse(result['retained_state_authenticated'])
        self.assertEqual(result['fallback_sequence'], 17)

    def test_mismatched_sequence_or_authorized_observation_is_rejected(self):
        from lanrith import recovery_state
        contracts = {'current_sequence': 18, 'fallback_sequence': 17, 'fallback_manifest_sha256': 'a'*64,
                     'retained_state_authenticated': False, 'authorized_to_boot': False}
        slot = {'deployment_sequence': 17, 'uki_name': 'lanrith_17.efi',
                'manifest_sha256': 'a'*64, 'authorized_to_boot': False}
        for change in ('sequence', 'manifest', 'boot', 'authenticated'):
            actual_contracts, actual_slot = dict(contracts), dict(slot)
            if change == 'sequence': actual_slot['deployment_sequence'] = 16
            if change == 'manifest': actual_slot['manifest_sha256'] = 'b'*64
            if change == 'boot': actual_slot['authorized_to_boot'] = True
            if change == 'authenticated': actual_contracts['retained_state_authenticated'] = True
            with self.subTest(change=change), patch.object(recovery_state, 'retained_contract', return_value={}), \
                    patch.object(repair, 'inspect_contracts', return_value=actual_contracts), \
                    patch.object(repair, 'inspect_slot', return_value=actual_slot), \
                    self.assertRaises(release.ReleaseError):
                recovery_state.assess_fallback(Path('/current'), Path('/fallback'), Path('/authority'),
                                       image_id='lanrith', disk='/dev/test', esp=Path('/esp'),
                                       state_mount=Path('/state'))


class RecoveryEspPortTests(unittest.TestCase):
    def test_requires_restricted_readonly_esp_options(self):
        esp = Path('/run/recovery-esp')
        for options, valid in (('ro,nodev,nosuid,noexec', True), ('rw,nodev,nosuid,noexec', False),
                               ('ro,nodev,nosuid', False)):
            payload = json.dumps({'filesystems': [{'target': str(esp), 'options': options}]})
            with self.subTest(options=options), patch.object(update, 'command', return_value=payload):
                if valid:
                    repair.require_readonly_esp(esp)
                else:
                    with self.assertRaises(release.ReleaseError): repair.require_readonly_esp(esp)


if __name__ == '__main__':
    unittest.main()
