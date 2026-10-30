"""Owner hardware and allocation sources stay bound across admission stages."""

import copy
from contextlib import redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lanrith import build, cli, config, hardware_config, local, owner_inputs, release


PROJECT = Path(__file__).resolve().parents[1]


def declaration():
    value = config.load(PROJECT/'examples/minimal.yaml')
    value['hardware']['interfaces']['core'] = {'name': 'port0', 'owner': 'vpp', 'state': 'down',
        'match': {'mac': '02:00:00:00:07:01'}}
    value['translation'] = {'nat64': {'enabled': True, 'internet_pool': '10.244.0.0/20',
                                    'private_pool': '10.244.16.0/20'}}
    value['access']['rules'].append({'action': 'allow',
        'from': {'network': 'home', 'addresses': 'fd42:1000:1000:10::42/128'}, 'to': 'uplink'})
    facts = {'interfaces': [{'name': 'port0', 'mac': '02:00:00:00:07:01', 'pci': '0000:07:00.0',
        'driver': 'virtio-pci', 'iommu_group': 6, 'iommu_members': ['0000:07:00.0']}],
        'hugepages': {'page_size_mib': 2, 'pages': 1024}}
    allocations = {'fd42:1000:1000:10::42': '10.244.31.42'}
    return config.normalize(value), {'target_facts': facts, 'retained_allocations': allocations}


def write_inputs(owner, options):
    for argument, name in owner_inputs.FILES.items():
        (owner/name).write_bytes(release.canonical(options[argument]))


class OwnerInputTests(unittest.TestCase):
    def test_optional_files_preserve_the_small_router(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = config.load(PROJECT/'examples/minimal.yaml')
            self.assertEqual(owner_inputs.load(Path(temporary), value), ({}, {}))

    def test_real_rendering_preserves_owner_selected_facts_and_source_map(self):
        value, expected = declaration()
        with tempfile.TemporaryDirectory() as temporary:
            owner = Path(temporary)
            write_inputs(owner, expected)
            options, records = owner_inputs.load(owner, value)
            self.assertEqual(options, expected)
            for name, record in records.items():
                raw = (owner/name).read_bytes()
                self.assertEqual(record, {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
            files = config.render(value, **options)
            self.assertIn('map 10.244.31.42 fd42:1000:1000:10::42\n', files['etc/tayga-nat64-internal.conf'])
            self.assertIn('0000:07:00.0', files['usr/share/lanrith/ownership.json'])
            self.assertTrue(set(records).isdisjoint(Path(name).name for name in files))

    def test_missing_hardware_evidence_and_disabled_translator_fail_admission(self):
        value, options = declaration()
        with tempfile.TemporaryDirectory() as temporary:
            owner = Path(temporary)
            with self.assertRaisesRegex(release.ReleaseError, 'verified VPP'):
                owner_inputs.load(owner, value)
            write_inputs(owner, options)
            value['translation']['nat64']['enabled'] = False
            with self.assertRaises(release.ReleaseError):
                owner_inputs.load(owner, value)

    def test_duplicate_nonfinite_and_nonobject_json_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = Path(temporary)
            value = config.load(PROJECT/'examples/minimal.yaml')
            path = owner/'translation-allocations.json'
            for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'[]', b'{'):
                with self.subTest(raw=raw):
                    path.write_bytes(raw)
                    with self.assertRaises(release.ReleaseError):
                        owner_inputs.load(owner, value)

    def test_linked_shared_and_oversized_sources_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = root/'owner'; owner.mkdir()
            value = config.load(PROJECT/'examples/minimal.yaml')
            source = root/'source'; source.write_bytes(b'{}\n')
            path = owner/'translation-allocations.json'
            path.symlink_to(source)
            with self.assertRaises((OSError, release.ReleaseError)):
                owner_inputs.load(owner, value)
            path.unlink()
            os.link(source, path)
            with self.assertRaises(release.ReleaseError):
                owner_inputs.load(owner, value)
            path.unlink()
            path.write_bytes(b' '*(1024*1024+1))
            with self.assertRaises(release.ReleaseError):
                owner_inputs.load(owner, value)

    def test_preflight_binds_sidecar_bytes_and_their_effective_meaning(self):
        value, options = declaration()
        selection = {'files': {}, 'manifest_sha256': 'b'*64, 'source_commit': 'c'*40,
                     'builder': 'example.invalid/builder', 'builder_digest': 'd'*64}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner = root/'owner'; (owner/'trust').mkdir(parents=True)
            platform = root/'platform'; platform.mkdir()
            (owner/'config.yaml').write_bytes(release.canonical(value))
            (owner/'platform.lock').write_text('{}\n')
            key, certificate = root/'disposable.key', owner/'trust/boot.crt'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Disposable Owner Input Test', '-keyout', str(key), '-out', str(certificate)],
                check=True, capture_output=True)
            key.chmod(0o600)
            write_inputs(owner, options)
            with patch.object(local.trust, 'lock', return_value=selection):
                request = local.inputs(owner, platform, 1)
                self.assertEqual(request['effective_configuration_sha256'], config.effective_digest(
                    value, {}, boot_inputs={'pcr_public_key_sha256': request['boot_inputs']['pcr_public_key_sha256']},
                    **options))
                for name, record in request['owner_inputs'].items():
                    self.assertEqual({k: request['files'][name][k] for k in record}, record)
                changed = copy.deepcopy(options)
                changed['retained_allocations']['fd42:1000:1000:10::42'] = '10.244.31.43'
                write_inputs(owner, changed)
                second = local.inputs(owner, platform, 1)
                self.assertNotEqual(request['owner_inputs'], second['owner_inputs'])
                self.assertNotEqual(request['effective_configuration_sha256'], second['effective_configuration_sha256'])

    def test_recovery_cli_loads_both_reviewed_sources_before_real_assembly(self):
        value, options = declaration()
        value['hardware']['boot']['recovery_console'] = 'ttyS0'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'config.yaml').write_bytes(release.canonical(value))
            write_inputs(root, options)
            base = root/'base.tar'; base.write_bytes(b'synthetic-base')
            credential = root/'recovery.hash'
            credential.write_text('scrypt:32768:8:1:'+'1'*32+':'+'2'*64+'\n')
            credential.chmod(0o600)
            arguments = ['build-recovery', str(root/'config.yaml'), '--qualification',
                '--base', str(base), '--initrd-base', str(base), '--workspace', str(root/'assembly'),
                '--output', str(root/'output'), '--version', '1.0.0', '--sequence', '9',
                '--recovery-passphrase-hash', str(credential),
                '--recovery-disk-by-id', '/dev/disk/by-id/synthetic-owner-disk']
            for flag, name in (('hardware-facts', 'hardware-facts.json'),
                               ('translation-allocations', 'translation-allocations.json')):
                arguments += ['--'+flag, str(root/name), '--'+flag+'-sha256',
                              hashlib.sha256((root/name).read_bytes()).hexdigest()]
            errors = io.StringIO()
            with patch.object(build, 'run', side_effect=release.ReleaseError('Stop before native image creation.')) as native, \
                    redirect_stderr(errors):
                self.assertEqual(cli.main(arguments), 1)
            self.assertEqual(native.call_count, 1, errors.getvalue())
            self.assertIn('Stop before native image creation.', errors.getvalue())
            overlay = root/'assembly/mkosi.extra'
            self.assertEqual(json.loads((overlay/'usr/share/lanrith/ownership.json').read_bytes()),
                             hardware_config.ownership_manifest(value, options['target_facts']))
            self.assertIn('map 10.244.31.42 fd42:1000:1000:10::42\n',
                          (overlay/'etc/tayga-nat64-internal.conf').read_text())
            self.assertTrue((root/'assembly/RECOVERY-ASSEMBLY').exists())
