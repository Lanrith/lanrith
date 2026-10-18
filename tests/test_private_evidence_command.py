"""Exercise the isolated evidence command with real signed handoff archives."""

import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import yaml

from lanrith import build, config, evidence, local, release


PROJECT = Path(__file__).resolve().parents[1]


class PrivateEvidenceCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authorities = tempfile.TemporaryDirectory(prefix='lanrith-evidence-command-keys.')
        cls.addClassCleanup(cls.authorities.cleanup)
        cls.keys = Path(cls.authorities.name)
        for name in ('boot', 'evidence'):
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Lanrith Disposable Evidence Command '+name,
                '-keyout', str(cls.keys/(name+'.key')), '-out', str(cls.keys/(name+'.crt'))],
                check=True, capture_output=True)
            (cls.keys/(name+'.key')).chmod(0o600)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lanrith-evidence-command.')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.owner = self.root/'owner'
        (self.owner/'trust').mkdir(parents=True)
        for name in ('boot', 'evidence'):
            shutil.copyfile(self.keys/(name+'.crt'), self.owner/'trust'/(name+'.crt'))
        value = yaml.safe_load((PROJECT/'examples/minimal.yaml').read_text())
        value['hostname'] = 'evidence-command-test'
        value['hardware']['machine_id'] = '5'*32
        value['release'] = {'sequence_floor': 100}
        (self.owner/'config.yaml').write_text(yaml.safe_dump(value))
        self.value = config.load(self.owner/'config.yaml')
        self.configuration = hashlib.sha256(release.canonical(self.value)).hexdigest()
        self.selection = {'schema': 1, 'repository': 'Lanrith/lanrith', 'version': 'v1.2.3',
            'source_commit': 'b'*40, 'signer_commit': 'b'*40, 'security_workflow_commit': 'b'*40,
            'manifest_sha256': 'c'*64, 'builder': 'ghcr.io/lanrith/lanrith-builder',
            'builder_digest': 'd'*64, 'files': {'inventory.json': 'e'*64}}
        (self.owner/'platform.lock').write_bytes(release.canonical(self.selection))
        self.artifacts = self.root/'artifacts'
        self.artifacts.mkdir()
        self.context = {'repository': 'example/router-config', 'source_commit': 'a'*40,
                        'workflow_commit': 'b'*40}

    def handoff(self, *, factory_configuration=None, update_configuration=None,
                factory_root=b'synthetic-root', profile='repository', serial=False, integration=False):
        value = yaml.safe_load((self.owner/'config.yaml').read_text())
        serial_hash, integrations = None, {}
        if serial:
            value['administration']['serial'] = {'enabled': True, 'tty': 'ttyS0'}
            serial_hash = self.root/'serial.hash'
            serial_hash.write_text('scrypt:32768:8:1:'+'1'*32+':'+'2'*64+'\n')
            serial_hash.chmod(0o600)
        if integration:
            value['extensions'] = ['example']
            directory = self.owner/'extensions/example'
            name = 'usr/share/lanrith/integrations/example/settings.json'
            path = directory/'root'/name
            path.parent.mkdir(parents=True)
            path.write_text('{"setting":"synthetic"}\n')
            path.chmod(0o644)
            manifest = {'schema': 1, 'id': 'example', 'features': [], 'health_units': [],
                'files': {name: {'sha256': release.file_record(path)['sha256'],
                                 'size': path.stat().st_size, 'mode': 0o644}}}
            (directory/'extension.json').write_bytes(release.canonical(manifest))
            pin = release.file_record(directory/'extension.json')['sha256']
            integrations['example'] = (directory, pin)
            (self.owner/'extensions.lock').write_bytes(release.canonical({'example': pin}))
        (self.owner/'config.yaml').write_text(yaml.safe_dump(value))
        self.value = config.load(self.owner/'config.yaml')
        self.configuration = hashlib.sha256(release.canonical(self.value)).hexdigest()
        # Use the assembly producer's identity, rather than manufacturing a
        # manifest from the evidence command's expected configuration digest.
        base = self.root/'base.tar'
        with tarfile.open(base, 'w') as archive:
            for name, data in {'etc/passwd': b'root:*:0:0:root:/root:/bin/bash\n',
                               'etc/group': b'root:x:0:\n'}.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(data))
        workspace = self.root/'assembly'
        identity = build.assembly(self.value, base.resolve(), workspace,
            version='1.2.3', sequence=107, integrations=integrations, serial_hash=serial_hash)
        self.effective_configuration = identity['configuration_sha256']
        self.serial_digest = release.file_record(serial_hash)['sha256'] if serial_hash else None
        self.serial_hash = serial_hash
        self.integration_digests = {name: pin[1] for name, pin in integrations.items()}
        self.assertNotEqual(self.effective_configuration, self.configuration)
        installed = json.loads((workspace/'mkosi.extra/usr/share/lanrith/installed.json').read_bytes())
        self.assertEqual(installed['configuration_sha256'], self.effective_configuration)
        manifests = {}
        for purpose in ('update', 'factory'):
            directory = self.root/purpose
            directory.mkdir()
            files = {role: 'synthetic.'+role for role in release.ROLES[purpose]}
            for role, name in files.items():
                data = ('synthetic-'+role).encode()
                if purpose == 'factory' and role == 'root':
                    data = factory_root
                (directory/name).write_bytes(data)
            manifest = release.unsigned_manifest(directory, purpose=purpose, version='1.2.3', sequence=107,
                configuration_sha256=((factory_configuration if purpose == 'factory' else update_configuration)
                                      or self.effective_configuration), files=files)
            (directory/'release.json').write_bytes(release.canonical(manifest))
            release.sign(directory, self.keys/'boot.key')
            manifests[purpose] = manifest
            with tarfile.open(self.artifacts/(purpose+'.tar.gz'), 'w:gz', format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(directory.iterdir()):
                    archive.add(path, arcname=path.name)
        self.deployment = {'schema': 1, 'configuration_sha256': self.configuration,
            'effective_configuration_sha256': self.effective_configuration,
            'serial_provisioning_sha256': self.serial_digest,
            'integration_digests': self.integration_digests,
            'platform_lock_sha256': release.file_record(self.owner/'platform.lock')['sha256'],
            'boot_certificate_sha256': release.file_record(self.owner/'trust/boot.crt')['sha256'],
            'evidence_certificate_sha256': release.file_record(self.owner/'trust/evidence.crt')['sha256'],
            **self.context, 'signing_profile': profile, 'deployment_sequence': 107,
            'release': manifests['update'], 'factory': manifests['factory']}
        (self.artifacts/'deployment.json').write_bytes(release.canonical(self.deployment))

    def environment(self, profile='repository'):
        environment = {name: value for name, value in os.environ.items() if not name.startswith('LANRITH_')}
        environment.update(GITHUB_REPOSITORY=self.context['repository'], GITHUB_SHA=self.context['source_commit'],
            GITHUB_RUN_NUMBER='7', GITHUB_RUN_ID='101', LANRITH_WORKFLOW_COMMIT=self.context['workflow_commit'],
            LANRITH_SIGNING_PROFILE=profile, LANRITH_EVIDENCE_KEY=(self.keys/'evidence.key').read_text(),
            LANRITH_EVIDENCE_CERTIFICATE=(self.keys/'evidence.crt').read_text())
        return environment

    def command(self, profile='repository'):
        return subprocess.run([sys.executable, '-B', str(PROJECT/'scripts/private-evidence.py'),
            '--owner', str(self.owner), '--artifacts', str(self.artifacts)], env=self.environment(profile),
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)

    def assemble_handoff(self):
        consumer = local.consumer()
        bundle = self.root/'platform'
        bundle.mkdir()
        (bundle/'inventory.json').write_text('{"synthetic":true}\n')
        with tarfile.open(bundle/'tools.tar.gz', 'w:gz') as archive:
            member = tarfile.TarInfo('scripts/reviewed-tool.py')
            member.size = 1
            archive.addfile(member, io.BytesIO(b'\n'))
        self.selection['files'] = {name: release.file_record(bundle/name)['sha256']
                                   for name in ('inventory.json', 'tools.tar.gz')}
        (self.owner/'platform.lock').write_bytes(release.canonical(self.selection))
        request = {name: value for name, value in self.deployment.items() if name not in
                   {'effective_configuration_sha256', 'serial_provisioning_sha256',
                    'deployment_sequence', 'release', 'factory'}}
        request['platform_lock_sha256'] = release.file_record(self.owner/'platform.lock')['sha256']
        path = self.root/'request.json'
        path.write_bytes(release.canonical(request))
        (bundle/'signing-admission.json').write_bytes(release.canonical({'request': request,
            'admitted_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'assessment_sha256': None}))

        def run(*arguments, **kwargs):
            if arguments[0] == 'docker':
                payload = Path(arguments[arguments.index('--output')+1])
                private = Path(arguments[arguments.index('--private')+1])
                receipt = json.loads((private/'admitted.json').read_bytes())
                self.assertEqual(receipt['effective_configuration_sha256'], self.effective_configuration)
                self.assertEqual(receipt['serial_provisioning_sha256'], self.serial_digest)
                shutil.copytree(self.root/'update', payload)
                shutil.copytree(self.root/'factory', payload.parent/'factory')
            else:
                self.assertEqual(arguments[:3], ('sudo', 'chown', '--recursive'))
            return subprocess.CompletedProcess(arguments, 0)

        environment = self.environment()
        environment.update(RUNNER_TEMP=str(self.root), LANRITH_BOOT_KEY=(self.keys/'boot.key').read_text(),
                           LANRITH_BOOT_CERTIFICATE=(self.keys/'boot.crt').read_text())
        if self.serial_hash:
            environment['LANRITH_SERIAL_PASSPHRASE_HASH'] = self.serial_hash.read_text()
        output = self.root/'host-handoff'
        with patch.dict(os.environ, environment, clear=True), patch.object(consumer, 'run', side_effect=run):
            consumer.assemble(self.owner, bundle, path, output)
        return output

    def test_complete_command_signs_verified_factory_and_update_in_both_profiles(self):
        self.handoff()
        for profile in ('repository', 'protected'):
            with self.subTest(profile=profile):
                self.deployment['signing_profile'] = profile
                (self.artifacts/'deployment.json').write_bytes(release.canonical(self.deployment))
                result = self.command(profile)
                self.assertEqual(result.returncode, 0, result.stderr)
                envelope = self.artifacts/'provenance.dsse.json'
                statement = evidence.verify(envelope, self.artifacts, self.owner/'trust/evidence.crt', **self.context)
                inputs = statement['predicate']['buildDefinition']['externalParameters']['inputs']
                self.assertEqual(inputs['platform'], self.selection)
                self.assertEqual(inputs['configuration_sha256'], self.configuration)
                self.assertEqual(inputs['effective_configuration_sha256'], self.effective_configuration)
                self.assertEqual(inputs['integration_digests'], self.integration_digests)
                self.assertEqual(inputs['serial_provisioning_sha256'], self.serial_digest)
                self.assertEqual(inputs['signing_profile'], profile)
                self.assertIs(inputs['protected_signing'], profile == 'protected')
                self.assertEqual({subject['name'] for subject in statement['subject']},
                                 {'deployment.json', 'factory.tar.gz', 'update.tar.gz'})
                envelope.unlink()

    def test_real_assembly_serial_and_integration_identity_is_admitted(self):
        self.handoff(serial=True, integration=True)
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        statement = evidence.verify(self.artifacts/'provenance.dsse.json', self.artifacts,
                                    self.owner/'trust/evidence.crt', **self.context)
        inputs = statement['predicate']['buildDefinition']['externalParameters']['inputs']
        self.assertEqual(inputs['effective_configuration_sha256'], self.effective_configuration)
        self.assertEqual(inputs['integration_digests'], self.integration_digests)
        self.assertEqual(inputs['serial_provisioning_sha256'], self.serial_digest)

    @unittest.skipUnless(Path('/dev/shm').is_mount(), 'Run in a builder with private tmpfs.')
    def test_host_and_evidence_handoff_share_real_assembly_identity(self):
        self.handoff(serial=True, integration=True)
        self.artifacts = self.assemble_handoff()
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        deployment = json.loads((self.artifacts/'deployment.json').read_bytes())
        self.assertEqual(deployment['configuration_sha256'], self.configuration)
        self.assertEqual(deployment['effective_configuration_sha256'], self.effective_configuration)
        self.assertEqual(deployment['serial_provisioning_sha256'], self.serial_digest)

    @unittest.skipUnless(Path('/dev/shm').is_mount(), 'Run in a builder with private tmpfs.')
    def test_host_rejects_trusted_manifests_with_wrong_effective_configuration(self):
        self.handoff(factory_configuration='f'*64, update_configuration='f'*64)
        with self.assertRaisesRegex(release.ReleaseError, 'Configuration digest differs.'):
            self.assemble_handoff()
        self.assertFalse((self.root/'host-handoff').exists())

    def test_config_only_hash_in_both_manifests_cannot_replace_assembly_identity(self):
        self.handoff(factory_configuration=self.configuration, update_configuration=self.configuration)
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Configuration digest differs.', result.stderr)
        self.assertFalse((self.artifacts/'provenance.dsse.json').exists())

    def test_changed_serial_provisioning_digest_is_rejected(self):
        self.handoff(serial=True)
        self.deployment['serial_provisioning_sha256'] = 'f'*64
        (self.artifacts/'deployment.json').write_bytes(release.canonical(self.deployment))
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.artifacts/'provenance.dsse.json').exists())

    def test_serial_provisioning_digest_must_match_selectedness(self):
        self.handoff()
        self.deployment['serial_provisioning_sha256'] = 'f'*64
        (self.artifacts/'deployment.json').write_bytes(release.canonical(self.deployment))
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Effective serial provisioning differs from configuration.', result.stderr)
        self.assertFalse((self.artifacts/'provenance.dsse.json').exists())

    def test_selected_serial_provisioning_digest_cannot_be_omitted(self):
        self.handoff(serial=True)
        self.deployment['serial_provisioning_sha256'] = None
        (self.artifacts/'deployment.json').write_bytes(release.canonical(self.deployment))
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Effective serial provisioning differs from configuration.', result.stderr)
        self.assertFalse((self.artifacts/'provenance.dsse.json').exists())

    def test_changed_integration_cannot_be_attested(self):
        self.handoff(integration=True)
        (self.owner/'extensions/example/root/usr/share/lanrith/integrations/example/settings.json').write_text('changed\n')
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Integration file differs from the reviewed bytes or mode.', result.stderr)
        self.assertFalse((self.artifacts/'provenance.dsse.json').exists())

    def test_changed_effective_configuration_digest_is_rejected(self):
        self.handoff()
        self.deployment['effective_configuration_sha256'] = 'f'*64
        (self.artifacts/'deployment.json').write_bytes(release.canonical(self.deployment))
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.artifacts/'provenance.dsse.json').exists())

    def test_factory_signed_for_another_configuration_is_rejected_before_evidence(self):
        self.handoff(factory_configuration='f'*64)
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Configuration digest differs.', result.stderr)
        self.assertFalse((self.artifacts/'provenance.dsse.json').exists())

    def test_matching_signed_pair_for_another_owner_configuration_is_rejected(self):
        self.handoff(factory_configuration='f'*64, update_configuration='f'*64)
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Configuration digest differs.', result.stderr)
        self.assertFalse((self.artifacts/'provenance.dsse.json').exists())

    def test_factory_and_update_with_different_signed_root_files_are_rejected(self):
        self.handoff(factory_root=b'another-signed-root')
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Factory and update do not contain the same verified-root triplet and UKI.', result.stderr)
        self.assertFalse((self.artifacts/'provenance.dsse.json').exists())

    def test_deployment_for_another_source_is_rejected_before_evidence(self):
        self.handoff()
        self.deployment['source_commit'] = 'f'*40
        (self.artifacts/'deployment.json').write_bytes(release.canonical(self.deployment))
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Build output differs from the immutable workflow inputs.', result.stderr)
        self.assertFalse((self.artifacts/'provenance.dsse.json').exists())
