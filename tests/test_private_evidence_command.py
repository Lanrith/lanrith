"""Exercise the isolated evidence command with real signed handoff archives."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

import yaml

from lanrith import config, evidence, release


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
                factory_root=b'synthetic-root', profile='repository'):
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
                                      or self.configuration), files=files)
            (directory/'release.json').write_bytes(release.canonical(manifest))
            release.sign(directory, self.keys/'boot.key')
            manifests[purpose] = manifest
            with tarfile.open(self.artifacts/(purpose+'.tar.gz'), 'w:gz', format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(directory.iterdir()):
                    archive.add(path, arcname=path.name)
        self.deployment = {'schema': 1, 'configuration_sha256': self.configuration, 'integration_digests': {},
            'platform_lock_sha256': release.file_record(self.owner/'platform.lock')['sha256'],
            'boot_certificate_sha256': release.file_record(self.owner/'trust/boot.crt')['sha256'],
            'evidence_certificate_sha256': release.file_record(self.owner/'trust/evidence.crt')['sha256'],
            **self.context, 'signing_profile': profile, 'deployment_sequence': 107,
            'release': manifests['update'], 'factory': manifests['factory']}
        (self.artifacts/'deployment.json').write_bytes(release.canonical(self.deployment))

    def command(self, profile='repository'):
        environment = {name: value for name, value in os.environ.items() if not name.startswith('LANRITH_')}
        environment.update(GITHUB_REPOSITORY=self.context['repository'], GITHUB_SHA=self.context['source_commit'],
            GITHUB_RUN_NUMBER='7', GITHUB_RUN_ID='101', LANRITH_WORKFLOW_COMMIT=self.context['workflow_commit'],
            LANRITH_SIGNING_PROFILE=profile, LANRITH_EVIDENCE_KEY=(self.keys/'evidence.key').read_text(),
            LANRITH_EVIDENCE_CERTIFICATE=(self.keys/'evidence.crt').read_text())
        return subprocess.run([sys.executable, '-B', str(PROJECT/'scripts/private-evidence.py'),
            '--owner', str(self.owner), '--artifacts', str(self.artifacts)], env=environment,
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)

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
                self.assertEqual(inputs['signing_profile'], profile)
                self.assertIs(inputs['protected_signing'], profile == 'protected')
                self.assertEqual({subject['name'] for subject in statement['subject']},
                                 {'deployment.json', 'factory.tar.gz', 'update.tar.gz'})
                envelope.unlink()

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
