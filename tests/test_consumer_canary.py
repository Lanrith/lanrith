"""The disposable canary must not run as a production signing path."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from lanrith.release import ReleaseError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('consumer_canary', ROOT/'scripts/qualify-consumer.py')
canary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary)
spec = importlib.util.spec_from_file_location('canary_archive', ROOT/'scripts/archive-consumer-qualification.py')
archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive)


class CanaryBoundaryTests(unittest.TestCase):
    def report(self):
        context = {'GITHUB_REPOSITORY': archive.REPOSITORY, 'GITHUB_REF': 'refs/heads/main',
                   'GITHUB_SHA': 'a'*40, 'LANRITH_WORKFLOW_COMMIT': 'b'*40, 'GITHUB_RUN_ID': '123'}
        report = {'schema': 1, 'kind': 'isolated-consumer-qualification', 'result': 'pass',
                  'repository': archive.REPOSITORY, 'source_commit': 'a'*40, 'workflow_commit': 'b'*40,
                  'platform_version': 'v0.1.32', 'platform_lock_sha256': 'c'*64, 'configuration_sha256': 'd'*64,
                  'deployment_record_sha256': 'e'*64, 'deployable': False, 'signing_authority': 'disposable-per-run',
                  'run_url': 'https://github.com/'+archive.REPOSITORY+'/actions/runs/123'}
        return context, report

    def test_archive_rejects_another_run_source_or_production_claim(self):
        context, report = self.report()
        self.assertEqual(archive.validate_report(json.dumps(report).encode(), context), report)
        for change in ({'source_commit': 'f'*40}, {'workflow_commit': 'f'*40}, {'run_url': report['run_url']+'4'},
                       {'deployable': True}, {'private_key': 'unwanted'}, {'configuration_sha256': '../configuration'}):
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                archive.validate_report(json.dumps({**report, **change}).encode(), context)
        for change in ({'GITHUB_REPOSITORY': 'Lanrith/lanrith'}, {'GITHUB_REF': 'refs/pull/1/merge'}):
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                archive.validate_report(json.dumps(report).encode(), {**context, **change})

    def test_canary_archive_requires_immutable_exact_report_bytes(self):
        context, report = self.report()
        raw = json.dumps(report).encode()
        published = {'immutable': True, 'draft': False, 'prerelease': True, 'tag_name': 'audit-test',
                     'target_commitish': context['GITHUB_SHA'],
                     'assets': [{'name': archive.NAME, 'digest': 'sha256:'+hashlib.sha256(raw).hexdigest()}]}
        archive.verify_archive(published, raw, 'audit-test', context['GITHUB_SHA'])
        for change in ({'immutable': False}, {'draft': True}, {'target_commitish': 'f'*40},
                       {'assets': []}, {'assets': [{'name': archive.NAME, 'digest': 'sha256:'+'f'*64}]}):
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                archive.verify_archive({**published, **change}, raw, 'audit-test', context['GITHUB_SHA'])

    def test_serial_fixture_uses_the_same_credential_contract_as_owner_assembly(self):
        from lanrith.recovery_console import HASH
        first, second = canary.disposable_serial_hash(), canary.disposable_serial_hash()
        self.assertIsNotNone(HASH.fullmatch(first))
        self.assertNotEqual(first, second)

    def test_only_the_isolated_repository_can_use_disposable_qualification(self):
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'Lanrith/config-template'}, clear=True), \
                self.assertRaisesRegex(ReleaseError, 'isolated canary'):
            canary.qualification(Path('/unused'), Path('/unused'))

    def test_deployment_secrets_are_rejected_before_any_build_or_key_generation(self):
        for name in ('LANRITH_BOOT_KEY', 'LANRITH_EVIDENCE_KEY', 'LANRITH_SERIAL_PASSPHRASE_HASH'):
            with self.subTest(name=name), patch.dict(os.environ,
                    {'GITHUB_REPOSITORY': 'Lanrith/config-template-qualification', name: 'fixture'}, clear=True), \
                    self.assertRaisesRegex(ReleaseError, 'must not receive deployment credentials'):
                canary.qualification(Path('/unused'), Path('/unused'))
