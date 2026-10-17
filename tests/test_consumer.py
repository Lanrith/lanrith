"""Private signing profiles preserve admission and identify their trust model."""

import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lanrith import local, release


class ConsumerSigningTests(unittest.TestCase):
    def setUp(self):
        self.consumer = local.consumer()
        self.context = patch.dict(os.environ, {'GITHUB_REF': 'refs/heads/main',
            'GITHUB_EVENT_NAME': 'push', 'LANRITH_SIGNING_PROFILE': 'protected'})
        self.context.start()
        self.addCleanup(self.context.stop)

    def metadata(self, *, private=True, branch='main', rules=None):
        values = {'': {'private': private, 'default_branch': branch},
                  '/rules/branches/main?per_page=100': rules if rules is not None else [
                      {'type': 'pull_request', 'parameters': {'required_approving_review_count': 1,
                                                           'dismiss_stale_reviews_on_push': True}},
                      {'type': 'required_status_checks', 'parameters': {
                          'required_status_checks': [{'context': 'Configuration checks'}]}}]}
        for name in ('lanrith-signing', 'lanrith-evidence'):
            values['/environments/'+name] = {'deployment_branch_policy': {
                'protected_branches': True, 'custom_branch_policies': False}}

        def run(*args, **kwargs):
            suffix = args[2].removeprefix('repos/example/router')
            return subprocess.CompletedProcess(args, 0, json.dumps(values[suffix]), '')
        return run

    def test_protected_is_the_default_and_requires_actual_controls(self):
        with patch.dict(os.environ):
            os.environ.pop('LANRITH_SIGNING_PROFILE', None)
            self.assertEqual(self.consumer.signing_profile(), 'protected')
        with patch.object(self.consumer, 'run', side_effect=self.metadata()) as run:
            value = self.consumer.protections('example/router')
        self.assertEqual(value['signing_profile'], 'protected')
        self.assertTrue(value['protected_signing'])
        self.assertEqual(run.call_count, 4)
        with patch.object(self.consumer, 'run', side_effect=self.metadata(rules=[])):
            with self.assertRaises(release.ReleaseError):
                self.consumer.protections('example/router')

    def test_repository_mode_does_not_claim_or_require_paid_controls(self):
        with patch.dict(os.environ, {'LANRITH_SIGNING_PROFILE': 'repository'}), \
                patch.object(self.consumer, 'run', side_effect=self.metadata()) as run:
            value = self.consumer.protections('example/router')
        self.assertFalse(value['protected_signing'])
        self.assertEqual(value['credential_scope'], 'repository')
        self.assertEqual(value['writer_trust'], 'all-repository-writers')
        self.assertEqual(run.call_count, 1)

    def test_unknown_profile_or_non_release_context_fails_before_api_access(self):
        for context in ({'LANRITH_SIGNING_PROFILE': 'unreviewed'},
                        {'GITHUB_REF': 'refs/heads/change'},
                        {'GITHUB_EVENT_NAME': 'pull_request'},
                        {'GITHUB_EVENT_NAME': 'pull_request_target'}):
            with self.subTest(context=context), patch.dict(os.environ, context), \
                    patch.object(self.consumer, 'run') as run:
                with self.assertRaises(release.ReleaseError):
                    self.consumer.protections('example/router')
                run.assert_not_called()

    def test_both_profiles_reject_public_repositories_and_wrong_release_branches(self):
        for profile in ('protected', 'repository'):
            for metadata in ({'private': False}, {'branch': 'other'}):
                with self.subTest(profile=profile, metadata=metadata), \
                        patch.dict(os.environ, {'LANRITH_SIGNING_PROFILE': profile}), \
                        patch.object(self.consumer, 'run', side_effect=self.metadata(**metadata)):
                    with self.assertRaises(release.ReleaseError):
                        self.consumer.protections('example/router')

    def test_changed_profile_rejects_assembly_before_key_materialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root/'bundle'
            bundle.mkdir()
            request = root/'request.json'
            value = {'signing_profile': 'repository'}
            request.write_text(json.dumps(value))
            (bundle/'signing-admission.json').write_text(json.dumps({'request': value,
                'admitted_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'assessment_sha256': None}))
            with patch.object(self.consumer.tempfile, 'TemporaryDirectory') as private:
                with self.assertRaisesRegex(release.ReleaseError, 'Signing profile changed'):
                    self.consumer.assemble(root, bundle, request, root/'output')
                private.assert_not_called()
            self.assertFalse((root/'output').exists())

    def test_boot_and_evidence_certificates_cannot_share_an_authority(self):
        with patch.object(self.consumer.trust, 'lock'), patch.object(self.consumer, 'fetch'), \
                patch.object(self.consumer.config, 'load'), \
                patch.object(self.consumer.release, 'public_key', return_value=b'same-public-key'):
            with self.assertRaisesRegex(release.ReleaseError, 'authorities must be separate'):
                self.consumer.preflight(Path('/synthetic-owner'), Path('/synthetic-platform'))
