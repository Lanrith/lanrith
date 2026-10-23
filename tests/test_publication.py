"""Exercise the actual privileged publication program with adversarial API data."""

import base64
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml


SOURCE, HEAD = 'a'*40, 'b'*40
REPO = 'Lanrith/router-policy-agent'


class PublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1]/'.github/workflows/publish-release.yml'
        workflow = yaml.safe_load(path.read_text())
        step = next(s for s in workflow['jobs']['publish']['steps'] if s.get('run'))
        cls.program = step['run'].split("python3 - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]

    def setUp(self):
        self.state = {'draft': True, 'prerelease': True, 'created': False, 'promoted': False,
                      'tamper_draft': False, 'tamper_published': False, 'wrong_tag': False, 'wrong_check': False}
        self.author = {'login': 'reviewer-app[bot]', 'type': 'Bot'}
        self.review = {'id': 7, 'state': 'APPROVED', 'commit_id': HEAD, 'author_association': 'OWNER',
                       'user': {'id': 1, 'login': 'owner', 'type': 'User'}}
        self.reviews = [self.review]
        self.policy = {'proposal_branch': 'automation/security-updates', 'mode': 'report-only', 'reviewer_app_id': None,
                       'required_workflows': {'.github/workflows/check.yml': ['Required checks']}}
        self.pull = {'number': 12, 'head_sha': HEAD, 'approvals': [{'id': 7, 'actor_id': 1}], 'candidate': None,
                     'validation': [{'workflow': '.github/workflows/check.yml', 'id': 33, 'attempt': 1}]}
        self.pr_ref = 'security/verified-update-automation'
        self.validation = {'event': 'pull_request', 'head_sha': HEAD, 'path': '.github/workflows/check.yml',
                           'status': 'completed', 'conclusion': 'success', 'run_attempt': 1}

    def run_program(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.chdir(temporary):
            root = Path('release')
            root.mkdir()
            value = {'schema': 1, 'kind': 'release-update-record', 'repository': REPO, 'source_commit': SOURCE,
                     'version': '0.1.3', 'pull_requests': [self.pull]}
            (root/'update-record.json').write_text(json.dumps(value))
            (root/'package.deb').write_bytes(b'synthetic qualified package')
            self.assets = [{'id': n, 'name': p.name, 'digest': 'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()}
                           for n, p in enumerate(sorted(root.iterdir()), 1)]
            with patch.dict(os.environ, {'GITHUB_REPOSITORY': REPO, 'GITHUB_SHA': SOURCE,
                    'RELEASE_VERSION': '0.1.3', 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}), \
                    patch('subprocess.run', side_effect=self.command):
                exec(compile(self.program, 'publish-release.yml', 'exec'), {})
            return json.loads(Path('verification/publication-verification.json').read_text())

    def command(self, args, **kwargs):
        if args[:3] == ('gh', 'api', 'unused'):
            raise AssertionError('Unexpected command')
        if args[:2] == ('gh', 'api'):
            endpoint = args[2]
            if '/contents/security/update-policy.json?' in endpoint:
                value = {'content': base64.b64encode(json.dumps(self.policy).encode()).decode()}
            elif '/contents/security/update-candidate.json?' in endpoint:
                value = {'content': base64.b64encode(json.dumps(self.pull['candidate']).encode()).decode()}
            elif endpoint.endswith('/pulls/12'):
                value = {'merged': True, 'merge_commit_sha': SOURCE, 'user': self.author,
                         'head': {'sha': HEAD, 'ref': self.pr_ref, 'repo': {'full_name': REPO}}}
            elif '/reviews?' in endpoint:
                value = [self.reviews] if '--paginate' in args else self.reviews
            elif '/actions/workflows/' in endpoint:
                value = {'workflow_runs': [{'id': 33}]}
            elif '/actions/runs/' in endpoint:
                value = self.validation
            elif '/check-runs?' in endpoint:
                value = {'check_runs': [{'name': 'Security update admission', 'status': 'completed',
                    'conclusion': 'success', 'app': {'id': 999 if self.state['wrong_check'] else 123, 'slug': 'security-reviewer'}}]}
            elif '/git/ref/tags/' in endpoint:
                value = {'object': {'type': 'commit', 'sha': 'f'*40 if self.state['wrong_tag'] else SOURCE}}
            elif '/releases/tags/' in endpoint:
                if not self.state['created']:
                    raise subprocess.CalledProcessError(1,args,stderr='gh: Not Found (HTTP 404)')
                assets = copy.deepcopy(self.assets)
                if self.state['tamper_draft'] or self.state['tamper_published'] and not self.state['draft']:
                    assets[0]['digest'] = 'sha256:'+'f'*64
                value = {'id': 9, 'draft': self.state['draft'], 'prerelease': self.state['prerelease'],
                         'immutable': not self.state['draft'], 'assets': assets,
                         'html_url': 'https://github.com/'+REPO+'/releases/tag/v0.1.3'}
            else:
                raise AssertionError('Unexpected API request: '+endpoint)
            return subprocess.CompletedProcess(args, 0, json.dumps(value), '')
        if args[:3] == ('gh', 'release', 'create'):
            self.assertIn('--draft', args)
            self.assertIn('--prerelease', args)
            self.assertIn('--latest=false', args)
            self.state['created'] = True
            return subprocess.CompletedProcess(args, 0, '', '')
        if args[:3] == ('gh', 'release', 'edit'):
            if '--draft=false' in args:
                self.state['draft'] = False
            if '--prerelease=false' in args:
                self.state['prerelease'], self.state['promoted'] = False, True
            return subprocess.CompletedProcess(args, 0, '', '')
        raise AssertionError('Unexpected executable: '+str(args))

    def test_reviewed_subject_is_sealed_and_verified_before_stable_promotion(self):
        report = self.run_program()
        self.assertTrue(self.state['promoted'])
        self.assertEqual(report['result'], 'pass')
        self.assertTrue(report['immutable'])
        self.assertEqual(report['source_commit'], SOURCE)

    def test_empty_fabricated_or_superseded_approvals_cannot_publish(self):
        for attack in ('empty', 'fabricated', 'superseded'):
            with self.subTest(attack=attack):
                self.setUp()
                if attack == 'empty':
                    self.pull['approvals'] = []
                elif attack == 'fabricated':
                    self.pull['approvals'][0]['id'] = 99
                else:
                    latest = copy.deepcopy(self.review)
                    latest.update(id=8, state='CHANGES_REQUESTED')
                    self.reviews.append(latest)
                with self.assertRaises(AssertionError):
                    self.run_program()
                self.assertFalse(self.state['created'])

    def test_failed_or_wrong_subject_validation_cannot_publish(self):
        for field, value in (('head_sha', 'f'*40), ('event', 'workflow_dispatch'), ('conclusion', 'failure'), ('run_attempt', 2)):
            with self.subTest(field=field):
                self.setUp()
                self.validation[field] = value
                with self.assertRaises(AssertionError):
                    self.run_program()
                self.assertFalse(self.state['created'])

    def test_a_bot_cannot_supply_the_human_review_for_source_changes(self):
        self.review['user'].update(login='another-app[bot]', type='Bot')
        with self.assertRaises(AssertionError):
            self.run_program()
        self.assertFalse(self.state['created'])

    def test_tampered_draft_assets_do_not_publish(self):
        self.state['tamper_draft'] = True
        with self.assertRaises(AssertionError):
            self.run_program()
        self.assertTrue(self.state['draft'])
        self.assertFalse(self.state['promoted'])

    def test_post_seal_mismatch_or_wrong_tag_stays_quarantined(self):
        for attack in ('tamper_published', 'wrong_tag'):
            with self.subTest(attack=attack):
                self.setUp()
                self.state[attack] = True
                with self.assertRaises(AssertionError):
                    self.run_program()
                self.assertFalse(self.state['draft'])
                self.assertTrue(self.state['prerelease'])
                self.assertFalse(self.state['promoted'])

    def test_report_only_requires_a_human_even_when_an_app_has_approved(self):
        self.pr_ref = 'automation/security-updates'
        self.pull['candidate'] = {'candidate_id': 'd'*64, 'requires_human': False}
        self.review['user'].update(login='security-reviewer[bot]', type='Bot')
        with self.assertRaises(AssertionError):
            self.run_program()
        self.assertFalse(self.state['created'])

    def test_automatic_release_requires_the_configured_app_check_and_approval(self):
        self.pr_ref = 'automation/security-updates'
        self.policy.update(mode='enforce', reviewer_app_id=123)
        self.pull['candidate'] = {'candidate_id': 'd'*64, 'requires_human': False}
        self.review['user'].update(login='security-reviewer[bot]', type='Bot')
        self.state['wrong_check'] = True
        with self.assertRaises(AssertionError):
            self.run_program()
        self.assertFalse(self.state['created'])
        self.state['wrong_check'] = False
        self.assertEqual(self.run_program()['result'], 'pass')

    def test_retry_resumes_identical_sealed_assets_without_reupload(self):
        self.state.update(created=True,draft=False,prerelease=True)
        self.assertEqual(self.run_program()['result'],'pass')
        self.assertTrue(self.state['promoted'])

    def test_stable_retry_does_not_repromote_an_older_release(self):
        self.state.update(created=True,draft=False,prerelease=False)
        self.assertEqual(self.run_program()['result'],'pass')
        self.assertFalse(self.state['promoted'])

    def test_a_later_comment_does_not_discard_an_existing_approval(self):
        comment=copy.deepcopy(self.review)
        comment.update(id=8,state='COMMENTED')
        self.reviews.append(comment)
        self.assertEqual(self.run_program()['result'],'pass')

    def test_dismissed_approval_cannot_publish(self):
        self.review['state']='DISMISSED'
        with self.assertRaises(AssertionError): self.run_program()
        self.assertFalse(self.state['created'])

    def test_an_independently_reviewed_pilot_can_publish_without_automatic_approval(self):
        self.pr_ref='automation/security-updates'
        self.pull['candidate']={'candidate_id':'d'*64,'requires_human':False}
        self.assertEqual(self.run_program()['result'],'pass')
