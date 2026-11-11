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



SOURCE, HEAD = 'a'*40, 'b'*40
REPO = 'Lanrith/router-policy-agent'


class PublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = (Path(__file__).resolve().parents[1]/'scripts/publish-release.py').read_text()

    def setUp(self):
        self.state = {'draft': True, 'prerelease': True, 'created': False, 'promoted': False,
                      'tamper_draft': False, 'tamper_published': False, 'wrong_tag': False, 'wrong_check': False}
        self.uploads = []
        self.upload_errors = []
        self.server_assets = None
        self.edits = []
        self.author = {'login': 'reviewer-app[bot]', 'type': 'Bot'}
        self.review = {'id': 7, 'state': 'APPROVED', 'commit_id': HEAD, 'author_association': 'OWNER',
                       'user': {'id': 1, 'login': 'owner', 'type': 'User'}}
        self.reviews = [self.review]
        self.reviewer_permission = 'admin'
        self.permission_user = {'id': 1, 'login': 'owner'}
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
                    patch('subprocess.run', side_effect=self.command), patch('time.sleep'):
                exec(compile(self.program, 'scripts/publish-release.py', 'exec'), {})
            return json.loads(Path('verification/publication-verification.json').read_text())

    def command(self, args, **kwargs):
        args = tuple(args)
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
            elif '/collaborators/' in endpoint and endpoint.endswith('/permission'):
                value = {'permission': self.reviewer_permission, 'user': self.permission_user}
            elif '/actions/workflows/' in endpoint:
                value = {'workflow_runs': [{'id': 33}]}
            elif '/actions/runs/' in endpoint:
                value = self.validation
            elif '/check-runs?' in endpoint:
                value = {'check_runs': [{'name': 'Security update admission', 'status': 'completed',
                    'conclusion': 'success', 'app': {'id': 999 if self.state['wrong_check'] else 123, 'slug': 'security-reviewer'}}]}
            elif '/git/ref/tags/' in endpoint:
                if not self.state['wrong_tag'] and (not self.state['created'] or self.state['draft']):
                    return subprocess.CompletedProcess(args,1,'','gh: Not Found (HTTP 404)')
                value = {'object': {'type': 'commit', 'sha': 'f'*40 if self.state['wrong_tag'] else SOURCE}}
            elif endpoint.endswith('/releases/9'):
                if not self.state['created']:
                    raise subprocess.CalledProcessError(1,args,stderr='gh: Not Found (HTTP 404)')
                assets = copy.deepcopy(self.assets if self.server_assets is None else self.server_assets)
                if assets and (self.state['tamper_draft'] or self.state['tamper_published'] and not self.state['draft']):
                    assets[0]['digest'] = 'sha256:'+'f'*64
                value = {'tag_name': 'v0.1.3', 'target_commitish': self.state.get('target',SOURCE), 'id': 9, 'draft': self.state['draft'], 'prerelease': self.state['prerelease'],
                         'immutable': not self.state['draft'], 'assets': assets,
                         'html_url': 'https://github.com/'+REPO+'/releases/tag/v0.1.3'}
            else:
                raise AssertionError('Unexpected API request: '+endpoint)
            return subprocess.CompletedProcess(args, 0, json.dumps(value), '')
        if args[:3] == ('gh', 'release', 'view'):
            if not self.state['created']:
                return subprocess.CompletedProcess(args,1,'','release not found')
            return subprocess.CompletedProcess(args,0,json.dumps({'apiUrl':'https://api.github.com/repos/'+REPO+'/releases/9'}),'')
        if args[:3] == ('gh', 'release', 'upload'):
            self.assertNotIn('--clobber', args)
            name = Path(args[4]).name
            self.assertFalse(any(a['name']==name for a in self.server_assets), 'Existing assets must never be overwritten')
            self.uploads.append(name)
            error = self.upload_errors.pop(0) if self.upload_errors else None
            if not error or error == 'uploaded then disconnected':
                self.server_assets.append(copy.deepcopy(next(a for a in self.assets if a['name']==name)))
            return subprocess.CompletedProcess(args, int(error is not None), '',
                'unexpected EOF' if error == 'uploaded then disconnected' else error or '')
        if args[:3] == ('gh', 'release', 'create'):

            self.assertFalse(self.state['created'],'An existing draft or sealed release must not be recreated')
            self.assertIn('--draft', args)
            self.assertIn('--prerelease', args)
            self.assertIn('--latest=false', args)
            self.assertFalse(any(str(a).startswith('release/') for a in args), 'Draft creation must not bulk upload files')
            self.state['created'] = True
            self.server_assets = []
            return subprocess.CompletedProcess(args, 0, '', '')
        if args[:3] == ('gh', 'release', 'edit'):
            self.edits.append(args)
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

    def test_private_organisation_member_with_write_access_can_approve(self):
        self.review['author_association'] = 'CONTRIBUTOR'
        self.reviewer_permission = 'write'
        self.assertEqual(self.run_program()['result'], 'pass')

    def test_association_does_not_authorize_a_read_only_or_unknown_reviewer(self):
        for permission in ('read', 'none'):
            with self.subTest(permission=permission):
                self.setUp()
                self.reviewer_permission = permission
                with self.assertRaises(AssertionError): self.run_program()
                self.assertFalse(self.state['created'])

    def test_permission_response_must_match_the_approving_account(self):
        self.permission_user = {'id': 99, 'login': 'owner'}
        with self.assertRaises(AssertionError): self.run_program()
        self.assertFalse(self.state['created'])

    def test_tampered_draft_assets_do_not_publish(self):
        self.state['tamper_draft'] = True
        with self.assertRaises(AssertionError):
            self.run_program()
        self.assertTrue(self.state['draft'])
        self.assertFalse(self.state['promoted'])

    def test_post_seal_mismatch_or_wrong_tag_stays_quarantined(self):
        for attack in ('tamper_published',):
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

    def test_an_unpublished_draft_is_resolved_by_numeric_id_before_sealing(self):
        self.state.update(created=True,draft=True)
        self.assertEqual(self.run_program()['result'],'pass')
        self.assertFalse(self.state['draft'])

    def test_conflicting_tag_fails_before_creating_or_sealing_a_release(self):
        self.state['wrong_tag'] = True
        with self.assertRaises(AssertionError): self.run_program()
        self.assertFalse(self.state['created'])
        self.assertEqual(self.edits, [])

    def test_partial_matching_draft_uploads_only_missing_assets(self):
        self.state['created'] = True
        self.server_assets = []
        # Start with no assets; a retry also works with one matching asset.
        original = self.command
        def existing(args, **kwargs):
            if tuple(args)[:3] == ('gh','release','view') and not self.server_assets:
                self.server_assets = [copy.deepcopy(self.assets[0])]
            return original(args, **kwargs)
        with patch.object(self, 'command', side_effect=existing):
            report = self.run_program()
        self.assertEqual(report['result'],'pass')
        self.assertEqual(self.uploads,['update-record.json'])

    def test_transient_uploads_retry_with_a_strict_limit(self):
        self.upload_errors = ['HTTP 502','connection reset by peer']
        self.assertEqual(self.run_program()['result'],'pass')
        self.assertEqual(self.uploads.count('package.deb'),3)

    def test_disconnected_success_is_verified_without_overwrite(self):
        self.upload_errors = ['uploaded then disconnected']
        self.assertEqual(self.run_program()['result'],'pass')
        self.assertEqual(self.uploads.count('package.deb'),1)

    def test_exhausted_or_fatal_upload_errors_preserve_draft_without_sealing(self):
        for errors, attempts in ((['HTTP 503']*4,3),(['HTTP 403'],1),(['HTTP 422'],1)):
            with self.subTest(errors=errors):
                self.setUp()
                self.upload_errors = errors
                with self.assertRaises(RuntimeError): self.run_program()
                self.assertEqual(len(self.uploads),attempts)
                self.assertTrue(self.state['draft'])
                self.assertEqual(self.edits,[])

    def test_other_source_draft_is_rejected_before_upload(self):
        self.state.update(created=True,target='f'*40)
        with self.assertRaises(AssertionError): self.run_program()
        self.assertEqual(self.uploads,[])
        self.assertEqual(self.edits,[])

    def test_extra_or_conflicting_draft_assets_cannot_be_resumed(self):
        for attack in ('extra','digest','duplicate'):
            with self.subTest(attack=attack):
                self.setUp()
                self.state['created'] = True
                original = self.command
                changed = False
                def inject(args, **kwargs):
                    nonlocal changed
                    if tuple(args)[:3] == ('gh','release','view') and not changed:
                        self.server_assets = copy.deepcopy(self.assets)
                        if attack == 'extra':
                            self.server_assets.append({'name':'unexpected.deb','digest':'sha256:'+'f'*64})
                        elif attack == 'digest':
                            self.server_assets[0]['digest']='sha256:'+'f'*64
                        else:
                            self.server_assets.append(copy.deepcopy(self.assets[0]))
                        changed = True
                    return original(args, **kwargs)
                with patch.object(self,'command',side_effect=inject), self.assertRaises(AssertionError):
                    self.run_program()
                self.assertEqual(self.uploads,[])
                self.assertEqual(self.edits,[])

    def test_incomplete_immutable_release_is_never_modified(self):
        self.state.update(created=True,draft=False)
        self.server_assets = []
        with self.assertRaises(AssertionError): self.run_program()
        self.assertEqual(self.uploads,[])
        self.assertEqual(self.edits,[])

    def test_new_draft_has_no_tag_until_its_complete_asset_set_is_sealed(self):
        original = self.command
        absent_observations = []
        def observe(args, **kwargs):
            result = original(args, **kwargs)
            if tuple(args)[:2] == ('gh','api') and '/git/ref/tags/' in args[2] and result.returncode:
                absent_observations.append(len(self.uploads))
            return result
        with patch.object(self,'command',side_effect=observe):
            self.assertEqual(self.run_program()['result'],'pass')
        self.assertEqual(absent_observations,[0,2])

    def test_conflicting_tag_created_during_upload_prevents_sealing(self):
        original = self.command
        def conflict(args, **kwargs):
            result = original(args, **kwargs)
            if tuple(args)[:3] == ('gh','release','upload'):
                self.state['wrong_tag'] = True
            return result
        with patch.object(self,'command',side_effect=conflict), self.assertRaises(AssertionError):
            self.run_program()
        self.assertTrue(self.state['draft'])
        self.assertEqual(self.edits,[])

    def test_tag_authorization_error_cannot_be_treated_as_an_absent_tag(self):
        original = self.command
        def forbidden(args, **kwargs):
            if tuple(args)[:2] == ('gh','api') and '/git/ref/tags/' in args[2]:
                return subprocess.CompletedProcess(args,1,'','gh: Forbidden (HTTP 403)')
            return original(args, **kwargs)
        with patch.object(self,'command',side_effect=forbidden), self.assertRaises(AssertionError):
            self.run_program()
        self.assertFalse(self.state['created'])
        self.assertEqual(self.uploads,[])
