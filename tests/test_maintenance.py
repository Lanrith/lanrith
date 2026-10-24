"""Security updates must prove their scope, subject and independent validation."""

import copy
import datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation import cleanup, evidence, inputs, releases, review
from automation.common import MaintenanceError, canonical, digest, document, safe_path


ROOT = Path(__file__).resolve().parents[1]
BASE, HEAD, PRODUCER = 'a'*40, 'b'*40, 'c'*40


def policy():
    return document((ROOT/'security/update-policy.json').read_bytes())


def reason():
    return {'id': 'GO-2026-6809', 'type': 'security-fix', 'package': 'stdlib', 'ecosystem': 'Go',
            'installed': '1.27.2', 'fixed': '1.27.3', 'source': 'https://api.osv.dev/v1/vulns/GO-2026-6809',
            'evidence_sha256': 'd'*64}


class CandidateTests(unittest.TestCase):
    def make(self):
        return evidence.candidate('Lanrith/lanrith', BASE, canonical(policy()),
            {'.go-version': b'1.27.2\n'}, {'.go-version': b'1.27.3\n'}, [reason()], PRODUCER)

    def test_candidate_binds_reason_policy_source_and_each_file(self):
        value = self.make()
        self.assertEqual(evidence.validate_candidate(value), value)
        for field, replacement in [('base_sha', 'f'*40), ('policy_sha256', 'f'*64), ('producer_sha', 'f'*40)]:
            with self.subTest(field=field):
                changed = copy.deepcopy(value)
                changed[field] = replacement
                with self.assertRaises(MaintenanceError):
                    evidence.validate_candidate(changed)
        for change in ('reason', 'bytes'):
            changed = copy.deepcopy(value)
            if change == 'reason':
                changed['reasons'][0]['fixed'] = '1.27.4'
            else:
                changed['changes']['.go-version']['after_sha256'] = 'f'*64
            with self.assertRaises(MaintenanceError):
                evidence.validate_candidate(changed)

    def test_candidate_identity_deduplicates_retries(self):
        first, second = self.make(), self.make()
        self.assertEqual(first['candidate_id'], second['candidate_id'])
        self.assertEqual(first['remediation_id'], second['remediation_id'])

    def test_no_reason_or_empty_change_cannot_be_proposed(self):
        with self.assertRaises(MaintenanceError):
            evidence.candidate('Lanrith/lanrith', BASE, b'{}', {'x': b'1'}, {'x': b'2'}, [], PRODUCER)
        with self.assertRaises(MaintenanceError):
            evidence.candidate('Lanrith/lanrith', BASE, b'{}', {'x': b'1'}, {'x': b'1'}, [reason()], PRODUCER)

    def test_ambiguous_json_and_unsafe_paths_are_rejected(self):
        with self.assertRaises(MaintenanceError):
            document('{"eligible":false,"eligible":true}')
        for name in ('../workflow.yml', '/tmp/payload', '.git/config', 'a//b', 'a/./b', 'a\\b'):
            with self.subTest(path=name), self.assertRaises(MaintenanceError):
                safe_path(name)

    def test_staging_records_only_allowed_regular_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner, staged = root/'owner', root/'staged'
            (owner/'security').mkdir(parents=True)
            (owner/'.go-version').write_bytes(b'1.27.3\n')
            evidence.write(owner/evidence.CANDIDATE, self.make())
            releases.stage(owner, staged)
            self.assertEqual((staged/'.go-version').read_bytes(), b'1.27.3\n')
            (owner/'.go-version').write_bytes(b'1.27.4\n')
            with self.assertRaises(MaintenanceError):
                releases.stage(owner, root/'other-stage')


class InputPolicyTests(unittest.TestCase):
    def validate(self, path, old, new, reasons=None):
        inputs.validate_changes({path: old}, {path: new}, reasons or [reason()], policy(),
                                lambda name: old, lambda name: new)

    def test_verified_patch_line_is_eligible_but_downgrades_and_migrations_are_not(self):
        self.validate('.go-version', b'1.27.2\n', b'1.27.3\n')
        for new in (b'1.27.1\n', b'1.28.0\n', b'1.27.4\n', b'latest\n', b'1.27.3-rc.1\n'):
            with self.subTest(version=new), self.assertRaises(MaintenanceError):
                self.validate('.go-version', b'1.27.2\n', new)

    def test_workflow_source_and_approval_policy_changes_need_human_review(self):
        for name in ('.github/workflows/check.yml', 'automation/review.py', 'security/update-policy.json',
                     'security/slsa-assessment.json', 'lanrith/runtime.py'):
            with self.subTest(path=name), self.assertRaises(MaintenanceError):
                self.validate(name, b'old', b'new')

    def test_alloy_source_replacement_cannot_hide_in_an_allowed_json_path(self):
        old = document((ROOT/'builders/alloy/source.json').read_bytes())
        new = dict(old, commit='f'*40)
        with self.assertRaises(MaintenanceError):
            self.validate('builders/alloy/source.json', canonical(old), canonical(new))

    def test_policy_cannot_enforce_with_the_author_as_reviewer(self):
        value = policy()
        review.policy_document(canonical(value), 'Lanrith/lanrith')
        for identity in (None, value['proposer_app_id'], 0):
            value.update(mode='enforce', reviewer_app_id=identity)
            with self.assertRaises(MaintenanceError):
                review.policy_document(canonical(value), 'Lanrith/lanrith')
        value['reviewer_app_id'] = 123
        review.policy_document(canonical(value), 'Lanrith/lanrith')

    def test_ui_script_or_new_dependency_is_not_a_dependency_only_patch(self):
        package = {'scripts': {'build': 'vite build'}, 'devDependencies': {'vite': '7.3.5'}}
        lock = {'lockfileVersion': 3, 'packages': {'': {'devDependencies': {'vite': '7.3.5'}}}}
        changed = copy.deepcopy(package)
        changed['scripts']['build'] = 'run-unreviewed-command'
        with self.assertRaises(MaintenanceError):
            inputs.validate_npm_manifests((canonical(package), canonical(lock)),
                (canonical(changed), canonical(lock)), [reason()], policy())
        changed_lock = copy.deepcopy(lock)
        changed_lock['packages']['node_modules/new-package'] = {'version': '1.0.0'}
        with self.assertRaises(MaintenanceError):
            inputs.validate_npm_manifests((canonical(package), canonical(lock)),
                (canonical(package), canonical(changed_lock)), [reason()], policy())


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.clock = datetime.datetime(2026, 10, 23, 12, tzinfo=datetime.timezone.utc)
        self.pr = {'number': 12, 'head': {'sha': HEAD}, 'base': {'sha': BASE}}
        self.policy = policy()
        self.policy['required_workflows'] = {'.github/workflows/check.yml': ['Required checks']}
        self.run = {'id': 123, 'run_attempt': 2, 'head_sha': HEAD, 'event': 'pull_request',
            'path': '.github/workflows/check.yml', 'head_repository': {'full_name': 'Lanrith/lanrith'},
            'status': 'completed', 'conclusion': 'success', 'updated_at': self.clock.isoformat(),
            'html_url': 'https://github.com/Lanrith/lanrith/actions/runs/123',
            'pull_requests': [{'number': 12, 'head': {'sha': HEAD}, 'base': {'sha': BASE}}]}
        self.job = {'id': 456, 'name': 'Required checks', 'status': 'completed', 'conclusion': 'success'}

    def get(self, endpoint):
        if '/jobs?' in endpoint:
            return {'total_count': 1, 'jobs': [self.job]}
        return {'workflow_runs': [self.run]}

    def evaluate(self):
        return review.validation_runs('Lanrith/lanrith', self.pr, self.policy, get=self.get, clock=self.clock)

    def test_complete_exact_subject_records_the_latest_attempt(self):
        result = self.evaluate()
        self.assertEqual(result[0]['run_attempt'], 2)
        self.assertEqual(result[0]['base_sha'], BASE)

    def test_wrong_head_base_pr_or_repository_does_not_authorize_approval(self):
        original = copy.deepcopy(self.run)
        mutations = [('head_sha', 'f'*40), ('event', 'workflow_dispatch'),
                     ('head_repository', {'full_name': 'other/fork'}),
                     ('pull_requests', [{'number': 12, 'head': {'sha': HEAD}, 'base': {'sha': 'f'*40}}]),
                     ('pull_requests', [{'number': 13, 'head': {'sha': HEAD}, 'base': {'sha': BASE}}])]
        for field, value in mutations:
            self.run = copy.deepcopy(original)
            self.run[field] = value
            with self.subTest(field=field), self.assertRaises(MaintenanceError):
                self.evaluate()

    def test_missing_skipped_failed_or_stale_validation_blocks(self):
        for result in ('skipped', 'failure', 'cancelled', None):
            self.job['conclusion'] = result
            with self.subTest(result=result), self.assertRaises(MaintenanceError):
                self.evaluate()
        self.job['conclusion'] = 'success'
        for delta in (-13, 1):
            self.run['updated_at'] = (self.clock+datetime.timedelta(hours=delta)).isoformat()
            with self.assertRaises(MaintenanceError):
                self.evaluate()


class CleanupTests(unittest.TestCase):
    def test_cleanup_excludes_active_runs_unknown_artifacts_and_retry_window(self):
        clock = datetime.datetime(2026, 10, 23, 12, tzinfo=datetime.timezone.utc)
        artifacts = [{'id': n, 'name': name, 'size_in_bytes': 1024, 'expired': False, 'workflow_run': {'id': n}}
                     for n, name in enumerate(('qualified-base-1', 'attested-base-1', 'owner-evidence', 'unsigned-package-stage-1'), 1)]
        runs = {n: {'status': 'completed', 'name': 'Release', 'updated_at': (clock-datetime.timedelta(hours=3)).isoformat()}
                for n in range(1, 5)}
        runs[2]['status'] = 'in_progress'
        runs[4]['updated_at'] = clock.isoformat()
        def get(endpoint, **kwargs):
            if kwargs.get('paginate'):
                return [{'artifacts': artifacts}]
            return runs[int(endpoint.rsplit('/', 1)[-1])]
        result = cleanup.plan('Lanrith/lanrith', get=get, clock=clock)
        self.assertEqual([a['id'] for a in result['artifacts']], [1])
        self.assertEqual(result['bytes'], 1024)


class ApprovalBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.policy = policy()
        self.policy.update(mode='enforce', reviewer_app_id=123)
        candidate = CandidateTests().make()
        self.record = evidence.decision(candidate, head=HEAD, base=BASE, policy=canonical(self.policy),
            checks=[{'run_id': 55, 'run_attempt': 1}], eligible=True, findings=[], reviewer_source=PRODUCER)
        self.record['admission_check'] = {'id': 99, 'app_id': 123}
        self.fresh = copy.deepcopy(self.record)
        self.check = {'id': 99, 'name': 'Security update admission', 'head_sha': HEAD,
                      'app': {'id': 123, 'slug': 'security-reviewer'}}
        self.pr = {'head': {'sha': HEAD}, 'base': {'sha': BASE}}
        self.writes = []

    def api(self, endpoint, **kwargs):
        if kwargs.get('method'):
            self.writes.append((endpoint, kwargs))
            if endpoint.endswith('/reviews'):
                return {'id': 21, 'state': 'APPROVED', 'commit_id': HEAD, 'submitted_at': '2026-10-23T12:00:00Z',
                        'user': {'login': 'security-reviewer[bot]'}, 'html_url': 'https://github.com/Lanrith/lanrith/pull/12#review-21'}
            return {}
        return self.check if '/check-runs/' in endpoint else self.pr

    def approve(self, enabled='true'):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)/'update-record.json'
            evidence.write(target, self.record)
            with patch.object(review, 'inspect', return_value=(self.fresh, self.policy)), patch.object(review, 'api', side_effect=self.api):
                return review.approve('Lanrith/lanrith', 12, target, PRODUCER, enabled)

    def test_success_records_the_review_but_waits_for_durable_evidence_before_merge(self):
        result = self.approve()
        self.assertEqual(result['approval']['review_id'], 21)
        self.assertTrue(self.writes[0][0].endswith('/reviews'))
        self.assertEqual(self.writes[0][1]['payload']['commit_id'], HEAD)
        self.assertEqual(len(self.writes), 1)
        self.assertIsNone(result['admission_check']['conclusion'])

    def test_changed_head_validation_or_app_cannot_submit_an_approval(self):
        for attack in ('head', 'validation', 'app', 'pr-race'):
            self.setUp()
            if attack == 'head': self.fresh['head_sha'] = 'f'*40
            elif attack == 'validation': self.fresh['validation'][0]['run_attempt'] = 2
            elif attack == 'app': self.check['app']['id'] = self.policy['proposer_app_id']
            else: self.pr['head']['sha'] = 'f'*40
            with self.subTest(attack=attack), self.assertRaises(MaintenanceError):
                self.approve()
            self.assertEqual(self.writes, [])

    def test_either_pilot_gate_prevents_approval(self):
        for mode, enabled in (('report-only', 'true'), ('enforce', 'false')):
            self.setUp()
            self.policy['mode'] = mode
            with self.subTest(mode=mode), self.assertRaises(MaintenanceError):
                self.approve(enabled)
            self.assertEqual(self.writes, [])


class EvidenceRetentionTests(unittest.TestCase):
    def test_public_metadata_is_recoverable_and_authentication_responses_are_excluded(self):
        import gzip
        import os
        import tarfile
        from unittest.mock import MagicMock
        from automation import common
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.dict(os.environ, {'LANRITH_EVIDENCE_DIR': str(root/'inputs')}):
                response = MagicMock()
                response.__enter__.return_value = response
                response.url = 'https://auth.docker.io/token'
                response.read.return_value = b'{"token":"sensitive-synthetic-test-token"}'
                with patch('urllib.request.urlopen', return_value=response):
                    common.fetch(response.url)
                self.assertFalse((root/'inputs').exists())
                response.url = 'https://api.osv.dev/v1/vulns/GO-2026-6809'
                response.read.return_value = b'{"id":"GO-2026-6809"}'
                with patch('urllib.request.urlopen', return_value=response):
                    common.fetch(response.url)
                common.metadata_bundle(root/'archive')
                with tarfile.open(root/'archive/input-evidence.tar.gz') as archive:
                    members = archive.getmembers()
                    raw = next(m for m in members if m.name.endswith('.response.gz'))
                    self.assertEqual(gzip.decompress(archive.extractfile(raw).read()), response.read.return_value)
                    self.assertEqual(len(members), 2)

    def test_native_source_cannot_rotate_signing_authority_in_a_security_update(self):
        from automation.native_sources import validate_unbound
        original = (ROOT/'builders/unbound-source.lock').read_bytes()
        changed = original.replace(b'UNBOUND_RELEASE_KEY_FINGERPRINT=', b'UNBOUND_RELEASE_KEY_FINGERPRINT=F')
        with self.assertRaises(MaintenanceError):
            validate_unbound(original, changed, [])

    def test_cleanup_rechecks_reruns_before_any_delete(self):
        record = {'schema': 1, 'kind': 'temporary-artifact-cleanup', 'repository': 'Lanrith/lanrith',
            'artifacts': [{'id': 1, 'name': 'qualified-base-1', 'run_id': 2, 'size_in_bytes': 10,
                           'completed_at': '2026-10-23T10:00:00Z'}]}
        changed = {'status': 'completed', 'name': 'Release', 'updated_at': '2026-10-23T12:00:00Z'}
        with patch.object(cleanup, 'api', return_value=changed) as api_call, self.assertRaises(MaintenanceError):
            cleanup.execute(record)
        self.assertEqual(api_call.call_count, 1)


class PublicationCompletionTests(unittest.TestCase):
    def setUp(self):
        self.candidate = CandidateTests().make()
        self.update = canonical({'repository': 'Lanrith/lanrith', 'source_commit': HEAD,
                                'pull_requests': [{'candidate': self.candidate}]})
        self.verification = {'repository': 'Lanrith/lanrith', 'source_commit': HEAD, 'result': 'pass',
            'immutable': True, 'run_id': '123', 'run_attempt': '1', 'tag': 'v1.0.1', 'release_id': 55,
            'assets': {'update-record.json': 'sha256:'+digest(self.update)}, 'update_record_sha256': digest(self.update)}
        self.issues = [{'number': 10, 'title': '['+self.candidate['remediation_id']+'] Apply verified security fixes',
                        'body': 'Candidate: '+self.candidate['candidate_id']},
                       {'number': 11, 'title': 'Unrelated issue', 'body': self.candidate['candidate_id']}]
        self.archived = True
        self.attempt = '1'
        self.audit_tag = None
        self.mutations = []

    def api(self, endpoint, **kwargs):
        if kwargs.get('method'):
            self.mutations.append((endpoint, kwargs))
            return {}
        if '/releases/tags/audit-' in endpoint:
            return {'immutable': self.archived, 'draft': False, 'html_url': 'https://example.test/audit',
                    'assets': [{'name': 'publication-verification.json', 'digest': 'sha256:'+digest(canonical(self.verification))}]}
        return {'id': 55, 'immutable': True, 'draft': False, 'prerelease': False, 'html_url': 'https://example.test/release',
                'assets': [{'name': n, 'digest': v} for n, v in self.verification['assets'].items()]}

    def download(self, *arguments, **kwargs):
        directory = Path(arguments[arguments.index('--dir')+1])
        (directory/'update-record.json').write_bytes(self.update)

    def complete(self):
        import os
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'verification.json'
            evidence.write(path, self.verification)
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': self.attempt}), \
                    patch.object(releases, 'api', side_effect=self.api), \
                    patch.object(releases, 'pages', return_value=self.issues), \
                    patch('automation.common.run', side_effect=self.download):
                return releases.complete('Lanrith/lanrith', HEAD, path, self.audit_tag)

    def test_only_the_exact_published_remediation_is_closed(self):
        self.assertEqual(self.complete()['closed_issues'], [10])
        self.assertEqual(len(self.mutations), 1)
        self.assertTrue(self.mutations[0][0].endswith('/issues/10'))
        self.assertIn('verified immutable release', self.mutations[0][1]['payload']['body'])

    def test_retry_uses_the_actual_archive_tag_and_original_publication_attempt(self):
        self.attempt = '2'
        self.audit_tag = 'audit-publication-123-2'
        self.assertEqual(self.complete()['closed_issues'], [10])

    def test_no_issue_closes_before_the_publication_record_is_immutable(self):
        self.archived = False
        with self.assertRaises(MaintenanceError): self.complete()
        self.assertEqual(self.mutations, [])

    def test_wrong_published_update_record_cannot_close_an_issue(self):
        self.update += b' '
        with self.assertRaises(MaintenanceError): self.complete()
        self.assertEqual(self.mutations, [])


class WatchdogTests(unittest.TestCase):
    def test_a_new_failure_is_not_hidden_by_an_earlier_success(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('maintenance_watchdog', ROOT/'scripts/watchdog.py')
        watchdog = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(watchdog)
        clock = datetime.datetime(2026, 10, 23, 12, tzinfo=datetime.timezone.utc)
        def get(endpoint):
            conclusion = 'failure' if 'security-audit.yml' in endpoint else 'success'
            return {'workflow_runs': [
                {'id': 2, 'status': 'completed', 'conclusion': conclusion, 'updated_at': clock.isoformat(), 'html_url': 'https://example.test/run/2'},
                {'id': 1, 'status': 'completed', 'conclusion': 'success', 'updated_at': clock.isoformat(), 'html_url': 'https://example.test/run/1'}]}
        with patch.object(watchdog, 'api', side_effect=get):
            findings, _ = watchdog.assess('Lanrith/lanrith', [], clock)
        self.assertEqual(len(findings), 1)
        self.assertIn('security-audit.yml: failure', findings[0])


class ResolverFreshnessTests(unittest.TestCase):
    def test_unsupported_go_and_node_security_migrations_need_attention(self):
        with patch.object(inputs, 'fetch_json', return_value=[{'version': 'go1.28.1', 'stable': True}]), self.assertRaises(MaintenanceError):
            inputs.go_security_update('1.26.10', ['1.26', '1.27'])
        with patch.object(inputs, 'fetch_json', return_value=[{'version': 'v24.23.1', 'security': True, 'lts': 'Krypton'}]), self.assertRaises(MaintenanceError):
            inputs.node_security_update('24.22.1', ['24'])

    def test_unchanged_debian_metadata_does_not_churn_a_pr(self):
        from automation import proposal
        raw = b'Origin: Debian\nSHA256:\n trusted-package-digest\n'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'builders').mkdir()
            selection = canonical({'debian_snapshot': '20260101T000000Z', 'security_snapshot': '20260101T000000Z'})
            (root/'build-inputs.json').write_bytes(selection)
            lock = ''.join(n+'_RELEASE_SHA256='+digest(raw)+'\n' for n in
                           ('DEBIAN', 'DEBIAN_SECURITY', 'DEBIAN_BOOKWORM', 'DEBIAN_BOOKWORM_SECURITY')).encode()
            (root/'builders/build-inputs.lock').write_bytes(lock)
            with patch.object(proposal, 'fetch', return_value=raw): proposal.refresh_snapshot(root)
            self.assertEqual((root/'build-inputs.json').read_bytes(), selection)
            self.assertEqual((root/'builders/build-inputs.lock').read_bytes(), lock)

    def test_a_binary_side_file_cannot_hide_in_a_manifest_patch(self):
        malicious = (b'--- a/internal/web/ui/package.json\n+++ b/internal/web/ui/package.json\n'
                     b'diff --git a/executable b/executable\nGIT binary patch\n')
        with self.assertRaises(MaintenanceError): inputs.ui_manifests({}, malicious)


class CleanupExecutionTests(unittest.TestCase):
    def setUp(self):
        self.record = {'schema': 1, 'kind': 'temporary-artifact-cleanup', 'repository': 'Lanrith/lanrith',
            'artifacts': [{'id': n, 'name': 'qualified-base-1', 'run_id': n, 'size_in_bytes': 10,
                           'completed_at': '2026-10-23T10:00:00Z'} for n in (1, 2)]}
        self.writes = []
        self.progress = []
        self.expired_first = True
        self.changed_second = False

    def api(self, endpoint, **kwargs):
        number = int(endpoint.rsplit('/', 1)[-1])
        if kwargs.get('method') == 'DELETE':
            self.writes.append(number)
            return None
        if '/runs/' in endpoint:
            return {'status': 'completed', 'name': 'Release', 'updated_at':
                    '2026-10-23T12:00:00Z' if number == 2 and self.changed_second else '2026-10-23T10:00:00Z'}
        if number == 1 and self.expired_first:
            self.assertTrue(kwargs['missing_ok'])
            return None
        return {'name': 'qualified-base-1', 'workflow_run': {'id': number}, 'size_in_bytes': 10}

    def execute(self):
        with patch.object(cleanup, 'api', side_effect=self.api):
            return cleanup.execute(self.record, progress=lambda value: self.progress.append(copy.deepcopy(value)))

    def test_expiry_is_an_absence_observation_and_does_not_abort_other_cleanup(self):
        result = self.execute()
        self.assertEqual(result['result'], 'pass')
        self.assertEqual(result['already_absent'], [1])
        self.assertEqual(result['deleted'], [2])
        self.assertEqual(self.writes, [2])
        self.assertEqual(self.progress[-1], result)

    def test_partial_execution_is_preserved_when_a_later_run_changes(self):
        self.expired_first, self.changed_second = False, True
        with self.assertRaises(MaintenanceError): self.execute()
        self.assertEqual(self.writes, [1])
        self.assertEqual(self.progress[-1]['deleted'], [1])
        self.assertEqual(self.progress[-1]['result'], 'blocked')


class DurableApprovalTests(unittest.TestCase):
    def setUp(self):
        self.factory=ApprovalBoundaryTests()
        self.factory.setUp()
        self.previous=self.factory.approve()
        self.fresh=copy.deepcopy(self.previous)
        self.check=self.factory.check
        self.pr=self.factory.pr
        self.archived=True
        self.bad_digest=False
        self.dismissed=False
        self.writes=[]

    def api(self, endpoint, **kwargs):
        if kwargs.get('method'):
            self.writes.append((endpoint,kwargs))
            return {}
        if '/releases/tags/' in endpoint:
            return {'immutable':self.archived,'draft':False,'html_url':'https://example.test/audit',
                    'assets':[{'name':'update-record.json','digest':'sha256:'+('f'*64 if self.bad_digest else digest(canonical(self.previous)))}]}
        if '/check-runs/' in endpoint:return self.check
        return self.pr

    def finalize(self):
        import os
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'update-record.json'
            evidence.write(path,self.previous)
            rows=[{'id':21,'state':'DISMISSED' if self.dismissed else 'APPROVED','commit_id':HEAD,
                   'user':{'login':'security-reviewer[bot]'}}]
            with patch.dict(os.environ,{'GITHUB_RUN_ID':'123'}),patch.object(review,'api',side_effect=self.api),patch.object(review,'pages',return_value=rows),patch.object(review,'inspect',return_value=(self.fresh,self.factory.policy)):
                return review.finalize('Lanrith/lanrith',12,path,PRODUCER,'true','audit-decision-123-1')

    def test_only_a_durable_exact_approval_releases_the_check(self):
        self.finalize()
        self.assertEqual(len(self.writes),1)
        self.assertTrue(self.writes[0][0].endswith('/check-runs/99'))
        self.assertEqual(self.writes[0][1]['payload']['conclusion'],'success')

    def test_archive_failure_dismissal_or_changed_validation_cannot_allow_merge(self):
        for attack in ('mutable','digest','dismissed','head','validation'):
            self.setUp()
            if attack=='mutable':self.archived=False
            elif attack=='digest':self.bad_digest=True
            elif attack=='dismissed':self.dismissed=True
            elif attack=='head':self.fresh['head_sha']='f'*40
            else:self.fresh['validation'][0]['run_attempt']=2
            with self.subTest(attack=attack),self.assertRaises(MaintenanceError):self.finalize()
            self.assertEqual(self.writes,[])
