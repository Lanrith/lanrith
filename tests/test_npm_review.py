"""Existing npm security fixes can be proposed without granting automatic approval."""

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from automation import evidence, inputs, proposal, review
from automation.common import MaintenanceError, canonical


ROOT = Path(__file__).resolve().parents[1]
BASE, HEAD, PRODUCER = 'a'*40, 'b'*40, 'c'*40
UI_PATCH = 'builders/alloy/ui-dependencies.patch'


class NpmReviewTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT/'security/update-policy.json').read_text())
        self.policy['mode'] = 'enforce'
        self.policy['automatic_minor_security_updates'] = False
        self.package = {'scripts': {'build': 'vite build'}, 'devDependencies': {'jsdom': '29.0.1'}}
        self.old = {'lockfileVersion': 3, 'packages': {
            '': {'devDependencies': self.package['devDependencies']},
            'node_modules/jsdom': {'version': '29.0.1', 'dependencies': {'undici': '^7.25.0'}},
            'node_modules/undici': {'version': '7.29.1', 'resolved': 'old', 'integrity': 'old',
                                    'dev': True, 'engines': {'node': '>=20.18.1'}}}}
        self.new = copy.deepcopy(self.old)
        self.new['packages']['node_modules/undici'].update(version='7.30.1',
            resolved='https://registry.npmjs.org/undici/-/undici-7.30.1.tgz', integrity='sha512-reviewed')
        self.reason = {'id': 'GHSA-xjj6-f33q-929c', 'type': 'security-fix', 'package': 'undici',
            'ecosystem': 'npm', 'installed': '7.29.1', 'fixed': '7.30.1',
            'source': 'https://api.osv.dev/v1/vulns/GHSA-xjj6-f33q-929c', 'evidence_sha256': 'd'*64}

    def validate(self, *, package=None, lock=None, reasons=None):
        selected = self.new if lock is None else lock
        dist = {k: self.new['packages']['node_modules/undici'][k] for k in ('resolved', 'integrity')}
        with patch.object(inputs, 'fetch_json', return_value={'dist': {
                'tarball': dist['resolved'], 'integrity': dist['integrity']}}):
            return inputs.validate_npm_manifests((canonical(self.package), canonical(self.old)),
                (canonical(self.package if package is None else package), canonical(selected)),
                [self.reason] if reasons is None else reasons, self.policy)

    def test_transitive_minor_fix_requires_human_without_adding_a_direct_dependency(self):
        self.assertTrue(self.validate())
        self.assertNotIn('undici', self.package['devDependencies'])

    def test_opted_in_advisory_bound_minor_needs_no_human_and_no_new_dependency(self):
        self.policy['automatic_minor_security_updates'] = True
        self.assertFalse(self.validate())
        self.assertNotIn('undici', self.package['devDependencies'])
        self.assertTrue(self.inspect(False)['eligible'])
        self.assertFalse(self.inspect(True)['eligible'])

    def test_opted_in_minor_still_rejects_unrelated_or_unverified_changes(self):
        self.policy['automatic_minor_security_updates'] = True
        with self.assertRaises(MaintenanceError):
            self.validate(reasons=[])
        lock = copy.deepcopy(self.new)
        lock['packages']['node_modules/jsdom'].update(version='29.0.2')
        with self.assertRaises(MaintenanceError):
            self.validate(lock=lock)

    def test_automatic_scope_stays_approved_packages_on_the_same_patch_line(self):
        for name, before, after, manual in (
                ('vite', '7.3.5', '7.3.7', False),
                ('vite', '7.3.5', '7.4.1', True),
                ('undici', '7.30.0', '7.30.1', True)):
            with self.subTest(name=name, after=after):
                self.assertIs(inputs.npm_requires_human(name, before, after, self.policy), manual)
        for after in ('7.29.0', '7.29.1', '8.0.0', '7.30.1-rc.1', 'latest'):
            with self.subTest(after=after), self.assertRaises(MaintenanceError):
                inputs.npm_requires_human('undici', '7.29.1', after, self.policy)

    def test_unapproved_package_still_needs_its_own_exact_security_reason(self):
        for reasons in ([], [dict(self.reason, fixed='7.30.0')], [dict(self.reason, package='other')]):
            with self.subTest(reasons=reasons), self.assertRaises(MaintenanceError):
                self.validate(reasons=reasons)

    def test_advisory_key_order_is_stable_but_content_changes_block_review(self):
        advisory = {'id': self.reason['id'], 'modified': '2026-10-23T22:30:05Z', 'affected': []}
        raw = json.dumps(advisory).encode()
        reordered = canonical(dict(reversed(list(advisory.items()))))
        changed = canonical(dict(advisory, modified='2026-10-24T06:00:00Z'))
        self.assertNotEqual(raw, reordered)
        with patch.object(inputs, 'fetch', side_effect=[raw, reordered, changed]), \
                patch.object(inputs, 'osv_queries', return_value=[{'vulns': [{'id': self.reason['id']}]}, {}]):
            reason = inputs.reason(self.reason['id'], 'npm', 'undici', '7.29.1', '7.30.1')
            inputs.validate_reason(reason)
            with self.assertRaisesRegex(MaintenanceError, 'Advisory evidence changed'):
                inputs.validate_reason(reason)

    def test_resolver_restores_direct_set_and_unrelated_caret_updates(self):
        original = copy.deepcopy(self.old)
        original['packages']['node_modules/undici']['version'] = '7.29.0'
        before = canonical(self.package), canonical(self.old)
        upstream = {'package.json': before[0], 'package-lock.json': canonical(original)}
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            ui = fixture/'internal/web/ui'
            ui.mkdir(parents=True)
            for name, raw in upstream.items():
                (ui/name).write_bytes(raw)
            subprocess.run(['git', 'init', '-q', str(fixture)], check=True)
            subprocess.run(['git', 'add', 'internal'], cwd=fixture, check=True)
            (ui/'package-lock.json').write_bytes(before[1])
            existing_patch = subprocess.check_output(['git', 'diff'], cwd=fixture)
        calls = []
        def run(*args, **kwargs):
            if args[0] != 'npm':
                return subprocess.run(args, check=True, **kwargs)
            calls.append(args)
            self.assertIn('--ignore-scripts', args)
            self.assertIn('--package-lock-only', args)
            ui = kwargs['cwd']
            if len(calls) == 1:
                self.assertIn('undici@7.30.1', args)
                package, lock = copy.deepcopy(self.package), copy.deepcopy(self.new)
                package['devDependencies']['undici'] = '7.30.1'
                lock['packages']['']['devDependencies'] = package['devDependencies']
                lock['packages']['node_modules/jsdom']['version'] = '29.0.9'
                (ui/'package.json').write_bytes(canonical(package))
                (ui/'package-lock.json').write_bytes(canonical(lock))
            else:
                self.assertEqual(json.loads((ui/'package.json').read_bytes()), self.package)
                self.assertEqual(json.loads((ui/'package-lock.json').read_bytes()), self.new)
            return subprocess.CompletedProcess(args, 0, b'', b'')
        advisory = {'affected': [{'package': {'name': 'undici'},
            'ranges': [{'events': [{'fixed': '7.30.1'}, {'fixed': '8.12.2'}]}]}]}
        metadata = {'dist': {'tarball': self.new['packages']['node_modules/undici']['resolved'],
                            'integrity': self.new['packages']['node_modules/undici']['integrity']}}
        # Queries are sorted by package identity: jsdom first, then undici.
        with patch.object(inputs, 'ui_manifests', return_value=before), \
                patch.object(proposal, 'contents', side_effect=lambda repo, path, sha: upstream[path.rsplit('/', 1)[-1]]), \
                patch.object(proposal, 'osv_queries', return_value=[{}, {'vulns': [{'id': self.reason['id']}]}]), \
                patch.object(proposal, 'fetch_json', return_value=advisory), \
                patch.object(inputs, 'reason', return_value=self.reason), \
                patch.object(inputs, 'fetch_json', return_value=metadata), \
                patch.object(proposal, 'run', side_effect=run):
            result, reasons = proposal.npm_updates({'commit': PRODUCER}, existing_patch, self.policy)
        self.assertEqual(len(calls), 2)
        self.assertEqual(reasons, [self.reason])
        self.assertIn(b'+      "version": "7.30.1"', result)
        self.assertIn(b'-      "version": "7.29.0"', result)

    def test_manual_candidate_cannot_change_scripts_graph_hooks_or_registry_identity(self):
        for attack in ('script', 'direct-addition', 'graph', 'hook', 'registry', 'integrity', 'unrelated'):
            package, lock = copy.deepcopy(self.package), copy.deepcopy(self.new)
            entry = lock['packages']['node_modules/undici']
            if attack == 'script':
                package['scripts']['build'] = 'unreviewed-command'
            elif attack == 'direct-addition':
                package['devDependencies']['undici'] = '7.30.1'
            elif attack == 'graph':
                lock['packages']['node_modules/new-package'] = {'version': '1.0.0'}
            elif attack == 'hook':
                entry['hasInstallScript'] = True
            elif attack == 'registry':
                entry['resolved'] = 'https://example.test/payload.tgz'
            elif attack == 'integrity':
                entry['integrity'] = 'sha512-tampered'
            else:
                lock['packages']['node_modules/jsdom']['version'] = '29.0.2'
            with self.subTest(attack=attack), self.assertRaises(MaintenanceError):
                self.validate(package=package, lock=lock)

    def inspect(self, requires_human):
        record = evidence.candidate('Lanrith/lanrith', BASE, canonical(self.policy),
            {UI_PATCH: b'old'}, {UI_PATCH: b'new'}, [self.reason], PRODUCER,
            requires_human=requires_human)
        pr = {'state': 'open', 'draft': False, 'number': 12, 'html_url': 'https://github.com/Lanrith/lanrith/pull/12',
            'base': {'sha': BASE, 'ref': 'main'},
            'head': {'sha': HEAD, 'ref': self.policy['proposal_branch'], 'repo': {'full_name': 'Lanrith/lanrith'}},
            'user': {'login': self.policy['proposer_login'], 'type': 'Bot', 'id': self.policy['proposer_user_id']}}
        def api(endpoint):
            if '/pulls/' in endpoint:
                return pr
            if endpoint.endswith('/commits/main'):
                return {'sha': BASE}
            return {'merge_base_commit': {'sha': BASE}}
        def contents(repo, name, revision):
            if name == 'security/update-policy.json':
                return canonical(self.policy)
            if name == evidence.CANDIDATE:
                return canonical(record)
            if name == UI_PATCH:
                return b'old' if revision == BASE else b'new'
            return b'{}'
        def manifests(pin, raw):
            return canonical(self.package), canonical(self.old if raw == b'old' else self.new)
        metadata = {'dist': {'tarball': self.new['packages']['node_modules/undici']['resolved'],
                             'integrity': self.new['packages']['node_modules/undici']['integrity']}}
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(review, 'api', side_effect=api), \
                patch.object(review, 'pages', return_value=[{'filename': UI_PATCH, 'status': 'modified'},
                    {'filename': evidence.CANDIDATE, 'status': 'added'}]), \
                patch.object(review, 'contents', side_effect=contents), \
                patch.object(review, 'validate_reasons'), \
                patch.object(review, 'validation_runs', return_value=[{'run_id': 123}]), \
                patch.object(inputs, 'ui_manifests', side_effect=manifests), \
                patch.object(inputs, 'fetch_json', return_value=metadata):
            result, _ = review.inspect('Lanrith/lanrith', 12, PRODUCER, Path(temporary)/'decision.json')
        return result

    def test_reviewer_derives_human_requirement_and_detects_forged_auto_classification(self):
        manual = self.inspect(True)
        self.assertFalse(manual['eligible'])
        self.assertEqual(manual['findings'], [inputs.HUMAN_NPM_REVIEW])
        self.assertTrue(manual['input_validation'])
        forged = self.inspect(False)
        self.assertFalse(forged['eligible'])
        self.assertIn('misclassified', forged['findings'][0])

    def test_manual_decision_cannot_submit_an_app_approval_even_when_enabled(self):
        record = self.inspect(True)
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(review, 'inspect', return_value=(record, self.policy)), \
                patch.object(review, 'api') as api:
            target = Path(temporary)/'decision.json'
            evidence.write(target, record)
            with self.assertRaises(MaintenanceError):
                review.approve('Lanrith/lanrith', 12, target, PRODUCER, 'true')
            api.assert_not_called()

    def test_manual_admission_requires_qualification_and_rejects_extra_findings(self):
        for attack in ('none', 'failed-validation', 'extra-finding', 'forged-classification'):
            record = self.inspect(True)
            if attack == 'extra-finding':
                record['findings'].append('Advisory evidence changed.')
            elif attack == 'forged-classification':
                record['candidate']['requires_human'] = False
            pr = {'head': {'ref': self.policy['proposal_branch'], 'repo': {'full_name': 'Lanrith/lanrith'}}}
            writes = []
            def api(endpoint, **kwargs):
                if kwargs.get('method'):
                    writes.append(kwargs['payload'])
                    return {'id': 99, 'app': {'id': self.policy['reviewer_app_id']}}
                if '/check-runs?' in endpoint:
                    return {'total_count': 0, 'check_runs': []}
                return pr
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(review, 'inspect', return_value=(record, self.policy)), \
                    patch.object(review, 'api', side_effect=api), \
                    patch.object(review, 'pages', return_value=[{'filename': UI_PATCH}]), \
                    patch.object(review, 'validation_runs', side_effect=(
                        MaintenanceError('Qualification failed.') if attack == 'failed-validation' else None),
                        return_value=[{'run_id': 123}]) as validation:
                result = review.admission('Lanrith/lanrith', 12, Path(temporary)/'decision.json',
                    PRODUCER, self.policy['reviewer_app_id'])
                self.assertEqual(result['admission_check']['conclusion'],
                                 'success' if attack == 'none' else 'failure')
                self.assertFalse(any('event' in value for value in writes))
                if attack in ('none', 'failed-validation'):
                    self.assertTrue(validation.call_args.kwargs['manual'])


if __name__ == '__main__':
    unittest.main()
