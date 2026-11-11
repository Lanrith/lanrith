"""Embedded fixes must preserve module identities, checksums and approval boundaries."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from automation import embedded_go, inputs
from automation.common import MaintenanceError, canonical
from lanrith import go_pins
from lanrith.release import ReleaseError

ROOT = Path(__file__).resolve().parents[1]


def selected():
    return json.loads((ROOT/'builders/alloy/source.json').read_bytes())['security_modules']


class EmbeddedWorkerPinsTests(unittest.TestCase):
    def setUp(self):
        self.pins = selected()
        self.manifest = {'Require': [{'Path': n, 'Version': v['version']} for n, v in self.pins.items()], 'Replace': []}
        self.calls = []

    def command(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if args[1:4] == ('mod', 'edit', '-json'):
            value = self.manifest
        elif args[1:4] == ('mod', 'download', '-json'):
            name, version = args[-1].split('@')
            value = {'Path': name, 'Version': version, 'Sum': self.pins[name]['sum'], 'GoModSum': self.pins[name]['go_mod_sum']}
        elif args[1] == 'list':
            value = {'Path': args[-1], 'Version': self.pins[args[-1]]['version']}
        else:
            value = {}
        return subprocess.CompletedProcess(args, 0, json.dumps(value), '')

    def test_existing_modules_are_checked_against_both_verified_hashes_and_selected_graph(self):
        with patch.dict('os.environ', {'GOPROXY': 'https://untrusted.invalid', 'GONOSUMDB': '*'}):
            go_pins.apply(Path('/fixture'), self.pins, self.command)
        self.assertTrue(any('-require=github.com/andybalholm/brotli@v1.2.7' in args for args, _ in self.calls))
        self.assertEqual(sum(args[1] == 'list' for args, _ in self.calls), 2)
        for _, kwargs in self.calls:
            self.assertEqual(kwargs['env']['GOSUMDB'], 'sum.golang.org')
            self.assertEqual(kwargs['env']['GONOSUMDB'], '')
            self.assertEqual(kwargs['env']['GOPROXY'], 'https://proxy.golang.org')

    def test_new_replaced_or_downgraded_modules_fail_before_editing_the_graph(self):
        for attack in ('new-module', 'replacement', 'downgrade'):
            self.setUp()
            name = next(iter(self.pins))
            if attack == 'new-module': self.manifest['Require'].pop()
            elif attack == 'replacement': self.manifest['Replace'] = [{'Old': {'Path': name}, 'New': {'Path': '/untrusted'}}]
            else: self.manifest['Require'][0]['Version'] = 'v99.0.0'
            with self.subTest(attack=attack), self.assertRaises(ReleaseError):
                go_pins.apply(Path('/fixture'), self.pins, self.command)
            self.assertEqual(len(self.calls), 1)

    def test_a_checksum_or_actual_version_substitution_is_not_a_successful_fix(self):
        for attack in ('checksum', 'version', 'replace'):
            def run(*args, **kwargs):
                value = self.command(*args, **kwargs)
                parsed = json.loads(value.stdout)
                if attack == 'checksum' and args[1:3] == ('mod', 'download'): parsed['Sum'] = 'h1:'+'A'*43+'='
                elif args[1] == 'list':
                    if attack == 'version': parsed['Version'] = 'v99.0.0'
                    elif attack == 'replace': parsed['Replace'] = {'Path': 'untrusted.invalid/fork'}
                value.stdout = json.dumps(parsed)
                return value
            with self.subTest(attack=attack), self.assertRaises(ReleaseError):
                go_pins.apply(Path('/fixture'), self.pins, run)

    def test_pin_schema_does_not_allow_new_dependencies_prereleases_or_unverified_hashes(self):
        for attack in ('module', 'prerelease', 'checksum', 'field'):
            value = selected();name = next(iter(value))
            if attack == 'module': value['untrusted.invalid/package'] = dict(value[name])
            elif attack == 'prerelease': value[name]['version'] = 'v1.2.8-rc.1'
            elif attack == 'checksum': value[name]['go_mod_sum'] = 'unchecked'
            else: value[name]['url'] = 'https://untrusted.invalid'
            with self.subTest(attack=attack), self.assertRaises(ReleaseError): go_pins.validate(value)

    def test_worker_applies_one_reviewed_pin_set_to_all_three_graphs_before_vendoring(self):
        text=(ROOT/'scripts/alloy-worker.py').read_text()
        self.assertIn("for graph in (beyla, source/'collector', source):", text)
        self.assertLess(text.index('go_pins.apply('), text.index("'mod', 'vendor'"))


class EmbeddedProposalTests(unittest.TestCase):
    def test_resolver_uses_minimum_stable_advisory_fix_and_the_shared_independent_graph_validator(self):
        before = selected();name = 'github.com/andybalholm/brotli';before[name]['version'] = 'v1.2.2'
        advisory = {'id': 'GO-2026-6888', 'affected': [{'package': {'name': name},
            'ranges': [{'events': [{'introduced': '0'}, {'fixed': '1.2.7'}]}]}]}
        record = {'id': advisory['id'], 'type': 'security-fix', 'ecosystem': 'Go', 'package': name,
                  'installed': 'v1.2.2', 'fixed': 'v1.2.7'}
        fixed = selected()[name]
        with patch.object(embedded_go, 'osv_queries', return_value=[{'vulns': [{'id': advisory['id']}]}, {}]), \
                patch.object(embedded_go, 'fetch_json', return_value=advisory), \
                patch.object(embedded_go, 'reason', return_value=record), \
                patch.object(embedded_go.go_dependencies, 'verified_download', return_value={'Sum': fixed['sum'], 'GoModSum': fixed['go_mod_sum']}) as download, \
                patch.object(embedded_go.go_dependencies, 'validate') as validate:
            after, reasons = embedded_go.update(before, allow_minor=True)
        self.assertEqual(after[name], fixed);self.assertEqual(reasons, [record])
        download.assert_called_once_with(name, 'v1.2.7')
        self.assertEqual(validate.call_args.kwargs, {'allow_minor': True})
        self.assertIn(b'github.com/andybalholm/brotli v1.2.7', validate.call_args.args[1][0])
        self.assertIn(fixed['sum'].encode(), validate.call_args.args[1][1])

    def test_no_findings_cause_no_download_or_candidate(self):
        with patch.object(embedded_go, 'osv_queries', return_value=[{}, {}]), \
                patch.object(embedded_go.go_dependencies, 'verified_download') as download:
            value, reasons = embedded_go.update(selected(), allow_minor=True)
        self.assertEqual(value, selected());self.assertEqual(reasons, []);download.assert_not_called()

    def test_missing_withdrawn_prerelease_major_and_unapproved_minor_fixes_need_human_review(self):
        for fixed, withdrawn, allow_minor in [('1.2.8-rc.1', False, True), ('2.0.0', False, True),
                ('1.3.0', False, False), ('1.2.8', True, True), (None, False, True)]:
            name = sorted(selected())[0]
            advisory = {'id': 'GO-SYNTHETIC', 'affected': [{'package': {'name': name},
                'ranges': [{'events': [{'fixed': fixed}] if fixed else [{'introduced': '0'}]}]}]}
            if withdrawn: advisory['withdrawn'] = '2026-11-06T00:00:00Z'
            with self.subTest(fixed=fixed), patch.object(embedded_go, 'osv_queries', return_value=[{'vulns': [{'id': advisory['id']}]}, {}]), \
                    patch.object(embedded_go, 'fetch_json', return_value=advisory), self.assertRaises(MaintenanceError):
                embedded_go.update(selected(), allow_minor=allow_minor)

    def test_data_only_candidate_needs_independent_verification_and_one_package_revision(self):
        old = json.loads((ROOT/'builders/alloy/source.json').read_bytes());new = copy.deepcopy(old)
        name = sorted(old['security_modules'])[0];new['security_modules'][name]['version'] = 'v1.2.8'
        prefix, _, number = old['package_version'].rpartition('+lanrith');new['package_version'] = prefix+'+lanrith'+str(int(number)+1)
        path = 'builders/alloy/source.json';policy = json.loads((ROOT/'security/update-policy.json').read_bytes())
        with patch.object(embedded_go, 'validate') as validate:
            inputs.validate_changes({path: canonical(old)}, {path: canonical(new)}, [], policy,
                lambda p: canonical(old), lambda p: canonical(new))
        validate.assert_called_once_with(old['security_modules'], new['security_modules'], [], allow_minor=True)
        new['package_version'] = old['package_version']
        with patch.object(embedded_go, 'validate'), self.assertRaises(MaintenanceError):
            inputs.validate_changes({path: canonical(old)}, {path: canonical(new)}, [], policy,
                lambda p: canonical(old), lambda p: canonical(new))
