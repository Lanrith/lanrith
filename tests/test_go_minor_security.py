"""Minor fixes permit only checksum-verified selections required by advisory roots."""
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from automation import go_dependencies as go, inputs, review
from automation.common import MaintenanceError, canonical, digest

NET, SYS, TEXT, TOOLS, SYNC = ('golang.org/x/'+n for n in ('net', 'sys', 'text', 'tools', 'sync'))


class MinimalSecurityGraphTests(unittest.TestCase):
    def setUp(self):
        self.old = {'Module': {'Path': 'example.test/app'}, 'Go': '1.27.2', 'Replace': None,
            'Require': [{'Path': n, 'Version': v} for n, v in ((NET, 'v0.60.0'), (SYS, 'v0.48.0'), (TEXT, 'v0.42.0'))]}
        self.new = copy.deepcopy(self.old)
        for row, value in zip(self.new['Require'], ('v0.62.0', 'v0.49.0', 'v0.43.0')):
            row['Version'] = value
        self.old_graph = {**{r['Path']: r['Version'] for r in self.old['Require']}, TOOLS: 'v0.50.0', SYNC: 'v0.23.0',
            'example.test/unchanged': 'v1.2.3'}
        self.new_graph = {**{r['Path']: r['Version'] for r in self.new['Require']}, TOOLS: 'v0.51.0', SYNC: 'v0.24.0',
            'example.test/unchanged': 'v1.2.3'}
        self.old_sums = {(n, v+s): 'h1:'+'A'*43+'=' for n, v in self.old_graph.items() for s in ('', '/go.mod')}
        self.new_sums = {(n, v+s): 'h1:'+('A' if n == 'example.test/unchanged' else 'B')*43+'='
                         for n, v in self.new_graph.items() for s in ('', '/go.mod')}
        self.advisory = {'id': 'GO-2026-6860', 'affected': [{'package': {'name': NET},
            'ranges': [{'events': [{'fixed': '0.62.0'}]}]}]}
        self.reasons = [{'type': 'security-fix', 'ecosystem': 'Go', 'package': NET, 'installed': 'v0.60.0',
            'fixed': 'v0.62.0', 'id': 'GO-2026-6860', 'source': 'https://api.osv.dev/v1/vulns/GO-2026-6860',
            'evidence_sha256': digest(canonical(self.advisory))}]

    def validate(self, allow_minor=True):
        def raw(value):
            return ''.join(n+' '+v+' '+h+'\n' for (n, v), h in sorted(value.items())).encode()
        with patch.object(go, 'module', side_effect=[self.old, self.new]), \
                patch.object(go, 'fetch_json', return_value=self.advisory), \
                patch.object(go, 'graph', side_effect=[self.old_graph, self.new_graph]) as graphs, \
                patch.object(go, 'verified_download', return_value={'Sum': 'h1:'+'B'*43+'=', 'GoModSum': 'h1:'+'B'*43+'='}) as download:
            go.validate((b'base', raw(self.old_sums)), (b'candidate', raw(self.new_sums)), self.reasons, allow_minor=allow_minor)
        return graphs, download

    def test_minor_fix_includes_only_minimal_existing_module_constraints_and_verified_sums(self):
        graphs, download = self.validate()
        self.assertEqual(graphs.call_args_list[1].args, (b'base', unittest.mock.ANY, {NET: 'v0.62.0'}))
        self.assertEqual({c.args for c in download.call_args_list},
            {(NET, 'v0.62.0'), (SYS, 'v0.49.0'), (TEXT, 'v0.43.0'), (TOOLS, 'v0.51.0'), (SYNC, 'v0.24.0')})

    def test_legacy_policy_keeps_minor_updates_disabled(self):
        with self.assertRaises(MaintenanceError):
            self.validate(False)

    def test_a_newer_unnecessary_root_cannot_be_justified_by_an_older_fixed_advisory(self):
        self.new['Require'][0]['Version'] = 'v0.63.0'
        self.reasons[0]['fixed'] = 'v0.63.0'
        with self.assertRaises(MaintenanceError):
            self.validate()

    def test_modified_or_withdrawn_go_advisory_blocks_the_update(self):
        self.advisory['withdrawn'] = '2026-10-28T10:00:00Z'
        with self.assertRaisesRegex(MaintenanceError, 'advisory evidence changed'):
            self.validate()

    def test_major_prerelease_downgrade_or_missing_advisory_cannot_qualify(self):
        for selected in ('v1.0.0', 'v0.62.0-rc.1', 'v0.59.0', 'latest'):
            self.setUp()
            self.reasons[0]['fixed'] = selected
            with self.subTest(selected=selected), self.assertRaises(MaintenanceError):
                self.validate()
        self.setUp()
        self.reasons = []
        with self.assertRaises(MaintenanceError):
            self.validate()

    def test_added_module_roles_toolchain_or_unnecessary_version_require_human_review(self):
        for attack in ('new-path', 'role', 'toolchain', 'unnecessary-version', 'graph-addition', 'advisory-root', 'major-closure'):
            self.setUp()
            if attack == 'new-path': self.new['Require'].append({'Path': 'unreviewed.test/code', 'Version': 'v1.0.0'})
            elif attack == 'role': self.new['Require'][0]['Indirect'] = True
            elif attack == 'toolchain': self.new['Go'] = '1.28.0'
            elif attack == 'unnecessary-version': self.new['Require'][1]['Version'] = 'v0.50.0'
            elif attack == 'graph-addition': self.new_graph['unreviewed.test/code'] = 'v1.0.0'
            elif attack == 'advisory-root': self.new_graph[NET] = 'v0.63.0'
            else: self.new_graph[TOOLS] = 'v1.0.0'
            with self.subTest(attack=attack), self.assertRaises(MaintenanceError):
                self.validate()

    def test_extra_tampered_removed_or_unpinned_checksums_cannot_hide_in_a_minor(self):
        for attack in ('extra', 'tamper', 'remove-unchanged', 'missing-root', 'unnecessary-version'):
            self.setUp()
            if attack == 'extra': self.new_sums[('unreviewed.test/code', 'v1.0.0')] = 'h1:'+'B'*43+'='
            elif attack == 'tamper': self.new_sums[(NET, 'v0.62.0')] = 'h1:'+'C'*43+'='
            elif attack == 'remove-unchanged': self.new_sums.pop(('example.test/unchanged', 'v1.2.3'))
            elif attack == 'missing-root': self.new_sums.pop((NET, 'v0.62.0'))
            else: self.new_sums[(SYS, 'v0.50.0')] = 'h1:'+'B'*43+'='
            with self.subTest(attack=attack), self.assertRaises(MaintenanceError):
                self.validate()

    def test_policy_opt_in_is_boolean_and_does_not_change_default_approval_rules(self):
        root = Path(__file__).resolve().parents[1]
        value = __import__('json').loads((root/'security/update-policy.json').read_bytes())
        self.assertIs(review.policy_document(canonical(value), 'Lanrith/lanrith')['automatic_minor_security_updates'], True)
        value['automatic_minor_security_updates'] = 'true'
        with self.assertRaises(MaintenanceError):
            review.policy_document(canonical(value), 'Lanrith/lanrith')


class ResolverSelectionTests(unittest.TestCase):
    def test_minor_resolver_uses_only_exact_advisory_fix_and_verifies_final_tidy(self):
        manifest = {'Require': [{'Path': NET, 'Version': 'v0.60.0'}]}
        selected = {'Require': [{'Path': NET, 'Version': 'v0.62.0'}]}
        advisory = {'affected': [{'package': {'name': NET}, 'ranges': [{'events': [{'fixed': '0.62.0'}]}]}]}
        record = {'id': 'GO-2026-6860', 'type': 'security-fix', 'ecosystem': 'Go', 'package': NET,
                  'installed': 'v0.60.0', 'fixed': 'v0.62.0'}
        calls = []
        def run(*args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, b'', b'')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'go.mod').write_bytes(b'base')
            (root/'go.sum').write_bytes(b'checksums')
            with patch.object(go, 'module', side_effect=[manifest, selected]), patch.object(go, 'osv_queries', return_value=[{'vulns': [{'id': record['id']}]}]), \
                    patch.object(go, 'fetch_json', return_value=advisory), patch.object(go, 'reason', return_value=record), \
                    patch.object(go, 'run', side_effect=run), patch.object(go, 'validate') as validate:
                self.assertEqual(go.update(root, allow_minor=True), [record])
        self.assertEqual(calls[0], ('go', 'get', NET+'@v0.62.0'))
        self.assertEqual(calls[-1], ('go', 'mod', 'tidy'))
        self.assertTrue(validate.call_args.kwargs['allow_minor'])

    def test_supported_node_lts_minor_requires_an_actual_official_security_release(self):
        rows = [{'version': 'v24.23.0', 'security': True, 'lts': 'Krypton'},
                {'version': 'v25.1.0', 'security': True, 'lts': 'Other'},
                {'version': 'v24.24.0', 'security': False, 'lts': 'Krypton'}]
        with patch.object(inputs, 'fetch_json', return_value=rows):
            selected, reasons = inputs.node_security_update('24.22.1', ['24'], allow_minor=True)
        self.assertEqual(selected, '24.23.0')
        self.assertEqual(reasons[0]['fixed'], '24.23.0')
