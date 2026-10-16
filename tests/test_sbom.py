"""Source replacements and embedded ecosystems stay visible to consumers."""

import unittest

from lanrith import sbom
from lanrith.release import ReleaseError


class SbomTests(unittest.TestCase):
    def test_go_inventory_uses_the_actual_replacement_and_compiler(self):
        metadata = {'GoVersion': 'go1.27.2', 'Deps': [
            {'Path': 'example.invalid/original', 'Version': 'v1.0.0',
             'Replace': {'Path': 'example.invalid/fixed', 'Version': 'v1.0.1'}}]}
        self.assertEqual(sbom.go_modules(metadata), [
            {'module': 'stdlib', 'version': '1.27.2'},
            {'module': 'example.invalid/fixed', 'version': 'v1.0.1'}])
        metadata['Deps'][0]['Replace'] = {'Path': '../unversioned'}
        with self.assertRaises(ReleaseError):
            sbom.go_modules(metadata)

    def test_debian_go_cargo_ui_and_embedded_java_graphs_are_preserved(self):
        simple = {'go_modules': {'binary': [{'module': 'example.invalid/shared', 'version': 'v1.0.0'}]}}
        components = {name: simple for name in ('node-exporter', 'discovery-bridge',
                       'router-policy-helper', 'router-policy-reader', 'router-policy-collector')}
        components['pam-rssh'] = {'source_commit': 'a'*40, 'queries': [
            {'package': {'ecosystem': 'crates.io', 'name': 'example-crate'}, 'version': '1.0.0'},
            {'commit': 'b'*40}]}
        components['alloy'] = {'modules': [{'module': 'example.invalid/shared', 'version': 'v1.0.0'}],
            'toolchains': {'go': '1.27.2', 'node': '24.16.0'},
            'beyla': {'commit': 'c'*40, 'obi_commit': 'd'*40,
                      'modules': [{'module': 'example.invalid/embedded', 'version': 'v2.0.0'}]},
            'npm_modules': [{'name': '@example/ui', 'version': '1.0.0', 'license': 'MIT', 'development': False}],
            'java_agent': {'queries': [{'package': {'name': 'example:agent'}, 'version': '1.0.0'}]}}
        inventory = {'packages': [{'name': name, 'version': '0.1.0'} for name in (
            'alloy', 'prometheus-node-exporter', 'discovery-bridge', 'router-policy-helper',
            'router-policy-reader', 'router-policy-collector')]}
        result = sbom.document(inventory, {'components': components}, '0.1.0', 'e'*64, '2026-10-16T00:00:00+00:00')
        names = [item['name'] for item in result['packages']]
        for required in ('example.invalid/shared', 'example.invalid/embedded', '@example/ui', 'example:agent',
                         'example-crate', 'Locked Cargo Git source', 'stdlib', 'Node.js'):
            self.assertIn(required, names)
        self.assertEqual(names.count('example.invalid/shared'), 1)
        identifiers = {item['SPDXID'] for item in result['packages']} | {'SPDXRef-DOCUMENT'}
        self.assertTrue(all(item['spdxElementId'] in identifiers and item['relatedSpdxElement'] in identifiers
                            for item in result['relationships']))
        components['node-exporter'] = {}
        with self.assertRaises(ReleaseError):
            sbom.document(inventory, {'components': components}, '0.1.0', 'e'*64, '2026-10-16T00:00:00+00:00')
