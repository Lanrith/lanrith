"""An unchanged toolchain must keep its reviewed immutable integration image."""

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from automation import go_dependencies, inputs, proposal
from automation.common import MaintenanceError, canonical


REPO = 'Lanrith/router-policy-agent'
IMAGE = 'docker.io/library/golang@sha256:'+'a'*64
REBUILT = 'docker.io/library/golang@sha256:'+'b'*64
POLICY = {'repository': REPO, 'paid_ai': False, 'automatic_minor_security_updates': True,
          'go_branches': ['1.26', '1.27'], 'maximum_changes': 30}


def reason(old, new):
    return {'id': 'GO-2026-6809', 'type': 'security-fix', 'ecosystem': 'Go', 'package': 'stdlib',
            'installed': old, 'fixed': new, 'source': 'https://api.osv.dev/v1/vulns/GO-2026-6809',
            'evidence_sha256': 'd'*64}


class ToolchainImageStabilityTests(unittest.TestCase):
    def toolchains(self):
        return {'go': {'current': '1.27.3', 'previous': '1.26.10'}, 'integration_image': IMAGE}

    def fixture(self, root, value):
        files = {'security/update-policy.json': canonical(POLICY), '.go-version': b'1.27.3\n',
                 '.github/toolchains.json': canonical(value),
                 'go.mod': b'module example.org/fixture\n\ngo 1.27.3\n', 'go.sum': b''}
        for name, raw in files.items():
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        for args in (['init', '-q'], ['add', '.'], ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.org',
                                               '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'Fixture']):
            subprocess.run(['git', *args], cwd=root, capture_output=True, check=True)
        return files

    def resolve(self, root, updates):
        actual_run = subprocess.run
        scans = []
        def command(args, **kwargs):
            if args == ['govulncheck', './...']:
                scans.append(args)
                return subprocess.CompletedProcess(args, 0, b'No vulnerabilities found.\n', b'')
            return actual_run(args, **kwargs)
        def security(version, branches):
            self.assertEqual(branches, POLICY['go_branches'])
            selected = updates.get(version, version)
            return selected, [reason(version, selected)] if selected != version else []
        with patch.object(go_dependencies, 'update', return_value=[]), \
                patch.object(inputs, 'go_security_update', side_effect=security), \
                patch.object(inputs, 'image', return_value=REBUILT) as image, \
                patch.object(proposal.subprocess, 'run', side_effect=command):
            result = proposal.propose(root, root, REPO, 'c'*40)
        self.assertEqual(scans, [['govulncheck', './...']])
        return result, image

    def test_current_resolution_preserves_every_input_despite_a_rebuilt_official_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before = self.fixture(root, self.toolchains())
            result, image = self.resolve(root, {})
            self.assertIsNone(result)
            image.assert_not_called()
            self.assertEqual({p: (root/p).read_bytes() for p in before}, before)

    def test_current_compiler_fix_preserves_the_previous_compiler_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, self.toolchains())
            result, image = self.resolve(root, {'1.27.3': '1.27.4'})
            image.assert_not_called()
            self.assertEqual(set(result['changes']), {'.go-version', '.github/toolchains.json'})
            expected = self.toolchains()
            expected['go']['current'] = '1.27.4'
            self.assertEqual(json.loads((root/'.github/toolchains.json').read_bytes()), expected)

    def test_previous_compiler_fix_resolves_and_independently_verifies_its_new_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, self.toolchains())
            result, image = self.resolve(root, {'1.26.10': '1.26.11'})
            self.assertEqual(set(result['changes']), {'.github/toolchains.json'})
            self.assertEqual(image.call_count, 2)
            self.assertTrue(all(c.args == ('golang', '1.26.11-bookworm') for c in image.call_args_list))
            expected = self.toolchains()
            expected['go']['previous'], expected['integration_image'] = '1.26.11', REBUILT
            self.assertEqual(json.loads((root/'.github/toolchains.json').read_bytes()), expected)

    def validate(self, before, after, reasons):
        path = '.github/toolchains.json'
        old, new = canonical(before), canonical(after)
        return inputs.validate_changes({path: old}, {path: new}, reasons, POLICY,
                                       lambda _: old, lambda _: new)

    def test_independent_review_rejects_image_drift_even_with_an_unrelated_security_reason(self):
        for current_fix in (False, True):
            with self.subTest(current_compiler_changes=current_fix):
                before = self.toolchains()
                after = copy.deepcopy(before)
                after['integration_image'] = REBUILT
                if current_fix:
                    after['go']['current'] = '1.27.4'
                with patch.object(inputs, 'image', return_value=REBUILT) as image, \
                        self.assertRaisesRegex(MaintenanceError, 'previous compiler security update'):
                    self.validate(before, after, [reason('1.27.3', '1.27.4')])
                image.assert_not_called()

    def test_independent_review_rejects_a_previous_compiler_fix_that_keeps_the_old_image(self):
        before = self.toolchains()
        after = copy.deepcopy(before)
        after['go']['previous'] = '1.26.11'
        with patch.object(inputs, 'image', return_value=REBUILT) as image, \
                self.assertRaisesRegex(MaintenanceError, 'selected compiler'):
            self.validate(before, after, [reason('1.26.10', '1.26.11')])
        image.assert_not_called()

    def test_toolchains_without_an_integration_image_still_allow_a_security_fix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = self.toolchains()
            del value['integration_image']
            self.fixture(root, value)
            result, image = self.resolve(root, {'1.26.10': '1.26.11'})
            self.assertEqual(set(result['changes']), {'.github/toolchains.json'})
            image.assert_not_called()


if __name__ == '__main__':
    unittest.main()
