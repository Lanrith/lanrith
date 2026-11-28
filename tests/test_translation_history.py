"""Private NAT64 reservation handover from accepted images into later builds."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from lanrith import build, config, owner_inputs, policy_agent, release, translation_history
from test_retained_allocations import declaration
from test_policy_agent import declaration as directory_declaration


class ReservationHistoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.owner = self.root/'owner'
        self.owner.mkdir()
        self.history = self.owner/'translation-allocations.json'
        self.base = self.root/'base.tar'
        self.base.write_bytes(b'synthetic assembly fixture')
        self.first = 'fd42:1234:5678:10::84'
        self.retired = 'fd42:1234:5678:10::85'
        self.new = 'fd42:1234:5678:10::86'

    def assemble(self, sequence, sources, destination=None):
        value = declaration()
        value['translation']['nat64']['private_pool'] = '10.255.223.128/28'
        value['access']['rules'][0]['from'] = {'addresses': list(sources)}
        options, _ = owner_inputs.load(self.owner, value)
        destination = destination or self.root/str(sequence)
        identity = build.assembly(value, self.base, destination, version='0.1.0', sequence=sequence, **options)
        root = destination/'mkosi.extra'
        manifest = json.loads((root/'usr/share/lanrith/nat64-internal.json').read_bytes())
        self.assertEqual(set(manifest['source_allocations']['active']), set(sources))
        self.assertEqual(json.loads((root/'usr/share/lanrith/installed.json').read_bytes())['configuration_sha256'],
                         identity['configuration_sha256'])
        return root, manifest['source_allocations']['reserved']

    def test_promote_add_retire_add_rollback_and_resume(self):
        self.history.write_bytes(release.canonical({self.first: '10.255.223.140'}))
        first_root, first_map = self.assemble(1, [self.first])
        subprocess.run([sys.executable, '-m', 'lanrith.translation_history', '--accepted-root', str(first_root),
                        '--history', str(self.history)], check=True)
        self.assertEqual(first_map[self.first], '10.255.223.140')
        added_root, added_map = self.assemble(2, [self.first, self.retired])
        translation_history.promote(added_root, self.history)
        retired_root, retired_map = self.assemble(3, [self.first])
        self.assertEqual(retired_map, added_map)
        firewall = (retired_root/'etc/nftables.conf').read_text()
        self.assertIn('ip daddr { '+first_map[self.first]+' }', firewall)
        self.assertNotIn(added_map[self.retired], firewall)
        translation_history.promote(retired_root, self.history)
        later_root, later_map = self.assemble(4, [self.first, self.new])
        self.assertTrue(added_map.items() <= later_map.items())
        self.assertNotIn(later_map[self.new], added_map.values())
        translation_history.promote(later_root, self.history)
        saved = self.history.read_bytes()
        self.assertEqual(self.history.stat().st_mode & 0o777, 0o600)
        translation_history.promote(later_root, self.history)
        with self.assertRaisesRegex(release.ReleaseError, 'rollback'):
            translation_history.promote(first_root, self.history)
        self.assertEqual(self.history.read_bytes(), saved)
        resumed, resumed_map = self.assemble(5, [self.first])
        self.assertEqual(later_map, resumed_map)
        translation_history.promote(resumed, self.history)
        receipt = json.loads(self.history.read_bytes())
        self.assertEqual(receipt['deployment_sequence'], 5)
        self.assertEqual(receipt['reserved'], later_map)
        value = declaration()
        value['translation']['nat64']['private_pool'] = receipt['pool']
        normalized = config.normalize(value)
        other = {**receipt, 'deployment_sequence': 6}
        for digest in (lambda r: config.effective_digest(normalized, {}, retained_allocations=r),
                       lambda r: config.rendered_digest(normalized, retained_allocations=r)):
            self.assertNotEqual(digest(receipt), digest(other))

        value = directory_declaration()
        value['translation'] = {'nat64': {'enabled': True, 'private_pool': receipt['pool']}}
        value['groups']['automation'] = [self.first]
        baseline = policy_agent.baseline(config.normalize(value), receipt)
        component = next(c for c in baseline['nat64'] if c['id'] == 'nat64-internal')
        self.assertEqual({m['source'] for m in component['source_mappings'] if m['ready']}, {self.first})

    def test_invalid_history_never_replaces_latest_or_publishes_an_image(self):
        root, reserved = self.assemble(1, [self.first, self.retired])
        with self.assertRaisesRegex(release.ReleaseError, 'missing'):
            translation_history.promote(root, self.history)
        translation_history.promote(root, self.history, initialize=True)
        with self.assertRaisesRegex(release.ReleaseError, 'already exists'):
            translation_history.promote(root, self.history, initialize=True)
        record = json.loads(self.history.read_bytes())
        for changed in ({'schema': True}, {'pool': '10.255.223.0/24'}, {'image_id': 'different'},
                        {'machine_id': 'a'*32}, {'configuration_sha256': 'invalid'}, {'deployment_sequence': True},
                        {'reserved': {self.first: reserved[self.first], self.retired: reserved[self.first]}},
                        {'reserved': {self.first: '10.255.223.150'}},
                        {'reserved': {'fe80::1': reserved[self.first]}}):
            with self.subTest(changed=changed):
                self.history.write_bytes(release.canonical({**record, **changed}))
                with self.assertRaises(release.ReleaseError):
                    self.assemble(2, [self.first])
                self.assertFalse((self.root/'2').exists())
        self.history.write_bytes(release.canonical(record))
        with self.assertRaisesRegex(release.ReleaseError, 'advance beyond'):
            self.assemble(1, [self.first], self.root/'rebuild')
        with self.assertRaisesRegex(release.ReleaseError, 'exhausted'):
            self.assemble(2, ['fd42:1234:5678:10::'+format(i, 'x') for i in range(1, 10)])
        self.assertFalse((self.root/'2').exists())

        next_root, _ = self.assemble(2, [self.first])
        path = next_root/'usr/share/lanrith/nat64-internal.json'
        manifest = json.loads(path.read_bytes())
        invalid = {**manifest['source_allocations']['reserved'], manifest['ipv6']: '10.255.223.141'}
        path.write_bytes(release.canonical({**manifest, 'source_allocations': {
            **manifest['source_allocations'], 'reserved': invalid}}))
        with self.assertRaisesRegex(release.ReleaseError, 'Retained NAT64 source conflicts'):
            translation_history.promote(next_root, self.history)
        self.assertEqual(self.history.read_bytes(), release.canonical(record))
        del manifest['source_allocations']['reserved'][self.retired]
        path.write_bytes(release.canonical(manifest))
        with self.assertRaisesRegex(release.ReleaseError, 'dropped or changed'):
            translation_history.promote(next_root, self.history)
        self.assertEqual(self.history.read_bytes(), release.canonical(record))
