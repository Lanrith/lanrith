"""Allocation identity must survive restart and never become authorization."""

import copy
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

from lanrith import config, nat64, nat64_allocations as allocations, translation
from lanrith.release import ReleaseError
from test_intent import minimal


def manifests():
    value = minimal()
    value['translation'] = {'nat64': {'enabled': True, 'private_pool': '10.255.208.0/28'}}
    return translation.manifests(config.normalize(value))


class AllocationTests(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0 and shutil.which('systemd-tmpfiles'), 'Needs disposable root tmpfiles fixture.')
    def test_generated_tmpfiles_preserve_legacy_custody_until_explicit_migration(self):
        value = minimal()
        value['translation'] = {'nat64': {'enabled': True, 'private_pool': '10.255.208.0/28'}}
        value = config.normalize(value)
        manifest = translation.manifests(value)[1]
        rules = nat64.render(value)['usr/lib/tmpfiles.d/80-lanrith-nat64-internal.conf']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root/'legacy'
            directory = parent/'10.255.208.0-28'
            parent.mkdir(mode=0o750)
            directory.mkdir(mode=0o700)
            state = directory/'dynamic.map'
            content = b'10.255.208.3 fd42:1234:5678:10::3 1234\n'
            state.write_bytes(content)
            state.chmod(0o600)
            for path in (parent, directory, state):
                os.chown(path, 65534, 65534)
            metadata = lambda path: (path.stat().st_uid, path.stat().st_gid, stat.S_IMODE(path.stat().st_mode))
            before = [metadata(path) for path in (parent, directory, state)]
            path = root/'rules.conf'
            path.write_text(rules.replace('/var/lib/tayga-nat64-internal', str(parent)))
            subprocess.run(['systemd-tmpfiles', '--create', str(path)], check=True, capture_output=True)
            self.assertEqual([metadata(p) for p in (parent, directory, state)], before)
            self.assertEqual(state.read_bytes(), content)
            with self.assertRaisesRegex(ReleaseError, 'owned by root'):
                allocations.load(manifest, directory)
            # A new installation still gets root-controlled, non-writable state.
            fresh = root/'fresh'
            path.write_text(rules.replace('/var/lib/tayga-nat64-internal', str(fresh)))
            subprocess.run(['systemd-tmpfiles', '--create', str(path)], check=True, capture_output=True)
            for p in (fresh, fresh/'10.255.208.0-28'):
                self.assertEqual(p.stat().st_uid, 0)
                self.assertEqual(p.stat().st_mode & 0o022, 0)
            self.assertEqual(allocations.load(manifest, fresh/'10.255.208.0-28'), {})

    def test_retains_legacy_mapping_and_reserved_source_without_reassignment(self):
        manifest = manifests()[1]
        manifest['source_allocations'] = {'reserved': {'fd42:1234:5678:10::4': '10.255.208.12'}}
        current = allocations.decode(manifest, b'# old TAYGA state\n10.255.208.3 fd42:1234:5678:10::3 1234\n')
        result = allocations.allocate(manifest, current, ['fd42:1234:5678:10::5'])
        self.assertEqual({key: result[key] for key in current}, current)
        self.assertEqual(allocations.decode(manifest, allocations.encode(manifest, result, 5678)), result)
        text = allocations.configuration(manifest, result).decode()
        self.assertIn('map 10.255.208.12 fd42:1234:5678:10::4\n', text)
        self.assertNotIn('dynamic-pool', text)
        self.assertNotIn('data-dir', text)

    def test_exhaustion_keeps_all_previous_and_retired_identities(self):
        manifest = manifests()[1]
        requested = ['fd42:1234:5678:10::'+format(i, 'x') for i in range(1, 101)]
        current = allocations.allocate(manifest, {}, requested)
        self.assertEqual(len(current), 13)
        self.assertEqual(allocations.allocate(manifest, current, ['fd42:1234:5678:11::1']), current)
        self.assertEqual(allocations.allocate(manifest, {}, list(reversed(requested))), current)

    def test_rejects_duplicate_conflicting_reserved_and_invalid_identity(self):
        manifest = manifests()[1]
        rows = [
            b'10.255.208.3 fd42:1234:5678:10::3 1234\n10.255.208.3 fd42:1234:5678:10::4 1234\n',
            b'10.255.208.3 fd42:1234:5678:10::3 1234\n10.255.208.4 fd42:1234:5678:10::3 1234\n',
            b'10.255.208.1 fd42:1234:5678:10::3 1234\n',
            b'10.255.208.15 fd42:1234:5678:10::3 1234\n',
            b'10.255.209.3 fd42:1234:5678:10::3 1234\n',
            b'10.255.208.3 ::ffff:192.0.2.1 1234\n',
            b'10.255.208.3 fe80::1 1234\n',
            b'10.255.208.3 fd42:1234:5678:10::3 0\n',
        ]
        for row in rows:
            with self.subTest(row=row), self.assertRaises(ReleaseError):
                allocations.decode(manifest, row)
        retained = copy.deepcopy(manifest)
        retained['source_allocations'] = {'reserved': {'fd42:1234:5678:10::3': '10.255.208.12'}}
        with self.assertRaises(ReleaseError):
            allocations.decode(retained, b'10.255.208.3 fd42:1234:5678:10::3 1234\n')

    def test_two_translators_allocate_independently(self):
        first, second = manifests()
        source = ['fd42:1234:5678:10::3']
        left, right = [allocations.allocate(manifest, {}, source) for manifest in (first, second)]
        self.assertNotEqual(left[source[0]], right[source[0]])
        with self.assertRaises(ReleaseError):
            allocations.validate(second, left)


if __name__ == '__main__':
    unittest.main()
