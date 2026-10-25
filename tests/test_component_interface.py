"""Reject incompatible attested component packages before allocating builders."""

import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from lanrith import components
from lanrith.release import ReleaseError


class ComponentInterfaceTests(unittest.TestCase):
    def check(self, names, *, changed=None):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode='w') as archive:
            for name in names:
                member = tarfile.TarInfo('./usr/bin/'+name)
                member.size, member.mode = 7, 0o755
                if changed:
                    changed(member)
                archive.addfile(member, io.BytesIO(b'fixture') if member.isfile() else None)
        process = Mock(stdout=io.BytesIO(payload.getvalue()))
        process.wait.return_value = 0
        process.poll.return_value = 0
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary)/'fixture.deb'
            package.write_bytes(b'synthetic authenticated package fixture')
            with patch.object(components.subprocess, 'Popen', return_value=process):
                return components.validate_binaries('router-policy-agent', [package])

    def test_complete_phase_b_interface_includes_the_profile_compiler(self):
        expected = components.REQUIRED_BINARIES['router-policy-agent']
        self.assertIn('router-policy-profile', self.check(sorted(expected)))

    def test_legacy_package_reports_the_missing_compiler(self):
        with self.assertRaisesRegex(ReleaseError, 'missing: router-policy-profile'):
            self.check(sorted(components.REQUIRED_BINARIES['router-policy-agent']-{'router-policy-profile'}))

    def test_extra_and_duplicate_commands_are_rejected(self):
        expected = sorted(components.REQUIRED_BINARIES['router-policy-agent'])
        for extra in ('unexpected-tool', expected[0]):
            with self.subTest(extra=extra), self.assertRaises(ReleaseError):
                self.check(expected+[extra])

    def test_links_nonexecutables_privileged_modes_and_unsafe_paths_are_rejected(self):
        def link(member):
            member.type, member.linkname = tarfile.SYMTYPE, '/tmp/elsewhere'

        def nonexecutable(member):
            member.mode = 0o644

        def privileged(member):
            member.mode = 0o4755

        def traversal(member):
            member.name = '../escape'

        for change in (link, nonexecutable, privileged, traversal):
            with self.subTest(change=change.__name__), self.assertRaises(ReleaseError):
                self.check(sorted(components.REQUIRED_BINARIES['router-policy-agent']), changed=change)
