"""The VM must not silently qualify one compiler against another base."""

import ast
import io
import json
from types import SimpleNamespace
import threading
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import qualify_bound_observation_vm as qualification
from vm import Guest
from lanrith.release import ReleaseError


class BoundVmFixtureTests(unittest.TestCase):
    def test_diagnostic_reports_only_fixed_fallback_errors_not_console_data(self):
        guest = Guest.__new__(Guest)
        guest.console = SimpleNamespace(condition=threading.Condition(), data=(
            b'Fallback partition differs from binding.\n'
            b'Automatic fallback diagnostic: verification early_failure.py:check:2\n'
            b'Recovery ESP is not read-only and restricted.\n'
            b'Automatic fallback unavailable; holding for recovery.\n'
            b'synthetic-secret-do-not-report\n'))
        guest.qmp = None
        guest.qmp_events = []
        guest.observed_diagnostics = {}
        result = guest.diagnostic()
        data = json.loads(result)
        self.assertIn('Fallback partition differs from binding.', data['literal_errors'])
        self.assertIn('Automatic fallback diagnostic: verification early_failure.py:check:2', data['literal_errors'])
        self.assertIn('Recovery ESP is not read-only and restricted.', data['literal_errors'])
        self.assertIn('Automatic fallback unavailable; holding for recovery.', data['literal_errors'])
        self.assertNotIn('synthetic-secret-do-not-report', result)

    def test_backup_diagnostic_preserves_only_allowlisted_location(self):
        guest = Guest.__new__(Guest)
        guest.console = SimpleNamespace(condition=threading.Condition(), data=(
            b'Synthetic device backup diagnostic: publish release recovery_backup_verity.py:enable:40\n'
            b'synthetic-secret-do-not-report\n'))
        guest.qmp = None
        guest.qmp_events = []
        guest.observed_diagnostics = {}
        result = guest.diagnostic()
        self.assertIn('Synthetic device backup diagnostic: publish release recovery_backup_verity.py:enable:40',
                      json.loads(result)['literal_errors'])
        self.assertNotIn('synthetic-secret-do-not-report', result)

    def test_serial_selection_diagnostic_filters_untrusted_console(self):
        guest = Guest.__new__(Guest)
        guest.console = SimpleNamespace(condition=threading.Condition(), data=(
            b'Synthetic serial selection diagnostic: release recovery_select.py:select_bound:42 errno=0\n'
            b'synthetic-secret-do-not-report\n'))
        guest.qmp = None
        guest.qmp_events = []
        guest.observed_diagnostics = {}
        result = guest.diagnostic()
        self.assertIn('Synthetic serial selection diagnostic: release recovery_select.py:select_bound:42 errno=0',
                      json.loads(result)['literal_errors'])
        self.assertNotIn('synthetic-secret-do-not-report', result)

    def test_target_claim_diagnostic_filters_untrusted_console(self):
        guest = Guest.__new__(Guest)
        guest.console = SimpleNamespace(condition=threading.Condition(), data=(
            b'Synthetic target claim stage: claim\n'
            b'Synthetic target readonly observation: disk=1 partition=1\n'
            b'Synthetic target claim diagnostic: claim os recovery_restore_target.py:claim:42 errno=16\n'
            b'synthetic-secret-do-not-report\n'))
        guest.qmp = None
        guest.qmp_events = []
        guest.observed_diagnostics = {}
        result = guest.diagnostic()
        self.assertIn('Synthetic target claim stage: claim', json.loads(result)['literal_errors'])
        self.assertIn('Synthetic target readonly observation: disk=1 partition=1', json.loads(result)['literal_errors'])
        self.assertIn('Synthetic target claim diagnostic: claim os recovery_restore_target.py:claim:42 errno=16',
                      json.loads(result)['literal_errors'])
        self.assertNotIn('synthetic-secret-do-not-report', result)

    def test_restore_guest_uses_the_host_result_markers(self):
        from qualify_restore_workflow_vm import restore_hook, RESTORE_SUCCESS, RESTORE_FAILURE
        script = restore_hook({'schema': 1})
        ast.parse(script)
        self.assertEqual(script.count(RESTORE_SUCCESS), 1)
        self.assertEqual(script.count(RESTORE_FAILURE), 1)

    def test_restore_interruption_hook_is_explicitly_selected(self):
        from qualify_restore_workflow_vm import restore_hook, RESTORE_INTERRUPT
        for enabled in (False, True):
            script = restore_hook({'schema': 1}, interrupt=enabled)
            tree = ast.parse(script)
            settings = [node.value.value for node in tree.body if isinstance(node, ast.Assign) and
                        any(isinstance(target, ast.Name) and target.id == 'interrupt' for target in node.targets) and
                        isinstance(node.value, ast.Constant)]
            self.assertEqual(settings, [enabled])
            self.assertEqual(script.count(RESTORE_INTERRUPT), 1)

    def test_restore_diagnostic_filters_untrusted_console(self):
        guest = Guest.__new__(Guest)
        guest.console = SimpleNamespace(condition=threading.Condition(), data=(
            b'Synthetic offline restore diagnostic: restore release recovery_restore.py:restore:42 errno=0\n'
            b'synthetic-secret-do-not-report\n'))
        guest.qmp = None
        guest.qmp_events = []
        guest.observed_diagnostics = {}
        result = guest.diagnostic()
        self.assertIn('Synthetic offline restore diagnostic: restore release recovery_restore.py:restore:42 errno=0',
                      json.loads(result)['literal_errors'])
        self.assertNotIn('syntynthetic-secret-do-not-report', result)

    def test_fsverity_diagnostic_does_not_retain_console_secrets(self):
        guest = Guest.__new__(Guest)
        guest.console = SimpleNamespace(condition=threading.Condition(), data=(
            b'Synthetic fsverity errno: 95\nsecret-fixture-value\n'))
        guest.qmp = None
        guest.qmp_events = []
        guest.observed_diagnostics = {}
        result = guest.diagnostic()
        self.assertIn('Synthetic fsverity errno: 95', json.loads(result)['literal_errors'])
        self.assertNotIn('secret-fixture-value', result)

    def test_fixture_preflight_requires_exact_root_owned_branch_files(self):
        with tempfile.TemporaryDirectory(prefix='lanrith-bound-fixture-') as temporary:
            root = Path(temporary)
            overlay = root/'mkosi/base/mkosi.extra'
            (overlay/'usr/lib').mkdir(parents=True)
            (overlay/'usr/lib/helper').write_bytes(b'expected-helper')
            (overlay/'usr/lib/other').write_bytes(b'expected-other')
            archive = root/'base.tar.gz'
            def write(entries):
                with tarfile.open(archive, 'w:gz') as tar:
                    for name, content, owner in entries:
                        member = tarfile.TarInfo('./usr/lib/'+name)
                        member.size = len(content)
                        member.uid = owner
                        member.gid = 0
                        tar.addfile(member, io.BytesIO(content))
            good = [('helper', b'expected-helper', 0), ('other', b'expected-other', 0)]
            with patch.object(qualification, 'PROJECT', root):
                write(good)
                self.assertEqual(qualification.require_matching_base(archive), 2)
                cases = (good[:1], [('helper', b'altered', 0), good[1]],
                         [('helper', b'expected-helper', 1), good[1]], good+[good[0]])
                for index, entries in enumerate(cases):
                    write(entries)
                    with self.subTest(index=index), self.assertRaises(ReleaseError):
                        qualification.require_matching_base(archive)


if __name__ == '__main__':
    unittest.main()
