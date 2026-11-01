"""Local service observations cannot expose bodies, credentials or mutation."""

import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import config, extension_observations, extensions, logs, logs_runtime
from lanrith.release import ReleaseError
from test_extension_network import IDENTITIES, manifest
from test_logs import declaration


SELECTED = [{'service': 'logs', 'user': 'example-agent'}]
OBSERVER = {'user': 'example-agent', 'uid': 1801, 'gid': 1801}


def settings():
    value = declaration()
    value['extensions'] = ['example-observer']
    return config.normalize(value)


class LogObservationContractTests(unittest.TestCase):
    def test_admitted_reader_changes_only_core_export_wiring(self):
        value = settings()
        original = config.render(value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extension, output = root/'extension', root/'output'
            extension.mkdir()
            pin = manifest(extension, observations=SELECTED)
            config.write(value, output)
            result = extensions.overlay(value, {'example-observer': (extension, pin)}, output)
            native = json.loads((output/'usr/share/lanrith/logs.json').read_bytes())
            self.assertEqual(native.pop('observer'), OBSERVER)
            self.assertEqual(native, json.loads(original['usr/share/lanrith/logs.json']))
            self.assertEqual(result['health_units'], [])
            for name in ('etc/nftables.conf', 'etc/lanrith/services.nft', 'usr/share/lanrith/health.json',
                         'etc/router-policy-agent/runtime/runtime.json'):
                self.assertEqual((output/name).read_text(), original[name])
            graph = (output/'etc/alloy/config.alloy').read_text()
            self.assertIn('template = "journal message withheld"', graph)
            self.assertIn('max_megabytes = 1', graph)
            self.assertIn('max_backups   = 2', graph)
            self.assertIn('format         = "json"', graph)
            self.assertIn('journal_time = "journal_time"', graph)
            self.assertEqual(graph.count('loki.source.journal '), 1)
            self.assertEqual(graph.count('otelcol.exporter.otlphttp '), 1)
            unit = (output/'etc/systemd/system/alloy.service.d/60-lanrith.conf').read_text()
            self.assertIn('RuntimeDirectory=lanrith-logs lanrith-log-observations\n', unit)
            self.assertIn('SupplementaryGroups=systemd-journal\n', unit)
            self.assertNotIn('example-agent', unit)
            self.assertNotIn('Group=1801', unit)

    def test_policy_and_logs_can_be_selected_independently_but_not_shared(self):
        declarations = extension_observations.declarations([
            {'service': 'policy', 'user': 'example-agent'}, *SELECTED], IDENTITIES)
        value = settings()
        self.assertEqual(extension_observations.resolve(value, [declarations]), OBSERVER)
        self.assertEqual(extension_observations.resolve(value, [declarations], service='logs'), OBSERVER)
        with self.assertRaises(ReleaseError):
            extension_observations.resolve(value, [declarations, declarations], service='logs')
        with self.assertRaises(ReleaseError):
            extension_observations.declarations(SELECTED*2, IDENTITIES)
        value['observability']['logs']['enabled'] = False
        with self.assertRaises(ReleaseError):
            extension_observations.resolve(value, [declarations], service='logs')

    def test_unselected_render_preserves_existing_files_and_declares_no_local_path(self):
        value = settings()
        self.assertEqual(logs.render(value), logs.render(value, observer=None))
        self.assertFalse(any('lanrith-log-observations' in text for text in logs.render(value).values()))

    def test_native_reader_contract_cannot_choose_a_path_or_undeclared_identity(self):
        native = json.loads(logs.render(settings(), observer=OBSERVER)['usr/share/lanrith/logs.json'])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'logs.json'
            for observer in (OBSERVER, None, {}, {**OBSERVER, 'uid': True}, {**OBSERVER, 'uid': 0},
                             {**OBSERVER, 'gid': 60000}, {**OBSERVER, 'path': '/tmp/events'},
                             {**OBSERVER, 'user': 'bad\nname'}):
                path.write_text(json.dumps({**native, 'observer': observer}))
                path.chmod(0o600)
                if observer == OBSERVER:
                    self.assertEqual(logs_runtime.load(path, owner=os.getuid())['observer'], OBSERVER)
                else:
                    with self.assertRaises(ValueError):
                        logs_runtime.load(path, owner=os.getuid())


@unittest.skipUnless(os.geteuid() == 0, 'Native group custody requires isolated root.')
class LogObservationCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lanrith-log-observer-test.', dir='/run')
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.path.chmod(0o750)
        self.account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        self.reader = SimpleNamespace(pw_uid=1801, pw_gid=1801)

    def prepare(self, reader=True):
        with patch.object(logs_runtime.pwd, 'getpwnam', return_value=self.reader if reader else self.account):
            logs_runtime.prepare_local(OBSERVER, self.account, self.path)

    def test_setgid_output_group_never_changes_the_exporters_primary_group(self):
        self.prepare()
        info = self.path.stat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (os.getuid(), 1801, 0o2750))
        file = self.path/'events.jsonl'
        file.write_text('synthetic metadata')
        file.chmod(0o640)
        self.prepare()
        self.assertEqual(file.stat().st_gid, 1801)
        self.prepare(reader=False)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o2700)
        self.assertEqual(file.stat().st_gid, os.getgid())
        self.assertEqual(file.read_text(), 'synthetic metadata')

    def test_unsafe_files_and_aliases_are_rejected_without_repair(self):
        file = self.path/'events.jsonl'
        for variant in ('symlink', 'hardlink', 'writable', 'oversize', 'unexpected', 'fifo'):
            with self.subTest(variant=variant):
                target = self.path/'retained'
                if variant == 'symlink':
                    target.write_text('retain')
                    file.symlink_to(target)
                elif variant == 'hardlink':
                    target.write_text('retain')
                    os.link(target, file)
                elif variant == 'fifo':
                    os.mkfifo(file)
                elif variant == 'unexpected':
                    target.write_text('retain')
                else:
                    file.write_bytes(b'x'*(1024*1024+1) if variant == 'oversize' else b'retain')
                    file.chmod(0o660 if variant == 'writable' else 0o640)
                with self.assertRaises((ValueError, OSError)):
                    self.prepare()
                if target.exists():
                    self.assertEqual(target.read_text(), 'retain')
                file.unlink(missing_ok=True)
                target.unlink(missing_ok=True)

    def test_unsafe_directory_or_ancestor_cannot_be_claimed(self):
        self.path.chmod(0o777)
        with self.assertRaises(ValueError):
            self.prepare()
        self.path.chmod(0o750)
        child = self.path/'child'
        child.mkdir(mode=0o750)
        self.path.chmod(0o770)
        with self.assertRaises(ValueError):
            logs_runtime.prepare_local(OBSERVER, self.account, child)
