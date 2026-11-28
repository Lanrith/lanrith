"""The boot journal contracts are compiled from normal owner inputs."""

import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from lanrith import build, config, journal
from lanrith.release import ReleaseError


ROOT = Path(__file__).resolve().parents[1]


def declaration(policy=None):
    value = config.load(ROOT/'examples/minimal.yaml')
    if policy is not None:
        value.setdefault('observability', {})['journal'] = policy
    return value


class JournalTests(unittest.TestCase):
    def test_local_policy_and_declared_budget(self):
        template = config.render(declaration())
        value = declaration({'system_keep_free_mib': 8192, 'system_max_use_mib': 512})
        name = 'etc/systemd/journald.conf.d/syslog.conf'
        owner = config.render(value)
        self.assertEqual(template[name], '[Journal]\nForwardToSyslog=no\nSystemMaxUse=1024M\n')
        self.assertIn('SystemKeepFree=8192M\n', owner[name])
        self.assertIn('SystemMaxUse=512M\n', owner[name])
        self.assertNotEqual(template['usr/share/lanrith/configuration.sha256'],
                            owner['usr/share/lanrith/configuration.sha256'])
        self.assertIn(journal.FLUSH, json.loads(template['usr/share/lanrith/health.json'])['units'])
        source = ROOT/'mkosi/base/mkosi.extra/etc/systemd/journald.conf.d/20-lanrith.conf'
        for limit in ('RuntimeMaxUse=256M', 'MaxRetentionSec=14day', 'SystemMaxFileSize=64M'):
            self.assertIn(limit, source.read_text())

    def test_invalid_declarations(self):
        for policy in ({'system_max_use_mib': 127}, {'system_max_use_mib': 65537}, {'system_keep_free_mib': 65536},
                       {'system_keep_free_mib': True}, {'system_max_use_mib': '128M'},
                       {'syslog_receiver_unit': '../receiver.service'}, {'syslog_receiver_unit': 'socket.target'},
                       {'syslog_receiver_unit': 'systemd-journald.service'}, {'forward': True}, None):
            with self.subTest(policy=policy), self.assertRaises(ReleaseError):
                value = declaration()
                value.setdefault('observability', {})['journal'] = policy
                config.normalize(value)

    def test_require_packaged_receiver_before_owner_image_can_be_built(self):
        receiver = 'fixture-log.service'
        value = declaration({'syslog_receiver_unit': receiver})
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for present in (False, True):
                base = directory/('base-'+str(present)+'.tar')
                with tarfile.open(base, 'w') as archive:
                    if present:
                        unit = tarfile.TarInfo('usr/lib/systemd/system/'+receiver)
                        content = b'[Service]\nExecStart=/usr/bin/fixture-log\n'
                        unit.size = len(content)
                        archive.addfile(unit, io.BytesIO(content))
                dest = directory/('image-'+str(present))
                if not present:
                    with self.assertRaisesRegex(ReleaseError, 'syslog receiver unit is absent'):
                        build.assembly(value, base, dest, version='0.1.0', sequence=1)
                    continue
                build.assembly(value, base, dest, version='0.1.0', sequence=1)
                tree = dest/'mkosi.extra'
                units = tree/'etc/systemd/system'
                self.assertTrue((tree/'usr/lib/lanrith/verify-journal-flush').stat().st_mode & 0o111)
                self.assertIn('Service='+receiver, (units/'syslog.socket.d/60-lanrith-receiver.conf').read_text())
                self.assertIn('Sockets=syslog.socket', (units/(receiver+'.d')/'60-lanrith-syslog.conf').read_text())
                self.assertIn(receiver, json.loads((tree/'usr/share/lanrith/health.json').read_bytes())['units'])
