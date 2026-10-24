"""Qualify the build-time image variant without operator root access."""

import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('root_access_policy', ROOT/'scripts/root-access.py')
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class RootAccessTests(unittest.TestCase):
    def fixture(self, root):
        files = {
            'etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nadmin:x:982:982:Admin:/home/admin:/bin/bash\n',
            'etc/shadow': 'root:$6$synthetic:1:0:99999:7:::\nadmin:!:1:0:99999:7:::\n',
            'etc/group': 'root:x:0:\nsudo:x:27:admin\nadmin:x:982:\n',
            'etc/gshadow': 'root:*::\nsudo:*::admin\nadmin:*::\n',
            'usr/lib/sysusers.d/60-admin.conf': 'u admin - "Admin" /home/admin /bin/bash\nm admin sudo\n',
            'usr/bin/tool': 'synthetic privileged tool\n',
        }
        for name, data in files.items():
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)
        (root/'usr/bin/tool').chmod(0o6755)
        for relative in POLICY.REMOVED:
            path = root/relative
            if path.exists():
                continue
            if relative in ('etc/sudoers.d', 'root/.ssh'):
                path.mkdir(parents=True)
                (path/'fixture').write_text('unsafe\n')
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('unsafe\n')

    def test_disabled_mode_removes_login_elevation_and_file_privileges(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            POLICY.apply_root_access(root, 'admin', 'disabled')
            POLICY.verify_root_access_disabled(root, 'admin')
            self.assertEqual((root/'etc/passwd').read_text().splitlines()[0],
                             'root:x:0:0:root:/root:/usr/sbin/nologin')
            self.assertEqual((root/'etc/shadow').read_text().split(':', 2)[1], '!')
            self.assertIn('sudo:x:27:', (root/'etc/group').read_text())
            self.assertIn('sudo:*::', (root/'etc/gshadow').read_text())
            self.assertNotIn('m admin sudo', (root/'usr/lib/sysusers.d/60-admin.conf').read_text())
            self.assertFalse((root/'usr/bin/tool').stat().st_mode & (stat.S_ISUID | stat.S_ISGID))

    def test_verifier_rejects_a_reintroduced_elevation_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            POLICY.apply_root_access(root, 'admin', 'disabled')
            path = root/'usr/bin/reintroduced'
            path.write_text('unsafe\n')
            path.chmod(0o4755)
            with self.assertRaisesRegex(ValueError, 'privileged executable mode'):
                POLICY.verify_root_access_disabled(root, 'admin')

    def test_enabled_mode_is_unchanged_and_unknown_modes_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            before = (root/'etc/passwd').read_bytes()
            POLICY.apply_root_access(root, 'admin', 'enabled')
            self.assertEqual((root/'etc/passwd').read_bytes(), before)
            self.assertTrue((root/'usr/bin/sudo').exists())
            with self.assertRaisesRegex(ValueError, 'Unknown root-access'):
                POLICY.apply_root_access(root, 'admin', 'unknown')


if __name__ == '__main__':
    unittest.main()
