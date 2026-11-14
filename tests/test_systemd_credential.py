"""Private-owner and exact PID1 ACL copies admit only the selected consumer."""

import errno
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest

from lanrith import systemd_credential as reader


def access(uid, *, group=0, other=0, extra=None):
    entries = [(1, 4, 0xffffffff), (2, 4, uid)]
    if extra is not None:
        entries.append((2, 4, extra))
    entries += [(4, group, 0xffffffff), (16, 4, 0xffffffff), (32, other, 0xffffffff)]
    return struct.pack('<I', 2)+b''.join(struct.pack('<HHI', *entry) for entry in entries)


class CredentialOwnerTests(unittest.TestCase):
    def test_private_owner_and_all_unsafe_file_forms(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root/'copy'
            path.write_bytes(b'synthetic-value')
            path.chmod(0o400)
            self.assertEqual(reader.read(path, 4096, os.geteuid()), b'synthetic-value')
            for mode in (0o440, 0o444, 0o640, 0o777):
                path.chmod(mode)
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    reader.read(path, 4096, os.geteuid())
            path.chmod(0o400)
            os.link(path, root/'alias')
            with self.assertRaises(ValueError):reader.read(path, 4096, os.geteuid())
            (root/'alias').unlink()
            with self.assertRaises(ValueError):reader.read(path, 1, os.geteuid())
            (root/'link').symlink_to(path)
            with self.assertRaises(OSError):reader.read(root/'link', 4096, os.geteuid())


@unittest.skipUnless(os.geteuid() == 0, 'Real root/named-user ACL needs isolated root.')
class CredentialACLTests(unittest.TestCase):
    def test_kernel_named_user_read_does_not_grant_even_the_owning_group(self):
        with tempfile.TemporaryDirectory(prefix='systemd-credential-test.', dir='/run') as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            path = root/'copy'
            path.write_bytes(b'synthetic-value')
            path.chmod(0o400)
            os.setxattr(path, 'system.posix_acl_access', access(2001))
            self.assertEqual((path.stat().st_uid, stat.S_IMODE(path.stat().st_mode)), (0, 0o440))
            self.assertEqual(reader.read(path, 4096, 2001), b'synthetic-value')
            with self.assertRaises(ValueError):reader.read(path, 4096, 2002)
            probe = 'from pathlib import Path;assert Path('+repr(str(path))+').read_bytes()==b"synthetic-value"'
            def run(uid):
                return subprocess.run(['setpriv', '--reuid='+str(uid), '--regid=0', '--clear-groups',
                    '--bounding-set=-all', '--no-new-privs', 'python3', '-I', '-c', probe], capture_output=True, timeout=5)
            self.assertEqual(run(2001).returncode, 0)
            self.assertNotEqual(run(2002).returncode, 0)
            for acl in (access(2001, group=4), access(2001, other=4), access(2001, extra=2002)):
                os.setxattr(path, 'system.posix_acl_access', acl)
                with self.assertRaises(ValueError):reader.read(path, 4096, 2001)
            os.removexattr(path, 'system.posix_acl_access')
            path.chmod(0o400)
            os.chown(path, 2001, 2001)
            self.assertEqual(reader.read(path, 4096, 2001), b'synthetic-value')
            with self.assertRaises(ValueError):reader.read(path, 4096, 2002)
