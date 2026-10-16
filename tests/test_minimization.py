"""Image pruning must retain licenses, runtime assets and hardware coverage."""

import hashlib
import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile
import unittest
import json
import shutil
import subprocess

from lanrith import embedded, image
from lanrith.release import ReleaseError

source = Path(__file__).resolve().parents[1]/'mkosi/base/mkosi.finalize'
loader = importlib.machinery.SourceFileLoader('neutral_finalize', str(source))
spec = importlib.util.spec_from_loader(loader.name, loader)
finalize = importlib.util.module_from_spec(spec)
loader.exec_module(finalize)
post_loader = importlib.machinery.SourceFileLoader('neutral_postinst', str(source.with_name('mkosi.postinst')))
post_spec = importlib.util.spec_from_loader(post_loader.name, post_loader)
postinst = importlib.util.module_from_spec(post_spec)
post_loader.exec_module(postinst)


class MinimizationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('mkosi'), 'Requires the pinned native builder.')
    def test_native_mkosi_accepts_both_minimal_base_recipes(self):
        packages = json.loads((source.parents[2]/'mkosi/packages.json').read_text())['packages']
        for name, text in (('root', image.base_configuration('20261016T100000Z', '0.1.0', packages)),
                           ('initrd', image.initrd_configuration('20261016T100000Z'))):
            with self.subTest(image=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root/'mkosi.conf').write_text(text)
                result = subprocess.run(['mkosi', '--directory', str(root), 'summary'], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(result.stderr, b'')

    def test_cleanup_preserves_licenses_drivers_and_utf8_runtime(self):
        keep = ('usr/share/doc/alloy/copyright', 'usr/share/doc/alloy/THIRD-PARTY-NOTICES.lanrith',
                'usr/share/doc/service/LICENSE.gz', 'usr/lib/locale/C.utf8/LC_CTYPE',
                'usr/lib/modules/test/kernel/drivers/net/example.ko', 'usr/bin/alloy',
                'usr/lib/systemd/systemd-sysupdate', 'usr/lib/systemd/systemd-import',
                'usr/lib/systemd/systemd-import-fs', 'usr/lib/systemd/systemd-pull',
                'usr/share/doc/systemd-container/copyright')
        remove = ('usr/share/doc/alloy/examples/config', 'usr/share/doc/alloy/security/beyla',
                  'usr/share/man/man8/example.8.gz', 'usr/share/locale/de/messages.mo',
                  'usr/lib/python3.13/__pycache__/os.pyc', 'boot/initrd.img-test',
                  'var/lib/dpkg/status', 'var/cache/apt/archive.deb', 'usr/bin/dpkg-query', 'usr/bin/make',
                  'usr/bin/machinectl', 'usr/bin/systemd-nspawn', 'usr/lib/systemd/systemd-machined',
                  'usr/lib/systemd/system/systemd-machined.service',
                  'usr/lib/systemd/system/systemd-sysupdate.timer',
                  'usr/lib/systemd/network/80-namespace-ns.network',
                  'usr/lib/systemd/portable/profile/default/service.conf')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in keep+remove:
                path = root/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())
            owned = keep[-5:] + remove[-7:]
            listing = root/'var/lib/dpkg/info/systemd-container.list'
            listing.parent.mkdir(parents=True, exist_ok=True)
            listing.write_text('\n'.join('/'+name for name in owned)+'\n')
            activation = root/'etc/systemd/system/multi-user.target.wants/systemd-machined.service'
            activation.parent.mkdir(parents=True)
            activation.symlink_to('/usr/lib/systemd/system/systemd-machined.service')
            mask = root/'etc/systemd/system/systemd-sysupdate.timer'
            mask.symlink_to('/dev/null')
            self.assertGreater(postinst.prune(root)['removed_paths'], 0)
            result = finalize.minimize(root)
            for name in keep:
                self.assertEqual((root/name).read_bytes(), name.encode())
            for name in remove:
                self.assertFalse((root/name).exists())
            self.assertFalse(activation.is_symlink())
            self.assertEqual(mask.readlink(), Path('/dev/null'))
            self.assertFalse((root/'usr/lib/systemd/portable').exists())
            self.assertEqual((root/'etc/default/locale').read_text(), 'LANG=C.UTF-8\n')
            self.assertGreater(result['removed_bytes'], 0)
            self.assertFalse(result['runtime_package_installation'])

    def test_scan_sidecar_must_match_the_unique_embedded_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, subject = root/'binary', root/'subject'
            data = b'independently scanned synthetic payload'
            subject.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            binary.write_bytes(b'prefix'+data+b'suffix')
            self.assertEqual(embedded.verify(binary, subject, digest)['offset'], 6)
            for data in (b'missing embedded bytes', data+data):
                binary.write_bytes(data)
                with self.assertRaises(ReleaseError):
                    embedded.verify(binary, subject, digest)
            subject.write_bytes(b'substituted scan sidecar')
            with self.assertRaises(ReleaseError):
                embedded.verify(binary, subject, digest)
