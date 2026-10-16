"""Public runtime recipes cannot reintroduce a household hardware profile."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class SourceBoundaryTests(unittest.TestCase):
    def test_private_hardware_defaults_fail_but_generic_owner_selection_passes(self):
        checker = Path(__file__).resolve().parents[1]/'scripts/check-source.py'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'scripts').mkdir()
            script = root/'scripts/check-source.py'
            shutil.copyfile(checker, script)
            profile = root/'mkosi/base/mkosi.extra/usr/lib/lanrith/driver-profile'
            profile.parent.mkdir(parents=True)
            for content in ('driver='+('i'+'40e'), '# bind '+('X'+'710'),
                            'vm.nr_hugepages = 2', 'profile='+('standalone'+'_lab')):
                profile.write_text(content+'\n')
                result = subprocess.run([sys.executable, str(script)], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
            profile.write_text('driver=$lanrith_vpp_linux_driver\n')
            result = subprocess.run([sys.executable, str(script)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
