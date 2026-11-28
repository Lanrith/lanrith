"""The signed backport selection is limited to the reviewed AMD64 sensor."""
import lzma
import unittest

from lanrith import ids_package
from lanrith.release import ReleaseError


class IdsPackageTests(unittest.TestCase):
    def test_single_exact_package_selection(self):
        row = ('Package: suricata\nVersion: '+ids_package.PACKAGE+'\nArchitecture: amd64\n'
               'Size: 100\nFilename: pool/main/s/suricata/suricata_8.0.8-1~bpo13+2_amd64.deb\n'
               'SHA256: '+'a'*64)
        def select(text):
            return ids_package.selected(lzma.compress(text.encode()), ids_package.PACKAGE)
        self.assertEqual(select(row)['size'], 100)
        for altered in [row+'\n\n'+row, row.replace('amd64\n', 'arm64\n'), row.replace('1:8.0.8', '1:7.0.10'),
                        row.replace('pool/main/', 'elsewhere/'), row.replace('100\n', '0\n')]:
            with self.subTest(altered=altered), self.assertRaises(ReleaseError):
                select(altered)
