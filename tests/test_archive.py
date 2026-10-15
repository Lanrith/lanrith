"""Handoff archives are bounded before extraction or metadata allocation."""

import gzip
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from lanrith import archive
from lanrith.release import ReleaseError


class ArchiveTests(unittest.TestCase):
    def extract(self, members, *, entries=2, maximum_file=32, maximum_size=48):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with tarfile.open(root/'input.gz', 'w:gz', format=tarfile.PAX_FORMAT) as output:
                for member in members:
                    output.addfile(member, io.BytesIO(b'x'*member.size))
            (root/'output').mkdir()
            names = archive.extract(root/'input.gz', root/'output', entries=entries,
                                    maximum_file=maximum_file, maximum_size=maximum_size)
            return names, {p.name: p.read_bytes() for p in (root/'output').iterdir()}

    @staticmethod
    def member(name='release.json', size=8, **changes):
        value = tarfile.TarInfo(name)
        value.size = size
        for key, change in changes.items():
            setattr(value, key, change)
        return value

    def test_valid_pax_timestamp_and_size(self):
        member = self.member(mtime=1.25)
        self.assertEqual(self.extract([member]), ({'release.json'}, {'release.json': b'x'*8}))

    def test_traversal_links_duplicates_counts_and_size_bounds(self):
        cases = ([self.member('../escape')], [self.member('/absolute')],
                 [self.member('nested/file')], [self.member(type=tarfile.SYMTYPE, linkname='/etc/passwd')],
                 [self.member(), self.member()], [self.member(size=33)],
                 [self.member('a', 25), self.member('b', 25)],
                 [self.member('a'), self.member('b'), self.member('c')],
                 [self.member(mode=0o4755)])
        for members in cases:
            with self.subTest(members=[m.name for m in members]), self.assertRaises(ReleaseError):
                self.extract(members)

    def test_metadata_bomb_rejected_before_body(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            member = self.member(size=1024**3, type=tarfile.XHDTYPE)
            with gzip.open(root/'input.gz', 'wb') as output:
                output.write(member.tobuf(format=tarfile.USTAR_FORMAT))
            (root/'output').mkdir()
            with self.assertRaisesRegex(ReleaseError, 'Oversized'):
                archive.extract(root/'input.gz', root/'output', entries=2, maximum_file=32, maximum_size=48)
