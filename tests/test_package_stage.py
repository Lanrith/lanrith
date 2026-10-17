"""A same-run package handoff cannot change source identity or payload bytes."""

import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest

from lanrith import package_stage
from lanrith.release import canonical, ReleaseError


class PackageStageTests(unittest.TestCase):
    def fixture(self, root):
        project, work, output = root/'project', root/'compiler', root/'output'
        project.mkdir()
        (project/'build-inputs.json').write_text('synthetic pinned inputs')
        (work/'packages').mkdir(parents=True)
        output.mkdir()
        for name in ('pam_rssh.so', 'pam-rssh.notices.txt', 'alloy-beyla.scan', 'alloy_1.0_amd64.deb'):
            (work/'packages'/name).write_bytes(('synthetic '+name).encode())
        (work/'packages/pam_rssh.so').chmod(0o755)
        for name in ('builder.tar', 'build-cache.json', 'custom-security.json', 'package-checkpoint.json'):
            (output/name).write_bytes(('synthetic '+name).encode())
        builder = 'lanrith-mkosi:'+('a'*64)
        package_stage.write(project, work, output, builder, '0.1.0', 'b'*40)
        return project, output/'package-stage.tar.gz', builder

    def restore(self, root, source, project, **kwargs):
        work, output = root/'native', root/'native-output'
        work.mkdir()
        output.mkdir()
        return package_stage.restore(source, project, work, output,
            kwargs.get('version', '0.1.0'), kwargs.get('commit', 'b'*40))

    def test_complete_handoff_preserves_packages_builder_evidence_and_file_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project, source, builder = self.fixture(root)
            self.assertEqual(self.restore(root, source, project), builder)
            self.assertEqual((root/'native/packages/pam_rssh.so').read_bytes(), b'synthetic pam_rssh.so')
            self.assertEqual(stat.S_IMODE((root/'native/packages/pam_rssh.so').stat().st_mode), 0o755)
            self.assertEqual((root/'native-output/builder.tar').read_bytes(), b'synthetic builder.tar')
            self.assertEqual((root/'native/custom-security.json').read_bytes(), b'synthetic custom-security.json')

    def test_another_source_version_or_input_selection_is_rejected_before_import(self):
        for alteration in ('source', 'version', 'inputs'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                project, source, _ = self.fixture(root)
                if alteration == 'inputs':
                    (project/'build-inputs.json').write_text('changed reviewed inputs')
                with self.assertRaises(ReleaseError):
                    self.restore(root, source, project, commit='c'*40 if alteration == 'source' else 'b'*40,
                                 version='0.1.1' if alteration == 'version' else '0.1.0')
                self.assertFalse((root/'native/packages').exists())
                self.assertFalse(any((root/'native-output').iterdir()))

    def test_changed_extra_and_missing_payloads_cannot_reach_the_native_workspace(self):
        for alteration in ('changed', 'extra', 'missing'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                project, source, _ = self.fixture(root)
                with tarfile.open(source, 'r:gz') as stream:
                    files = {entry.name: stream.extractfile(entry).read() for entry in stream}
                if alteration == 'changed':
                    files['packages/alloy_1.0_amd64.deb'] = b'changed package'
                elif alteration == 'extra':
                    files['unselected.sh'] = b'unselected data'
                else:
                    del files['packages/alloy-beyla.scan']
                    metadata = json.loads(files['stage.json'])
                    del metadata['files']['packages/alloy-beyla.scan']
                    files['stage.json'] = canonical(metadata)
                with tarfile.open(source, 'w:gz', format=tarfile.USTAR_FORMAT) as stream:
                    for name, data in files.items():
                        entry = tarfile.TarInfo(name)
                        entry.size, entry.mode = len(data), 0o600
                        stream.addfile(entry, io.BytesIO(data))
                with self.assertRaises(ReleaseError):
                    self.restore(root, source, project)
                self.assertFalse((root/'native/packages').exists())
                self.assertFalse(any((root/'native-output').iterdir()))


if __name__ == '__main__':
    unittest.main()
