"""Empty diagnostics survive publication without weakening evidence checks."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

import yaml

from lanrith.release import ReleaseError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('assessment_diagnostics', ROOT/'scripts/security-audit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AssessmentDiagnosticTests(unittest.TestCase):
    def test_empty_and_nonempty_raw_bytes_have_matching_archive_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = {'debian.stderr.txt': b'', 'debian.stdout.txt': b'policy passed\n'}
            for name, raw in data.items():
                (root/name).write_bytes(raw)
            records, archive = audit.archive_diagnostics(root)
            self.assertEqual(records, {name: hashlib.sha256(raw).hexdigest() for name, raw in data.items()})
            self.assertGreater(archive['size'], 0)
            self.assertEqual(archive['sha256'], hashlib.sha256((root/archive['name']).read_bytes()).hexdigest())
            with tarfile.open(root/archive['name'], 'r:gz') as bundle:
                self.assertEqual(bundle.getnames(), sorted(data))
                for member in bundle:
                    self.assertTrue(member.isfile())
                    self.assertEqual(bundle.extractfile(member).read(), data[member.name])
                    self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
            self.assertEqual((root/'debian.stderr.txt').read_bytes(), b'')

    def test_archive_bytes_do_not_depend_on_source_file_timestamps_or_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archives = []
            for n in range(2):
                directory = root/str(n)
                directory.mkdir()
                path = directory/'scanner.txt'
                path.write_bytes(b'same evidence\n')
                path.chmod(0o600 if n else 0o644)
                os.utime(path, (100+n, 100+n))
                audit.archive_diagnostics(directory)
                archives.append((directory/'diagnostics.tar.gz').read_bytes())
            self.assertEqual(*archives)

    def test_symlinks_hardlinks_and_special_files_are_rejected(self):
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                directory = root/'diagnostics'
                directory.mkdir()
                outside = root/'outside.txt'
                outside.write_bytes(b'outside')
                path = directory/'scanner.txt'
                if kind == 'symlink':
                    path.symlink_to(outside)
                elif kind == 'hardlink':
                    os.link(outside, path)
                else:
                    os.mkfifo(path)
                with self.assertRaises((ReleaseError, OSError)):
                    audit.archive_diagnostics(directory)
                self.assertFalse((directory/'diagnostics.tar.gz').exists())

    def test_unsafe_names_reserved_outputs_and_oversized_files_are_rejected(self):
        for name in ('bad name.txt', '.hidden', 'security-assessment.json', 'diagnostics.tar.gz', 'a'*101):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root/name).write_bytes(b'original')
                with self.assertRaises(ReleaseError):
                    audit.archive_diagnostics(root)
                self.assertEqual((root/name).read_bytes(), b'original')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (root/'large.txt').open('wb') as stream:
                stream.truncate(16*1024*1024+1)
            with self.assertRaises(ReleaseError):
                audit.archive_diagnostics(root)
            self.assertFalse((root/'diagnostics.tar.gz').exists())


class AssessmentPublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = yaml.safe_load((ROOT/'.github/workflows/security-audit.yml').read_text())
        cls.program = next(s['run'] for s in workflow['jobs']['publish']['steps']
                           if s.get('name') == 'Publish immutable freshness evidence')

    def execute(self, *, program=None, mutation=None, immutable=True, tamper=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root/'assessments'/('a'*12)
            directory.mkdir(parents=True)
            (directory/'debian.stderr.txt').write_bytes(b'')
            (directory/'debian.stdout.txt').write_bytes(b'policy passed\n')
            diagnostics, archive = audit.archive_diagnostics(directory)
            report = {'schema': 1, 'result': 'pass', 'supported': True, 'diagnostics': diagnostics,
                      'diagnostic_archive': archive}
            (directory/'security-assessment.json').write_text(json.dumps(report))
            # This fixture tests upload transport, not provenance signing.
            (directory/'security-assessment.json.intoto.jsonl').write_bytes(b'nonempty transport fixture\n')
            if mutation:
                mutation(directory, report)
            executable = root/'bin/gh'
            executable.parent.mkdir()
            executable.write_text('#!'+sys.executable+'\n'+r'''
import hashlib,json,os,pathlib,sys
args=sys.argv[1:]
state=pathlib.Path(os.environ['FAKE_RELEASE_STATE'])
if args[:2]==['release','create']:
    files=[pathlib.Path(a) for a in args[3:] if pathlib.Path(a).is_file()]
    if not files or any(p.stat().st_size==0 for p in files):
        raise SystemExit('HTTP 400: Bad Content-Length')
    assets=[{'name':p.name,'digest':'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]
    state.write_text(json.dumps({'draft':True,'prerelease':True,'immutable':False,'assets':assets}))
elif args[:2]==['release','edit']:
    value=json.loads(state.read_text());value.update(draft=False,immutable=os.environ['FAKE_IMMUTABLE']=='true')
    state.write_text(json.dumps(value))
elif args[:1]==['api']:
    value=json.loads(state.read_text())
    if os.environ['FAKE_TAMPER']=='true': value['assets'][0]['digest']='sha256:'+'f'*64
    print(json.dumps(value))
else:
    raise SystemExit('Unexpected fake gh request')
''')
            executable.chmod(0o755)
            state = root/'state.json'
            environment = {**os.environ, 'PATH': str(executable.parent)+os.pathsep+os.environ['PATH'],
                'GITHUB_REPOSITORY': 'Lanrith/lanrith', 'GITHUB_SHA': 'b'*40,
                'FAKE_RELEASE_STATE': str(state), 'FAKE_IMMUTABLE': str(immutable).lower(),
                'FAKE_TAMPER': str(tamper).lower()}
            result = subprocess.run(['bash', '-e', '-c', program or self.program], cwd=root,
                                    env=environment, capture_output=True, text=True, timeout=30)
            return result, json.loads(state.read_text()) if state.exists() else None

    def test_empty_stderr_publishes_only_complete_nonempty_assets(self):
        result, state = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(state['immutable'])
        self.assertEqual({a['name'] for a in state['assets']},
                         {'security-assessment.json', 'security-assessment.json.intoto.jsonl', 'diagnostics.tar.gz'})

    def test_missing_or_empty_provenance_and_modified_archive_block_before_upload(self):
        def corrupt(directory, report):
            with (directory/'diagnostics.tar.gz').open('ab') as stream:
                stream.write(b'tampered')
        for mutation in (corrupt, lambda d, r: (d/'security-assessment.json.intoto.jsonl').write_bytes(b''),
                         lambda d, r: (d/'security-assessment.json.intoto.jsonl').unlink()):
            with self.subTest(mutation=mutation):
                result, state = self.execute(mutation=mutation)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(state)

    def test_archive_member_bytes_must_match_the_report_before_upload(self):
        def corrupt(directory, report):
            report['diagnostics']['debian.stderr.txt'] = 'f'*64
            (directory/'security-assessment.json').write_text(json.dumps(report))
        result, state = self.execute(mutation=corrupt)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(state)

    def test_duplicate_or_traversing_members_cannot_be_published(self):
        for name in ('../outside.txt', 'debian.stderr.txt'):
            def corrupt(directory, report):
                path = directory/'diagnostics.tar.gz'
                with tarfile.open(path, 'w:gz') as bundle:
                    for member_name in ('debian.stderr.txt', name):
                        member = tarfile.TarInfo(member_name)
                        member.size = 0
                        bundle.addfile(member, io.BytesIO(b''))
                report['diagnostic_archive'].update(size=path.stat().st_size,
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                (directory/'security-assessment.json').write_text(json.dumps(report))
            with self.subTest(name=name):
                result, state = self.execute(mutation=corrupt)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(state)

    def test_mutable_or_wrong_publication_bytes_fail_verification(self):
        for arguments in ({'immutable': False}, {'tamper': True}):
            with self.subTest(arguments=arguments):
                result, _ = self.execute(**arguments)
                self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
