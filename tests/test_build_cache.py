"""Cached build data must earn trust before reaching Docker or the compiler."""

import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from lanrith import build_cache as cache
from lanrith.release import canonical, file_record


class BuildCacheTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ)
        self.environment.start()
        os.environ.pop('LANRITH_BUILD_CACHE', None)
        self.addCleanup(self.environment.stop)

    def fixture(self, root, *, member='compiler/aa/'+('a'*64)+'-d', image_tag=None):
        project, candidate, work = root/'project', root/'candidate', root/'work'
        for name in ('scripts/build.py', 'lanrith/build_cache.py', 'builders/probe/Containerfile',
                     'builders/alloy/source.json',
                     '.github/workflows/build-base.yml', 'requirements.txt', 'pyproject.toml', 'build-inputs.json'):
            path = project/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic reviewed input: '+name)
        candidate.mkdir()
        work.mkdir()
        tag = 'lanrith-mkosi:'+('a'*64)
        image = io.BytesIO()
        with tarfile.open(fileobj=image, mode='w', format=tarfile.USTAR_FORMAT) as stream:
            data = canonical([{'RepoTags': [image_tag or tag], 'Layers': []}])
            entry = tarfile.TarInfo('manifest.json')
            entry.size = len(data)
            stream.addfile(entry, io.BytesIO(data))
        with tarfile.open(candidate/'cache.tar.gz', 'w:gz', format=tarfile.USTAR_FORMAT) as stream:
            for name, data in (('images.tar', image.getvalue()), (member, b'synthetic compiler data')):
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = 0o600
                stream.addfile(entry, io.BytesIO(data))
        metadata = {'schema': 1, 'source_commit': 'a'*40, 'key': cache.key(project),
            'payload': file_record(candidate/'cache.tar.gz'), 'images': {'mkosi': tag},
            'compiler_identity': 'c'*64}
        (candidate/'cache.json').write_bytes(canonical(metadata))
        (candidate/'cache.intoto.jsonl').write_text('synthetic provenance test fixture')
        tree = {'truncated': False, 'tree': [{'path': name, 'mode': '100644', 'type': 'blob',
            'sha': hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data, usedforsecurity=False).hexdigest()}
            for name, data in cache.producer_files(project).items()]}
        tree['tree'].append({'path': 'builders/alloy/licenses', 'mode': '040000', 'type': 'tree', 'sha': 'b'*40})
        environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
            'GITHUB_REPOSITORY': 'Lanrith/lanrith', 'GITHUB_SHA': 'a'*40, 'GITHUB_REF': 'refs/heads/main',
            'LANRITH_REUSABLE_WORKFLOW_REPOSITORY': 'Lanrith/lanrith', 'LANRITH_REUSABLE_WORKFLOW_SHA': 'a'*40,
            'GITHUB_WORKFLOW_REF': 'Lanrith/lanrith/.github/workflows/release.yml@refs/heads/main'}
        return project, candidate, work, metadata, tree, environment

    def runner(self, tree, calls, *, signature=0):
        def run(argv, **kwargs):
            calls.append(argv)
            if argv[:3] == ['gh', 'attestation', 'verify']:
                self.assertIn('--deny-self-hosted-runners', argv)
                self.assertEqual(argv[argv.index('--source-ref')+1], 'refs/heads/main')
                self.assertEqual(argv[argv.index('--source-digest')+1], 'a'*40)
                self.assertEqual(argv[argv.index('--signer-digest')+1], 'a'*40)
                self.assertEqual(argv[argv.index('--predicate-type')+1], 'https://slsa.dev/provenance/v1')
                return subprocess.CompletedProcess(argv, signature)
            if argv[:2] == ['gh', 'api']:
                return subprocess.CompletedProcess(argv, 0, canonical(tree))
            self.assertEqual(argv[:2], ['docker', 'load'])
            return subprocess.CompletedProcess(argv, 0)
        return run

    def test_signed_compatible_cache_is_imported_only_after_both_subjects_and_source_are_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            project, candidate, work, metadata, tree, environment = self.fixture(Path(temporary))
            calls = []
            with patch.object(cache.subprocess, 'run', side_effect=self.runner(tree, calls)):
                result = cache.initialize(project, work, candidate, environment)
            self.assertEqual(result['status'], 'verified')
            self.assertEqual([argv[:2] for argv in calls],
                [['gh', 'attestation'], ['gh', 'attestation'], ['gh', 'api'], ['docker', 'load']])
            self.assertIn(metadata['images']['mkosi'], cache.image_arguments('mkosi'))
            self.assertTrue(cache.reuse_image('mkosi', metadata['images']['mkosi']))
            self.assertFalse(cache.reuse_image('mkosi', 'lanrith-mkosi:'+('f'*64)))
            destination = work/'fresh-compiler'
            destination.mkdir()
            self.assertFalse(cache.restore_compiler(destination, 'd'*64))
            self.assertFalse(any(destination.iterdir()))
            self.assertTrue(cache.restore_compiler(destination, 'c'*64))
            self.assertEqual(next(destination.glob('*/*')).read_bytes(), b'synthetic compiler data')

    def test_corruption_and_bad_signature_never_reach_docker(self):
        for alteration in ('payload', 'signature', 'producer', 'alloy-source', 'truncated-tree',
                           'added-producer', 'added-root-module', 'missing-bundle'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                project, candidate, work, _, tree, environment = self.fixture(Path(temporary))
                if alteration == 'payload':
                    with (candidate/'cache.tar.gz').open('ab') as stream:
                        stream.write(b'tampering')
                elif alteration == 'producer':
                    tree['tree'][0]['sha'] = 'f'*40
                elif alteration == 'alloy-source':
                    (project/'builders/alloy/source.json').write_text('changed source selection')
                elif alteration == 'truncated-tree':
                    tree['truncated'] = True
                elif alteration in ('added-producer', 'added-root-module'):
                    tree['tree'].append({'path': 'scripts/hidden.py' if alteration == 'added-producer' else 'subprocess.py', 'sha': 'f'*40,
                                         'type': 'blob', 'mode': '100644'})
                elif alteration == 'missing-bundle':
                    (candidate/'cache.intoto.jsonl').unlink()
                calls = []
                with patch.object(cache.subprocess, 'run', side_effect=self.runner(
                        tree, calls, signature=1 if alteration == 'signature' else 0)):
                    result = cache.initialize(project, work, candidate, environment)
                self.assertEqual(result['status'], 'rejected')
                self.assertFalse(any(argv[0] == 'docker' for argv in calls))
                self.assertNotIn('--cache-from', cache.image_arguments('mkosi'))
                self.assertFalse((work/'build-cache/incoming').exists())

    def test_signed_but_unsafe_payloads_and_base_image_replacement_are_rejected(self):
        for member, tag in (('../escaped', None), ('scripts/execute.py', None),
                            ('compiler/aa/'+('a'*64)+'-d', 'debian:trixie')):
            with self.subTest(member=member, tag=tag), tempfile.TemporaryDirectory() as temporary:
                project, candidate, work, _, tree, environment = self.fixture(
                    Path(temporary), member=member, image_tag=tag)
                calls = []
                with patch.object(cache.subprocess, 'run', side_effect=self.runner(tree, calls)):
                    self.assertEqual(cache.initialize(project, work, candidate, environment)['status'], 'rejected')
                self.assertFalse(any(argv[0] == 'docker' for argv in calls))
                self.assertFalse((work/'build-cache/escaped').exists())

    def test_cache_miss_and_service_failure_leave_a_clean_build_available(self):
        for failure in (False, True):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                project, candidate, work, _, _, environment = self.fixture(Path(temporary))
                with patch.object(cache.subprocess, 'run', side_effect=subprocess.TimeoutExpired('gh', 60)):
                    result = cache.initialize(project, work, candidate if failure else None, environment)
                self.assertEqual(result['status'], 'rejected' if failure else 'miss')
                cache.record_image('mkosi', 'lanrith-mkosi:'+('b'*64))
                self.assertNotIn('--cache-from', cache.image_arguments('mkosi'))

    def test_only_main_can_offer_a_cache_to_the_signing_job(self):
        with tempfile.TemporaryDirectory() as temporary:
            project, _, work, _, _, environment = self.fixture(Path(temporary))
            environment['GITHUB_REF'] = 'refs/pull/1/merge'
            environment['GITHUB_WORKFLOW_REF'] = 'Lanrith/lanrith/.github/workflows/package-check.yml@refs/pull/1/merge'
            cache.initialize(project, work, None, environment)
            with patch.object(cache.subprocess, 'run') as command:
                self.assertFalse(cache.export(project, work/'export', environment))
            command.assert_not_called()
            self.assertFalse((work/'export').exists())

    def test_compiler_retention_is_bounded_and_does_not_retain_modules_or_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            project, _, work, _, _, environment = self.fixture(Path(temporary))
            cache.initialize(project, work, None, environment)
            compiler = work/'compiler'
            (compiler/'aa').mkdir(parents=True)
            for index in range(4):
                path = compiler/'aa'/(str(index)*64+'-d')
                path.write_bytes(b'12345678')
                os.utime(path, ns=(index, index))
            (compiler/'aa/README').write_text('not a compiler cache entry')
            with patch.object(cache, 'COMPILER_LIMIT', 16):
                cache.retain_compiler(compiler, 'c'*64)
            root, value = cache.state()
            self.assertEqual(sorted(p.name for p in (root/'compiler/aa').iterdir()),
                             [str(index)*64+'-d' for index in (2, 3)])
            self.assertEqual(value['compiler_identity'], 'c'*64)

    def test_export_failure_is_optional_and_cannot_emit_a_cache_ready_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            project, _, work, _, _, environment = self.fixture(Path(temporary))
            cache.initialize(project, work, None, environment)
            outputs = work/'outputs'
            environment['GITHUB_OUTPUT'] = str(outputs)
            with patch.object(cache.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'docker')):
                self.assertFalse(cache.export(project, work/'export', environment))
            self.assertFalse(outputs.exists())
            self.assertFalse((work/'export').exists())

    def test_export_round_trip_retains_only_public_acceleration_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project, candidate, work, metadata, tree, environment = self.fixture(root)
            with tarfile.open(candidate/'cache.tar.gz', 'r:gz') as stream:
                image_data = stream.extractfile('images.tar').read()
            cache.initialize(project, work, None, environment)
            cache.record_image('mkosi', metadata['images']['mkosi'])
            compiler = work/'objects/aa'
            compiler.mkdir(parents=True)
            (compiler/('c'*64+'-d')).write_bytes(b'synthetic compiler output')
            cache.retain_compiler(compiler.parent, 'c'*64)
            def save(argv, **_):
                self.assertEqual(argv[:3], ['docker', 'save', '--output'])
                Path(argv[3]).write_bytes(image_data)
                return subprocess.CompletedProcess(argv, 0)
            environment['GITHUB_OUTPUT'] = str(work/'github-output')
            exported = root/'export'
            with patch.object(cache.subprocess, 'run', side_effect=save), \
                    patch.object(cache.shutil, 'disk_usage', return_value=unittest.mock.Mock(free=64*1024**3)):
                seal = cache.export(project, exported, environment)
                self.assertTrue(seal)
            self.assertEqual({p.name for p in exported.iterdir()}, {'cache.json', 'cache.tar.gz'})
            self.assertFalse((work/'github-output').exists())
            self.assertTrue(cache.offer(exported, seal, environment))
            self.assertIn('cache-ready=true\n', (work/'github-output').read_text())
            (exported/'cache.intoto.jsonl').write_text('synthetic independently signed cache')
            next_work = root/'next-build'
            next_work.mkdir()
            calls = []
            with patch.object(cache.subprocess, 'run', side_effect=self.runner(tree, calls)):
                self.assertEqual(cache.initialize(project, next_work, exported, environment)['status'], 'verified')
            next_compiler = next_work/'compiler'
            next_compiler.mkdir()
            self.assertTrue(cache.restore_compiler(next_compiler, 'c'*64))
            self.assertEqual(next(next_compiler.glob('*/*')).read_bytes(), b'synthetic compiler output')

    def test_qualification_cannot_offer_modified_or_extra_cache_data(self):
        for alteration in ('changed', 'extra'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                root.joinpath('cache.json').write_bytes(b'synthetic metadata')
                root.joinpath('cache.tar.gz').write_bytes(b'synthetic payload')
                seal = {'key': cache.PREFIX+'a'*64, 'files': {name: file_record(root/name)
                    for name in ('cache.json', 'cache.tar.gz')}}
                if alteration == 'changed':
                    root.joinpath('cache.tar.gz').write_bytes(b'modified by a later stage')
                else:
                    root.joinpath('unselected').write_bytes(b'unselected data')
                outputs = root/'outputs'
                with self.assertRaises(ValueError):
                    cache.offer(root, seal, {'GITHUB_OUTPUT': str(outputs)})
                self.assertFalse(outputs.exists())


@unittest.skipUnless(shutil.which('go'), 'Requires a native Go compiler; CI supplies one on hosted runners.')
class NativeCompilerCacheTests(unittest.TestCase):
    def test_warm_compiler_cache_preserves_the_binary_bytes(self):
        compiler = subprocess.run(['go', 'version'], capture_output=True,
            env={**os.environ, 'GOENV': 'off', 'GOTOOLCHAIN': 'local'}, timeout=30)
        if compiler.returncode or not compiler.stdout.startswith(b'go version go'):
            self.skipTest('Requires a native Go compiler; an unavailable wrapper is insufficient.')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'main.go').write_text('package main\nfunc main() { println("synthetic-cache-probe") }\n')
            environment = {**os.environ, 'GOENV': 'off', 'GOTOOLCHAIN': 'local', 'GOCACHE': str(root/'cache'),
                'GOMODCACHE': str(root/'modules'), 'GOPROXY': 'off', 'CGO_ENABLED': '0', 'GOCACHEPROG': ''}
            values, compilations = [], []
            with patch.dict(os.environ):
                for name in ('cold', 'warm', 'changed'):
                    if name == 'warm':
                        # Exercise the real cache handoff rather than leaving
                        # the compiler pointed at its original workspace.
                        handoff = root/'handoff'
                        handoff.mkdir(mode=0o700)
                        cache.save_state(handoff, {'capture': True})
                        os.environ['LANRITH_BUILD_CACHE'] = str(handoff)
                        cache.retain_compiler(root/'cache', 'c'*64)
                        (handoff/'incoming').mkdir()
                        (handoff/'compiler').rename(handoff/'incoming/compiler')
                        (root/'restored-cache').mkdir()
                        self.assertTrue(cache.restore_compiler(root/'restored-cache', 'c'*64))
                        environment['GOCACHE'] = str(root/'restored-cache')
                    elif name == 'changed':
                        (root/'main.go').write_text('package main\nfunc main() { println("changed-cache-probe") }\n')
                    result = subprocess.run(['go', 'build', '-x', '-trimpath', '-buildvcs=false', '-o', str(root/name), 'main.go'],
                                            cwd=root, env=environment, capture_output=True, timeout=120)
                    self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                    values.append(file_record(root/name)['sha256'])
                    compilations.append(len(re.findall(rb'/compile\s', result.stderr)))
            self.assertEqual(values[0], values[1])
            self.assertNotEqual(values[1], values[2])
            self.assertGreater(compilations[0], 0)
            self.assertEqual(compilations[1], 0)
            self.assertGreater(compilations[2], 0)
            self.assertTrue(any((root/'restored-cache').glob('*/*-d')))


class CompilerIdentityTests(unittest.TestCase):
    def test_library_bytes_and_symlink_selection_invalidate_reuse_without_file_timestamps(self):
        spec = importlib.util.spec_from_file_location('compiler_identity',
            Path(__file__).parents[1]/'scripts/compiler-identity.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            library = root/'library.so'
            library.write_bytes(b'synthetic C library')
            link = root/'selected'
            link.symlink_to('library.so')
            before = module.identity([root])
            os.utime(library, (1, 1))
            self.assertEqual(module.identity([root]), before)
            library.write_bytes(b'patched C library')
            self.assertNotEqual(module.identity([root]), before)
            before = module.identity([root])
            link.unlink()
            link.symlink_to('./library.so')
            self.assertNotEqual(module.identity([root]), before)


if __name__ == '__main__':
    unittest.main()
