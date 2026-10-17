"""Read actual tar headers while retaining neutral-image privacy checks."""

import importlib.util
import hashlib
import datetime
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from lanrith.release import ReleaseError

source = Path(__file__).resolve().parents[1] / 'scripts/base-evidence.py'
spec = importlib.util.spec_from_file_location('base_evidence', source)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class BaseArchiveEvidenceTests(unittest.TestCase):
    def test_updates_require_real_executable_helpers(self):
        names = {}
        for name in {'usr/lib/systemd/systemd', 'usr/bin/python3'} | evidence.UPDATE_TOOLS:
            member = tarfile.TarInfo(name)
            member.size, member.mode = 16, 0o755
            names[name] = member
        evidence.runtime_components(names)
        for name in evidence.UPDATE_TOOLS:
            with self.subTest(missing=name), self.assertRaises(ReleaseError):
                evidence.runtime_components({key: member for key, member in names.items() if key != name})
            for attribute, value in (('mode', 0o644), ('size', 0), ('type', tarfile.SYMTYPE)):
                with self.subTest(tool=name, attribute=attribute), self.assertRaises(ReleaseError):
                    invalid = tarfile.TarInfo(name)
                    invalid.size, invalid.mode = 16, 0o755
                    setattr(invalid, attribute, value)
                    evidence.runtime_components({**names, name: invalid})

    def test_build_tools_and_caches_cannot_return_to_the_runtime(self):
        evidence.runtime_paths(['usr/bin/python3', 'usr/bin/tcpdump', 'usr/lib/locale/C.utf8/LC_CTYPE'])
        for name in ('usr/bin/dpkg-query', 'usr/bin/gcc', 'usr/bin/git', 'usr/bin/systemd-nspawn',
                     'usr/lib/systemd/systemd-machined', 'usr/lib/systemd/network/80-namespace-ns.network',
                     'var/lib/apt/lists/Packages',
                     'usr/share/locale/de/messages.mo', 'usr/lib/python3.13/__pycache__/os.pyc'):
            with self.subTest(path=name), self.assertRaises(ReleaseError):
                evidence.runtime_paths([name])

    def run_fixture(self, directory, *, prefix, state=False, duplicate=False, altered_binary=False):
        metadata = b'Package: synthetic\nVersion: 1\n\n'
        subject = b'synthetic embedded scan subject'
        alloy = b'synthetic executable prefix'+subject+b'suffix'
        (directory/'apt-metadata').write_bytes(metadata)
        (directory/'alloy-beyla.scan').write_bytes(subject)
        with tarfile.open(directory/'lanrith-initrd-base.tar.gz', 'w:gz') as archive:
            for name in ('usr/lib/systemd/systemd', 'usr/bin/python3'):
                member = tarfile.TarInfo(name)
                member.size = 7
                archive.addfile(member, io.BytesIO(b'fixture'))
        with tarfile.open(directory/'lanrith-base.tar.gz', 'w:gz') as archive:
            names = ['usr/lib/systemd/systemd', 'usr/bin/python3'] + sorted(evidence.UPDATE_TOOLS)
            names += ['usr/bin/'+name for name in ('alloy', 'prometheus-node-exporter', 'discovery-bridge',
                'router-policy-helper', 'router-policy-reader', 'router-policy-collector',
                'router-policy-check', 'router-policy-status', 'router-policy-recover')]
            for name in names:
                data = alloy if name == 'usr/bin/alloy' else b'synthetic fixture'
                if altered_binary and name == 'usr/bin/discovery-bridge':
                    data = b'changed after the package scan'
                member = tarfile.TarInfo(prefix+name)
                member.size = len(data)
                member.mode = 0o755
                archive.addfile(member, io.BytesIO(data))
            if state:
                member = tarfile.TarInfo(prefix+'var/lib/lanrith/ssh-host-keys')
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            if duplicate:
                member = tarfile.TarInfo('usr/bin/python3')
                member.size = len(metadata)
                archive.addfile(member, io.BytesIO(metadata))
        (directory/'inventory.json').write_text(json.dumps({'packages': []}))
        digest = hashlib.sha256(b'synthetic fixture').hexdigest()
        components = {'alloy': {'binary_sha256': hashlib.sha256(alloy).hexdigest(),
            'beyla': {'binary_sha256': hashlib.sha256(subject).hexdigest()}}}
        for name, binaries in {'node-exporter': ['prometheus-node-exporter'],
            'discovery-bridge': ['discovery-bridge'], 'router-policy-reader': ['router-policy-reader'],
            'router-policy-collector': ['router-policy-collector'],
            'router-policy-helper': ['router-policy-check','router-policy-helper','router-policy-status','router-policy-recover']}.items():
            components[name] = {'binary_sha256': {binary: digest for binary in binaries}}
        (directory/'custom-security.json').write_text(json.dumps({'result': 'pass', 'components': components,
            'assessed_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}))

        def audited(arguments, **_):
            status = Path(arguments[arguments.index('--status')+1])
            status.write_text('{}' if status.name == 'package-policy.json' else 'Synthetic audit passed\n')
            if '--source-map-output' in arguments:
                Path(arguments[arguments.index('--source-map-output')+1]).write_text('{}')

        with patch.object(sys, 'argv', ['base-evidence.py', '--directory', str(directory), '--version', '0.1.0']), \
                patch.object(evidence.subprocess, 'run', side_effect=audited), \
                patch.object(evidence.sbom, 'document', return_value={'synthetic': True}):
            evidence.main()
        self.assertEqual((directory/'apt-metadata').read_bytes(), metadata)
        self.assertFalse(json.loads((directory/'security.json').read_text())['production_qualified'])

    def test_metadata_uses_the_real_header_for_both_native_tar_spellings(self):
        for prefix in ('', './'):
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as temporary:
                self.run_fixture(Path(temporary), prefix=prefix)

    def test_owner_state_and_normalized_duplicate_headers_remain_rejected(self):
        for change in ({'state': True}, {'duplicate': True}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(ReleaseError):
                    self.run_fixture(Path(temporary), prefix='./', **change)

    def test_changed_installed_binary_cannot_reuse_the_package_scan(self):
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(
                ReleaseError, 'Installed custom binary differs'):
            self.run_fixture(Path(temporary), prefix='./', altered_binary=True)

    def test_initrd_cannot_reintroduce_build_tools_or_a_second_kernel(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'initrd.tar.gz'
            for extra in ('usr/bin/dpkg', 'boot/vmlinuz-test', '../escape', 'etc/ssl/private/owner.key',
                          'usr/share/info/dir'):
                with self.subTest(path=extra):
                    with tarfile.open(path, 'w:gz') as archive:
                        for name in ('usr/lib/systemd/systemd', 'usr/bin/python3', extra):
                            archive.addfile(tarfile.TarInfo(name))
                    with self.assertRaises(ReleaseError):
                        evidence.initrd_paths(path)

    def test_repackaging_cannot_refresh_an_expired_or_invalid_custom_assessment(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.run_fixture(directory, prefix='./')
            custom = json.loads((directory/'custom-security.json').read_text())
            now = datetime.datetime.now(datetime.timezone.utc)
            for stamp in (None, 'malformed', now.replace(tzinfo=None).isoformat(),
                          (now-datetime.timedelta(hours=25)).isoformat(),
                          (now+datetime.timedelta(minutes=5)).isoformat()):
                with self.subTest(stamp=stamp), self.assertRaises(ReleaseError):
                    evidence.binary_subjects({**custom, 'assessed_at': stamp})
