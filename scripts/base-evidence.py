#!/usr/bin/env python3
"""Generate inventory-bound policy, vulnerability and SBOM evidence."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import copy
import re
import shutil
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith.release import canonical, file_record, require
from lanrith import sbom, embedded, components

ROOT = Path(__file__).resolve().parents[1]

UPDATE_TOOLS = {'usr/lib/systemd/systemd-sysupdate', 'usr/lib/systemd/systemd-import',
                'usr/lib/systemd/systemd-import-fs', 'usr/lib/systemd/systemd-pull'}


def runtime_components(names):
    require({'usr/lib/systemd/systemd', 'usr/bin/python3'} | UPDATE_TOOLS <= names.keys(),
            'Base is missing required runtime components.')
    require(all(names[name].isfile() and names[name].size > 0 and names[name].mode & 0o111
                for name in UPDATE_TOOLS), 'A required update tool is not an executable regular file.')


def runtime_paths(names):
    for name in names:
        require(not name.startswith(('usr/share/man/', 'usr/share/info/', 'usr/share/locale/',
                                     'var/lib/dpkg/', 'var/lib/apt/', 'var/cache/apt/')) and
                '__pycache__' not in Path(name).parts and
                not re.fullmatch(r'usr/(?:s?bin)/(?:dpkg.*|apt.*|gcc(?:-[0-9]+)?|g\+\+|g?make|git|cargo|rustc|node|npm)', name),
                'Base contains unnecessary package-manager, build or cache payload.')
        require(not re.fullmatch(r'usr/(?:bin|sbin)/(?:machinectl|importctl|portablectl|systemd-nspawn|systemd-dissect|mount[.]ddi)', name)
                and not re.fullmatch(r'usr/lib/systemd/systemd-(?:machined|nspawn|importd|portabled|export|mountfsd|mountwork|nsresourced|nsresourcework)', name)
                and not name.startswith(('usr/lib/systemd/network/80-namespace-ns.',
                                         'usr/lib/systemd/portable/')),
                'Base contains an unused container runtime component.')


def initrd_paths(path):
    names = set()
    with tarfile.open(path) as archive:
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            require(not name.startswith('/') and '..' not in Path(name).parts and name not in names and
                    not member.isdev() and not member.isfifo(), 'Initrd has an unsafe or duplicate path.')
            require(not name.startswith(('boot/', 'vmlinuz', 'initrd.img')),
                    'Initrd contains a redundant boot image.')
            require(not name.startswith(('root/.ssh/', 'etc/ssh/ssh_host_', 'var/lib/lanrith/')) and
                    not (member.isfile() and name.startswith('etc/ssl/private/')),
                    'Initrd contains owner identity or private material.')
            names.add(name)
    require({'usr/lib/systemd/systemd', 'usr/bin/python3'} <= names,
            'Initrd is missing required factory runtime components.')
    runtime_paths(names)


def binary_subjects(custom):
    try:
        stamp = datetime.datetime.fromisoformat(custom['assessed_at'])
    except (KeyError, TypeError, ValueError):
        require(False, 'Custom package security assessment timestamp is malformed.')
    require(stamp.tzinfo is not None and datetime.timedelta(0) <=
            datetime.datetime.now(datetime.timezone.utc)-stamp <= datetime.timedelta(hours=24),
            'Custom package security assessment is stale or future-dated.')
    components = custom.get('components', {})
    require(custom.get('result') == 'pass' and isinstance(components, dict),
            'Custom package security assessment failed.')
    alloy = components.get('alloy', {})
    expected = {'alloy': alloy.get('binary_sha256'),
                'alloy-beyla': alloy.get('beyla', {}).get('binary_sha256')}
    for name in ('node-exporter', 'discovery-bridge', 'router-policy-helper',
                 'router-policy-reader', 'router-policy-collector'):
        subjects = components.get(name, {}).get('binary_sha256')
        require(isinstance(subjects, dict) and subjects and not set(subjects) & set(expected),
                'Custom binary scan subjects are missing or ambiguous.')
        expected.update(subjects)
    require(all(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest)
                for digest in expected.values()), 'Custom binary scan subject digest is malformed.')
    return expected


class SubjectReader:
    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()

    def read(self, length):
        data = self.stream.read(length)
        self.digest.update(data)
        return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    directory = args.directory
    inventory = json.loads((directory/'inventory.json').read_text())
    custom = json.loads((directory/'custom-security.json').read_text())
    subjects = binary_subjects(custom)
    initrd_paths(directory/'lanrith-initrd-base.tar.gz')
    subprocess.run([sys.executable, str(ROOT/'security/audit-package-manifest.py'),
                    '--manifest', str(directory/'inventory.json'), '--policy', str(ROOT/'security/policy.json'),
                    '--release', args.version, '--status', str(directory/'package-policy.json')], check=True)
    # Inspect the archive without extracting it or following its symlinks.
    with tarfile.open(directory/'lanrith-base.tar.gz') as archive:
        names = {}
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            require(not name.startswith('/') and '..' not in Path(name).parts and name not in names,
                    'Base archive has an unsafe or duplicate path.')
            names[name] = member
            require(not member.isdev() and not member.isfifo(), 'Base contains a device or FIFO.')
            require(not name.startswith(('root/.ssh/', 'etc/ssh/ssh_host_', 'var/lib/lanrith/')),
                    'Base contains owner identity or deployment state.')
            require(not member.isfile() or not name.startswith('etc/ssl/private/'),
                    'Base contains package-generated TLS private material.')
            if member.isfile() and 0 < member.size <= 2*1024*1024:
                data = archive.extractfile(member).read()
                if b'\0' not in data:
                    markers = [b'-----BEGIN '+kind+b'PRIVATE KEY-----' for kind in
                               (b'', b'RSA ', b'EC ', b'DSA ', b'OPENSSH ', b'ENCRYPTED ')]
                    require(not any(marker in data for marker in markers),
                            'Base contains private-key material in a text file.')
        runtime_components(names)
        runtime_paths(names)
        metadata = directory/'apt-metadata'
        require(metadata.is_file() and not metadata.is_symlink() and
                0 < metadata.stat().st_size < 256*1024*1024, 'Build APT metadata is missing or oversized.')
        require('usr/share/lanrith/apt-metadata' not in names and
                'usr/share/doc/alloy/security/beyla' not in names,
                'Scan-only evidence must not be deployed in the router filesystem.')
        scan_names = {'alloy', 'prometheus-node-exporter'}.union(*components.REQUIRED_BINARIES.values())
        require(set(subjects) == scan_names | {'alloy-beyla'}, 'Custom binary scan coverage is incomplete.')
        with tarfile.open(directory/'go-binaries.tar.gz', 'w:gz') as binaries, \
                tempfile.TemporaryDirectory(prefix='embedded-subject.', dir=directory) as temporary:
            found = set()
            for member in archive.getmembers():
                path = Path(member.name.removeprefix('./'))
                if path.parent.as_posix() == 'usr/bin' and path.name in scan_names:
                    require(member.isfile(), 'A scan subject is not a regular binary.')
                    content = SubjectReader(archive.extractfile(member))
                    scan_member = copy.copy(member)
                    scan_member.name = path.name
                    scan_member.mode = 0o644
                    binaries.addfile(scan_member, content)
                    require(content.digest.hexdigest() == subjects[scan_member.name],
                            'Installed custom binary differs from its scanned subject.')
                    found.add(scan_member.name)
            require(found == scan_names, 'Fresh binary scan coverage is incomplete.')
            installed_alloy = Path(temporary)/'alloy'
            with installed_alloy.open('wb') as stream:
                shutil.copyfileobj(archive.extractfile(names['usr/bin/alloy']), stream)
            require(file_record(installed_alloy)['sha256'] == subjects['alloy'],
                    'Installed Alloy changed while binding its embedded scan subject.')
            subject = directory/'alloy-beyla.scan'
            embedded_record = embedded.verify(installed_alloy, subject, subjects['alloy-beyla'])
            scan_member = tarfile.TarInfo('alloy-beyla')
            scan_member.size = subject.stat().st_size
            scan_member.mode = 0o644
            with subject.open('rb') as stream:
                content = SubjectReader(stream)
                binaries.addfile(scan_member, content)
            require(content.digest.hexdigest() == subjects['alloy-beyla'],
                    'Embedded scan subject changed during evidence packaging.')
    subprocess.run([sys.executable, str(ROOT/'security/audit-debian-vulnerabilities.py'),
                    '--manifest', str(directory/'inventory.json'), '--policy', str(ROOT/'security/policy.json'),
                    '--release', args.version, '--suite', 'trixie', '--apt-metadata', str(directory/'apt-metadata'),
                    '--source-map-output', str(directory/'package-sources.json'),
                    '--tracker', str(directory/'tracker.json.gz'),
                    '--tracker-url', 'https://security-tracker.debian.org/tracker/data/json',
                    '--status', str(directory/'debian-security.txt')], check=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    digest = file_record(directory/'inventory.json')['sha256']
    (directory/'sbom.spdx.json').write_bytes(canonical(sbom.document(inventory, custom, args.version, digest, stamp)))
    security = {'schema': 1, 'assessed_at': stamp, 'inventory_sha256': digest,
                'policy_sha256': file_record(ROOT/'security/policy.json')['sha256'],
                'package_policy': json.loads((directory/'package-policy.json').read_text()),
                'custom': custom,
                'debian': (directory/'debian-security.txt').read_text(),
                'package_sources_sha256': file_record(directory/'package-sources.json')['sha256'],
                'apt_metadata_sha256': file_record(directory/'apt-metadata')['sha256'],
                'embedded_beyla': embedded_record,
                'production_qualified': False}
    require(security['custom'].get('result') == 'pass', 'Custom package security assessment failed.')
    (directory/'security.json').write_bytes(canonical(security))
    (directory/'policy.json').write_bytes((ROOT/'security/policy.json').read_bytes())


if __name__ == '__main__':
    main()
