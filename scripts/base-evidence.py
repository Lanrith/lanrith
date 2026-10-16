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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith.release import canonical, file_record, require
from lanrith import sbom

ROOT = Path(__file__).resolve().parents[1]


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
        require('usr/lib/systemd/systemd' in names and 'usr/bin/python3' in names,
                'Base is missing required runtime components.')
        metadata = names['usr/share/lanrith/apt-metadata']
        require(metadata.isfile() and 0 < metadata.size < 256 * 1024 * 1024, 'Base APT metadata is missing or oversized.')
        (directory/'apt-metadata').write_bytes(archive.extractfile(metadata).read())
        scan_names = {'alloy', 'prometheus-node-exporter', 'discovery-bridge', 'router-policy-helper',
                      'router-policy-reader', 'router-policy-collector', 'router-policy-check',
                      'router-policy-status', 'router-policy-recover'}
        require(set(subjects) == scan_names | {'alloy-beyla'}, 'Custom binary scan coverage is incomplete.')
        with tarfile.open(directory/'go-binaries.tar.gz', 'w:gz') as binaries:
            found = set()
            for member in archive.getmembers():
                path = Path(member.name.removeprefix('./'))
                if (path.parent.as_posix() == 'usr/bin' and path.name in scan_names or
                        path.as_posix() == 'usr/share/doc/alloy/security/beyla'):
                    require(member.isfile(), 'A scan subject is not a regular binary.')
                    content = SubjectReader(archive.extractfile(member))
                    scan_member = copy.copy(member)
                    scan_member.name = 'alloy-beyla' if path.name == 'beyla' else path.name
                    scan_member.mode = 0o644
                    binaries.addfile(scan_member, content)
                    require(content.digest.hexdigest() == subjects[scan_member.name],
                            'Installed custom binary differs from its scanned subject.')
                    found.add(scan_member.name)
            require(found == scan_names | {'alloy-beyla'}, 'Fresh binary scan coverage is incomplete.')
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
                'production_qualified': False}
    require(security['custom'].get('result') == 'pass', 'Custom package security assessment failed.')
    (directory/'security.json').write_bytes(canonical(security))
    (directory/'policy.json').write_bytes((ROOT/'security/policy.json').read_bytes())


if __name__ == '__main__':
    main()
