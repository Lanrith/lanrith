#!/usr/bin/env python3
"""Rescan a retained public package inventory without rebuilding or executing it."""

import argparse
import datetime
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith.release import canonical, file_record, require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    def run(*argv, check=True, **kwargs):
        return subprocess.run(argv, check=check, stdin=subprocess.DEVNULL, **kwargs)
    releases = json.loads(run('gh', 'api', 'repos/Lanrith/lanrith/releases?per_page=100',
                              capture_output=True, text=True).stdout)
    versions = [item for item in releases if not item['draft'] and
                __import__('re').fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', item['tag_name'])]
    require(versions, 'No published platform exists to assess.')
    args.output.mkdir(mode=0o755)
    for item in versions[:3]:
        with tempfile.TemporaryDirectory(prefix='lanrith-rescan.') as temporary:
            work = Path(temporary)
            run('gh', 'release', 'download', item['tag_name'], '--repo', 'Lanrith/lanrith', '--dir', str(work),
                '--pattern', 'selection.json', '--pattern', 'selection.json.intoto.jsonl')
            selection = json.loads((work/'selection.json').read_text())
            run('gh', 'attestation', 'verify', str(work/'selection.json'),
                '--bundle', str(work/'selection.json.intoto.jsonl'), '--repo', 'Lanrith/lanrith',
                '--signer-workflow', 'Lanrith/lanrith/.github/workflows/build-base.yml',
                '--source-digest', selection['source_commit'], '--signer-digest', selection['signer_commit'],
                '--deny-self-hosted-runners')
            names = ['inventory.json', 'package-sources.json', 'policy.json', 'security.json', 'go-binaries.tar.gz']
            for name in names:
                run('gh', 'release', 'download', item['tag_name'], '--repo', 'Lanrith/lanrith', '--dir', str(work), '--pattern', name)
                require(file_record(work/name)['sha256'] == selection['files'][name], 'Retained security input differs.')
            inventory = selection['files']['inventory.json']
            with urllib.request.urlopen('https://security-tracker.debian.org/tracker/data/json', timeout=90) as response:
                data = response.read(256*1024*1024+1)
            require(0 < len(data) <= 256*1024*1024, 'Invalid Debian advisory feed size.')
            (work/'tracker.json.gz').write_bytes(gzip.compress(data, mtime=0))
            failures = []
            gate = run(sys.executable, str(ROOT/'security/audit-debian-vulnerabilities.py'),
                '--manifest', str(work/'inventory.json'), '--policy', str(work/'policy.json'),
                '--release', item['tag_name'][1:], '--suite', 'trixie', '--source-map', str(work/'package-sources.json'),
                '--tracker', str(work/'tracker.json.gz'), '--tracker-url', 'https://security-tracker.debian.org/tracker/data/json',
                '--status', str(work/'debian-security.txt'), capture_output=True, check=False)
            if gate.returncode:
                failures.append('debian-admission')
            # A positive scan does not execute binaries. The archive is already digest-bound.
            import tarfile
            binaries = work/'binaries'
            binaries.mkdir()
            with tarfile.open(work/'go-binaries.tar.gz') as archive:
                members = archive.getmembers()
                require(members and all(m.isfile() and '/' not in m.name and m.size <= 512*1024*1024 for m in members),
                        'Unsafe retained binary scan archive.')
                archive.extractall(binaries, filter='data')
            for binary in binaries.iterdir():
                scan = run('govulncheck', '-mode=binary', str(binary), stdout=subprocess.DEVNULL, check=False)
                if scan.returncode:
                    failures.append('go-binary-'+binary.name)
            for repository, patched in (('FDio/vpp', {'GHSA-rc9p-89wj-mx7h'}), ('apalrd/tayga', set())):
                feed = json.loads(run('gh', 'api', 'repos/'+repository+'/security-advisories',
                                      capture_output=True, text=True).stdout)
                if not all(record.get('ghsa_id') in patched for record in feed):
                    failures.append('native-upstream-advisory')
            old = json.loads((work/'security.json').read_text())
            queries = old['custom']['components']['pam-rssh']['queries']
            request = urllib.request.Request('https://api.osv.dev/v1/querybatch',
                data=json.dumps({'queries': queries}).encode(), headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(request, timeout=60) as response:
                result = json.load(response)['results']
            if len(result) != len(queries) or any(entry.get('vulns') for entry in result):
                failures.append('pam-dependencies')
            report = {'schema': 1, 'result': 'fail' if failures else 'pass', 'inventory_sha256': inventory,
                      'platform_version': item['tag_name'], 'source_commit': os.environ['GITHUB_SHA'],
                      'assessed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'debian_feed_sha256': hashlib.sha256(data).hexdigest(),
                      'failures': sorted(set(failures)),
                      'revoked_sha256': json.loads((ROOT/'security/revocations.json').read_text())['revoked_sha256']}
            destination = args.output/inventory[:12]
            destination.mkdir()
            (destination/'security-assessment.json').write_bytes(canonical(report))
            print('Retained inventory '+inventory[:12]+' assessment: '+report['result']+'.')


if __name__ == '__main__':
    main()
