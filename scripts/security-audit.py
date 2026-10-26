#!/usr/bin/env python3
"""Rescan a retained public package inventory without rebuilding or executing it."""

import argparse
import datetime
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith.release import canonical, file_record, require
from lanrith import archive as handoff
from lanrith import advisories, embedded
from lanrith.release import ReleaseError


def retained_binary_names(components):
    names = {'alloy', 'alloy-beyla', 'prometheus-node-exporter', 'discovery-bridge',
             'router-policy-helper', 'router-policy-reader', 'router-policy-collector',
             'router-policy-check', 'router-policy-status', 'router-policy-recover'}
    # Published inventories predate the Phase B profile compiler. Require it
    # precisely when the authenticated component evidence includes that binary.
    if any('router-policy-profile' in component.get('binary_sha256', {})
           for component in components.values()):
        names.add('router-policy-profile')
    return names


def dependency_scan(queries, name, destination, failures, scanner_errors):
    try:
        value = advisories.report(queries, diagnostic=destination/(name+'-diagnostic.json'))
        (destination/(name+'-advisories.json')).write_bytes(canonical(value))
        if value['findings']:
            print(json.dumps(value['findings'], sort_keys=True), flush=True)
            failures.append(name)
    except (ReleaseError, ValueError, OSError, KeyError):
        failures.append(name)
        scanner_errors.append(name)


def archive_diagnostics(destination):
    """Preserve raw bytes, including empty logs, in one digest-bound asset."""
    require(destination.is_dir() and not destination.is_symlink() and
            destination.resolve() == destination.absolute(), 'Diagnostic directory is unsafe.')
    paths = sorted(destination.iterdir())
    require(0 < len(paths) <= 64 and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,99}', p.name) and
            p.name not in {'diagnostics.tar.gz', 'security-assessment.json',
                           'security-assessment.json.intoto.jsonl'} for p in paths),
            'Diagnostic file inventory is unsafe or already packaged.')
    records, payloads, total = {}, {}, 0
    for path in paths:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                    0 <= before.st_size <= 16*1024*1024, 'Diagnostic file metadata is unsafe.')
            data = stream.read(16*1024*1024+1)
            after = os.fstat(stream.fileno())
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                    len(data) == before.st_size, 'Diagnostic file changed during inspection.')
        total += len(data)
        require(total <= 64*1024*1024, 'Diagnostic inventory exceeds its size limit.')
        records[path.name] = hashlib.sha256(data).hexdigest()
        payloads[path.name] = data
    archive = destination/'diagnostics.tar.gz'
    with archive.open('xb') as target, gzip.GzipFile(fileobj=target, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as bundle:
            for name, data in payloads.items():
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.mtime = len(data), 0o644, 0
                member.uid = member.gid = 0
                member.uname = member.gname = ''
                bundle.addfile(member, io.BytesIO(data))
    return records, file_record(archive)


def support_decisions(completed):
    # Unknown scanner coverage cannot be retired as a known vulnerable release.
    # The newest stable release always remains supported and blocking if unsafe.
    if completed and completed[0][1]['result'] == 'pass' and not completed[0][1]['scanner_errors']:
        for destination, report in completed[1:]:
            if report['result'] != 'pass' and not report['scanner_errors']:
                report.update(supported=False, retirement_reason='superseded-vulnerable',
                              superseded_by=completed[0][1]['platform_version'])
                (destination/'security-assessment.json').write_bytes(canonical(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    def run(*argv, check=True, **kwargs):
        return subprocess.run(argv, check=check, stdin=subprocess.DEVNULL, **kwargs)
    pages = json.loads(run('gh', 'api', '--paginate', '--slurp',
        'repos/Lanrith/lanrith/releases?per_page=100', capture_output=True, text=True).stdout)
    require(isinstance(pages, list) and all(isinstance(page, list) for page in pages),
            'Retained release enumeration is malformed.')
    releases = [item for page in pages for item in page]
    versions = [item for item in releases if not item['draft'] and not item['prerelease'] and
                __import__('re').fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', item['tag_name'])]
    versions.sort(key=lambda item: tuple(map(int, item['tag_name'][1:].split('.'))), reverse=True)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
            stream.write('retained='+('true' if versions else 'false')+'\n')
    if not versions:
        print('No published platform exists yet; no retained assessment is required.')
        return
    args.output.mkdir(mode=0o755)
    completed = []
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
                '--source-ref', 'refs/heads/main', '--deny-self-hosted-runners')
            names = ['inventory.json', 'package-sources.json', 'policy.json', 'security.json', 'go-binaries.tar.gz']
            for name in names:
                run('gh', 'release', 'download', item['tag_name'], '--repo', 'Lanrith/lanrith', '--dir', str(work), '--pattern', name)
                require(file_record(work/name)['sha256'] == selection['files'][name], 'Retained security input differs.')
            old = json.loads((work/'security.json').read_text())
            inventory = selection['files']['inventory.json']
            destination = args.output/inventory[:12]
            destination.mkdir()
            with urllib.request.urlopen('https://security-tracker.debian.org/tracker/data/json', timeout=90) as response:
                data = response.read(256*1024*1024+1)
            require(0 < len(data) <= 256*1024*1024, 'Invalid Debian advisory feed size.')
            (work/'tracker.json.gz').write_bytes(gzip.compress(data, mtime=0))
            failures = []
            scanner_errors = []
            gate = run(sys.executable, str(ROOT/'security/audit-debian-vulnerabilities.py'),
                '--manifest', str(work/'inventory.json'), '--policy', str(work/'policy.json'),
                '--release', item['tag_name'][1:], '--suite', 'trixie', '--source-map', str(work/'package-sources.json'),
                '--tracker', str(work/'tracker.json.gz'), '--tracker-url', 'https://security-tracker.debian.org/tracker/data/json',
                '--status', str(work/'debian-security.txt'), capture_output=True, check=False)
            (destination/'debian.stdout.txt').write_bytes(gate.stdout)
            (destination/'debian.stderr.txt').write_bytes(gate.stderr)
            if gate.returncode:
                print(gate.stderr.decode(errors='replace')[-16000:], flush=True)
            if gate.returncode:
                failures.append('debian-admission')
                if b'installed source-package vulnerabilities violate policy' not in gate.stderr:
                    scanner_errors.append('debian-admission')
            # A positive scan does not execute binaries. The archive is already digest-bound.
            binaries = work/'binaries'
            binaries.mkdir()
            expected_binaries = retained_binary_names(old['custom']['components'])
            members = handoff.extract(work/'go-binaries.tar.gz', binaries, entries=len(expected_binaries),
                                     maximum_file=1024*1024*1024, maximum_size=2*1024*1024*1024)
            require(members == expected_binaries,
                'Retained binary scan coverage is incomplete.')
            for binary in binaries.iterdir():
                scan = run('govulncheck', '-mode=binary', str(binary), capture_output=True, check=False)
                (destination/(binary.name+'.govulncheck.txt')).write_bytes(scan.stdout+scan.stderr)
                if scan.returncode:
                    failures.append('go-binary-'+binary.name)
                    print(binary.name+': '+(scan.stdout+scan.stderr).decode(errors='replace')[-24000:], flush=True)
                    if scan.returncode != 3:
                        scanner_errors.append('go-binary-'+binary.name)
            for repository, patched in (('FDio/vpp', {'GHSA-rc9p-89wj-mx7h'}), ('apalrd/tayga', set())):
                feed = json.loads(run('gh', 'api', 'repos/'+repository+'/security-advisories',
                                      capture_output=True, text=True).stdout)
                if not all(record.get('ghsa_id') in patched for record in feed):
                    failures.append('native-upstream-advisory')
            require(embedded.verify(binaries/'alloy', binaries/'alloy-beyla',
                    old['custom']['components']['alloy']['beyla']['binary_sha256']) == old['embedded_beyla'],
                    'Retained Beyla scan subject differs from the deployed embedded payload.')
            dependency_scan(old['custom']['components']['pam-rssh']['queries'],
                            'pam-dependencies', destination, failures, scanner_errors)
            dependency_scan(old['custom']['components']['alloy']['java_agent']['queries'],
                            'alloy-embedded-java', destination, failures, scanner_errors)
            dependency_scan(advisories.npm_queries(old['custom']['components']['alloy']['npm_modules']),
                            'alloy-ui-dependencies', destination, failures, scanner_errors)
            alloy = old['custom']['components']['alloy']
            for repository in ('grafana/alloy', 'grafana/beyla', 'grafana/opentelemetry-ebpf-instrumentation',
                               'open-telemetry/opentelemetry-ebpf-instrumentation'):
                feed = json.loads(run('gh', 'api', 'repos/'+repository+'/security-advisories', '--paginate',
                                      capture_output=True, text=True).stdout)
                require(isinstance(feed, list), 'Retained embedded-source advisory coverage is malformed.')
                covered = alloy['source_fix_ancestry'] if repository.startswith('open-telemetry/') else {}
                try:
                    advisories.source_coverage(feed, covered)
                except (ReleaseError, ValueError, KeyError):
                    failures.append('alloy-embedded-source-advisory')
            diagnostics, diagnostic_archive = archive_diagnostics(destination)
            report = {'schema': 1, 'result': 'fail' if failures else 'pass', 'inventory_sha256': inventory,
                      'platform_version': item['tag_name'], 'source_commit': os.environ['GITHUB_SHA'],
                      'assessed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'debian_feed_sha256': hashlib.sha256(data).hexdigest(),
                      'failures': sorted(set(failures)),
                      'scanner_errors': sorted(set(scanner_errors)),
                      'supported': True,
                      'diagnostics': diagnostics, 'diagnostic_archive': diagnostic_archive,
                      'revoked_sha256': json.loads((ROOT/'security/revocations.json').read_text())['revoked_sha256']}
            (destination/'security-assessment.json').write_bytes(canonical(report))
            completed.append((destination, report))
            print('Retained inventory '+inventory[:12]+' assessment: '+report['result']+'.')
    support_decisions(completed)


if __name__ == '__main__':
    main()
