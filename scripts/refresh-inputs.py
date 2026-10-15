#!/usr/bin/env python3
"""Propose public inputs; this tool never merges or approves them."""

import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith.release import require


def run(*argv):
    return subprocess.run(argv, check=True, stdin=subprocess.DEVNULL, capture_output=True, text=True).stdout


def source(repository, tag):
    value = json.loads(run('gh', 'api', 'repos/'+repository+'/git/ref/tags/'+tag))['object']
    for _ in range(4):
        if value['type'] == 'commit':
            require(re.fullmatch('[0-9a-f]{40}', value['sha']), 'Invalid release source identity.')
            return value['sha']
        require(value['type'] == 'tag', 'Unsupported release tag object.')
        value = json.loads(run('gh', 'api', 'repos/'+repository+'/git/tags/'+value['sha']))['object']
    raise ValueError('Release tag nesting exceeds the limit.')


def main():
    selection = json.loads((ROOT/'build-inputs.json').read_text())
    for component in ('discovery-bridge', 'router-policy-agent'):
        repository = 'Lanrith/'+component
        releases = json.loads(run('gh', 'api', 'repos/'+repository+'/releases?per_page=100'))
        candidates = [item for item in releases if not item['draft'] and not item['prerelease'] and
                      re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', item['tag_name'])]
        if not candidates:
            print(component+': awaiting its first qualified release.')
            continue
        chosen = max(candidates, key=lambda item: tuple(map(int, item['tag_name'][1:].split('.'))))
        revision = source(repository, chosen['tag_name'])
        manifest_name = 'release.json' if component == 'discovery-bridge' else 'component-release.json'
        with tempfile.TemporaryDirectory(prefix='lanrith-input-refresh.') as temporary:
            work = Path(temporary)
            run('gh', 'release', 'download', chosen['tag_name'], '--repo', repository, '--dir', str(work),
                '--pattern', manifest_name, '--pattern', manifest_name+'.intoto.jsonl')
            run('gh', 'attestation', 'verify', str(work/manifest_name), '--bundle', str(work/(manifest_name+'.intoto.jsonl')),
                '--repo', repository, '--signer-workflow', repository+'/.github/workflows/build-release.yml',
                '--source-digest', revision, '--signer-digest', revision, '--deny-self-hosted-runners')
            manifest = json.loads((work/manifest_name).read_text())
            require(manifest['source_commit'] == revision and manifest['version'] == chosen['tag_name'][1:],
                    'Component metadata differs from its signed release.')
            files = {manifest_name: hashlib.sha256((work/manifest_name).read_bytes()).hexdigest()}
            if component == 'discovery-bridge':
                files.update({name: digest for name, digest in manifest['platforms']['amd64']['artifacts'].items()
                              if name.endswith('_amd64.deb')})
            else:
                files.update({name: record['sha256'] for name, record in manifest['files'].items()
                              if name.endswith('_amd64.deb') or name == 'security.txt'})
            require(any(name.endswith('.deb') for name in files), 'Qualified component has no admitted native packages.')
            selection['component_releases'][component] = {'repository': repository, 'tag': chosen['tag_name'],
                'source_commit': revision, 'workflow_commit': revision, 'files': files}
    policy = json.loads((ROOT/'security/policy.json').read_text())
    for component, pin in selection['component_releases'].items():
        names = ['discovery-bridge'] if component == 'discovery-bridge' else [
            'router-policy-reader', 'router-policy-helper', 'router-policy-collector']
        for name in names:
            policy['required_exact_packages'][name] = pin['tag'][1:]
            policy['local_package_sources'][name]['version'] = pin['tag'][1:]
    # Snapshot metadata is a proposal. apt verifies Debian archive signatures in the actual build.
    stamp = (datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=1)).strftime('%Y%m%dT120000Z')
    path = ROOT/'builders/build-inputs.lock'
    text = path.read_text()
    for key, archive, suite in (('DEBIAN_RELEASE_SHA256', 'debian', 'trixie'),
                                 ('DEBIAN_SECURITY_RELEASE_SHA256', 'debian-security', 'trixie-security')):
        url = f'https://snapshot.debian.org/archive/{archive}/{stamp}/dists/{suite}/Release'
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(2*1024*1024+1)
        require(0 < len(data) <= 2*1024*1024 and b'\nSHA256:\n' in data, 'Invalid proposed Debian Release metadata.')
        digest = hashlib.sha256(data).hexdigest()
        text = re.sub(r'^'+key+r'=[0-9a-f]{64}$', key+'='+digest, text, flags=re.MULTILINE)
        field = 'security_release_sha256' if 'SECURITY' in key else 'debian_release_sha256'
        selection[field] = digest
    text = re.sub(r'^(DEBIAN_(?:SECURITY_)?SNAPSHOT)=[0-9TZ]+$', r'\g<1>='+stamp, text, flags=re.MULTILINE)
    path.write_text(text)
    selection['debian_snapshot'] = selection['security_snapshot'] = stamp
    selection['custom_package_inputs'] = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((ROOT/'builders').rglob('*')) if path.is_file() and '__pycache__' not in path.parts}
    (ROOT/'build-inputs.json').write_text(json.dumps(selection, sort_keys=True, indent=2)+'\n')
    (ROOT/'security/policy.json').write_text(json.dumps(policy, sort_keys=True, indent=2)+'\n')
    print('Proposed public snapshot and qualified component pins. Review source/patch, package and security diffs before merging.')


if __name__ == '__main__':
    main()
