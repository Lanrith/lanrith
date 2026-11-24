"""Check complete published Go binaries against proposed inputs, without executing them."""
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile

from lanrith import archive
from .common import canonical, digest, document, now, osv_queries, pages, require, run, sha, unique, version


def findings(raw):
    require(0 < len(raw) <= 16*1024*1024, 'Published binary scanner output is empty or excessive.')
    decoder, text, offset, records = json.JSONDecoder(object_pairs_hook=unique), raw.decode(), 0, []
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        value, offset = decoder.raw_decode(text, offset)
        require(isinstance(value, dict) and len(value) == 1, 'Invalid binary scanner message.')
        records.append(value)
    configs = [r['config'] for r in records if 'config' in r]
    inventories = [r['SBOM'] for r in records if 'SBOM' in r]
    require(len(configs) == len(inventories) == 1 and configs[0].get('scanner_name') == 'govulncheck' and
            configs[0].get('scan_mode') == 'binary' and configs[0].get('scan_level') == 'symbol' and
            configs[0].get('db') == 'https://vuln.go.dev', 'Binary scan coverage is not complete symbol analysis.')
    modules = {m['path']: m['version'] for m in inventories[0]['modules']}
    modules['stdlib'] = inventories[0]['go_version'].removeprefix('go')
    result = set()
    for message in records:
        if 'finding' not in message:
            continue
        value = message['finding']
        require(value.get('trace'), 'Binary finding lacks its affected subject.')
        frame = value['trace'][0]
        if not frame.get('function'):
            continue  # Inventory/package overlap is not a reachable-symbol finding.
        module = frame['module']
        # Go nested modules can be attributed to their parent by the binary
        # scanner. Resolve the most specific actual SBOM owner of the package.
        owners = [m for m in modules if frame.get('package') == m or frame.get('package', '').startswith(m+'/')]
        if owners:
            module = max(owners, key=len)
        require(module in modules and re.fullmatch(r'GO-[0-9]{4}-[0-9]+', value['osv']),
                'Reachable finding is not bound to the binary inventory.')
        result.add((value['osv'], module, modules[module]))
    return sorted(result)


def covered(binary, observed, root, previous):
    alloy = document((root/'builders/alloy/source.json').read_bytes())
    node = document((root/'builders/node-exporter/source.json').read_bytes())
    selection = document((root/'build-inputs.json').read_bytes())
    proposed = {}
    if binary in ('alloy', 'alloy-beyla'):
        proposed = {n: p['version'] for n, p in alloy['security_modules'].items()}
        proposed['stdlib'] = alloy['go_version'].removeprefix('go')
    elif binary == 'prometheus-node-exporter':
        proposed['stdlib'] = node['go_version'].removeprefix('go')
    else:
        component = 'discovery-bridge' if binary == 'discovery-bridge' else 'router-policy-agent'
        if selection['component_releases'][component] != previous['component_releases'][component]:
            # component_selection already authenticated a newly qualified release;
            # image qualification rescans the exact replacement binaries.
            return []
    blockers = []
    for identity, module, installed in observed:
        selected = proposed.get(module)
        if selected and version(selected) > version(installed):
            old, new = osv_queries([{'package': {'ecosystem': 'Go', 'name': module}, 'version': value}
                                   for value in (installed, selected)])
            if (identity in {v['id'] for v in old.get('vulns', [])} and
                    identity not in {v['id'] for v in new.get('vulns', [])}):
                continue
        blockers.append(binary+': '+identity+' in '+module+' '+installed+
                        '; no verified fix is covered by the proposed inputs')
    return blockers


def reconcile(root, tools, previous):
    releases = [r for r in pages('repos/Lanrith/lanrith/releases?per_page=100')
                if not r['draft'] and not r['prerelease'] and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', r['tag_name'])]
    if not releases:
        return
    release = max(releases, key=lambda r: version(r['tag_name']))
    require(release.get('immutable') is True, 'Published vulnerability coverage needs an immutable release.')
    assets = {a['name']: a for a in release['assets']}
    names = ['selection.json', 'selection.json.intoto.jsonl', 'security.json', 'go-binaries.tar.gz']
    require(all(n in assets and 0 < assets[n]['size'] <= (512*1024*1024 if n.endswith('.tar.gz') else 16*1024*1024)
                for n in names), 'Published Go inventory is missing or exceeds download bounds.')
    spec = importlib.util.spec_from_file_location('retained_security_scan', tools/'scripts/security-audit.py')
    scan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scan)
    blockers = []
    with tempfile.TemporaryDirectory(prefix='lanrith-published-go.') as temporary:
        work = Path(temporary)
        for name in names:
            run('gh', 'release', 'download', release['tag_name'], '--repo', 'Lanrith/lanrith',
                '--dir', str(work), '--pattern', name, capture_output=True, timeout=300)
        selected = document((work/'selection.json').read_bytes())
        run('gh', 'attestation', 'verify', str(work/'selection.json'), '--bundle', str(work/'selection.json.intoto.jsonl'),
            '--repo', 'Lanrith/lanrith', '--signer-workflow', 'Lanrith/lanrith/.github/workflows/build-base.yml',
            '--source-digest', sha(selected['source_commit']), '--signer-digest', sha(selected['signer_commit']),
            '--source-ref', 'refs/heads/main', '--deny-self-hosted-runners', capture_output=True)
        for name in ('security.json', 'go-binaries.tar.gz'):
            with (work/name).open('rb') as stream:
                require(hashlib.file_digest(stream, 'sha256').hexdigest() == selected['files'][name],
                        'Published vulnerability subject differs from authenticated selection.')
        old = document((work/'security.json').read_bytes(), maximum=16*1024*1024)
        expected = scan.retained_binary_names(old['custom']['components'])
        binaries = work/'binaries'
        binaries.mkdir()
        require(archive.extract(work/'go-binaries.tar.gz', binaries, entries=len(expected),
                    maximum_file=1024**3, maximum_size=2*1024**3) == expected, 'Published Go binary coverage is incomplete.')
        for name in sorted(expected):
            result = run('govulncheck', '-json', '-mode=binary', str(binaries/name), capture_output=True, timeout=300)
            observed = findings(result.stdout)
            blockers.extend(covered(name, observed, root, previous))
            if os.environ.get('LANRITH_EVIDENCE_DIR'):
                destination = Path(os.environ['LANRITH_EVIDENCE_DIR'])
                destination.mkdir(parents=True, exist_ok=True)
                identity = digest(canonical({'release': release['tag_name'], 'binary': name}))
                (destination/(identity+'.json')).write_bytes(canonical({'schema': 1, 'release': release['html_url'],
                    'selection_sha256': digest((work/'selection.json').read_bytes()), 'binary': name,
                    'response_sha256': digest(result.stdout), 'retrieved_at': now()}))
                (destination/(identity+'.response.gz')).write_bytes(gzip.compress(result.stdout, mtime=0))
    require(not blockers, 'Reachable published vulnerabilities require a reviewed remediation:\n'+'\n'.join(blockers))
