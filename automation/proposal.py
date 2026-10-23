"""Resolve security-only proposals without executing dependency install hooks."""

import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from . import evidence, inputs
from .common import (api, canonical, contents, digest, document, fetch, fetch_json, now,
                     osv_queries, pages, repository, require, run, sha, version)


def component_selection(repo, tag):
    repository(repo)
    version(tag)
    release = api('repos/'+repo+'/releases/tags/'+tag)
    require(release.get('immutable') is True and not release['draft'] and not release['prerelease'], 'Component is not a qualified stable release.')
    name = 'release.json' if repo.endswith('/discovery-bridge') else 'component-release.json'
    with tempfile.TemporaryDirectory(prefix='lanrith-component.') as temporary:
        root = Path(temporary)
        run('gh', 'release', 'download', tag, '--repo', repo, '--dir', str(root),
            '--pattern', name, '--pattern', name+'.intoto.jsonl',
            '--pattern', 'update-record.json', '--pattern', 'update-record.json.intoto.jsonl', capture_output=True)
        raw = (root/name).read_bytes()
        manifest = document(raw)
        revision = sha(manifest['source_commit'])
        require(manifest['version'] == tag[1:], 'Component release version differs from its manifest.')
        run('gh', 'attestation', 'verify', str(root/name), '--bundle', str(root/(name+'.intoto.jsonl')),
            '--repo', repo, '--signer-workflow', repo+'/.github/workflows/build-release.yml',
            '--source-digest', revision, '--signer-digest', revision, '--source-ref', 'refs/heads/main',
            '--deny-self-hosted-runners', capture_output=True)
        audit = (root/'update-record.json').read_bytes()
        history = document(audit)
        require(history['repository'] == repo and history['source_commit'] == revision and
                history['version'].removeprefix('v') == tag[1:] and history['pull_requests'] and
                all(p['approvals'] and p['validation'] for p in history['pull_requests']),
                'Component lacks its qualified change and approval history.')
        run('gh', 'attestation', 'verify', str(root/'update-record.json'),
            '--bundle', str(root/'update-record.json.intoto.jsonl'), '--repo', repo,
            '--signer-workflow', repo+'/.github/workflows/build-release.yml',
            '--source-digest', revision, '--signer-digest', revision, '--source-ref', 'refs/heads/main',
            '--deny-self-hosted-runners', capture_output=True)
        files = {name: digest(raw), 'update-record.json': digest(audit)}
        if repo.endswith('/discovery-bridge'):
            files.update({n: h for n, h in manifest['platforms']['amd64']['artifacts'].items() if n.endswith('_amd64.deb')})
        else:
            files.update({n: r['sha256'] for n, r in manifest['files'].items() if n.endswith('_amd64.deb') or n == 'security.txt'})
        require(any(n.endswith('_amd64.deb') for n in files), 'Component contains no native package.')
        return {'repository': repo, 'tag': tag, 'source_commit': revision, 'workflow_commit': revision, 'files': files}


def component_reason(component, old, selected):
    return {'id': selected['repository']+'@'+selected['tag'], 'type': 'qualified-component-update',
            'package': component, 'ecosystem': 'Lanrith', 'installed': old['tag'], 'fixed': selected['tag'],
            'source': 'https://github.com/'+selected['repository']+'/releases/tag/'+selected['tag'],
            'evidence_sha256': digest(canonical(selected))}


def npm_updates(pin, patch, policy):
    before = inputs.ui_manifests(pin, patch)
    old_package, lock = map(document, before)
    identities = sorted({(p.rsplit('node_modules/', 1)[-1], r['version'])
                         for p, r in lock['packages'].items() if p and 'version' in r})
    queries = [{'package': {'ecosystem': 'npm', 'name': n}, 'version': v} for n, v in identities]
    results = osv_queries(queries)
    fixes, reasons = {}, []
    for (name, installed), result in zip(identities, results):
        for vulnerability in result.get('vulns', []):
            advisory = fetch_json('https://api.osv.dev/v1/vulns/'+vulnerability['id'])
            choices = []
            for affected in advisory['affected']:
                if affected.get('package', {}).get('name') != name:
                    continue
                for interval in affected.get('ranges', []):
                    for event in interval.get('events', []):
                        value = event.get('fixed')
                        if value and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value) and version(value)[:2] == version(installed)[:2] and version(value) > version(installed):
                            choices.append(value)
            require(choices and name in policy['npm_packages'],
                    'UI advisory needs a reviewed compatibility/source change: '+name+' '+vulnerability['id'])
            fixed = min(choices, key=version)
            fixes[name] = max((fixed, fixes.get(name, fixed)), key=version)
            reasons.append(inputs.reason(vulnerability['id'], 'npm', name, installed, fixed))
    if not fixes:
        return patch, []
    # Vitest's packages share a patch line; resolve its direct parent to the fixed mocker line.
    direct = {n: v for n, v in fixes.items() if n in old_package.get('devDependencies', {}) or n in old_package.get('dependencies', {})}
    for name, fixed in fixes.items():
        if name.startswith('@vitest/'):
            direct['vitest'] = max((fixed, direct.get('vitest', fixed)), key=version)
    require(direct, 'Transitive UI fix has no reviewed parent update.')
    with tempfile.TemporaryDirectory(prefix='lanrith-ui-proposal.') as temporary:
        root = Path(temporary)
        ui = root/'internal/web/ui'
        ui.mkdir(parents=True)
        for name in ('package.json', 'package-lock.json'):
            (ui/name).write_bytes(contents('grafana/alloy', 'internal/web/ui/'+name, pin['commit']))
        run('git', 'init', '-q', str(root), capture_output=True)
        run('git', 'add', 'internal', cwd=root, capture_output=True)
        patch_path = root/'existing.patch'
        patch_path.write_bytes(patch)
        run('git', 'apply', str(patch_path), cwd=root, capture_output=True)
        run('npm', 'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', '--save-exact',
            *(name+'@'+value for name, value in sorted(direct.items())), cwd=ui,
            env={**os.environ, 'npm_config_cache': str(root/'npm-cache')}, capture_output=True, timeout=300)
        # npm may opportunistically refresh unrelated caret dependencies. Preserve their
        # reviewed versions and let npm verify that they still satisfy the fixed parents.
        lock_path = ui/'package-lock.json'
        resolved = document(lock_path.read_bytes())
        for name, record in lock['packages'].items():
            package_name = name.rsplit('node_modules/', 1)[-1]
            if name and package_name not in policy['npm_packages'] and name in resolved['packages']:
                resolved['packages'][name] = record
        lock_path.write_text(json.dumps(resolved, indent=2)+'\n')
        run('npm', 'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', cwd=ui,
            env={**os.environ, 'npm_config_cache': str(root/'npm-cache')}, capture_output=True, timeout=300)
        after = tuple((ui/name).read_bytes() for name in ('package.json', 'package-lock.json'))
        # Resolve all findings against the actual final graph, not intermediate requested versions.
        new_lock = document(after[1])['packages']
        reasons = [inputs.reason(r['id'], 'npm', r['package'], r['installed'],
                    next(v['version'] for p, v in new_lock.items() if p.rsplit('node_modules/', 1)[-1] == r['package']))
                   for r in reasons]
        inputs.validate_npm_manifests(before, after, reasons, policy)
        result = run('git', 'diff', '--no-ext-diff', '--', 'internal/web/ui/package.json',
                     'internal/web/ui/package-lock.json', cwd=root, capture_output=True).stdout
        return result, reasons


def debian_reasons(owner, tools):
    releases = pages('repos/Lanrith/lanrith/releases?per_page=100')
    releases = [r for r in releases if not r['draft'] and not r['prerelease'] and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', r['tag_name'])]
    if not releases:
        return []
    release = max(releases, key=lambda r: version(r['tag_name']))
    with tempfile.TemporaryDirectory(prefix='lanrith-debian-proposal.') as temporary:
        root = Path(temporary)
        run('gh', 'release', 'download', release['tag_name'], '--repo', 'Lanrith/lanrith', '--dir', str(root),
            '--pattern', 'selection.json', '--pattern', 'selection.json.intoto.jsonl', '--pattern', 'package-sources.json',
            capture_output=True)
        selection = document((root/'selection.json').read_bytes())
        run('gh', 'attestation', 'verify', str(root/'selection.json'), '--bundle', str(root/'selection.json.intoto.jsonl'),
            '--repo', 'Lanrith/lanrith', '--signer-workflow', 'Lanrith/lanrith/.github/workflows/build-base.yml',
            '--source-digest', sha(selection['source_commit']), '--signer-digest', sha(selection['signer_commit']),
            '--source-ref', 'refs/heads/main', '--deny-self-hosted-runners', capture_output=True)
        sources = (root/'package-sources.json').read_bytes()
        require(digest(sources) == selection['files']['package-sources.json'], 'Installed source inventory differs from its provenance.')
        raw = fetch('https://security-tracker.debian.org/tracker/data/json', maximum=128*1024*1024)
        tracker = json.loads(raw)
        spec = importlib.util.spec_from_file_location('debian_gate', tools/'security/audit-debian-vulnerabilities.py')
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        findings = gate.evaluate(document(sources)['packages'], tracker, 'trixie')[0]
        result = []
        for identity, package, installed, fixed, urgency in findings:
            require(urgency == 'available-fix', 'Debian advisory has no available fixed version: '+identity)
            record = tracker[package][identity]
            result.append({'id': identity, 'type': 'debian-security-fix', 'package': package,
                'ecosystem': 'Debian', 'installed': installed, 'fixed': fixed,
                'source': 'https://security-tracker.debian.org/tracker/data/json',
                'evidence_sha256': digest(canonical(record))})
        return result


def refresh_snapshot(root):
    stamp = datetime.datetime.now(datetime.timezone.utc).replace(minute=0, second=0, microsecond=0).strftime('%Y%m%dT%H%M%SZ')
    selection = document((root/'build-inputs.json').read_bytes())
    path = root/'builders/build-inputs.lock'
    text = path.read_text()
    require(all(stamp >= selection[key] for key in ('debian_snapshot', 'security_snapshot')), 'Snapshot would regress.')
    metadata_rows = []
    for prefix, archive, suite in (('DEBIAN', 'debian', 'trixie'), ('DEBIAN_SECURITY', 'debian-security', 'trixie-security'),
                                   ('DEBIAN_BOOKWORM', 'debian', 'bookworm'), ('DEBIAN_BOOKWORM_SECURITY', 'debian-security', 'bookworm-security')):
        metadata = fetch(f'https://snapshot.debian.org/archive/{archive}/{stamp}/dists/{suite}/Release', maximum=2*1024*1024)
        require(b'\nSHA256:\n' in metadata, 'Debian snapshot has no archive digest coverage.')
        metadata_rows.append((prefix, archive, metadata))
    previous = inputs.lock_values(text.encode())
    if all(previous[prefix+'_RELEASE_SHA256'] == digest(metadata) for prefix, archive, metadata in metadata_rows):
        return
    for prefix, archive, metadata in metadata_rows:
        for key, value in ((prefix+'_SNAPSHOT', stamp), (prefix+'_RELEASE_SHA256', digest(metadata))):
            text, count = re.subn(r'^'+key+r'=.+$', key+'='+value, text, flags=re.MULTILINE)
            require(count == 1, 'Expected one builder lock entry: '+key)
        if 'BOOKWORM' not in prefix:
            selection['security_release_sha256' if archive.endswith('security') else 'debian_release_sha256'] = digest(metadata)
    selection['debian_snapshot'] = selection['security_snapshot'] = stamp
    path.write_text(text)
    (root/'build-inputs.json').write_bytes(canonical(selection))


def propose(root, tools, repo, producer):
    repository(repo)
    policy_raw = (root/'security/update-policy.json').read_bytes()
    policy = document(policy_raw)
    require(policy['repository'] == repo and policy['paid_ai'] is False, 'Proposal policy is for another repository.')
    base = run('git', 'rev-parse', 'HEAD', cwd=root, capture_output=True, text=True).stdout.strip()
    require(not run('git', 'status', '--porcelain', cwd=root, capture_output=True).stdout, 'Proposals need a clean checkout.')
    before = {name: (root/name).read_bytes() for name in run('git', 'ls-files', '-z', cwd=root, capture_output=True, text=True).stdout.split('\0') if name}
    reasons = []
    if (root/'go.mod').exists():
        from .go_dependencies import update
        reasons.extend(update(root))
    for name in ('.go-version',):
        current = (root/name).read_text().strip()
        selected, found = inputs.go_security_update(current, policy['go_branches'])
        reasons.extend(found)
        if selected != current:
            (root/name).write_text(selected+'\n')
    toolchains = root/'.github/toolchains.json'
    if toolchains.exists():
        value = document(toolchains.read_bytes())
        for role, current in value['go'].items():
            selected, found = inputs.go_security_update(current, policy['go_branches'])
            reasons.extend(found)
            value['go'][role] = selected
        if 'integration_image' in value:
            value['integration_image'] = inputs.image('golang', value['go']['previous']+'-bookworm')
        toolchains.write_bytes(canonical(value))
    if repo == 'Lanrith/lanrith':
        for name in ('builders/alloy/source.json', 'builders/node-exporter/source.json'):
            path = root/name
            pin = document(path.read_bytes())
            current = pin['go_version'].removeprefix('go')
            selected, found = inputs.go_security_update(current, policy['go_branches'])
            reasons.extend(found)
            if selected != current:
                pin['go_version'] = ('go' if name.endswith('node-exporter/source.json') else '')+selected
                pin['builder' if 'node-exporter' in name else 'go_image'] = inputs.image('golang', selected+'-bookworm')
            path.write_bytes(canonical(pin))
        alloy = root/'builders/alloy/source.json'
        pin = document(alloy.read_bytes())
        selected, found = inputs.node_security_update(pin['node_version'], policy['node_branches'])
        reasons.extend(found)
        if selected != pin['node_version']:
            pin['node_version'] = selected
            pin['node_image'] = inputs.image('node', selected+'-bookworm')
            alloy.write_bytes(canonical(pin))
        patch = root/'builders/alloy/ui-dependencies.patch'
        updated, found = npm_updates(pin, patch.read_bytes(), policy)
        if updated != patch.read_bytes():
            prefix, separator, number = pin['package_version'].rpartition('+lanrith')
            require(separator and number.isdigit(), 'Alloy package has no reviewed local revision.')
            pin['package_version'] = prefix+'+lanrith'+str(int(number)+1)
            patch.write_bytes(updated)
            alloy.write_bytes(canonical(pin))
        reasons.extend(found)
        found = debian_reasons(root, tools)
        if found:
            refresh_snapshot(root)
            unbound_fixes = {r['fixed'] for r in found if r['package'] == 'unbound'}
            if unbound_fixes:
                from .native_sources import unbound
                require(len(unbound_fixes) == 1, 'Unbound advisories disagree on the required source version.')
                path = root/'builders/unbound-source.lock'
                path.write_bytes(unbound(path.read_bytes(), unbound_fixes.pop()))
            reasons.extend(found)
        selection = document((root/'build-inputs.json').read_bytes())
        for component, old in selection['component_releases'].items():
            values = pages('repos/'+old['repository']+'/releases?per_page=100')
            tags = [r['tag_name'] for r in values if not r['draft'] and not r['prerelease'] and
                    re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', r['tag_name']) and
                    version(r['tag_name'])[:2] == version(old['tag'])[:2]]
            if tags and version(max(tags, key=version)) > version(old['tag']):
                selected = component_selection(old['repository'], max(tags, key=version))
                selection['component_releases'][component] = selected
                reasons.append(component_reason(component, old, selected))
        selection['custom_package_inputs'] = {path.relative_to(root).as_posix(): digest(path.read_bytes())
            for path in sorted((root/'builders').rglob('*')) if path.is_file() and '__pycache__' not in path.parts}
        (root/'build-inputs.json').write_bytes(canonical(selection))
        security_path = root/'security/policy.json'
        security = document(security_path.read_bytes())
        versions = {'alloy': pin['package_version']}
        unbound_version = inputs.lock_values((root/'builders/unbound-source.lock').read_bytes())['UNBOUND_VERSION']
        versions.update({n: unbound_version for n in ('unbound', 'libunbound8', 'unbound-anchor')})
        for component, selected in selection['component_releases'].items():
            for name in (['discovery-bridge'] if component == 'discovery-bridge' else ['router-policy-reader', 'router-policy-helper', 'router-policy-collector']):
                versions[name] = selected['tag'][1:]
        for name, value in versions.items():
            security['required_exact_packages'][name] = value
            security['local_package_sources'][name]['version'] = value
        security_path.write_bytes(canonical(security))
    if (root/'go.mod').exists():
        # A new advisory without an eligible fix still needs an actionable failure.
        # The scanner loads source; it does not execute dependency installation hooks.
        from .go_dependencies import environment
        result = subprocess.run(['govulncheck', './...'], cwd=root, env=environment(),
                                capture_output=True, timeout=600)
        print(result.stdout.decode(errors='replace'))
        require(result.returncode == 0, 'Reachable Go vulnerability or incomplete source scan: '+
                (result.stdout+result.stderr).decode(errors='replace')[-2000:])
    after = {name: (root/name).read_bytes() for name in before}
    changed = {name for name in before if before[name] != after[name]}
    if not changed:
        print('No new security input change is required.')
        return None
    # Canonical formatting by itself is not an update reason.
    require(reasons, 'Input bytes changed without a security or qualified-component reason.')
    reasons = sorted({canonical(r): r for r in reasons}.values(),
                     key=lambda r: (r['type'], r['package'], r['installed'], r['fixed'], r['id']))
    inputs.validate_changes({n: before[n] for n in changed}, {n: after[n] for n in changed},
                            reasons, policy, before.__getitem__, after.__getitem__)
    record = evidence.candidate(repo, base, policy_raw, {n: before[n] for n in changed},
                                {n: after[n] for n in changed}, reasons, producer,
                                requires_human='builders/unbound-source.lock' in changed)
    evidence.write(root/evidence.CANDIDATE, record)
    print('Prepared '+record['candidate_id']+' for '+record['remediation_id'])
    return record
