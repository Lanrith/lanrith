"""Authenticated version metadata and narrow dependency input validation."""

import base64
import datetime
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse
import urllib.request

from .common import (canonical, digest, document, fetch, fetch_json, osv_queries,
                     require, run, version)


def changed_fields(before, after):
    require(isinstance(before, dict) and isinstance(after, dict) and set(before) == set(after),
            'Automatic updates cannot change the input schema.')
    return {key for key in before if before[key] != after[key]}


def stable_patch(before, after, branches):
    old, new = version(before), version(after)
    require(old[:2] == new[:2] and old < new and '.'.join(map(str, old[:2])) in branches,
            'Version change leaves its reviewed stable patch line.')


def image(name, tag):
    require(name in ('golang', 'node') and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-bookworm', tag),
            'Image is outside reviewed official toolchains.')
    token = fetch_json('https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/'+name+':pull')['token']
    request = urllib.request.Request('https://registry-1.docker.io/v2/library/'+name+'/manifests/'+tag,
        headers={'Authorization': 'Bearer '+token,
                 'Accept': 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'})
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read(2*1024*1024+1)
    require(len(raw) <= 2*1024*1024, 'Image index is too large.')
    value = document(raw)
    matches = [entry for entry in value['manifests'] if entry.get('platform', {}).get('os') == 'linux' and
               entry['platform'].get('architecture') == 'amd64' and not entry['platform'].get('variant')]
    require(len(matches) == 1 and re.fullmatch(r'sha256:[0-9a-f]{64}', matches[0]['digest']),
            'Official image has no unique native digest.')
    return 'docker.io/library/'+name+'@'+matches[0]['digest']


def reason(identity, ecosystem, package, installed, fixed):
    raw = fetch('https://api.osv.dev/v1/vulns/'+identity)
    advisory = document(raw)
    require(advisory.get('id') == identity and not advisory.get('withdrawn'), 'Advisory is missing or withdrawn.')
    queries = [{'package': {'ecosystem': ecosystem, 'name': package}, 'version': v}
               for v in (installed, fixed)]
    old, new = osv_queries(queries)
    require(identity in {v['id'] for v in old.get('vulns', [])} and
            identity not in {v['id'] for v in new.get('vulns', [])},
            'The recorded version change does not resolve this advisory.')
    return {'id': identity, 'type': 'security-fix', 'ecosystem': ecosystem, 'package': package,
            'installed': installed, 'fixed': fixed, 'source': 'https://api.osv.dev/v1/vulns/'+identity,
            'evidence_sha256': digest(canonical(advisory))}


def go_security_update(current, branches):
    version(current)
    releases = fetch_json('https://go.dev/dl/?mode=json')
    candidates = [r['version'].removeprefix('go') for r in releases if r.get('stable') and
                  version(r['version'].removeprefix('go'))[:2] == version(current)[:2]]
    require(candidates, 'Go branch is no longer supported; human migration is required.')
    results = osv_queries([{'package': {'ecosystem': 'Go', 'name': 'stdlib'}, 'version': current}])[0]
    if not results.get('vulns'):
        return current, []
    selected = max(candidates, key=version)
    stable_patch(current, selected, branches)
    reasons = [reason(v['id'], 'Go', 'stdlib', current, selected) for v in results['vulns']]
    return selected, reasons


def node_security_update(current, branches):
    old = version(current)
    require(str(old[0]) in branches, 'Node branch is not reviewed.')
    releases = fetch_json('https://nodejs.org/dist/index.json')
    choices = [r for r in releases if r.get('security') is True and r.get('lts') and
               version(r['version'])[:2] == old[:2] and version(r['version']) > old]
    if not choices:
        require(not any(r.get('security') is True and r.get('lts') and version(r['version'])[0] == old[0] and
                        version(r['version']) > old for r in releases),
                'Node security release requires a reviewed minor-version migration.')
        return current, []
    selected = max(choices, key=lambda r: version(r['version']))
    fixed = selected['version'][1:]
    return fixed, [{'id': 'node-'+selected['version'], 'type': 'node-security-release', 'package': 'node',
        'ecosystem': 'Node.js', 'installed': current, 'fixed': fixed,
        'source': 'https://nodejs.org/dist/index.json', 'evidence_sha256': digest(canonical(selected))}]


def validate_reason(record):
    require(record['type'] == 'security-fix' and
            record['source'] == 'https://api.osv.dev/v1/vulns/'+record['id'] and
            re.fullmatch(r'(?:GO-[0-9]{4}-[0-9]+|GHSA-[a-z0-9-]+|CVE-[0-9]{4}-[0-9]+)', record['id']),
            'Unapproved advisory identity or source.')
    # Modified upstream advisories need a fresh candidate, not a silently changed review.
    fresh = reason(record['id'], record['ecosystem'], record['package'], record['installed'], record['fixed'])
    require(fresh == record, 'Advisory evidence changed since this candidate was proposed.')


def has_reason(reasons, ecosystem, package, before, after):
    require(any(r['type'] == 'security-fix' and r['ecosystem'] == ecosystem and r['package'] == package and
                r['installed'] == before and r['fixed'] == after for r in reasons),
            'A version change has no matching security-fix reason.')


def validate_go(before, after, reasons, policy):
    old, new = before.removeprefix('go'), after.removeprefix('go')
    stable_patch(old, new, policy['go_branches'])
    has_reason(reasons, 'Go', 'stdlib', old, new)


def lock_values(raw):
    result = {}
    for line in raw.decode().splitlines():
        if line and not line.startswith('#'):
            key, separator, value = line.partition('=')
            require(separator and key not in result, 'Malformed builder lock input.')
            result[key] = value
    return result


HUMAN_NATIVE_REVIEW = 'Native source upgrade requires independent human review.'
HUMAN_NPM_REVIEW = 'UI dependency change outside the approved patch set requires independent human review.'
HUMAN_REVIEW_FINDINGS = frozenset((HUMAN_NATIVE_REVIEW, HUMAN_NPM_REVIEW))


def npm_requires_human(name, before, after, policy):
    old, new = version(before), version(after)
    require(old[0] == new[0] and old < new,
            'UI security fix must advance an existing stable major version.')
    return name not in policy['npm_packages'] or old[:2] != new[:2]


def validate_npm_manifests(before, after, reasons, policy):
    old_package, old_lock = (document(v) for v in before)
    new_package, new_lock = (document(v) for v in after)
    manual = False
    fields = changed_fields(old_package, new_package)
    require(fields <= {'dependencies', 'devDependencies'}, 'UI manifest changed commands, overrides or metadata.')
    for group in ('dependencies', 'devDependencies'):
        old, new = old_package.get(group, {}), new_package.get(group, {})
        for name in changed_fields(old, new):
            if npm_requires_human(name, old[name], new[name], policy):
                has_reason(reasons, 'npm', name, old[name], new[name])
                manual = True
    require(changed_fields(old_lock, new_lock) <= {'packages'} and new_lock.get('lockfileVersion') == 3,
            'UI lockfile changed its format or unrelated metadata.')
    old, new = old_lock['packages'], new_lock['packages']
    require(set(old) == set(new), 'Adding or removing dependencies requires human review.')
    changed = []
    for path in sorted(old):
        if old[path] == new[path]:
            continue
        if path == '':
            require(changed_fields(old[path], new[path]) <= {'dependencies', 'devDependencies'},
                    'UI root lock metadata changed.')
            for group in ('dependencies', 'devDependencies'):
                require(new[path].get(group) == new_package.get(group), 'UI manifest and lock disagree.')
            continue
        fields = changed_fields(old[path], new[path])
        require(fields <= {'version', 'resolved', 'integrity', 'dependencies', 'peerDependencies'},
                'UI dependency changed installation hooks, executables or unrelated metadata.')
        name = path.rsplit('node_modules/', 1)[-1]
        if npm_requires_human(name, old[path]['version'], new[path]['version'], policy):
            has_reason(reasons, 'npm', name, old[path]['version'], new[path]['version'])
            manual = True
        metadata = fetch_json('https://registry.npmjs.org/'+urllib.parse.quote(name, safe='')+'/'+new[path]['version'])
        dist = metadata['dist']
        require(new[path]['resolved'] == dist['tarball'] and new[path]['integrity'] == dist['integrity'] and
                urllib.parse.urlsplit(dist['tarball']).hostname == 'registry.npmjs.org' and
                new[path]['integrity'].startswith('sha512-'), 'UI dependency does not match its registry integrity.')
        changed.append(name)
    require(changed and any(r['ecosystem'] == 'npm' and r['package'] in changed for r in reasons),
            'UI patch has no matching advisory fix.')
    for r in reasons:
        if r['ecosystem'] == 'npm':
            matching = [(p, v) for p, v in old.items() if p.rsplit('node_modules/', 1)[-1] == r['package'] and
                        v.get('version') == r['installed']]
            require(matching and all(new[p]['version'] == r['fixed'] for p, _ in matching),
                    'UI patch did not apply the recorded fix to all affected instances.')
    return manual


def ui_manifests(pin, patch):
    require(len(patch) <= 1024*1024, 'UI patch is too large.')
    paths = re.findall(rb'^\+\+\+ b/(.+)$', patch, re.MULTILINE)
    require(paths and len(paths) == len(set(paths)) and set(paths) <= {
        b'internal/web/ui/package.json', b'internal/web/ui/package-lock.json'}, 'UI patch touches executable source.')
    allowed = {b'internal/web/ui/package.json', b'internal/web/ui/package-lock.json'}
    headers = re.findall(rb'^diff --git a/(.+) b/(.+)$', patch, re.MULTILINE)
    require(all(a == b and a in allowed for a, b in headers) and not re.search(
        rb'^(?:GIT binary patch|new file mode|deleted file mode|old mode|new mode|rename |copy )', patch, re.MULTILINE),
        'UI patch changes file type, identity or binary source.')
    from .common import contents
    with tempfile.TemporaryDirectory(prefix='lanrith-ui-review.') as temporary:
        root = Path(temporary)
        for filename in ('package.json', 'package-lock.json'):
            path = root/'internal/web/ui'/filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents('grafana/alloy', 'internal/web/ui/'+filename, pin['commit']))
        run('git', 'init', '-q', str(root), capture_output=True)
        patch_file = root/'dependency.patch'
        patch_file.write_bytes(patch)
        run('git', 'apply', '--check', str(patch_file), cwd=root, capture_output=True)
        run('git', 'apply', str(patch_file), cwd=root, capture_output=True)
        require(all(p.is_file() and not p.is_symlink() and p.stat().st_size <= 4*1024*1024
                    for p in (root/'internal/web/ui/package.json', root/'internal/web/ui/package-lock.json')),
                'UI manifests must remain bounded regular files.')
        return tuple((root/'internal/web/ui'/filename).read_bytes()
                     for filename in ('package.json', 'package-lock.json'))


def validate_changes(before, after, reasons, policy, read_before, read_after):
    manual_findings = []
    require(set(before) == set(after) and len(before) <= policy['maximum_changes'], 'Unexpected update file coverage.')
    if {'go.mod', 'go.sum'} & set(before):
        from .go_dependencies import validate
        validate((read_before('go.mod'), read_before('go.sum')),
                 (read_after('go.mod'), read_after('go.sum')), reasons)
    for path in sorted(before):
        old_raw, new_raw = before[path], after[path]
        if path in ('go.mod', 'go.sum'):
            continue
        elif path == '.go-version':
            validate_go(old_raw.decode().strip(), new_raw.decode().strip(), reasons, policy)
        elif path == '.github/toolchains.json':
            old, new = document(old_raw), document(new_raw)
            require(changed_fields(old, new) <= {'go', 'integration_image'}, 'Toolchain schema changed.')
            for role in changed_fields(old['go'], new['go']):
                validate_go(old['go'][role], new['go'][role], reasons, policy)
            if old.get('integration_image') != new.get('integration_image'):
                require(new['integration_image'] == image('golang', new['go']['previous']+'-bookworm'),
                        'Integration image does not match the selected compiler.')
        elif path in ('builders/alloy/source.json', 'builders/node-exporter/source.json'):
            old, new = document(old_raw), document(new_raw)
            allowed = {'go_version', 'go_image', 'node_version', 'node_image', 'package_version'} if 'alloy' in path else {'go_version', 'builder'}
            fields = changed_fields(old, new)
            require(fields <= allowed, 'Component update changed reviewed source or build recipes.')
            if 'go_version' in fields:
                validate_go(old['go_version'], new['go_version'], reasons, policy)
                key = 'go_image' if 'alloy' in path else 'builder'
                require(new[key] == image('golang', new['go_version'].removeprefix('go')+'-bookworm'),
                        'Go image differs from the authenticated selected version.')
            require(not fields & {'go_image', 'builder'} or 'go_version' in fields,
                    'Image changed without a compiler security update.')
            if fields & {'node_version', 'node_image'}:
                stable_patch(old['node_version'], new['node_version'],
                             ['.'.join(map(str, version(old['node_version'])[:2]))])
                require(str(version(new['node_version'])[0]) in policy['node_branches'] and
                        any(r['type'] == 'node-security-release' and r['installed'] == old['node_version'] and
                            r['fixed'] == new['node_version'] for r in reasons), 'Node patch has no matching security release.')
                require(new['node_image'] == image('node', new['node_version']+'-bookworm'), 'Node image does not match its security release.')
            if 'package_version' in fields:
                prefix, separator, number = old['package_version'].rpartition('+lanrith')
                require(separator and new['package_version'] == prefix+'+lanrith'+str(int(number)+1) and
                        'builders/alloy/ui-dependencies.patch' in after, 'Unexpected local package revision.')
        elif path == 'builders/alloy/ui-dependencies.patch':
            pin = document(read_before('builders/alloy/source.json'))
            if validate_npm_manifests(ui_manifests(pin, old_raw), ui_manifests(pin, new_raw), reasons, policy):
                manual_findings.append(HUMAN_NPM_REVIEW)
        elif path == 'builders/unbound-source.lock':
            from .native_sources import validate_unbound
            validate_unbound(old_raw, new_raw, reasons)
            manual_findings.append(HUMAN_NATIVE_REVIEW)
        elif path == 'build-inputs.json':
            old, new = document(old_raw), document(new_raw)
            require(changed_fields(old, new) <= {'custom_package_inputs', 'debian_snapshot', 'security_snapshot',
                'debian_release_sha256', 'security_release_sha256', 'component_releases'}, 'Platform selection changed unrelated inputs.')
            for name, expected in new['custom_package_inputs'].items():
                require(name.startswith('builders/') and digest(read_after(name)) == expected,
                        'Custom input selection differs from the actual reviewed bytes.')
            require(set(old['custom_package_inputs']) == set(new['custom_package_inputs']), 'Custom recipe coverage changed.')
            if old['component_releases'] != new['component_releases']:
                from .proposal import component_selection
                for component in changed_fields(old['component_releases'], new['component_releases']):
                    a, b = old['component_releases'][component], new['component_releases'][component]
                    stable_patch(a['tag'], b['tag'], ['.'.join(map(str, version(a['tag'])[:2]))])
                    require(b['repository'] in policy['component_repositories'] and
                            b == component_selection(b['repository'], b['tag']), 'Component release lacks matching qualified provenance.')
            for key, archive, suite in (('debian_snapshot', 'debian', 'trixie'), ('security_snapshot', 'debian-security', 'trixie-security')):
                if new[key] != old[key]:
                    require(any(r['type'] == 'debian-security-fix' for r in reasons), 'Unrelated daily Debian snapshot churn.')
                    require(re.fullmatch('[0-9]{8}T[0-9]{6}Z', new[key]) and new[key] >= old[key] and
                            datetime.datetime.strptime(new[key], '%Y%m%dT%H%M%SZ').replace(tzinfo=datetime.timezone.utc) <=
                            datetime.datetime.now(datetime.timezone.utc), 'Debian snapshot moved backwards or into the future.')
                    metadata = fetch(f'https://snapshot.debian.org/archive/{archive}/{new[key]}/dists/{suite}/Release')
                    field = 'security_release_sha256' if archive.endswith('security') else 'debian_release_sha256'
                    require(digest(metadata) == new[field], 'Debian selection metadata does not match its snapshot.')
        elif path == 'builders/build-inputs.lock':
            old, new = lock_values(old_raw), lock_values(new_raw)
            fields = changed_fields(old, new)
            require(fields and all(re.fullmatch(r'DEBIAN_(?:BOOKWORM_)?(?:SECURITY_)?(?:SNAPSHOT|RELEASE_SHA256)', field)
                                   for field in fields), 'Builder lock changed unrelated recipes or compilers.')
            selection = document(read_after('build-inputs.json'))
            for prefix, archive, suite in (('DEBIAN', 'debian', 'trixie'), ('DEBIAN_SECURITY', 'debian-security', 'trixie-security'),
                                           ('DEBIAN_BOOKWORM', 'debian', 'bookworm'), ('DEBIAN_BOOKWORM_SECURITY', 'debian-security', 'bookworm-security')):
                if prefix+'_SNAPSHOT' in fields or prefix+'_RELEASE_SHA256' in fields:
                    require(new[prefix+'_SNAPSHOT'] == selection['debian_snapshot'], 'Builder snapshot differs from platform selection.')
                    raw = fetch(f"https://snapshot.debian.org/archive/{archive}/{new[prefix+'_SNAPSHOT']}/dists/{suite}/Release")
                    require(digest(raw) == new[prefix+'_RELEASE_SHA256'], 'Builder archive metadata digest differs.')
        elif path == 'security/policy.json':
            old, new = document(old_raw), document(new_raw)
            require(changed_fields(old, new) <= {'required_exact_packages', 'local_package_sources'}, 'Update weakens a security rule.')
            selection = document(read_after('build-inputs.json'))
            expected = {'alloy': document(read_after('builders/alloy/source.json'))['package_version']}
            unbound_version = lock_values(read_after('builders/unbound-source.lock'))['UNBOUND_VERSION']
            expected.update({n: unbound_version for n in ('unbound', 'libunbound8', 'unbound-anchor')})
            for component, pin in selection['component_releases'].items():
                for name in (['discovery-bridge'] if component == 'discovery-bridge' else
                             ['router-policy-reader', 'router-policy-helper', 'router-policy-collector']):
                    expected[name] = pin['tag'][1:]
            for name in changed_fields(old['required_exact_packages'], new['required_exact_packages']):
                require(name in expected and new['required_exact_packages'][name] == expected[name], 'Package policy version is not derived from selected inputs.')
            for name in changed_fields(old['local_package_sources'], new['local_package_sources']):
                a, b = old['local_package_sources'][name], new['local_package_sources'][name]
                require(name in expected and changed_fields(a, b) == {'version'} and b['version'] == expected[name],
                        'Local source policy changed more than its selected package version.')
        else:
            require(False, 'This path needs human review: '+path)
    return manual_findings
