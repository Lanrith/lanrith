"""Resolve advisory-bound fixes and independently verify their minimal Go graph."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from .common import canonical, digest, document, fetch, fetch_json, osv_queries, require, run, unique, version
from .inputs import reason


def environment():
    return {**os.environ, 'GOTOOLCHAIN': 'local', 'GOENV': 'off', 'GOWORK': 'off', 'GOFLAGS': '',
            'GOPROXY': 'https://proxy.golang.org', 'GOSUMDB': 'sum.golang.org',
            'GOPRIVATE': '', 'GONOSUMDB': '', 'GONOPROXY': ''}


def module(raw):
    with tempfile.TemporaryDirectory(prefix='lanrith-go-manifest.') as temporary:
        path = Path(temporary)/'go.mod'
        path.write_bytes(raw)
        return document(run('go', 'mod', 'edit', '-json', str(path), capture_output=True,
                            env=environment()).stdout)


def sums(raw):
    result = {}
    for line in raw.decode().splitlines():
        fields = line.split()
        require(len(fields) == 3 and re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', fields[2]), 'Malformed module checksum.')
        require(tuple(fields[:2]) not in result, 'Duplicate module checksum.')
        result[tuple(fields[:2])] = fields[2]
    return result


def advancement(current, fixed, allow_minor):
    old, new = version(current), version(fixed)
    require(old < new and old[0] == new[0] and (allow_minor or old[:2] == new[:2]),
            'Go security fix changes an unapproved major or minor version.')


def graph(raw, checksums, targets=None):
    """Resolve data with the pinned Go tool; never execute project or dependency code."""
    with tempfile.TemporaryDirectory(prefix='lanrith-go-graph.') as temporary:
        root = Path(temporary)
        (root/'go.mod').write_bytes(raw)
        (root/'go.sum').write_bytes(checksums)
        if targets:
            run('go', 'mod', 'edit', *('-require='+name+'@'+fixed for name, fixed in sorted(targets.items())),
                cwd=root, env=environment(), capture_output=True)
        raw_graph = run('go', 'list', '-mod=mod', '-m', '-json', 'all', cwd=root,
                        env=environment(), capture_output=True, timeout=300).stdout
    require(len(raw_graph) <= 8*1024*1024, 'Go graph exceeds the review bound.')
    decoder, text, offset, result = json.JSONDecoder(object_pairs_hook=unique), raw_graph.decode(), 0, {}
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        row, offset = decoder.raw_decode(text, offset)
        require(isinstance(row, dict) and not row.get('Error') and not row.get('Replace'),
                'Go graph contains a failed or replaced module.')
        if row.get('Main') is True:
            continue
        name, selected = row.get('Path'), row.get('Version')
        require(isinstance(name, str) and isinstance(selected, str) and name not in result and len(result) < 5000,
                'Go graph identities are missing, repeated or excessive.')
        result[name] = selected
    return result


def verified_download(name, selected):
    value = document(run('go', 'mod', 'download', '-json', name+'@'+selected, capture_output=True,
                         env=environment(), timeout=300).stdout)
    require(value.get('Path') == name and value.get('Version') == selected and value.get('Sum') and
            value.get('GoModSum') and not value.get('Error'), 'Go sum database verification is incomplete.')
    # Retain the actual public module constraints in the existing signed input-evidence bundle.
    escaped = ''.join('!'+c.lower() if c.isupper() else c for c in name)
    path = Path(value['GoMod'])
    require(path.is_file() and not path.is_symlink() and path.stat().st_size < 1024*1024 and
            fetch('https://proxy.golang.org/'+escaped+'/@v/'+selected+'.mod') == path.read_bytes(),
            'Public module constraints differ from their checksum-database-verified bytes.')
    return value


def minimum_targets(reasons, requirements, allow_minor):
    """Derive roots from authenticated fixed ranges, not candidate-selected versions."""
    targets, actual = {}, {}
    for record in reasons:
        if record['type'] != 'security-fix' or record['ecosystem'] != 'Go' or record['package'] not in requirements:
            continue
        name, selected = record['package'], record['fixed']
        installed = requirements[name]['Version']
        require(record['installed'] == installed and actual.get(name, selected) == selected and
                record['source'] == 'https://api.osv.dev/v1/vulns/'+record['id'],
                'Go advisory roots disagree with the installed version or authenticated source.')
        advancement(installed, selected, allow_minor)
        advisory = fetch_json(record['source'])
        require(advisory.get('id') == record['id'] and not advisory.get('withdrawn') and
                digest(canonical(advisory)) == record['evidence_sha256'], 'Go advisory evidence changed.')
        choices = [event['fixed'] for affected in advisory['affected']
                   if affected.get('package', {}).get('name') == name
                   for interval in affected.get('ranges', []) for event in interval.get('events', [])
                   if 'fixed' in event and re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+', event['fixed']) and
                   version(event['fixed'])[0] == version(installed)[0] and
                   (allow_minor or version(event['fixed'])[:2] == version(installed)[:2]) and
                   version(event['fixed']) > version(installed)]
        require(choices, 'Go advisory has no permitted stable fix.')
        minimum = 'v'+min(choices, key=version).removeprefix('v')
        targets[name] = max((targets.get(name, minimum), minimum), key=version)
        actual[name] = selected
    return targets, actual


def validate(before, after, reasons, *, allow_minor=False):
    old, new = module(before[0]), module(after[0])
    require(set(old) == set(new) and all(old[k] == new[k] for k in old if k != 'Require'),
            'Go update changed language, toolchain, replacements, tools or module metadata.')
    a, b = ({r['Path']: r for r in value['Require']} for value in (old, new))
    require(set(a) == set(b) and len(a) == len(old['Require']) and len(b) == len(new['Require']),
            'Adding, removing or duplicating Go modules requires human review.')
    targets, actual = minimum_targets(reasons, a, allow_minor)
    require(targets, 'Go update has no exact authenticated advisory root.')
    previous_graph, expected_graph = graph(before[0], before[1]), graph(before[0], before[1], targets)
    require(set(previous_graph) == set(expected_graph), 'Adding or removing transitive Go modules requires human review.')
    require(all(expected_graph.get(name) == selected for name, selected in actual.items()),
            'Go advisory root is not the selected minimal fixed version.')
    for name in a:
        require(a[name].get('Indirect', False) == b[name].get('Indirect', False), 'Go dependency role changed.')
        require(b[name]['Version'] == expected_graph.get(name),
                'Go requirement is not the minimal selection derived from the security fix: '+name)
    old_sums, new_sums = sums(before[1]), sums(after[1])
    expected = dict(old_sums)
    changed = {name for name in expected_graph if expected_graph[name] != previous_graph[name]}
    require(changed and set(targets) <= changed, 'Go security fix does not advance its recorded roots.')
    for name in sorted(changed):
        current, selected = previous_graph[name], expected_graph[name]
        advancement(current, selected, allow_minor)
        keys = {(name, selected), (name, selected+'/go.mod')}
        present = keys & set(new_sums)
        if name in a:
            require(present == keys, 'A changed Go requirement lacks its verified module checksums.')
        for key in list(expected):
            if key[0] == name and key not in new_sums:
                del expected[key]
        if not present:
            continue
        value = verified_download(name, selected)
        for key in present:
            expected[key] = value['GoModSum'] if key[1].endswith('/go.mod') else value['Sum']
    require(changed and expected == new_sums, 'Go checksums include unrelated or unverified changes.')


def update(root, *, allow_minor=False):
    old = ((root/'go.mod').read_bytes(), (root/'go.sum').read_bytes())
    manifest = module(old[0])
    identities = [(r['Path'], r['Version']) for r in manifest['Require']]
    results = osv_queries([{'package': {'ecosystem': 'Go', 'name': name}, 'version': v} for name, v in identities])
    fixes = {}
    for (name, installed), result in zip(identities, results):
        for item in result.get('vulns', []):
            advisory = fetch_json('https://api.osv.dev/v1/vulns/'+item['id'])
            fixed_versions = [event['fixed'] for affected in advisory['affected']
                              for interval in affected.get('ranges', []) for event in interval.get('events', [])
                              if 'fixed' in event]
            require(not fixed_versions or re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', installed),
                    'Advisory requires human review of a non-stable module version: '+name+' '+item['id'])
            choices = [event['fixed'] for affected in advisory['affected']
                       if affected.get('package', {}).get('name') == name
                       for interval in affected.get('ranges', []) for event in interval.get('events', [])
                       if 'fixed' in event and re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+', event['fixed']) and
                       version(event['fixed'])[0] == version(installed)[0] and
                       (allow_minor or version(event['fixed'])[:2] == version(installed)[:2]) and
                       version(event['fixed']) > version(installed)]
            # Inventory advisories without fixes may be unreachable. Actual source/binary scans remain required.
            if not choices:
                require(not fixed_versions, 'Security fix requires a reviewed module migration: '+name+' '+item['id'])
                print('No patch-line module fix; source scan or human review required: '+name+' '+item['id'])
                continue
            selected = 'v'+min(choices, key=version).removeprefix('v')
            value = fixes.setdefault(name, {'installed': installed, 'fixed': selected, 'ids': set()})
            value['fixed'] = max((value['fixed'], selected), key=version)
            value['ids'].add(item['id'])
    if not fixes:
        return []
    run('go', 'get', *(n+'@'+v['fixed'] for n, v in sorted(fixes.items())), cwd=root,
        env=environment(), capture_output=True, timeout=300)
    run('go', 'mod', 'tidy', cwd=root, env=environment(), capture_output=True, timeout=300)
    run('go', 'mod', 'download', 'all', cwd=root, env=environment(), capture_output=True, timeout=300)
    # Downloading unused graph nodes can add unnecessary sums; keep the proposed lockfile tidy.
    run('go', 'mod', 'tidy', cwd=root, env=environment(), capture_output=True, timeout=300)
    selected = {r['Path']: r['Version'] for r in module((root/'go.mod').read_bytes())['Require']}
    records = [reason(identity, 'Go', name, v['installed'], selected[name])
               for name, v in sorted(fixes.items()) for identity in sorted(v['ids'])]
    validate(old, ((root/'go.mod').read_bytes(), (root/'go.sum').read_bytes()), records, allow_minor=allow_minor)
    return records
