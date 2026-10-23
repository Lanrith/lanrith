"""Resolve patch-only fixes in an existing public Go module graph."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from .common import canonical, document, fetch_json, osv_queries, require, run, version
from .inputs import has_reason, reason, stable_patch


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


def validate(before, after, reasons):
    old, new = module(before[0]), module(after[0])
    require(set(old) == set(new) and all(old[k] == new[k] for k in old if k != 'Require'),
            'Go update changed language, toolchain, replacements, tools or module metadata.')
    a, b = ({r['Path']: r for r in value['Require']} for value in (old, new))
    require(set(a) == set(b), 'Adding or removing Go modules requires human review.')
    old_sums, new_sums = sums(before[1]), sums(after[1])
    expected = dict(old_sums)
    changed = set()
    for name in a:
        require(a[name].get('Indirect', False) == b[name].get('Indirect', False), 'Go dependency role changed.')
        if a[name]['Version'] == b[name]['Version']:
            continue
        current, fixed = a[name]['Version'], b[name]['Version']
        stable_patch(current, fixed, ['.'.join(map(str, version(current)[:2]))])
        has_reason(reasons, 'Go', name, current, fixed)
        value = document(run('go', 'mod', 'download', '-json', name+'@'+fixed, capture_output=True,
                             env=environment(), timeout=300).stdout)
        require(value.get('Path') == name and value.get('Version') == fixed and
                value.get('Sum') and value.get('GoModSum'), 'Go sum database verification is incomplete.')
        for key in list(expected):
            if key[0] == name and key not in new_sums:
                del expected[key]
        expected[(name, fixed)], expected[(name, fixed+'/go.mod')] = value['Sum'], value['GoModSum']
        changed.add(name)
    require(changed and expected == new_sums, 'Go checksums include unrelated or unverified changes.')


def update(root):
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
                       version(event['fixed'])[:2] == version(installed)[:2] and version(event['fixed']) > version(installed)]
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
    records = [reason(identity, 'Go', name, v['installed'], v['fixed'])
               for name, v in sorted(fixes.items()) for identity in sorted(v['ids'])]
    validate(old, ((root/'go.mod').read_bytes(), (root/'go.sum').read_bytes()), records)
    return records
