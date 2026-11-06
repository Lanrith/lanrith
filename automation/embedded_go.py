"""Resolve advisory-bound updates for the reviewed embedded Go dependency pins."""
import re

from lanrith.go_pins import validate as pins
from . import go_dependencies
from .common import fetch_json, osv_queries, require, version
from .inputs import reason


def manifests(value):
    pins(value)
    module = 'module example.invalid/lanrith/embedded\n\ngo 1.27.3\n\nrequire (\n'
    module += ''.join('\t'+name+' '+item['version']+'\n' for name, item in sorted(value.items()))+')\n'
    sums = ''.join(name+' '+item['version']+suffix+' '+item[key]+'\n'
                   for name, item in sorted(value.items()) for suffix, key in [('', 'sum'), ('/go.mod', 'go_mod_sum')])
    return module.encode(), sums.encode()


def validate(before, after, reasons, *, allow_minor=False):
    pins(before);pins(after)
    require(before != after, 'Embedded dependency update has no changes.')
    go_dependencies.validate(manifests(before), manifests(after), reasons, allow_minor=allow_minor)


def update(before, *, allow_minor=False):
    pins(before)
    identities = sorted(before)
    results = osv_queries([{'package': {'ecosystem': 'Go', 'name': name}, 'version': before[name]['version']}
                           for name in identities])
    require(len(results) == len(identities), 'Embedded advisory query coverage is incomplete.')
    after = {name: dict(item) for name, item in before.items()}
    reasons = []
    for name, result in zip(identities, results):
        installed = before[name]['version'];fixes = []
        for entry in result.get('vulns', []):
            advisory = fetch_json('https://api.osv.dev/v1/vulns/'+entry['id'])
            require(advisory.get('id') == entry['id'] and not advisory.get('withdrawn'), 'Embedded advisory is missing or withdrawn.')
            choices = [event['fixed'] for affected in advisory['affected']
                       if affected.get('package', {}).get('name') == name
                       for interval in affected.get('ranges', []) for event in interval.get('events', [])
                       if 'fixed' in event and re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+', event['fixed']) and
                       version(event['fixed'])[0] == version(installed)[0] and
                       (allow_minor or version(event['fixed'])[:2] == version(installed)[:2]) and
                       version(event['fixed']) > version(installed)]
            require(choices, 'Embedded vulnerability requires a human-reviewed migration: '+name+' '+entry['id'])
            fixes.append(('v'+min(choices, key=version).removeprefix('v'), entry['id']))
        if not fixes:
            continue
        selected = max((v for v, _ in fixes), key=version)
        resolved = go_dependencies.verified_download(name, selected)
        after[name] = {'version': selected, 'sum': resolved['Sum'], 'go_mod_sum': resolved['GoModSum']}
        reasons.extend(reason(identity, 'Go', name, installed, selected) for _, identity in fixes)
    if reasons:
        validate(before, after, reasons, allow_minor=allow_minor)
    return after, reasons
