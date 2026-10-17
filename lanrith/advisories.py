"""Bound complete dependency queries to a fresh, well-formed OSV response."""

import hashlib
import json
import re
import urllib.request

from .release import require, unique


def cargo_queries(lock):
    queries = []
    for package in lock['package']:
        source = package.get('source', '')
        if source.startswith(('registry+', 'git+')):
            queries.append({'package': {'ecosystem': 'crates.io', 'name': package['name']},
                            'version': package['version']})
        if source.startswith('git+'):
            commit = source.rsplit('#', 1)[-1]
            require(re.fullmatch(r'[0-9a-f]{40}', commit), 'Cargo Git dependency has no immutable commit.')
            queries.append({'commit': commit})
        require(not source or source.startswith(('registry+', 'git+')), 'Unknown Cargo dependency source.')
    require(queries, 'Cargo advisory coverage is empty.')
    return queries


def npm_queries(modules):
    require(isinstance(modules, list) and modules, 'UI dependency coverage is empty.')
    queries = {}
    for module in modules:
        require(isinstance(module.get('name'), str) and module['name'] and
                isinstance(module.get('version'), str) and module['version'], 'Invalid UI dependency identity.')
        identity = (module['name'], module['version'])
        queries[identity] = {'package': {'ecosystem': 'npm', 'name': identity[0]}, 'version': identity[1]}
    return [queries[key] for key in sorted(queries)]


def source_coverage(feed, fixes):
    require(isinstance(feed, list) and isinstance(fixes, dict), 'Upstream source advisory coverage is malformed.')
    seen = set()
    for advisory in feed:
        identity = advisory.get('ghsa_id')
        require(isinstance(identity, str) and identity not in seen and identity in fixes,
                'An upstream source advisory lacks reviewed fix coverage.')
        seen.add(identity)
        affected = advisory.get('vulnerabilities')
        require(isinstance(affected, list) and affected and
                all(isinstance(item, dict) and isinstance(item.get('patched_versions'), str) and
                    item['patched_versions'] for item in affected), 'An upstream source advisory has unknown fix coverage.')
        require({item['patched_versions'] for item in affected} ==
                {item['fixed_tag'] for item in fixes[identity]},
                'An upstream advisory changed its required fix; source ancestry must be reviewed again.')
    return True


def assess(queries):
    require(isinstance(queries, list) and 0 < len(queries) <= 1000, 'Invalid dependency advisory query set.')
    request = urllib.request.Request('https://api.osv.dev/v1/querybatch',
        data=json.dumps({'queries': queries}).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=90) as response:
        raw = response.read(16*1024*1024+1)
    require(0 < len(raw) <= 16*1024*1024, 'Dependency advisory response exceeds its bound.')
    value = json.loads(raw, object_pairs_hook=unique)
    results = value.get('results')
    require(isinstance(results, list) and len(results) == len(queries) and
            all(isinstance(item, dict) and set(item) <= {'vulns', 'next_page_token'} and
                ('vulns' not in item or isinstance(item['vulns'], list)) and
                ('next_page_token' not in item or isinstance(item['next_page_token'], str)) and
                not item.get('next_page_token') and not item.get('vulns') for item in results),
            'Dependencies have unresolved advisories or incomplete coverage.')
    return hashlib.sha256(raw).hexdigest()
