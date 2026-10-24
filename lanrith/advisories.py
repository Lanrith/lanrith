"""Bound complete dependency queries to a fresh, well-formed OSV response."""

import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import quote
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


def _write_diagnostic(path, value):
    if path is None:
        return
    path = Path(path)
    require(path.parent.is_dir() and not path.parent.is_symlink() and not path.is_symlink(),
            'Dependency diagnostic path is unsafe.')
    data = (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)


def _advisory_details(identities):
    """Retain public affected/fixed ranges without trusting result identifiers as URLs."""
    details = []
    if len(identities) > 100:
        return [{'result': 'error', 'error': 'FindingLimit'}], False
    complete = True
    for identity in identities:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}', identity):
            details.append({'result': 'invalid', 'error': 'AdvisoryIdentity'})
            complete = False
            continue
        try:
            with urllib.request.urlopen('https://api.osv.dev/v1/vulns/'+quote(identity, safe=''),
                                        timeout=30) as response:
                raw = response.read(2*1024*1024+1)
        except OSError as error:
            details.append({'id': identity, 'result': 'error', 'error': type(error).__name__})
            complete = False
            continue
        digest = hashlib.sha256(raw).hexdigest()
        try:
            value = json.loads(raw, object_pairs_hook=unique)
        except (ValueError, UnicodeDecodeError):
            value = None
        valid = 0 < len(raw) <= 2*1024*1024 and isinstance(value, dict) and value.get('id') == identity
        aliases = value.get('aliases', []) if valid else None
        summary = value.get('summary') if valid else None
        affected = value.get('affected') if valid else None
        valid = valid and isinstance(aliases, list) and all(isinstance(item, str) for item in aliases) and \
            (summary is None or isinstance(summary, str)) and isinstance(affected, list)
        normalized = []
        if valid:
            for item in affected:
                package = item.get('package') if isinstance(item, dict) else None
                ranges = item.get('ranges', []) if isinstance(item, dict) else None
                if not isinstance(package, dict) or not isinstance(package.get('ecosystem'), str) or \
                        not isinstance(package.get('name'), str) or not isinstance(ranges, list):
                    valid = False
                    break
                selected_ranges = []
                for affected_range in ranges:
                    events = affected_range.get('events') if isinstance(affected_range, dict) else None
                    range_type = affected_range.get('type') if isinstance(affected_range, dict) else None
                    if not isinstance(range_type, str) or not isinstance(events, list) or not all(
                            isinstance(event, dict) and len(event) == 1 and
                            next(iter(event)) in ('introduced', 'fixed', 'last_affected', 'limit') and
                            isinstance(next(iter(event.values())), str) for event in events):
                        valid = False
                        break
                    selected_ranges.append({'type': range_type, 'events': events})
                if not valid:
                    break
                normalized.append({'package': {'ecosystem': package['ecosystem'], 'name': package['name']},
                                   'ranges': selected_ranges})
        if valid:
            details.append({'id': identity, 'result': 'pass', 'response_sha256': digest,
                            'summary': summary, 'aliases': aliases, 'affected': normalized})
        else:
            details.append({'id': identity, 'result': 'invalid', 'response_sha256': digest})
            complete = False
    return details, complete


def report(queries, *, diagnostic=None):
    require(isinstance(queries, list) and 0 < len(queries) <= 1000, 'Invalid dependency advisory query set.')
    query_data = json.dumps(queries, sort_keys=True, separators=(',', ':')).encode()
    base = {'schema': 1, 'service': 'OSV querybatch', 'query_count': len(queries),
            'queries_sha256': hashlib.sha256(query_data).hexdigest(), 'queries': queries}
    request = urllib.request.Request('https://api.osv.dev/v1/querybatch',
        data=json.dumps({'queries': queries}).encode(), headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            raw = response.read(16*1024*1024+1)
    except OSError as error:
        _write_diagnostic(diagnostic, {**base, 'result': 'error', 'error': type(error).__name__})
        raise
    if not 0 < len(raw) <= 16*1024*1024:
        _write_diagnostic(diagnostic, {**base, 'result': 'invalid', 'response_bytes': len(raw),
                                      'error': 'ResponseSize'})
        require(False, 'Dependency advisory response exceeds its bound.')
    response_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError) as error:
        _write_diagnostic(diagnostic, {**base, 'result': 'invalid', 'response_sha256': response_sha256,
                                      'error': type(error).__name__})
        raise
    results = value.get('results') if isinstance(value, dict) else None
    valid = isinstance(value, dict) and set(value) == {'results'} and isinstance(results, list) and \
        len(results) == len(queries)
    if valid:
        valid = all(isinstance(item, dict) and set(item) <= {'vulns', 'next_page_token'} and
                    ('vulns' not in item or isinstance(item['vulns'], list)) and
                    ('next_page_token' not in item or isinstance(item['next_page_token'], str))
                    for item in results)
    findings = []
    incomplete = []
    if valid:
        for index, item in enumerate(results):
            if item.get('next_page_token'):
                incomplete.append(index)
            for advisory in item.get('vulns', []):
                if not isinstance(advisory, dict) or not isinstance(advisory.get('id'), str):
                    valid = False
                    break
                findings.append({'query_index': index, 'id': advisory['id'], 'advisory': advisory})
    advisory_details, details_complete = _advisory_details(sorted({item['id'] for item in findings})) \
        if diagnostic is not None and valid and findings else ([], True)
    result = 'pass' if valid and not findings and not incomplete else 'fail' if valid else 'invalid'
    _write_diagnostic(diagnostic, {**base, 'result': result, 'response_sha256': response_sha256,
                                  'results': results if isinstance(results, list) else None,
                                  'advisory_ids': sorted({item['id'] for item in findings}),
                                  'advisories': advisory_details, 'advisory_details_complete': details_complete,
                                  'finding_count': len(findings), 'incomplete_query_indexes': incomplete})
    require(valid and not incomplete, 'Dependency advisory coverage is incomplete or malformed.')
    grouped = [{'query': query, 'advisories': [v['id'] for v in result.get('vulns', [])]}
               for query, result in zip(queries, results) if result.get('vulns')]
    return {'schema': 1, 'feed_sha256': response_sha256,
            'queries': queries, 'results': results, 'findings': grouped}


def assess(queries, *, diagnostic=None):
    value = report(queries, diagnostic=diagnostic)
    require(not value['findings'], 'Dependencies have unresolved advisories.')
    return value['feed_sha256']
