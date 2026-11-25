"""Resolve exact existing Python requirements using advisories and hashed PyPI wheels."""
import re
import tomllib

from .common import fetch_json, osv_queries, require, version
from .inputs import reason


def requirements(project, locked):
    dependencies = tomllib.loads(project.decode())['project']['dependencies']
    result = {}
    for entry in dependencies:
        match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9_.-]*)==([0-9]+\.[0-9]+\.[0-9]+)', entry)
        require(match is not None, 'Python automation needs exact stable existing requirements.')
        name, selected = match.groups()
        require(name not in result, 'Duplicate Python requirement.')
        result[name] = selected
    lines = locked.decode().replace('\\\n', '').splitlines()
    require(len(lines) == len(result), 'Python lock coverage differs from project dependencies.')
    for line in lines:
        fields = line.split()
        require(fields and fields[0] in dependencies and all(re.fullmatch(r'--hash=sha256:[0-9a-f]{64}', f)
                for f in fields[1:]), 'Python lock has unreviewed options, sources or dependencies.')
    require({line.split()[0] for line in lines} == set(dependencies), 'Python lock repeats or omits a dependency.')
    return result


def wheel_hashes(name, selected):
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name), 'Invalid Python package name.')
    version(selected)
    data = fetch_json('https://pypi.org/pypi/'+name+'/'+selected+'/json')
    normalize = lambda n: re.sub(r'[-_.]+', '-', n).lower()
    require(normalize(data['info']['name']) == normalize(name) and data['info']['version'] == selected and
            not data['info'].get('requires_dist'), 'Python update changes identity or needs a reviewed dependency graph.')
    wheels = [f for f in data['urls'] if f['packagetype'] == 'bdist_wheel' and not f.get('yanked')]
    require(wheels and len(wheels) <= 200 and all(
        f['filename'].endswith('.whl') and f['url'].startswith('https://files.pythonhosted.org/packages/') and
        re.fullmatch(r'[0-9a-f]{64}', f['digests']['sha256']) for f in wheels),
        'Python release lacks approved stable wheel hashes.')
    return sorted({f['digests']['sha256'] for f in wheels})


def resolve(before, *, allow_minor=False):
    project, lock = before
    installed = requirements(project, lock)
    queries = [{'package': {'ecosystem': 'PyPI', 'name': n}, 'version': v} for n, v in installed.items()]
    results = osv_queries(queries)
    selected, reasons = dict(installed), []
    for (name, current), result in zip(installed.items(), results):
        identities = []
        for entry in result.get('vulns', []):
            advisory = fetch_json('https://api.osv.dev/v1/vulns/'+entry['id'])
            require(advisory.get('id') == entry['id'] and not advisory.get('withdrawn'), 'Python advisory is missing or withdrawn.')
            fixes = [event['fixed'] for affected in advisory.get('affected', [])
                     if affected.get('package', {}).get('ecosystem') == 'PyPI' and
                     affected['package']['name'].lower() == name.lower()
                     for interval in affected.get('ranges', []) for event in interval.get('events', [])
                     if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', event.get('fixed', '')) and
                     version(current) < version(event['fixed']) and version(current)[0] == version(event['fixed'])[0] and
                     (allow_minor or version(current)[:2] == version(event['fixed'])[:2])]
            require(fixes, 'Python advisory requires a reviewed migration: '+name+' '+entry['id'])
            selected[name] = max((selected[name], min(fixes, key=version)), key=version)
            identities.append(entry['id'])
        reasons.extend(reason(identity, 'PyPI', name, current, selected[name]) for identity in identities)
    if not reasons:
        return before, []
    for name, current in installed.items():
        project = project.replace((name+'=='+current).encode(), (name+'=='+selected[name]).encode())
    lines = []
    for name, chosen in selected.items():
        lines.append(name+'=='+chosen+' '+ ' '.join('--hash=sha256:'+h for h in wheel_hashes(name, chosen)))
    return (project, ('\n'.join(lines)+'\n').encode()), reasons


def validate(before, after, reasons, *, allow_minor=False):
    expected, observed = resolve(before, allow_minor=allow_minor)
    require(expected != before and after == expected, 'Python changes differ from the minimal authenticated security fix.')
    actual = [r for r in reasons if r['ecosystem'] == 'PyPI']
    require(sorted(actual, key=lambda r: r['id']) == sorted(observed, key=lambda r: r['id']),
            'Python candidate has unrelated or missing advisory evidence.')


def update(root, *, allow_minor=False):
    paths = [root/'pyproject.toml', root/'requirements.txt']
    before = tuple(p.read_bytes() for p in paths)
    after, reasons = resolve(before, allow_minor=allow_minor)
    for path, raw in zip(paths, after):
        path.write_bytes(raw)
    return reasons
