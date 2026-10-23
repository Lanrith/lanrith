"""Bounded data handling and GitHub API access for trusted maintenance jobs."""

import base64
import datetime
import hashlib
import gzip
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import urllib.parse
import urllib.request


class MaintenanceError(ValueError):
    """A maintenance operation could not establish its required evidence."""


def require(condition, message):
    if not condition:
        raise MaintenanceError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key: '+key)
        result[key] = value
    return result


def document(raw):
    require(isinstance(raw, (bytes, str)) and len(raw) <= 8*1024*1024,
            'JSON input exceeds the maintenance data limit.')
    def invalid_constant(value):
        raise MaintenanceError('Non-finite JSON number: '+value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def timestamp(value):
    require(isinstance(value, str), 'Missing evidence timestamp.')
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.tzinfo is not None, 'Evidence timestamps must contain a timezone.')
    return result


def sha(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value), 'Invalid Git commit identity.')
    return value


def repository(value):
    require(value in ('Lanrith/lanrith', 'Lanrith/discovery-bridge', 'Lanrith/router-policy-agent'),
            'Repository is outside the maintenance installation.')
    return value


def safe_path(value):
    require(isinstance(value, str) and value and len(value) < 240 and
            re.fullmatch(r'[A-Za-z0-9_.+/@-]+', value) and
            not value.startswith('/') and '\\' not in value and
            all(part not in ('', '.', '..', '.git') for part in value.split('/')) and
            PurePosixPath(value).as_posix() == value, 'Unsafe maintenance path.')
    return value


def run(*arguments, **kwargs):
    return subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL,
                          timeout=kwargs.pop('timeout', 120), **kwargs)


def api(endpoint, *, method='GET', payload=None, paginate=False):
    require(endpoint.startswith(('repos/', 'orgs/', 'users/', 'app/')) and
            not any(c in endpoint for c in ('\n', '\r', '#')), 'Invalid GitHub API endpoint.')
    command = ['gh', 'api', '--method', method, '-H', 'Accept: application/vnd.github+json', endpoint]
    if paginate:
        command += ['--paginate', '--slurp']
    if payload is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=canonical(payload) if payload is not None else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False)
    require(result.returncode == 0, 'GitHub API operation failed: '+method+' '+endpoint+
            ' '+result.stderr.decode(errors='replace')[-1000:])
    require(len(result.stdout) <= 32*1024*1024, 'GitHub API response exceeds its bound.')
    return document(result.stdout) if result.stdout.strip() else None


def pages(endpoint):
    result = api(endpoint, paginate=True)
    require(isinstance(result, list) and all(isinstance(p, list) for p in result),
            'GitHub pagination did not return complete list pages.')
    return [item for page in result for item in page]


def contents(repo, path, ref):
    require(repo in ('Lanrith/lanrith', 'Lanrith/discovery-bridge', 'Lanrith/router-policy-agent', 'grafana/alloy'),
            'Unapproved source repository.')
    safe_path(path)
    sha(ref)
    value = api('repos/'+repo+'/contents/'+path+'?ref='+ref)
    require(value.get('type') == 'file' and value.get('encoding') == 'base64' and
            value.get('size', 8*1024*1024+1) <= 4*1024*1024,
            'Maintenance inputs must be bounded regular source files.')
    return base64.b64decode(value['content'], validate=False)


def fetch(url, *, data=None, maximum=8*1024*1024):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname in {
        'api.osv.dev', 'go.dev', 'nodejs.org', 'registry.npmjs.org',
        'snapshot.debian.org', 'security-tracker.debian.org', 'proxy.golang.org',
        'security.debian.org', 'nlnetlabs.nl',
        'registry-1.docker.io', 'auth.docker.io'}, 'Unapproved maintenance metadata origin.')
    request = urllib.request.Request(url, data=canonical(data) if data is not None else None,
                                     headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=90) as response:
        redirected = urllib.parse.urlsplit(response.url)
        require(redirected.scheme == 'https' and redirected.hostname == parsed.hostname,
                'Metadata redirected away from its approved HTTPS origin.')
        raw = response.read(maximum+1)
    require(0 < len(raw) <= maximum, 'Maintenance metadata exceeds its bound.')
    # Archive only public upstream inputs. In particular, never retain registry
    # bearer-token responses, request headers, App tokens or private keys.
    destination = os.environ.get('LANRITH_EVIDENCE_DIR')
    if destination and parsed.hostname != 'auth.docker.io':
        root = Path(destination)
        root.mkdir(parents=True, exist_ok=True)
        identity = digest(canonical({'url': url, 'query': data}))
        (root/(identity+'.json')).write_bytes(canonical({'schema': 1, 'url': url,
            'query': data, 'response_sha256': digest(raw), 'retrieved_at': now()}))
        (root/(identity+'.response.gz')).write_bytes(gzip.compress(raw, mtime=0))
    return raw


def metadata_bundle(destination):
    directory = os.environ.get('LANRITH_EVIDENCE_DIR')
    if not directory or not Path(directory).exists():
        return
    files = sorted(Path(directory).iterdir())
    if not files:
        return
    require(len(files) <= 2000 and all(p.is_file() and not p.is_symlink() and
            re.fullmatch(r'[0-9a-f]{64}\.(json|response.gz)', p.name) for p in files),
            'Unexpected public metadata evidence files.')
    require(sum(p.stat().st_size for p in files) <= 30*1024*1024, 'Public evidence archive exceeds its bound.')
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination/'input-evidence.tar.gz', 'w:gz') as archive:
        for path in files:
            archive.add(path, arcname=path.name, recursive=False)


def fetch_json(url, *, data=None):
    return document(fetch(url, data=data))


def version(value):
    require(isinstance(value, str) and re.fullmatch(r'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value),
            'Only exact stable versions may enter the automatic lane.')
    return tuple(map(int, value.removeprefix('v').split('.')))


def osv_queries(queries):
    require(isinstance(queries, list) and 0 < len(queries) <= 1000, 'Invalid advisory query coverage.')
    value = fetch_json('https://api.osv.dev/v1/querybatch', data={'queries': queries})
    results = value.get('results')
    require(isinstance(results, list) and len(results) == len(queries) and
            all(isinstance(r, dict) and not r.get('next_page_token') for r in results),
            'Advisory service returned incomplete coverage.')
    return results
