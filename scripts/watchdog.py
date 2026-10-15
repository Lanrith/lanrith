#!/usr/bin/env python3
"""Report a missing retained-release assessment independently of the scan job."""

import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile

repository = os.environ['GITHUB_REPOSITORY']
def gh(*arguments):
    return subprocess.run(['gh', *arguments], check=True, capture_output=True, text=True).stdout

releases = json.loads(gh('api', 'repos/'+repository+'/releases?per_page=100'))
import re
supported = [r for r in releases if not r['draft'] and
             re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', r['tag_name'])]
if not supported:
    print('No published platform release exists; qualification admission remains closed.')
    raise SystemExit(0)
latest = max(datetime.datetime.fromisoformat(r['published_at'].replace('Z','+00:00')) for r in supported)
result = json.loads(gh('run', 'list', '--repo', repository, '--workflow', 'security-audit.yml',
    '--status', 'success', '--branch', 'main', '--limit', '1', '--json', 'updatedAt,databaseId,headSha'))
now = datetime.datetime.now(datetime.timezone.utc)
healthy = bool(result) and datetime.timedelta(0) <= now-datetime.datetime.fromisoformat(
    result[0]['updatedAt'].replace('Z','+00:00')) <= datetime.timedelta(hours=48)
if healthy:
    assessed = datetime.datetime.fromisoformat(result[0]['updatedAt'].replace('Z','+00:00'))
    healthy = assessed >= latest or now-latest <= datetime.timedelta(hours=48)
else:
    healthy = datetime.timedelta(0) <= now-latest <= datetime.timedelta(hours=48)
if not healthy:
    title = 'Security assessment has not succeeded within 48 hours'
    issues = json.loads(gh('issue', 'list', '--repo', repository, '--state', 'open',
                           '--search', title+' in:title', '--json', 'number,title'))
    if not any(item['title'] == title for item in issues):
        with tempfile.TemporaryDirectory(prefix='lanrith-watchdog.') as temporary:
            body = Path(temporary)/'issue.md'
            body.write_text('The independent watchdog found no successful main-branch retained-release security workflow within 48 hours.\n\nInspect failed or missing scheduled runs. Production admission still requires inventory-bound evidence within 24 hours; do not bypass it to clear this alert.\n')
            gh('issue', 'create', '--repo', repository, '--title', title, '--body-file', str(body))
    raise SystemExit('No fresh successful retained-release security assessment.')
print('Security assessment watchdog passed.')
