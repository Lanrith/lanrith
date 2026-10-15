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

result = json.loads(gh('run', 'list', '--repo', repository, '--workflow', 'security-audit.yml',
    '--status', 'success', '--branch', 'main', '--limit', '1', '--json', 'updatedAt,databaseId,headSha'))
now = datetime.datetime.now(datetime.timezone.utc)
healthy = bool(result) and datetime.timedelta(0) <= now-datetime.datetime.fromisoformat(
    result[0]['updatedAt'].replace('Z','+00:00')) <= datetime.timedelta(hours=48)
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
