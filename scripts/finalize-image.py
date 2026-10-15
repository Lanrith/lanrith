#!/usr/bin/python3
"""Verify persistent identities and the actual final boot transaction."""

import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(os.environ['BUILDROOT']).resolve()
root.chmod(0o755)
profile = json.loads((root/'usr/share/lanrith/resolved.json').read_text())
username = profile['administration']['username']
if username != 'admin':
    if any(line.split(':')[0] == username for line in (root/'etc/passwd').read_text().splitlines()):
        raise ValueError('Administrator account conflicts with a reserved service identity.')
    for name in ('passwd', 'shadow', 'group', 'gshadow'):
        path = root/'etc'/name
        if not path.is_file():
            continue
        lines = []
        for line in path.read_text().splitlines():
            fields = line.split(':')
            if fields[0] == 'admin':
                fields[0] = username
                if name == 'passwd':
                    fields[5] = '/home/'+username
            if name in ('group', 'gshadow'):
                fields[-1] = ','.join(username if member == 'admin' else member for member in fields[-1].split(','))
            lines.append(':'.join(fields))
        path.write_text('\n'.join(lines)+'\n')
    for path in (root/'usr/lib/sysusers.d').glob('*.conf'):
        lines = []
        for line in path.read_text().splitlines():
            fields = line.split()
            if len(fields) > 1 and fields[0] in ('u', 'g', 'm') and fields[1] == 'admin':
                fields[1] = username
                line = ' '.join(fields)
            lines.append(line)
        path.write_text('\n'.join(lines)+'\n')
users = {row[0]: {'uid': int(row[2]), 'gid': int(row[3])}
         for line in (root/'etc/passwd').read_text().splitlines() if line and (row := line.split(':'))}
expected = json.loads((root/'usr/share/lanrith/service-identities.json').read_text())
for name, identity in expected.items():
    if name == 'admin':
        name = username
    if users.get(name) != identity:
        raise ValueError('A persistent service identity changed during assembly.')
required = ['multi-user.target', 'boot-complete.target', 'lanrith-health.service', 'lanrith-observation.service']
required.extend(json.loads((root/'usr/share/lanrith/installed.json').read_text())['integration_health_units'])
with tempfile.TemporaryDirectory(prefix='boot-transaction.', dir=root/'run') as temporary:
    fixture = Path(temporary)
    fixture.chmod(0o755)
    (fixture/'var.mount').write_text('[Mount]\nWhat=/dev/mapper/state\nWhere=/var\nType=ext4\n')
    result = subprocess.run(['systemd-analyze', '--root', str(root), '--man=no', 'verify', *required],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
        env={'PATH': '/usr/sbin:/usr/bin', 'SYSTEMD_LOG_TARGET': 'console', 'SYSTEMD_LOG_LEVEL': 'warning',
             'SYSTEMD_UNIT_PATH': '/run/'+fixture.name+':/etc/systemd/system:/usr/lib/systemd/system'})
    if result.returncode or result.stderr.strip():
        # Ordering-cycle warnings can have exit status zero and still drop a required job.
        raise ValueError('Final native boot transaction failed: '+result.stderr.strip())
print('Final identities and native boot transaction verified.')
