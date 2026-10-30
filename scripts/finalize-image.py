#!/usr/bin/python3
"""Verify persistent identities and the actual final boot transaction."""

import json
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


def enabled_socket_units(root):
    """Verify vendor boot sockets explicitly, including their service pairing."""
    names = set()
    for prefix in ('etc/systemd/system', 'run/systemd/system', 'usr/lib/systemd/system'):
        for activation in ('sockets.target.wants', 'sockets.target.requires'):
            names.update(path.name for path in (root/prefix/activation).glob('*.socket'))
    result = []
    for name in sorted(names):
        overrides = [root/prefix/name for prefix in ('etc/systemd/system', 'run/systemd/system')]
        override = next((path for path in overrides if path.exists() or path.is_symlink()), None)
        if override is not None and override.is_symlink() and override.readlink() == Path('/dev/null'):
            continue
        result.append(name)
    return result


def remove_obsolete_helpers(root):
    """Old bases can retain unused Bind entrypoints with a missing TSIG module.

    Authoritative DNS now uses the compiled DNS runtime and systemd credentials.
    Remove only these retired files, including when assembling on an older base.
    """
    for name in ('bind-runtime', 'bind_runtime.py'):
        path = root/'usr/lib/lanrith'/name
        if path.is_symlink():
            path.unlink()
        elif path.exists():
            if not path.is_file():
                raise ValueError('Obsolete runtime path is not a regular file.')
            path.unlink()


def finalize_policy(root):
    """Compile and consume the policy baseline inside an isolated netns."""
    source = root/'usr/lib/lanrith-build/policy-baseline.json'
    if not source.exists() and not source.is_symlink():
        return
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('Build-only policy compiler input has unsafe metadata.')
    for relative in ('usr/bin/router-policy-profile', 'usr/sbin/nft', 'usr/bin/python3'):
        path = root/relative
        if not path.is_file() or path.is_symlink():
            raise ValueError('Policy profile compiler dependency is unavailable.')
    scratch = root/'run/lanrith-policy-build'
    if scratch.exists() or scratch.is_symlink():
        raise ValueError('Policy profile scratch path already exists.')
    scratch.mkdir(mode=0o700)
    program = r'''
import pathlib, subprocess
root = pathlib.Path('/run/lanrith-policy-build')
# Loading and listing are separate operations in this same disposable network namespace.
subprocess.run(['/usr/sbin/nft', '-f', '/etc/nftables.conf'],
    check=True, stdin=subprocess.DEVNULL, capture_output=True)
listing = subprocess.run(['/usr/sbin/nft', '-j', 'list', 'ruleset'],
    check=True, stdin=subprocess.DEVNULL, capture_output=True).stdout
(root/'ruleset.json').write_bytes(listing)
(root/'output').mkdir(mode=0o700)
subprocess.run(['/usr/bin/router-policy-profile',
    '-baseline', '/usr/lib/lanrith-build/policy-baseline.json',
    '-ruleset', '/run/lanrith-policy-build/ruleset.json',
    '-output-directory', '/run/lanrith-policy-build/output'],
    check=True, stdin=subprocess.DEVNULL)
'''
    result = subprocess.run(['unshare', '--net', '--fork', '--', 'chroot', str(root),
                             '/usr/bin/python3', '-I', '-S', '-c', program],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
                            env={'PATH': '/usr/sbin:/usr/bin'})
    if result.returncode:
        raise ValueError('Policy profile compilation failed in its isolated namespace.')
    output = scratch/'output'
    expected = {'router-profile.json', 'router-guards.nft', 'router-profile-metadata.json'}
    if {path.name for path in output.iterdir()} != expected:
        raise ValueError('Policy profile compiler emitted an unexpected artifact set.')
    metadata = json.loads((output/'router-profile-metadata.json').read_text())
    if (set(metadata) != {'schema_version', 'profile_sha256', 'floor_sha256', 'guards_sha256'} or
            metadata['schema_version'] != 1):
        raise ValueError('Policy profile metadata is malformed.')
    profile = (output/'router-profile.json').read_bytes()
    if not profile.endswith(b'\n') or profile.endswith(b'\n\n'):
        raise ValueError('Policy profile compiler emitted an ambiguous record terminator.')
    profile = profile[:-1]
    guards = (output/'router-guards.nft').read_bytes()
    for data, key in ((profile, 'profile_sha256'), (guards, 'guards_sha256')):
        if hashlib.sha256(data).hexdigest() != metadata[key]:
            raise ValueError('Policy profile artifact differs from its compiler pin.')
    destination = root/'etc/router-policy-agent/profile'
    if destination.exists() or destination.is_symlink():
        raise ValueError('Policy runtime profile destination already exists.')
    destination.mkdir(mode=0o700, parents=True)
    (destination/'profile.json').write_bytes(profile)
    (destination/'profile.json').chmod(0o400)
    os.replace(output/'router-guards.nft', destination/'guards.nft')
    (destination/'guards.nft').chmod(0o400)
    (output/'router-profile.json').unlink()
    public = root/'usr/share/lanrith/policy-profile-metadata.json'
    if public.exists() or public.is_symlink():
        raise ValueError('Policy profile metadata destination already exists.')
    os.replace(output/'router-profile-metadata.json', public)
    public.chmod(0o444)
    shutil.rmtree(scratch)
    shutil.rmtree(root/'usr/lib/lanrith-build')

root = Path(os.environ['BUILDROOT']).resolve()
root.chmod(0o755)
# Assembly embeds the build-owned boundary function in this script. mkosi
# remounts a finalize script as /work/finalize, without its siblings.
remove_obsolete_helpers(root)
finalize_policy(root)
check(root)
administration = json.loads((root/'usr/share/lanrith/administration.json').read_text())
installed = json.loads((root/'usr/share/lanrith/installed.json').read_text())
os_release = root/'usr/lib/os-release'
lines = os_release.read_text().splitlines()
branding = {'NAME':'Lanrith','PRETTY_NAME':'Lanrith '+installed['platform_version'],
            'ID':'lanrith','ID_LIKE':'debian','VERSION':installed['platform_version'],
            'VERSION_ID':installed['platform_version'],'IMAGE_ID':installed['image_id'],
            'IMAGE_VERSION':installed['platform_version'],
            'LANRITH_DEPLOYMENT_SEQUENCE':str(installed['deployment_sequence'])}
lines = [line for line in lines if line.partition('=')[0] not in branding]
os_release.write_text('\n'.join(lines+[key+'='+json.dumps(value) for key,value in branding.items()])+'\n')
username = administration['username']
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
apply_root_access(root, username, ROOT_ACCESS)
users = {row[0]: {'uid': int(row[2]), 'gid': int(row[3])}
         for line in (root/'etc/passwd').read_text().splitlines() if line and (row := line.split(':'))}
expected = json.loads((root/'usr/share/lanrith/service-identities.json').read_text())
for name, identity in expected.items():
    if name == 'admin':
        name = username
    if users.get(name) != identity:
        raise ValueError('A persistent service identity changed during assembly.')
home = root/'home'/username
ssh = home/'.ssh'
authorized = ssh/'authorized_keys'
if home.is_symlink() or ssh.is_symlink() or authorized.is_symlink() or not authorized.is_file():
    raise ValueError('Administrator SSH identity has an unsafe final path.')
for path, mode in ((home, 0o700), (ssh, 0o700), (authorized, 0o600)):
    path.chmod(mode)
    os.chown(path, users[username]['uid'], users[username]['gid'])
integration_identities = root/'usr/share/lanrith/integration-identities.json'
if integration_identities.exists():
    extra = json.loads(integration_identities.read_text())
    groups = {row[0]: {'gid': int(row[2]), 'members': set(filter(None, row[3].split(',')))}
              for line in (root/'etc/group').read_text().splitlines() if line and (row := line.split(':'))}
    for item in extra['users']:
        if users.get(item['name']) != {key: item[key] for key in ('uid', 'gid')}:
            raise ValueError('An integration service identity changed during assembly.')
    for item in extra['groups']:
        members = {username if name == 'admin' else name for name in item.get('members', [])}
        if groups.get(item['name']) != {'gid': item['gid'], 'members': members}:
            raise ValueError('An integration service group changed during assembly.')
for parent, unit in (('boot-complete.target.requires', 'lanrith-health.service'),
                     ('boot-complete.target.requires', 'systemd-boot-check-no-failures.service'),
                     ('multi-user.target.wants', 'lanrith-observation.service')):
    link = root/'usr/lib/systemd/system'/parent/unit
    if not link.is_symlink() or link.readlink() != Path('/usr/lib/systemd/system')/unit:
        raise ValueError('Final assembly lost a required boot-acceptance activation.')
required = ['default.target', 'multi-user.target', 'boot-complete.target',
            'systemd-boot-check-no-failures.service', 'lanrith-health.service', 'lanrith-observation.service']
required.extend(json.loads((root/'usr/share/lanrith/installed.json').read_text())['integration_health_units'])
# Verifying a target alone can miss a broken socket's implicit service link.
# Include each unmasked boot socket so that pairing errors fail before VM boot.
required.extend(enabled_socket_units(root))
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
