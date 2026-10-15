"""Bounded root-owned boot acceptance and staging entry points."""

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile

from .release import canonical, read, require, ReleaseError
from .update import accepted_boot, command, promote, stage
from . import factory


INSTALLED = Path('/usr/share/lanrith/installed.json')


def status():
    require(INSTALLED.stat().st_uid==0 and not INSTALLED.stat().st_mode & 0o022,
            'Installed image metadata is not protected.')
    value=json.loads(read(INSTALLED,65536))
    observation=Path('/run/lanrith/boot.json')
    boot=None
    if observation.exists():
        require(observation.stat().st_uid==0 and not observation.stat().st_mode & 0o022,
                'Boot observation is not protected.')
        boot=json.loads(read(observation,65536))
    return {key:value[key] for key in ('image_id','platform_version','deployment_sequence')} | {'boot':boot}


def installed():
    require(os.geteuid() == 0, 'Runtime administration requires root.')
    require(INSTALLED.stat().st_uid == 0 and not INSTALLED.stat().st_mode & 0o022,
            'Installed image metadata is not protected.')
    return json.loads(read(INSTALLED, 65536))


def health():
    value = installed()
    expected = {'kernel.unprivileged_bpf_disabled': 2, 'net.core.bpf_jit_harden': 2,
                'kernel.kptr_restrict': 2, 'kernel.dmesg_restrict': 1, 'kernel.yama.ptrace_scope': 2,
                'kernel.perf_event_paranoid': 3, 'kernel.unprivileged_userns_clone': 0,
                'kernel.io_uring_disabled': 2, 'kernel.kexec_load_disabled': 1, 'dev.tty.ldisc_autoload': 0,
                'fs.suid_dumpable': 0, 'fs.protected_fifos': 2, 'fs.protected_regular': 2,
                'fs.protected_hardlinks': 1, 'fs.protected_symlinks': 1, 'kernel.randomize_va_space': 2}
    for key, setting in expected.items():
        require(Path('/proc/sys', key.replace('.', '/')).read_text().strip() == str(setting),
                'Required kernel hardening is not active.')
    factory.secure_boot(value['boot'].get('secure_boot', True))
    factory.initialize(value)
    require(Path(value['state_directory'], 'recovery-key-enrolled').is_file(),
            'Offline recovery-key storage is not acknowledged.')
    require('ro' in command(['findmnt', '--noheadings', '--output', 'OPTIONS', '/']).strip().split(','),
            'Root filesystem is not read-only.')
    resolved = json.loads(read(Path('/usr/share/lanrith/resolved.json'), 1024 * 1024))
    units = ['nftables.service', 'ssh.service', 'systemd-networkd.service']
    units.extend(value.get('integration_health_units', []))
    for feature, unit in (('dns', 'unbound.service'), ('dhcp4', 'kea-dhcp4-server.service'), ('ntp', 'chrony.service')):
        if resolved['services'].get(feature, {}).get('enabled'):
            units.append(unit)
    for unit in units:
        require(command(['systemctl', 'is-active', unit]).strip() == 'active', 'Required service is not active.')
    for network in resolved['networks'].values():
        arguments = ['ip'] + (['-netns', network['namespace']] if 'namespace' in network else [])
        rows = json.loads(command(arguments+['-j', 'address', 'show', 'dev', network['name']]))
        require(len(rows) == 1, 'Required network interface is absent.')
        observed = {item['local'] for item in rows[0].get('addr_info', [])}
        import ipaddress
        require(all(str(ipaddress.ip_interface(address).ip) in observed for address in network['addresses']),
                'Declared gateway address is absent.')
    return value


def publish():
    value = health()
    require(command(['systemctl', 'is-active', 'boot-complete.target']).strip() == 'active',
            'Boot acceptance target is not complete.')
    current = Path(command(['bootctl', '--print-stub-path']).strip())
    expected = value['uki_name']
    if current.name != expected:
        command(['/usr/lib/systemd/systemd-bless-boot', 'good'])
    stable = accepted_boot(current, expected, Path(value['esp']))
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch(r'[0-9a-f-]{36}', boot_id), 'Invalid boot identity.')
    observation = {'schema': 1, 'accepted': True, 'boot_complete': True, 'boot_id': boot_id,
                   'image_id': value['image_id'], 'platform_version': value['platform_version'],
                   'deployment_sequence': value['deployment_sequence'], 'selected_entry': stable.name}
    directory = Path('/run/lanrith')
    directory.mkdir(mode=0o755, exist_ok=True)
    require(not directory.is_symlink() and directory.stat().st_uid == 0 and
            not directory.stat().st_mode & 0o022, 'Unsafe boot-observation directory.')
    descriptor, name = tempfile.mkstemp(prefix='.boot-', dir=directory)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(canonical(observation))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o644)
        os.replace(name, directory / 'boot.json')
    finally:
        Path(name).unlink(missing_ok=True)
    return observation


def accept(sequence):
    value = publish()
    require(value['deployment_sequence'] == sequence, 'Running image is not the requested deployment.')
    command(['bootctl', 'set-default', value['selected_entry']])
    return value


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('health')
    commands.add_parser('publish')
    commands.add_parser('status')
    commands.add_parser('initialize')
    commands.add_parser('recovery')
    commands.add_parser('accept').add_argument('sequence', type=int)
    commands.add_parser('stage').add_argument('directory', type=Path)
    commands.add_parser('promote').add_argument('directory', type=Path)
    args = parser.parse_args(arguments)
    try:
        if args.command == 'status':
            print(json.dumps(status(),sort_keys=True))
        elif args.command == 'health':
            health()
            print('Local boot health checks passed.')
        elif args.command == 'publish':
            print(json.dumps(publish(), sort_keys=True))
        elif args.command == 'initialize':
            factory.initialize(installed())
            print('Verified A/B slots and encrypted state.')
        elif args.command == 'recovery':
            factory.recovery(installed())
        elif args.command == 'accept':
            print(json.dumps(accept(args.sequence), sort_keys=True))
        elif args.command == 'stage':
            print(json.dumps(stage(args.directory), sort_keys=True))
        else:
            print(json.dumps(promote(args.directory), sort_keys=True))
    except (ReleaseError, OSError, ValueError, KeyError) as error:
        print(str(error) if isinstance(error, ReleaseError) else 'Runtime operation failed.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
