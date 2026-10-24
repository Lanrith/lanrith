"""Bounded root-owned boot acceptance and staging entry points."""

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

from .release import canonical, read, require, ReleaseError
from .update import accepted_boot, boot_esp, command, promote, stage, writable_esp
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
    return {key:value[key] for key in ('image_id','platform_version','deployment_sequence',
                                       'configuration_sha256')} | {'boot':boot}


def telemetry():
    """Emit a replay-identifiable heartbeat for the authenticated remote sink."""
    value = status()
    boot = value['boot']
    require(isinstance(boot, dict) and set(boot) == {'schema', 'accepted', 'boot_complete', 'boot_id',
            'image_id', 'platform_version', 'deployment_sequence', 'selected_entry'} and
            boot['schema'] == 1 and boot['accepted'] is True and boot['boot_complete'] is True and
            boot['image_id'] == value['image_id'] and boot['platform_version'] == value['platform_version'] and
            boot['deployment_sequence'] == value['deployment_sequence'] and
            re.fullmatch(r'[0-9a-f-]{36}', boot['boot_id']) and
            isinstance(boot['selected_entry'], str), 'Accepted boot observation is unavailable.')
    require(re.fullmatch(r'[0-9a-f]{64}', value['configuration_sha256']),
            'Installed configuration identity is malformed.')
    return {'schema': 1, 'event': 'lanrith-heartbeat', 'boot_id': boot['boot_id'],
            'selected_entry': boot['selected_entry'], 'image_id': value['image_id'],
            'platform_version': value['platform_version'],
            'deployment_sequence': value['deployment_sequence'],
            'configuration_sha256': value['configuration_sha256'],
            'monotonic_ns': time.monotonic_ns()}


def installed():
    require(os.geteuid() == 0, 'Runtime administration requires root.')
    require(INSTALLED.stat().st_uid == 0 and not INSTALLED.stat().st_mode & 0o022,
            'Installed image metadata is not protected.')
    return json.loads(read(INSTALLED, 65536))


def watchdog_health(policy, *, sysfs=Path('/sys/class/watchdog'), manager_fds=Path('/proc/1/fd')):
    if not policy or policy['mode'] == 'disabled':
        return
    device = Path(policy['device'])
    observed = sysfs/device.name
    if not observed.exists():
        require(policy['mode'] == 'auto', 'Required hardware watchdog is absent.')
        return
    require((observed/'state').read_text().strip() == 'active',
            'Configured hardware watchdog is not active.')
    for descriptor in manager_fds.iterdir():
        try:
            if descriptor.readlink() == device:
                return
        except OSError:
            # Unrelated manager descriptors can close while being observed.
            continue
    require(False, 'System manager does not own the configured hardware watchdog.')


def health():
    value = installed()
    require(Path('/etc/machine-id').read_text().strip() == value['machine_id'],
            'Running device identity differs from the signed owner configuration.')
    expected = {'kernel.unprivileged_bpf_disabled': 2, 'net.core.bpf_jit_harden': 2,
                'kernel.kptr_restrict': 2, 'kernel.dmesg_restrict': 1, 'kernel.yama.ptrace_scope': 2,
                'kernel.perf_event_paranoid': 3, 'kernel.unprivileged_userns_clone': 0,
                'kernel.io_uring_disabled': 2, 'kernel.kexec_load_disabled': 1, 'dev.tty.ldisc_autoload': 0,
                'fs.suid_dumpable': 0, 'fs.protected_fifos': 2, 'fs.protected_regular': 2,
                'fs.protected_hardlinks': 1, 'fs.protected_symlinks': 1, 'kernel.randomize_va_space': 2}
    for key, setting in expected.items():
        require(Path('/proc/sys', key.replace('.', '/')).read_text().strip() == str(setting),
                'Required kernel hardening is not active.')
    loaded = {line.split()[0] for line in Path('/proc/modules').read_text().splitlines() if line}
    require(not loaded & {'dccp', 'sctp', 'rds', 'tipc', 'can', 'can_raw', 'can_bcm', 'can_gw',
                          'bluetooth', 'btusb', 'af_802154', 'ieee802154', 'mac802154', 'nfc'},
            'A disabled kernel protocol module is loaded.')
    factory.secure_boot(value['boot'].get('secure_boot', True))
    watchdog_health(value.get('watchdog'))
    factory.initialize(value)
    require(Path(value['state_directory'], 'recovery-key-enrolled').is_file(),
            'Offline recovery-key storage is not acknowledged.')
    require('ro' in command(['findmnt', '--noheadings', '--output', 'OPTIONS', '/']).strip().split(','),
            'Root filesystem is not read-only.')
    state_options = set(command(['findmnt', '--noheadings', '--output', 'OPTIONS', '/var']).strip().split(','))
    require({'nodev', 'nosuid', 'noexec'} <= state_options,
            'Persistent state filesystem permits device, set-ID or executable content.')
    # Boot acceptance requires the generated mount policy to be effective, not
    # merely present in the signed root.
    boot_esp(value)
    from .boot_health import check
    check(json.loads(read(Path('/usr/share/lanrith/health.json'), 1024*1024)))
    return value


def bless(value=None):
    """Bless one healthy counted boot through the bounded ESP write window."""
    value = installed() if value is None else value
    require(command(['systemctl', 'is-active', 'boot-complete.target']).strip() == 'active',
            'Boot acceptance target is not complete.')
    current = Path(command(['bootctl', '--print-stub-path']).strip())
    expected = value['uki_name']
    esp = boot_esp(value)
    if current.name != expected and current.exists():
        with writable_esp(value, esp=esp):
            command(['/usr/lib/systemd/systemd-bless-boot', 'good'])
    return accepted_boot(current, expected, esp)


def publish():
    value = health()
    stable = bless(value)
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
    commands.add_parser('bless')
    commands.add_parser('telemetry')
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
        elif args.command == 'bless':
            print(bless().name)
        elif args.command == 'telemetry':
            print(json.dumps(telemetry(), sort_keys=True, separators=(',', ':')))
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
        if isinstance(error, ReleaseError):
            message = str(error)
        else:
            # Paths, command arguments and parser input can contain owner data.
            # Report only the fixed operation, exception category and errno.
            details = 'operation='+args.command+'; exception='+type(error).__name__
            if isinstance(error, OSError) and type(error.errno) is int:
                details += '; errno='+str(error.errno)
            message = 'Runtime operation failed. ['+details+']'
        print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
