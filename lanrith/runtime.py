"""Bounded root-owned boot acceptance and staging entry points."""

import argparse
import json
import os
from pathlib import Path
import sys
import time

from .release import canonical, read, require, unique, ReleaseError
from .update import accepted_boot, boot_esp, command, promote, stage, writable_esp
from . import factory, health_observation
from .policy_runtime import read as protected_read


INSTALLED = Path('/usr/share/lanrith/installed.json')
BOOT_OBSERVATION = Path('/run/lanrith/boot.json')


def boot_event(value, *, unavailable='Current boot observation is unavailable.'):
    from .slot_state import check_health_directory
    check_health_directory(BOOT_OBSERVATION.parent)
    event = json.loads(protected_read(BOOT_OBSERVATION, 2048), object_pairs_hook=unique)
    expected = {'schema': 1, 'boot_complete': True, 'boot_id': health_observation.boot_id(),
                'image_id': value['image_id'], 'platform_version': value['platform_version'],
                'deployment_sequence': value['deployment_sequence'], 'selected_entry': value['uki_name']}
    require(isinstance(event, dict) and set(event) == set(expected) | {'accepted'} and
            type(event['schema']) is int and type(event['accepted']) is bool and
            event['boot_complete'] is True and type(event['deployment_sequence']) is int and
            all(event[k] == v for k, v in expected.items()), unavailable)
    return event


def require_accepted_boot(value):
    """Return the protected event for the running, committed boot or raise."""
    from . import image_operation
    unavailable = 'Current committed boot acceptance is unavailable.'
    event = boot_event(value, unavailable=unavailable)
    require(event['accepted'] and image_operation.visible_accepted(value) == image_operation.identity(value), unavailable)
    return event


def historical_boot(value):
    try:
        event = boot_event(value)
        if event['accepted']:
            receipt = BOOT_OBSERVATION.with_name('committed-boot.json')
            require(protected_read(receipt, 2048) == canonical(health_observation.binding(value)),
                    'Committed boot observation is unavailable.')
        return event
    except (OSError, ValueError, RecursionError):
        return None


def status():
    value = json.loads(protected_read(INSTALLED, 65536), object_pairs_hook=unique)
    return {key: value[key] for key in ('image_id', 'platform_version', 'deployment_sequence',
                                        'configuration_sha256')} | {
        'boot': historical_boot(value), 'boot_scope': 'historical',
        'health': health_observation.status(BOOT_OBSERVATION.with_name('health.json'), value)}


def telemetry():
    """Emit a replay-identifiable heartbeat for the authenticated remote sink."""
    value = json.loads(protected_read(INSTALLED, 65536), object_pairs_hook=unique)
    boot = historical_boot(value)
    require(boot is not None and boot['accepted'], 'Accepted boot observation is unavailable.')
    return {'schema': 1, 'event': 'lanrith-heartbeat', 'boot_id': boot['boot_id'],
            'selected_entry': boot['selected_entry'], 'image_id': value['image_id'],
            'platform_version': value['platform_version'],
            'deployment_sequence': value['deployment_sequence'],
            'configuration_sha256': value['configuration_sha256'],
            'monotonic_ns': time.monotonic_ns(), 'emitted_unix_ns': time.time_ns()}


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
    with health_observation.attempt(BOOT_OBSERVATION.with_name('health.json'), value):
        check_health(value)
    return value


def check_health(value):
    from .credential_operation import ready
    from .extension_credential_operation import required_ready
    require(ready(value), 'Required credentials have not been admitted.')
    require(required_ready(value), 'Required extension credentials have not been admitted.')
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
    device, _ = factory.initialize(value)
    from .recovery_enrollment import verified, header
    require(verified(Path(value['state_directory']), device, header(device)), 'Offline recovery key is unverified.')
    require('ro' in command(['findmnt', '--noheadings', '--output', 'OPTIONS', '/']).strip().split(','),
            'Root filesystem is not read-only.')
    state_options = set(command(['findmnt', '--noheadings', '--output', 'OPTIONS', '/var']).strip().split(','))
    require({'nodev', 'nosuid', 'noexec'} <= state_options,
            'Persistent state filesystem permits device, set-ID or executable content.')
    # Boot acceptance requires the generated mount policy to be effective, not
    # merely present in the signed root.
    boot_esp(value)
    from .boot_health import check
    check(json.loads(read(Path('/usr/share/lanrith/health.json'), 1024*1024)), settle_seconds=8)


def complete_target():
    # A local daemon can recover after the target's first dependency job failed.
    # Requeue boot completion from the promotion worker, outside the gate itself.
    if command(['systemctl', 'show', '-P', 'ActiveState', 'boot-complete.target']).strip() != 'active':
        command(['systemctl', 'start', 'boot-complete.target'], timeout=70)


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


def refresh_boot_seed():
    """Refresh the boot seed without leaving the verified ESP writable."""
    value = installed()
    esp = boot_esp(value)
    with writable_esp(value, esp=esp):
        command(['bootctl', '--esp-path='+str(esp), '--graceful', 'random-seed'])


def invalidate_boot_receipt():
    """Withdraw the public commit projection before changing private promotion state."""
    BOOT_OBSERVATION.with_name('committed-boot.json').unlink(missing_ok=True)


def publish_boot(value, stable, *, accepted=False):
    """Only the promotion transaction may replace a pending boot with an acceptance."""
    boot_id = health_observation.boot_id()
    require(stable.name == value['uki_name'], 'Selected boot entry differs from the running image.')
    observation = {'schema': 1, 'accepted': accepted, 'boot_complete': True, 'boot_id': boot_id,
                   'image_id': value['image_id'], 'platform_version': value['platform_version'],
                   'deployment_sequence': value['deployment_sequence'], 'selected_entry': stable.name}
    directory = BOOT_OBSERVATION.parent
    directory.mkdir(mode=0o755, exist_ok=True)
    with health_observation.publication_lock(directory):
        if not accepted:
            existing = historical_boot(value)
            if existing is not None:
                return existing
        else:
            from . import image_operation
            require(image_operation.visible_accepted(value) == image_operation.identity(value),
                    'Current committed boot acceptance is unavailable.')
        health_observation.publish(BOOT_OBSERVATION, observation)
        if accepted:
            require_accepted_boot(value)
            health_observation.publish(directory/'committed-boot.json', health_observation.binding(value))
    return observation


def publish():
    value = installed()
    latest = health_observation.status(BOOT_OBSERVATION.with_name('health.json'), value)
    require(latest['result'] == 'passed', 'Fresh whole-boot health is unavailable.')
    event = historical_boot(value)
    if event and event['accepted']:
        return require_accepted_boot(value)
    require(command(['systemctl', 'is-active', 'boot-complete.target'], timeout=2).strip() == 'active',
            'Boot acceptance target is not complete.')
    # Pending publication observes an already stable entry. The blessing unit
    # and promotion handle counted entries that still need a writable ESP.
    current = Path(command(['bootctl', '--print-stub-path'], timeout=2).strip())
    mount = value.get('esp', 'auto')
    esp = Path(command(['bootctl', '--print-esp-path'], timeout=2).strip() if mount == 'auto' else mount)
    return publish_boot(value, accepted_boot(current, value['uki_name'], esp))


def accept(sequence):
    from . import image_operation
    value = installed()
    require(value['deployment_sequence'] == sequence, 'Running image is not the requested deployment.')
    with image_operation.operation_lock():
        return image_operation.promote_running(value, manual=True)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('health')
    commands.add_parser('bless')
    commands.add_parser('refresh-boot-seed')
    commands.add_parser('accepted-boot')
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
        elif args.command == 'refresh-boot-seed':
            refresh_boot_seed()
            print('Boot loader random seed refreshed.')
        elif args.command == 'accepted-boot':
            require_accepted_boot(installed())
        elif args.command == 'telemetry':
            print(json.dumps(telemetry(), sort_keys=True, separators=(',', ':')))
        elif args.command == 'publish':
            print(json.dumps(publish(), sort_keys=True))
        elif args.command == 'initialize':
            factory.initialize(installed())
            print('Verified active root and encrypted state.')
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
