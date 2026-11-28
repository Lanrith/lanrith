"""Inspect declared hardware and bind only an explicitly isolated PCI function."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from .release import ReleaseError, canonical, read, require


def check_ownership_manifest(manifest):
    require(isinstance(manifest, dict) and set(manifest) == {'schema', 'facts', 'facts_sha256', 'ownership'} and
            manifest['schema'] == 1 and
            hashlib.sha256(canonical(manifest['facts'])).hexdigest() == manifest['facts_sha256'],
            'Hardware ownership manifest is inconsistent.')
    facts, ownership = manifest['facts'], manifest['ownership']
    require(isinstance(facts, dict) and set(facts) == {'interfaces', 'hugepages'} and
            isinstance(facts['interfaces'], list) and isinstance(ownership, dict) and
            set(ownership) == {'bindings', 'hugepages'} and isinstance(ownership['bindings'], list) and
            1 <= len(ownership['bindings']) <= 256 and ownership['hugepages'] == facts['hugepages'],
            'Hardware ownership manifest is inconsistent.')
    pages = ownership['hugepages']
    require(isinstance(pages, dict) and set(pages) == {'page_size_mib', 'pages'} and
            type(pages['page_size_mib']) is int and pages['page_size_mib'] in (2, 1024) and
            type(pages['pages']) is int and pages['pages'] > 0 and
            2048 <= pages['pages']*pages['page_size_mib'] <= 1048576,
            'Hardware ownership memory plan is inconsistent.')
    selected = set()
    for binding in ownership['bindings']:
        require(isinstance(binding, dict) and set(binding) ==
                {'name', 'mac', 'pci', 'driver', 'iommu_group', 'iommu_members', 'state'} and
                binding['state'] == 'down' and type(binding['iommu_group']) is int and
                binding['iommu_group'] >= 0 and binding['iommu_members'] == [binding['pci']] and
                binding['pci'] not in selected and binding['driver'] != 'vfio-pci' and
                sum(item == {k: v for k, v in binding.items() if k != 'state'}
                    for item in facts['interfaces']) == 1,
                'Hardware ownership binding is inconsistent.')
        selected.add(binding['pci'])
    return ownership

def ownership_memory(ownership, *, sysfs=Path('/sys')):
    pages = ownership['hugepages']
    available = sysfs/f'kernel/mm/hugepages/hugepages-{pages["page_size_mib"]*1024}kB/nr_hugepages'
    require(int(available.read_text()) == pages['pages'], 'Declared hugepage allocation differs.')


def ownership_status(manifest, *, sysfs=Path('/sys')):
    ownership = check_ownership_manifest(manifest)
    ownership_memory(ownership, sysfs=sysfs)
    for binding in ownership['bindings']:
        vfio_device(binding['pci'], binding['iommu_group'], sysfs=sysfs)


def pci_device(bdf, group=None, *, sysfs=Path('/sys')):
    require(isinstance(bdf, str) and re.fullmatch(r'[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]', bdf),
            'Invalid PCI function selection.')
    device = sysfs/'bus/pci/devices'/bdf
    require(device.is_dir(), 'Declared PCI function is absent.')
    isolated = (device/'iommu_group').resolve(strict=True)
    require(isolated.parent == sysfs/'kernel/iommu_groups' and isolated.name.isdecimal(),
            'PCI function has no valid IOMMU group.')
    if group is not None:
        require(str(group).isdecimal() and isolated.name == str(group), 'Unexpected IOMMU group.')
    members = list((isolated/'devices').iterdir())
    require(len(members) == 1 and members[0].name == bdf and members[0].resolve() == device.resolve(),
            'PCI function does not exclusively own its IOMMU group.')
    return device


def vfio_device(bdf, group=None, *, sysfs=Path('/sys')):
    device = pci_device(bdf, group, sysfs=sysfs)
    require((device/'driver').resolve(strict=True).name == 'vfio-pci' and not (device/'net').exists(),
            'Declared PCI function is not exclusively owned by VFIO.')
    return device


STATE = Path('/run/lanrith-hardware-ownership')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')


def timestamp():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def binding_lock(directory):
    directory.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(directory, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        info = os.fstat(fd)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                'Unsafe hardware ownership state directory.')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def driver_name(device):
    try:
        return (device/'driver').resolve(strict=True).name
    except FileNotFoundError:
        require(not (device/'driver').is_symlink(), 'PCI driver link is inconsistent.')
        return None


def override(device):
    value = (device/'driver_override').read_text().rstrip('\n')
    return '' if value == '(null)' else value


def netdevs(device):
    try:
        return sorted(entry.name for entry in (device/'net').iterdir())
    except FileNotFoundError:
        return []


def object_id(path):
    info = path.stat()
    return [info.st_dev, info.st_ino]


def instance(device):
    return {'pci_object': object_id(device), 'group_object': object_id(device/'iommu_group'),
            'pci_ids': {key: (device/key).read_text().strip() for key in
                        ('vendor', 'device', 'subsystem_vendor', 'subsystem_device', 'revision', 'class')}}


def read_record(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    directory = path.parent.lstat()
    require(stat.S_ISDIR(directory.st_mode) and stat.S_IMODE(directory.st_mode) == 0o700 and
            directory.st_uid == os.geteuid() and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o600, 'Hardware ownership record is not private.')
    record = json.loads(read(path, 16384))
    require(isinstance(record, dict), 'Malformed hardware ownership record.')
    return record


class Reservation:
    """The one verified Linux function a bind transaction may change."""

    def __init__(self, item, digest, state, sysfs):
        self.bdf = item['pci']
        self.group = item['iommu_group']
        self.interface = item['name']
        self.mac = item['mac']
        self.driver = item['driver']
        require(isinstance(self.interface, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', self.interface)
                and isinstance(self.mac, str) and re.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}', self.mac)
                and isinstance(self.driver, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', self.driver)
                and self.driver != 'vfio-pci', 'Declare the expected Linux interface, MAC and kernel driver.')
        self.sysfs = sysfs
        self.device = pci_device(self.bdf, self.group, sysfs=sysfs)
        self.path = state/(self.bdf+'.json')
        self.identity = {'boot_id': BOOT_ID.read_text().strip(), 'manifest_sha256': digest,
                         'binding': item, 'instance': instance(self.device)}

    def record(self):
        record = read_record(self.path)
        if record is None:
            return None
        require(isinstance(record, dict) and record.get('identity') == self.identity
                and record.get('phase') in ('prepared', 'pending', 'restoring', 'restored', 'bound')
                and record.get('prior_override') in ('', self.driver)
                and type(record.get('attempts')) is int and 0 <= record['attempts'] <= 2
                and isinstance(record.get('observed_at'), str), 'Stale or invalid hardware ownership record.')
        return record

    def save(self, record):
        # The directory lock covers both this temporary file and the PCI changes.
        pending = self.path.with_suffix('.pending')
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(record))
        os.replace(pending, self.path)

    def observe(self):
        device = pci_device(self.bdf, self.group, sysfs=self.sysfs)
        require(instance(device) == self.identity['instance'], 'PCI function or IOMMU group was replaced.')
        return driver_name(device), override(device), netdevs(device)

    def linux_interface(self, names, *, restoring=False):
        require(len(names) == 1 and (restoring or names == [self.interface]) and
                (self.device/'net'/names[0]).samefile(self.sysfs/'class/net'/names[0]) and
                (self.device/'net'/names[0]/'address').read_text().strip().lower() == self.mac,
                'PCI interface or MAC differs from the declared device.')
        return names[0]

    def inspect(self, record):
        driver, current, names = self.observe()
        if driver == 'vfio-pci':
            require(not (self.device/'net').exists() and (not record or record['phase'] in ('pending', 'bound')),
                    'Unexpected VFIO state.')
            if record:
                require(current == 'vfio-pci', 'PCI driver override changed.')
            return driver
        prior = record['prior_override'] if record else current
        require(prior in ('', self.driver), 'Foreign PCI driver override.')
        if record and record['phase'] in ('pending', 'restoring'):
            require(current in (prior, 'vfio-pci'), 'PCI driver override changed.')
            if record['phase'] == 'pending' and record['attempts']:
                require(driver is None, 'PCI driver changed after the verified detach.')
            if driver is None:
                require(not names and (current == 'vfio-pci' or record['phase'] == 'restoring'),
                        'Unexplained driverless PCI function.')
                return None
        else:
            require(current == prior and (not record or record['phase'] in ('prepared', 'restored')),
                    'PCI binding changed outside the reservation.')
        require(driver == self.driver, 'PCI function has an unexpected kernel driver.')
        self.linux_interface(names, restoring=record is not None and record['phase'] == 'restoring')
        return driver

    def driver_write(self, driver, operation):
        (self.sysfs/'bus/pci/drivers'/driver/operation).write_text(self.bdf+'\n')

    def restore(self, record, run):
        # A crash between clearing the override and binding Linux resumes here.
        driver = self.inspect(record)
        require(driver in (None, self.driver), 'Unexpected driver during Linux restoration.')
        record['phase'] = 'restoring'
        self.save(record)
        self.inspect(record)
        if override(self.device) != record['prior_override']:
            (self.device/'driver_override').write_text(record['prior_override']+'\n')
        if self.inspect(record) is None:
            self.driver_write(self.driver, 'bind')
        driver, current, names = self.observe()
        require(driver == self.driver and current == record['prior_override'], 'Linux PCI restore failed.')
        name = self.linux_interface(names, restoring=True)
        run(['ip', 'link', 'set', 'dev', name, 'down'], check=True, timeout=15)
        record['phase'] = 'restored'
        self.save(record)
        raise ReleaseError('VFIO binding failed. Restored the Linux driver and lowered its link.')

    def bind(self, run):
        record = self.record()
        driver = self.inspect(record)
        if driver == 'vfio-pci':
            if record and record['phase'] != 'bound':
                record['phase'] = 'bound'
                self.save(record)
            return
        if record and record['phase'] == 'restoring':
            self.restore(record, run)
        if driver == self.driver:
            if not record or record['phase'] == 'restored':
                record = {'identity': self.identity, 'observed_at': timestamp(),
                          'prior_override': override(self.device), 'phase': 'prepared', 'attempts': 0}
                self.save(record)
            require(self.inspect(record) == self.driver, 'PCI ownership changed before link setup.')
            run(['ip', 'link', 'set', 'dev', self.interface, 'down'], check=True, timeout=15)
            try:
                run(['modprobe', 'vfio-pci'], check=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                self.restore(record, run)
            require(self.inspect(record) == self.driver, 'PCI ownership changed before detachment.')
            record['phase'] = 'pending'
            self.save(record)
            require(self.inspect(record) == self.driver, 'PCI ownership changed before override.')
            try:
                (self.device/'driver_override').write_text('vfio-pci\n')
                require(self.inspect(record) == self.driver and override(self.device) == 'vfio-pci',
                        'PCI ownership changed before detachment.')
                self.driver_write(self.driver, 'unbind')
            except OSError:
                if self.inspect(record) == self.driver:
                    self.restore(record, run)
        while record['attempts'] < 2:
            driver = self.inspect(record)
            if driver == 'vfio-pci':
                break
            require(driver is None, 'PCI function was not detached.')
            record['attempts'] += 1
            self.save(record)
            driver = self.inspect(record)
            if driver == 'vfio-pci':
                break
            require(driver is None, 'PCI driver changed before binding VFIO.')
            try:
                self.driver_write('vfio-pci', 'bind')
            except OSError:
                pass  # The driver link, isolation and override determine the actual outcome.
        if self.inspect(record) != 'vfio-pci':
            self.restore(record, run)
        record['phase'] = 'bound'
        self.save(record)


def bind_owned(manifest, *, sysfs=Path('/sys'), state=STATE, run=subprocess.run):
    ownership = check_ownership_manifest(manifest)
    ownership_memory(ownership, sysfs=sysfs)
    digest = hashlib.sha256(canonical(manifest)).hexdigest()
    with binding_lock(state):
        reservations = [Reservation(item, digest, state, sysfs) for item in ownership['bindings']]
        for reservation in reservations:
            reservation.inspect(reservation.record())
        for reservation in reservations:
            reservation.bind(run)
        ownership_status(manifest, sysfs=sysfs)


def bind_device(bdf, group, interface, mac, driver, *, sysfs=Path('/sys'), state=STATE, run=subprocess.run):
    item = {'pci': bdf, 'iommu_group': str(group), 'name': interface, 'mac': mac, 'driver': driver}
    digest = hashlib.sha256(canonical(item)).hexdigest()
    with binding_lock(state):
        Reservation(item, digest, state, sysfs).bind(run)


def network_status(value, *, sysfs=Path('/sys'), run=subprocess.run):
    for interface in value['interfaces']:
        if interface.get('owner') == 'vpp':
            continue
        device = sysfs/'class/net'/interface['name']
        require(device.is_dir(), 'A declared Linux network interface is absent.')
        kind, expected = next(iter(interface['match'].items()))
        if kind == 'mac':
            observed = (device/'address').read_text().strip().lower()
        elif kind == 'driver':
            observed = (device/'device/driver').resolve(strict=True).name
        else:
            result = run(['udevadm', 'info', '--query=property', '--path', str(device)],
                         check=True, capture_output=True, text=True, timeout=15)
            properties = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            observed = properties.get('ID_PATH', '')
        require(fnmatch.fnmatchcase(observed, expected), 'A declared interface selector does not match.')
    acceleration = value.get('acceleration')
    if acceleration:
        if value['vpp_enabled']:
            for bdf in acceleration['pci']:
                vfio_device(bdf, sysfs=sysfs)
        pages = sysfs/'kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'
        require(int(pages.read_text()) == acceleration['hugepages_mib']//2,
                'Declared hugepage allocation differs.')


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    bind = commands.add_parser('bind')
    for option in ('bdf', 'group', 'interface', 'mac', 'driver'):
        bind.add_argument('--'+option, required=True)
    verify = commands.add_parser('verify')
    verify.add_argument('--bdf', required=True)
    verify.add_argument('--group', required=True)
    commands.add_parser('status').add_argument('--details', action='store_true')
    commands.add_parser('bind-owned')
    args = parser.parse_args(arguments)
    try:
        if args.command == 'bind':
            bind_device(args.bdf, args.group, args.interface, args.mac, args.driver)
        elif args.command == 'verify':
            vfio_device(args.bdf, args.group)
        else:
            if args.command == 'bind-owned':
                bind_owned(json.loads(read(Path('/usr/share/lanrith/ownership.json'), 1024*1024)))
            else:
                value = json.loads(read(Path('/usr/share/lanrith/hardware.json'), 1024*1024))
                path = Path('/usr/share/lanrith/ownership.json')
                manifest = json.loads(read(path, 1024*1024)) if path.exists() else None
                if args.details:
                    from .hardware_diagnostics import collect
                    print(json.dumps(collect(value, manifest), sort_keys=True))
                network_status(value)
                if manifest is not None:
                    ownership_status(manifest)
                if args.details:
                    return 0
        print('Declared router hardware verified.')
    except ReleaseError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print('Declared router hardware verification failed.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
