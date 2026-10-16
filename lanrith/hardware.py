"""Inspect declared hardware and bind only an explicitly isolated PCI function."""

import argparse
import fnmatch
import json
from pathlib import Path
import re
import subprocess
import sys

from .release import ReleaseError, read, require


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


def bind_device(bdf, group, interface, mac, driver, *, sysfs=Path('/sys'), run=subprocess.run):
    require(isinstance(interface, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', interface) and
            isinstance(mac, str) and re.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}', mac) and
            isinstance(driver, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', driver) and
            driver != 'vfio-pci', 'Declare the expected Linux interface, MAC and kernel driver.')
    device = pci_device(bdf, group, sysfs=sysfs)
    observed_driver = (device/'driver').resolve(strict=True).name
    if observed_driver == 'vfio-pci':
        vfio_device(bdf, group, sysfs=sysfs)
        return
    require(observed_driver == driver, 'PCI function has an unexpected kernel driver.')
    require(sorted(path.name for path in (device/'net').iterdir()) == [interface] and
            (sysfs/'class/net'/interface/'address').read_text().strip().lower() == mac,
            'PCI interface or MAC differs from the declared device.')
    # No state changes occur until every device identity and isolation check passes.
    run(['ip', 'link', 'set', 'dev', interface, 'down'], check=True, timeout=15)
    run(['modprobe', 'vfio-pci'], check=True, timeout=15)
    (device/'driver_override').write_text('vfio-pci\n')
    (device/'driver/unbind').write_text(bdf+'\n')
    (sysfs/'bus/pci/drivers_probe').write_text(bdf+'\n')
    vfio_device(bdf, group, sysfs=sysfs)


def network_status(value, *, sysfs=Path('/sys'), run=subprocess.run):
    for interface in value['hardware']['interfaces'].values():
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
    acceleration = value['hardware'].get('acceleration')
    if acceleration:
        if value['services'].get('vpp', {}).get('enabled'):
            for bdf in acceleration['pci']:
                vfio_device(bdf, sysfs=sysfs)
        pages = sysfs/'kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'
        require(int(pages.read_text()) >= acceleration['hugepages_mib']//2,
                'Declared hugepage allocation is unavailable.')


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    bind = commands.add_parser('bind')
    for option in ('bdf', 'group', 'interface', 'mac', 'driver'):
        bind.add_argument('--'+option, required=True)
    verify = commands.add_parser('verify')
    verify.add_argument('--bdf', required=True)
    verify.add_argument('--group', required=True)
    commands.add_parser('status')
    args = parser.parse_args(arguments)
    try:
        if args.command == 'bind':
            bind_device(args.bdf, args.group, args.interface, args.mac, args.driver)
        elif args.command == 'verify':
            vfio_device(args.bdf, args.group)
        else:
            value = json.loads(read(Path('/usr/share/lanrith/resolved.json'), 1024*1024))
            network_status(value)
        print('Declared router hardware verified.')
    except (ReleaseError, OSError, ValueError, subprocess.SubprocessError):
        print('Declared router hardware verification failed.', file=sys.stderr)
        return 1
    return 0
