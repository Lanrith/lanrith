"""Sample the configured ports and VFIO character devices during privileged maintenance."""

import hashlib
import os
from pathlib import Path
import stat
import time

from . import hardware
from .release import canonical, require


def sample(operation):
    try:
        return operation()
    except (OSError, ValueError):
        return None


def page_counts(pool, sysfs):
    directory = sysfs/f'kernel/mm/hugepages/hugepages-{pool["page_size_mib"]*1024}kB'
    return {**pool, **{key: sample(lambda: int((directory/key).read_text()))
                       for key in ('nr_hugepages', 'free_hugepages', 'resv_hugepages')}}


def pre_bind(bdf, item, digest, state, sysfs):
    if item is None:
        # The explicit VPP profile passes its selectors directly to the bind CLI.
        record = hardware.read_record(state/(bdf+'.json'))
        if record is None:
            return None
        identity = record.get('identity')
        item = identity.get('binding') if isinstance(identity, dict) else None
        require(isinstance(item, dict) and set(item) == {'pci', 'iommu_group', 'name', 'mac', 'driver'}
                and item['pci'] == bdf, 'Explicit VPP binding has no matching observation.')
        digest = hashlib.sha256(canonical(item)).hexdigest()
    reservation = hardware.Reservation(item, digest, state, sysfs)
    record = reservation.record()
    if record:
        return {'name': reservation.interface, 'mac': reservation.mac, 'driver': reservation.driver,
                'boot_id': record['identity']['boot_id'], 'observed_at': record['observed_at'],
                'phase': record['phase']}


def character_devices(device, group, devfs):
    numbers = set()
    try:
        legacy = (devfs/'vfio'/group).stat()
    except FileNotFoundError:
        pass
    else:
        require(stat.S_ISCHR(legacy.st_mode), 'Invalid VFIO group character device.')
        numbers.add(legacy.st_rdev)
    cdevs = device/'vfio-dev'
    if cdevs.is_dir():
        for child in cdevs.iterdir():
            try:
                major, minor = (child/'dev').read_text().split(':')
            except FileNotFoundError:
                continue  # The kernel can expose a vfio-dev entry without cdev support.
            numbers.add(os.makedev(int(major), int(minor)))
    return numbers


def process_devices(directory, by_number, matches, pid, deadline):
    complete = True
    with os.scandir(directory) as descriptors:
        for fd in descriptors:
            if time.monotonic() >= deadline:
                raise TimeoutError
            try:
                info = fd.stat()
            except FileNotFoundError:
                continue  # The process exited or closed this FD.
            except PermissionError:
                complete = False
                continue
            if stat.S_ISCHR(info.st_mode) and info.st_rdev in by_number:
                matches[by_number[info.st_rdev]].add(pid)
    return complete


def holders(selections, proc):
    """Sample open group and device cdev FDs in the caller's PID namespace."""
    by_number = {number: bdf for bdf, numbers in selections.items() for number in numbers}
    matches = {bdf: set() for bdf in selections}
    complete = True
    deadline = time.monotonic() + 3
    if by_number:
        try:
            with os.scandir(proc) as processes:
                for process in processes:
                    if time.monotonic() >= deadline:
                        raise TimeoutError
                    if process.name.isdecimal():
                        try:
                            if not process_devices(Path(process.path)/'fd', by_number, matches,
                                                   int(process.name), deadline):
                                complete = False
                        except FileNotFoundError:
                            continue
                        except PermissionError:
                            complete = False
        except OSError:
            complete = False
    when = hardware.timestamp()
    return {bdf: {'sampled_at': when, 'scan': 'complete' if complete and numbers else 'unknown',
                  'observed_pids': sorted(matches[bdf])} for bdf, numbers in selections.items()}


def collect(value, manifest, *, sysfs=Path('/sys'), proc=Path('/proc'), devfs=Path('/dev'), state=hardware.STATE):
    require(os.geteuid() == 0, 'Detailed hardware diagnostics require root.')
    result = {'sampled_at': hardware.timestamp(), 'linux_ports': [], 'pci': [], 'hugepages': None}
    for interface in value['interfaces']:
        if interface.get('owner') == 'vpp':
            continue
        port = sysfs/'class/net'/interface['name']
        result['linux_ports'].append({'name': interface['name'],
                                      'driver': sample(lambda: (port/'device/driver').resolve(strict=True).name),
                                      'mtu': sample(lambda: int((port/'mtu').read_text()))})
    bindings = {}
    acceleration = value.get('acceleration')
    selected = []
    digest = None
    if manifest is not None:
        ownership = hardware.check_ownership_manifest(manifest)
        bindings = {item['pci']: item for item in ownership['bindings']}
        digest = hashlib.sha256(canonical(manifest)).hexdigest()
        selected = list(bindings)
        result['mode'] = 'dormant-reservation'
        result['hugepages'] = page_counts(ownership['hugepages'], sysfs)
    elif acceleration:
        result['mode'] = 'active-vpp' if value['vpp_enabled'] else 'page-reservation'
        selected = acceleration['pci'] if value['vpp_enabled'] else []
        result['hugepages'] = page_counts({'page_size_mib': 2, 'pages': acceleration['hugepages_mib']//2}, sysfs)
    else:
        result['mode'] = 'linux'
    selections = {}
    for bdf in selected:
        device = sysfs/'bus/pci/devices'/bdf
        group = sample(lambda: (device/'iommu_group').resolve(strict=True))
        row = {'pci': bdf, 'driver': sample(lambda: (hardware.driver_name(device) or 'unbound') if device.is_dir() else None),
               'netdevs': sample(lambda: hardware.netdevs(device) if device.is_dir() else None),
               'iommu_group': group.name if group else None,
               'iommu_members': sample(lambda: sorted(p.name for p in (group/'devices').iterdir())) if group else None,
               'pre_bind': sample(lambda: pre_bind(bdf, bindings.get(bdf), digest, state, sysfs))}
        result['pci'].append(row)
        if row['driver'] == 'vfio-pci':
            # A group FD cannot attribute a consumer to one function in a changed/shared group.
            expected = bindings[bdf]['iommu_group'] if bdf in bindings else None
            isolated = sample(lambda: hardware.pci_device(bdf, expected, sysfs=sysfs))
            selections[bdf] = set()
            if group and isolated is not None:
                selections[bdf] = sample(lambda: character_devices(isolated, group.name, devfs)) or set()
    consumers = holders(selections, proc)
    for row in result['pci']:
        row['vfio_descriptors'] = consumers.get(row['pci'])
    return result
