#!/usr/bin/python3
"""Exercise PCI detach recovery only inside the isolated QEMU e1000e fixture."""

import json
import mmap
import os
from pathlib import Path
import shutil
import sys
from unittest.mock import patch

from lanrith import boot_health, build, config, hardware
from ssh_listeners_systemd import run, stage as stage_ssh, write

ROOT = Path(__file__).resolve().parents[1]
BDF = '0000:01:00.0'
MAC = '02:00:00:00:00:51'
DEVICE = Path('/sys/bus/pci/devices')/BDF
UNIT = 'lanrith-hardware-ownership.service'
STATUS = '/usr/lib/lanrith/router-network-status'


def guard():
    if (os.geteuid() != 0 or 'rdinit=/fixture-init' not in Path('/proc/cmdline').read_text()
            or run('systemd-detect-virt', '--vm').stdout.strip() != 'qemu'
            or not Path('/opt/fixture-platform').is_mount() or Path('/usr/share/lanrith/installed.json').exists()
            or (DEVICE/'vendor').read_text().strip() != '0x8086'):
        raise RuntimeError('Requires the isolated QEMU fixture.')


def injected(mode):
    guard()
    original = hardware.Reservation.driver_write

    def inject(reservation, driver, operation):
        assert reservation.bdf == BDF and reservation.mac == MAC
        if mode == '--fail-vfio' and (driver, operation) == ('vfio-pci', 'bind'):
            raise OSError('Synthetic failed VFIO probe')
        original(reservation, driver, operation)
        if mode == '--interrupt' and operation == 'unbind':
            os._exit(77)

    with patch.object(hardware.Reservation, 'driver_write', inject):
        hardware.bind_owned(json.loads(Path('/usr/share/lanrith/ownership.json').read_bytes()))


def details(check=True):
    return json.loads(run(STATUS, '--details', check=check).stdout)


def qualify():
    guard()
    run('modprobe', 'e1000e')
    run('udevadm', 'settle')
    name, = hardware.netdevs(DEVICE)
    assert (DEVICE/'net'/name/'address').read_text().strip() == MAC
    assert hardware.driver_name(DEVICE) == 'e1000e'
    group = int((DEVICE/'iommu_group').resolve(strict=True).name)
    hardware.pci_device(BDF, group)
    assert int(Path('/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages').read_text()) == 1024
    value = config.load(ROOT/'examples/minimal.yaml')
    value['hardware']['interfaces']['core'] = {'name': name, 'owner': 'vpp', 'state': 'down', 'match': {'mac': MAC}}
    value['networks']['home'].pop('dhcp4')
    value['networks']['home'].update(dns=False, ra=False)
    value['services'].update(dns={'enabled': False}, dhcp4={'enabled': False})
    value['administration']['serial'] = {'enabled': False}
    facts = {'interfaces': [{'name': name, 'mac': MAC, 'pci': BDF, 'driver': 'e1000e',
                             'iommu_group': group, 'iommu_members': [BDF]}],
             'hugepages': {'page_size_mib': 2, 'pages': 1024}}
    value = config.normalize(value)
    files = config.render(value, target_facts=facts)
    work = Path('/run/hardware-fixture')
    work.mkdir()
    base = work/'base.tar'
    base.write_bytes(b'synthetic')
    build.assembly(value, base, work/'image', version='0.1.0', sequence=7, target_facts=facts)
    overlay = work/'image/mkosi.extra'
    shutil.copytree(overlay/'usr/lib/lanrith', '/usr/lib/lanrith', dirs_exist_ok=True)
    for path in ('usr/share/lanrith/ownership.json', 'usr/share/lanrith/hardware.json', 'etc/nftables.conf'):
        write('/'+path, files[path])
    units = Path('/run/systemd/system')
    write(units/UNIT, files['usr/lib/systemd/system/'+UNIT])
    write(units/'nftables.service', Path('/opt/fixture-platform/usr/lib/systemd/system/nftables.service').read_text())
    write('/etc/systemd/network/10-core.link', files['etc/systemd/network/10-core.link'])
    run('udevadm', 'control', '--reload')
    stage_ssh(files)
    write(units/'lanrith-ssh-host-key.service', '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
          'ExecStart=/usr/bin/test -s /var/lib/lanrith/ssh-host-keys/ssh_host_ed25519_key\n')
    run('systemctl', 'mask', '--runtime', 'ssh.socket')
    for port in ('wan', 'lan'):
        run('ip', 'link', 'add', port, 'address', value['hardware']['interfaces'][port]['match']['mac'],
            'type', 'dummy')
        run('ip', 'link', 'set', port, 'up')
    for address in value['networks']['home']['addresses']:
        run('ip', 'address', 'add', address, 'dev', 'lan', *(['nodad'] if ':' in address else []))
    ports = {port: (Path('/sys/class/net')/port/'ifindex').read_text() for port in ('wan', 'lan')}
    plan = json.loads(files['usr/share/lanrith/health.json'])

    def start():
        outcome = run('systemctl', 'start', UNIT, check=False)
        if outcome.returncode:
            raise RuntimeError(run('journalctl', '-b', '-u', UNIT, '-u', 'nftables', '-n', '35', '-o', 'cat').stdout)

    drop = units/(UNIT+'.d')/'fixture.conf'

    def fail(mode):
        write(drop, '[Service]\nExecStart=\nExecStart=/usr/bin/python3 '+str(Path(__file__).resolve())+' '+mode+'\n'
              'Environment=PYTHONPATH=/source:/source/tests\n')
        run('systemctl', 'daemon-reload')
        assert run('systemctl', 'start', UNIT, check=False).returncode
        assert run('systemctl', 'is-failed', UNIT).stdout.strip() == 'failed'
        log = run('journalctl', '-b', '-u', UNIT, '-n', '18', '-o', 'cat').stdout
        assert (hardware.STATE/(BDF+'.json')).is_file(), log
        if mode == '--interrupt':
            assert run('systemctl', 'show', '-P', 'ExecMainStatus', UNIT).stdout.strip() == '77', log
        else:
            assert json.loads((hardware.STATE/(BDF+'.json')).read_text())['phase'] == 'restored', log

    ownership_path = Path('/usr/share/lanrith/ownership.json')
    hardware_path = Path('/usr/share/lanrith/hardware.json')
    linux = json.loads(hardware_path.read_bytes())
    ownership_path.unlink()
    hardware_path.write_text(json.dumps({**linux, 'interfaces': linux['interfaces']+[
        {'name': name, 'match': {'mac': MAC}}]}))
    baseline = details()
    assert baseline['mode'] == 'linux' and baseline['pci'] == [] and baseline['hugepages'] is None
    assert {'name': name, 'driver': 'e1000e', 'mtu': 1500} in baseline['linux_ports']
    denied = run('setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', STATUS, '--details', check=False)
    assert denied.returncode and not denied.stdout and 'require root' in denied.stderr
    hardware_path.write_text(json.dumps(linux))
    ownership_path.write_text(files['usr/share/lanrith/ownership.json'])
    fail('--fail-vfio')
    assert hardware.driver_name(DEVICE) == 'e1000e' and hardware.override(DEVICE) == ''
    restored, = hardware.netdevs(DEVICE)
    assert not int((DEVICE/'net'/restored/'flags').read_text(), 16) & 1
    assert run(STATUS, check=False).returncode
    print('Two failed VFIO binds restored e1000e, its empty override and a down netdev.', flush=True)
    run('udevadm', 'settle')
    fail('--interrupt')
    assert hardware.driver_name(DEVICE) is None and hardware.netdevs(DEVICE) == []
    assert hardware.override(DEVICE) == 'vfio-pci'
    assert details(check=False)['pci'][0]['driver'] == 'unbound'
    try:
        boot_health.check_features(plan)
    except boot_health.LocalRequirementFailed:
        pass
    else:
        raise AssertionError('Core ownership check accepted a detached device.')
    drop.unlink()
    run('systemctl', 'daemon-reload')
    start()
    run('systemctl', 'start', 'systemd-networkd.service', 'ssh.service')
    boot_health.check(plan)
    assert all((Path('/sys/class/net')/port/'ifindex').read_text() == index for port, index in ports.items())
    assert run(STATUS).stdout.strip() == 'Declared router hardware verified.'
    first = details()
    print(json.dumps(first, sort_keys=True), flush=True)
    row, = first['pci']
    assert first['mode'] == 'dormant-reservation' and row['driver'] == 'vfio-pci' and row['netdevs'] == []
    assert row['pre_bind']['mac'] == MAC and row['pre_bind']['driver'] == 'e1000e'
    assert row['pre_bind']['phase'] == 'bound' and row['iommu_members'] == [BDF]
    assert all(port['mtu'] == 1500 for port in first['linux_ports'])
    assert row['vfio_descriptors']['scan'] == 'complete' and row['vfio_descriptors']['observed_pids'] == []
    run('systemctl', 'restart', UNIT)
    assert details()['pci'][0]['pre_bind'] == row['pre_bind']
    with open('/dev/vfio/'+str(group), 'rb+', buffering=0):
        assert os.getpid() in details()['pci'][0]['vfio_descriptors']['observed_pids']
    assert details()['pci'][0]['vfio_descriptors']['observed_pids'] == []
    for entry in (DEVICE/'vfio-dev').glob('vfio*'):
        cdev = Path('/dev/vfio/devices')/entry.name
        if cdev.exists():
            with cdev.open('rb+', buffering=0):
                assert os.getpid() in details()['pci'][0]['vfio_descriptors']['observed_pids']
            print('Selected VFIO device cdev descriptor observed.', flush=True)
    pool = first['hugepages']
    with mmap.mmap(-1, 2*1024*1024, flags=mmap.MAP_ANONYMOUS | mmap.MAP_PRIVATE | 0x40000) as page:
        reserved = details()['hugepages']
        assert reserved['resv_hugepages'] == pool['resv_hugepages']+1
        page[0] = 1
        allocated = details()['hugepages']
        assert allocated['free_hugepages'] == pool['free_hugepages']-1
        assert allocated['nr_hugepages'] == pool['nr_hugepages'] == 1024
    # Simulate an already-VFIO function bound outside this binder.
    (hardware.STATE/(BDF+'.json')).unlink()
    run('systemctl', 'restart', UNIT)
    assert details()['pci'][0]['pre_bind'] is None
    boot_health.check(plan)
    ownership_path.unlink()
    accel = {'pci': [BDF], 'hugepages_mib': 2048}
    hardware_path.write_text(json.dumps({**linux, 'acceleration': accel}))
    page_only = details()
    assert page_only['mode'] == 'page-reservation' and page_only['pci'] == []
    hardware_path.write_text(json.dumps({**linux, 'acceleration': accel, 'vpp_enabled': True}))
    active = details()
    assert active['mode'] == 'active-vpp' and active['pci'][0]['pre_bind'] is None
    # Exercise the explicit bind CLI from the original active VPP integration.
    drivers = Path('/sys/bus/pci/drivers')
    (drivers/'vfio-pci/unbind').write_text(BDF+'\n')
    (DEVICE/'driver_override').write_text('\n')
    (drivers/'e1000e/bind').write_text(BDF+'\n')
    run('udevadm', 'settle')
    run('/usr/bin/python3', '-m', 'lanrith.hardware', 'bind', '--bdf', BDF, '--group', str(group),
        '--interface', name, '--mac', MAC, '--driver', 'e1000e')
    active = details()
    assert active['pci'][0]['driver'] == 'vfio-pci' and active['pci'][0]['pre_bind']['mac'] == MAC
    print('Linux-only, page-only and explicit VPP binding modes passed.', flush=True)
    print('Normal unit restart recovered the interrupted bind. The compiled core gate passed with real '
          'nftables, networkd and SSH. Matching group FD open/close and HugeTLB reserve/fault were visible.', flush=True)


if __name__ == '__main__':
    if sys.argv[1:] in (['--fail-vfio'], ['--interrupt']):
        sys.exit(injected(sys.argv[1]))
    if sys.argv[1:] != ['--disposable-systemd']:
        raise SystemExit('Requires --disposable-systemd and the emulated PCI fixture.')
    qualify()
