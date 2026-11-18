#!/usr/bin/env python3
"""Verify native udev naming with an inherited parent/VLAN MAC address."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import config


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


if '--isolated' not in sys.argv:
    assert os.geteuid() == 0, 'Native link checks require an isolated root namespace.'
    subprocess.run(['unshare', '--mount', '--net', '--', sys.executable, __file__, '--isolated'], check=True)
    print('Native udev selects the physical-link rule for its parent, never its VLAN.')
    raise SystemExit(0)

run('mount', '--make-rprivate', '/')
# sysfs must expose this new network namespace's links to udev.
run('mount', '-t', 'sysfs', '-o', 'ro,nosuid,nodev,noexec', 'sysfs', '/sys')
value = config.load(ROOT/'examples/minimal.yaml')
key = next(key for key, interface in value['hardware']['interfaces'].items()
           if 'mac' in interface['match'])
interface = value['hardware']['interfaces'][key]
run('ip', 'link', 'add', 'fixture-parent', 'type', 'veth', 'peer', 'name', 'fixture-peer')
run('ip', 'link', 'set', 'fixture-parent', 'address', interface['match']['mac'])
run('ip', 'link', 'add', 'link', 'fixture-parent', 'name', 'fixture-vlan', 'type', 'vlan', 'id', '10')
with tempfile.TemporaryDirectory(prefix='lanrith-link.') as temporary:
    target = Path('/etc/systemd/network')
    assert target.is_dir()
    run('mount', '--bind', temporary, str(target))
    try:
        path = target/'05-fixture.link'
        generated = config.render(value)['etc/systemd/network/10-'+key+'.link']
        # Positive control: the parent's MAC selector also matches its VLAN.
        path.write_text(generated.replace('Kind=!vlan\n', ''))
        before = run('udevadm', 'test-builtin', 'net_setup_link', '/sys/class/net/fixture-vlan')
        assert 'ID_NET_LINK_FILE='+str(path) in before
        path.write_text(generated)
        after = run('udevadm', 'test-builtin', 'net_setup_link', '/sys/class/net/fixture-vlan')
        assert 'ID_NET_LINK_FILE='+str(path) not in after
        parent = run('udevadm', 'test-builtin', 'net_setup_link', '/sys/class/net/fixture-parent')
        assert 'ID_NET_LINK_FILE='+str(path) in parent
    finally:
        run('umount', str(target))
