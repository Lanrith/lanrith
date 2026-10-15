#!/usr/bin/env python3
"""Parse and load synthetic network configurations in a disposable namespace."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config

if '--isolated' not in sys.argv:
    if os.geteuid() != 0:
        raise SystemExit('Native configuration checks require an isolated root namespace.')
    subprocess.run(['unshare', '--net', '--', sys.executable, str(Path(__file__).resolve()), '--isolated'], check=True)
    raise SystemExit(0)

for example in ('minimal.yaml', 'segmented.yaml'):
    value = config.load(Path(__file__).resolve().parents[1]/'examples'/example)
    with tempfile.TemporaryDirectory(prefix='lanrith-native.') as temporary:
        output = Path(temporary)/'root'
        config.write(value, output)
        names = {network['name'] for network in value['networks'].values()}
        names.add(value['hardware']['interfaces'][value['uplink']['interface']]['name'])
        try:
            for name in names:
                subprocess.run(['ip', 'link', 'add', name, 'type', 'dummy'], check=True)
                subprocess.run(['ip', 'link', 'set', name, 'up'], check=True)
            subprocess.run(['nft', '--check', '--file', str(output/'etc/nftables.conf')], check=True)
            subprocess.run(['nft', '--file', str(output/'etc/nftables.conf')], check=True)
            subprocess.run(['unbound-checkconf', str(output/'etc/unbound/unbound.conf.d/lanrith.conf')], check=True)
        # Ubuntu's Kea AppArmor profile permits /etc/kea, not arbitrary /tmp files.
        # Use the production configuration boundary without changing that policy.
        descriptor, name = tempfile.mkstemp(prefix='lanrith-native.', suffix='.json', dir='/etc/kea')
        os.close(descriptor)
        candidate = Path(name)
        try:
            shutil.copyfile(output/'etc/kea/kea-dhcp4.conf', candidate)
            candidate.chmod(0o644)
            subprocess.run(['kea-dhcp4', '-t', str(candidate)], check=True)
        finally:
            candidate.unlink()
        finally:
            for name in names:
                subprocess.run(['ip', 'link', 'delete', name], check=False, capture_output=True)
print('Both synthetic topologies passed native firewall, DNS and DHCP parsing.')
