#!/usr/bin/env python3
"""Parse and load synthetic network configurations in a disposable namespace."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil
import ipaddress
import time

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
            # No gateway addresses have been assigned yet, as can happen
            # before IPv6 DAD completes during boot. Explicit DNS listeners
            # must start without opening wildcard addresses.
            # Respect Ubuntu's existing Unbound AppArmor configuration boundary.
            descriptor, name = tempfile.mkstemp(prefix='lanrith-native.', suffix='.conf', dir='/etc/unbound')
            os.close(descriptor)
            candidate_dns = Path(name)
            candidate_dns.write_text((output/'etc/unbound/unbound.conf.d/lanrith.conf').read_text()+
                '  port: 1053\n  username: ""\n  directory: "/etc/unbound"\n  use-syslog: no\n')
            daemon = subprocess.Popen(['unbound', '-d', '-p', '-c', str(candidate_dns)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            try:
                expected = {'127.0.0.1', '::1'} | {
                    str(ipaddress.ip_interface(address).ip) for network in value['networks'].values()
                    if network.get('dns') for address in network['addresses']}
                deadline = time.monotonic()+10
                while True:
                    sockets = subprocess.run(['ss', '--no-header', '--listening', '--udp', '--tcp', '--numeric',
                                               'sport = :1053'], check=True, capture_output=True, text=True)
                    observed = {(row[0], row[4].removesuffix(':1053').strip('[]'))
                                for line in sockets.stdout.splitlines() if (row := line.split())}
                    if observed == {(protocol, address) for protocol in ('tcp', 'udp') for address in expected}:
                        break
                    if daemon.poll() is not None or time.monotonic() >= deadline:
                        raise AssertionError('DNS did not bind only its declared addresses before network readiness.')
                    time.sleep(0.05)
            finally:
                daemon.terminate()
                daemon.communicate(timeout=10)
                candidate_dns.unlink()
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
